import os
import sys
import json
import time
import shlex
import shutil
import signal
import asyncio
import secrets
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

try:
    # mcp >= 2.0 renamed FastMCP to MCPServer
    from mcp.server.mcpserver import MCPServer
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer

mcp = MCPServer("FVolForensics")


# Path to the fvol binary. Set FVOL_PATH, or put fvol on your PATH.
FVOL_PATH = os.environ.get("FVOL_PATH") or shutil.which("fvol") or "fvol"
# Optional semicolon-separated symbol directories (needed for Linux/macOS images).
FVOL_SYMBOL_DIRS = os.environ.get("FVOL_SYMBOL_DIRS", "")
# Seconds before a single fvol run is killed. 0 disables the limit.
FVOL_TIMEOUT = float(os.environ.get("FVOL_TIMEOUT", "600"))
# Web UI mode: unset or 0 runs fvol on the command line. 1 starts `fvol serve` on first use and
# runs every plugin there, so the user can watch in the browser. A URL printed by `fvol serve`
# (http://127.0.0.1:8765/#token=...) attaches to a server that is already running.
FVOL_WEB = os.environ.get("FVOL_WEB", "").strip()
# Token for FVOL_WEB when the URL does not carry one.
FVOL_WEB_TOKEN = os.environ.get("FVOL_WEB_TOKEN", "")
# Output root for a server started by this MCP server (fvol serve -o).
FVOL_WEB_OUTPUT_DIR = os.path.expanduser(os.environ.get("FVOL_WEB_OUTPUT_DIR", "~/.cache/fvol-mcp/serve-output"))
# Extra arguments for a server started by this MCP server, such as "--port 8765 --parallel 4".
FVOL_WEB_ARGS = os.environ.get("FVOL_WEB_ARGS", "")
# 0 keeps the browser closed when this MCP server starts `fvol serve`.
FVOL_WEB_BROWSER = os.environ.get("FVOL_WEB_BROWSER", "1") != "0"

MEMORY_EXTENSIONS = [
    '.raw', '.vmem', '.dmp', '.mem', '.bin', '.img', '.001', '.dump', '.lime', '.core', '.elf',
    '.raw.gz', '.raw.xz', '.raw.bz2', '.mem.gz', '.mem.xz', '.mem.bz2',
]


async def run_fvol(cmd_args, global_args=None):
    """Run fvol with the given arguments and return its output or an error message"""
    cmd = [FVOL_PATH]
    if FVOL_SYMBOL_DIRS:
        cmd += ["-s", FVOL_SYMBOL_DIRS]
    cmd += (global_args or []) + cmd_args

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            # stdin must not be inherited: it carries the MCP stdio protocol.
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=FVOL_TIMEOUT or None
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return f"Error: fvol timed out after {FVOL_TIMEOUT:g} seconds"

        stdout_text = stdout.decode('utf-8', errors='replace')
        if process.returncode != 0:
            stderr_text = stderr.decode('utf-8', errors='replace')
            return f"Error running fvol (exit code {process.returncode}): {stderr_text or stdout_text}"

        return stdout_text
    except FileNotFoundError:
        return f"Error: fvol binary not found at '{FVOL_PATH}'. Set FVOL_PATH or add fvol to your PATH."
    except Exception as e:
        return f"Exception running fvol: {str(e)}"


def check_dump(memory_dump_path: str):
    """Normalize a memory dump path; return (path, error message or None)"""
    memory_dump_path = os.path.normpath(os.path.expanduser(memory_dump_path))
    if not os.path.isfile(memory_dump_path):
        return memory_dump_path, f"Error: Memory dump file not found at {memory_dump_path}"
    return memory_dump_path, None


def prepare_dump_dir(dump_dir: str):
    """Create the output directory if needed; return (path, error message or None)"""
    dump_dir = os.path.normpath(os.path.expanduser(dump_dir))
    try:
        os.makedirs(dump_dir, exist_ok=True)
    except Exception as e:
        return dump_dir, f"Error creating dump directory: {str(e)}"
    return dump_dir, None


class FvolWeb:
    """Runs plugins inside an `fvol serve` web UI through its HTTP API, so the user can watch
    each run appear in the browser. Tool output is the run's `fvol` output, the same text the
    command line prints."""

    def __init__(self):
        self.base = None      # http://127.0.0.1:8765
        self.token = None
        self.proc = None      # the `fvol serve` process, when this server started it
        self.lock = asyncio.Lock()
        self.busy = 0         # plugin runs in flight on the open image
        self.idle = asyncio.Condition()
        self.plugins = None   # name -> requirements, from /api/plugins

    @property
    def url(self):
        return f"{self.base}/#token={self.token}" if self.base else None

    # --- server lifecycle -------------------------------------------------------------

    async def attach(self, url: str) -> Optional[str]:
        """Use a running `fvol serve`; return an error message or None"""
        parts = urllib.parse.urlsplit(url.strip())
        token = urllib.parse.parse_qs(parts.fragment).get("token", [FVOL_WEB_TOKEN])[0]
        if parts.scheme not in ("http", "https") or not parts.netloc:
            return f"Error: '{url}' is not an fvol serve URL (http://127.0.0.1:8765/#token=...)"
        if not token:
            return "Error: no token: give the whole URL fvol serve printed, or set FVOL_WEB_TOKEN"
        await self.close()
        self.base, self.token = f"{parts.scheme}://{parts.netloc}", token
        try:
            await self.api("GET", "/api/session")
        except Exception as e:
            self.base = self.token = None
            return f"Error: cannot reach fvol serve at {url}: {e}"
        return None

    async def start(self) -> Optional[str]:
        """Start `fvol serve` and open it in the browser; return an error message or None"""
        await self.close()
        token = secrets.token_hex(16)
        cmd = [FVOL_PATH, "serve", "--token", token, "-o", FVOL_WEB_OUTPUT_DIR]
        if FVOL_SYMBOL_DIRS:
            cmd += ["-s", FVOL_SYMBOL_DIRS]
        cmd += shlex.split(FVOL_WEB_ARGS)
        os.makedirs(FVOL_WEB_OUTPUT_DIR, exist_ok=True)
        try:
            self.proc = await asyncio.create_subprocess_exec(
                *cmd,
                # stdin and stdout carry the MCP protocol: fvol serve must not touch them.
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                preexec_fn=die_with_parent,
            )
        except FileNotFoundError:
            return f"Error: fvol binary not found at '{FVOL_PATH}'. Set FVOL_PATH or add fvol to your PATH."

        # fvol serve prints "  open    http://127.0.0.1:8765/#token=..." once it listens.
        banner = []
        try:
            while True:
                line = (await asyncio.wait_for(self.proc.stdout.readline(), 30)).decode(errors="replace")
                if not line:
                    break
                banner.append(line)
                if line.strip().startswith("open") and "http" in line:
                    parts = urllib.parse.urlsplit(line.split()[-1])
                    self.base, self.token = f"{parts.scheme}://{parts.netloc}", token
                    break
        except asyncio.TimeoutError:
            pass
        if not self.base:
            await self.close()
            return "Error: fvol serve did not start:\n" + "".join(banner)

        asyncio.get_running_loop().create_task(self._drain(self.proc))
        if FVOL_WEB_BROWSER:
            open_browser(self.url)
        print(f"fvol serve: {self.url}", file=sys.stderr)
        return None

    async def _drain(self, proc):
        # keep the pipe empty so fvol serve never blocks on a full stdout
        async for line in proc.stdout:
            sys.stderr.write("fvol serve: " + line.decode(errors="replace"))

    async def close(self):
        """Forget the server; stop it if this MCP server started it"""
        proc, self.proc = self.proc, None
        self.base = self.token = None
        self.plugins = None
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), 5)
            except asyncio.TimeoutError:
                proc.kill()

    async def ensure(self) -> Optional[str]:
        """Make sure a server is there, starting one when FVOL_WEB asks for it"""
        if self.proc and self.proc.returncode is not None:
            print("fvol serve exited; starting it again", file=sys.stderr)
            self.base = None
        if self.base:
            return None
        if FVOL_WEB.startswith("http"):
            return await self.attach(FVOL_WEB)
        return await self.start()

    # --- HTTP -------------------------------------------------------------------------

    def _request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"X-Vol-Token": self.token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=max(FVOL_TIMEOUT, 60) if FVOL_TIMEOUT else None) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            text = e.read().decode(errors="replace")
            try:
                text = json.loads(text).get("error", text)
            except (ValueError, AttributeError):
                pass
            raise RuntimeError(f"HTTP {e.code}: {text}") from None

    async def api(self, method, path, body=None, raw=False):
        out = await asyncio.to_thread(self._request, method, path, body)
        return out if raw else json.loads(out)

    # --- analysis ---------------------------------------------------------------------

    async def open_image(self, path: str, deadline: float) -> Optional[str]:
        """Show the image in the web UI, waiting for runs on another image to finish first"""
        async with self.lock:
            session = await self.api("GET", "/api/session")
            same = session.get("image") and os.path.realpath(session["image"]) == os.path.realpath(path)
            if not same:
                async with self.idle:
                    await self.idle.wait_for(lambda: self.busy == 0)
                body = {"file": path}
                if FVOL_SYMBOL_DIRS:
                    body["symbol_dirs"] = [d for d in FVOL_SYMBOL_DIRS.split(";") if d]
                session = await self.api("POST", "/api/session", body)
            while session.get("state") == "warming":
                if time.monotonic() > deadline:
                    return f"Error: fvol serve is still opening {path} after {FVOL_TIMEOUT:g} seconds"
                await asyncio.sleep(0.3)
                session = await self.api("GET", "/api/session")
            if session.get("state") == "failed":
                return f"Error opening {path} in fvol serve: {session.get('error')}"
            self.busy += 1
            return None

    async def run_plugin(self, memory_dump_path, plugin, plugin_args, dump_dir=None, renderer="quick") -> str:
        try:
            error = await self.ensure()
            if error:
                return error
            args, error = await self.web_args(plugin, plugin_args)
            if error:
                return error
            if dump_dir:
                dump_dir, error = prepare_dump_dir(dump_dir)
                if error:
                    return error
                args["dump"] = True

            deadline = time.monotonic() + FVOL_TIMEOUT if FVOL_TIMEOUT else float("inf")
            error = await self.open_image(memory_dump_path, deadline)
            if error:
                return error
            try:
                return await self._run(plugin, args, plugin_args, dump_dir, renderer, deadline)
            finally:
                async with self.idle:
                    self.busy -= 1
                    self.idle.notify_all()
        except Exception as e:
            return f"Exception running fvol in the web UI ({self.url}): {e}"

    async def _run(self, plugin, args, plugin_args, dump_dir, renderer, deadline) -> str:
        label = " ".join([plugin.split(".")[-1]] + plugin_args + (["--dump"] if dump_dir else []))
        name = ("Claude: " + label)[:80]
        batch = await self.api("POST", "/api/batches", {"name": name, "entries": [{"plugin": plugin, "args": args}]})
        run_id = batch["runs"][0]

        while True:
            run = await self.api("GET", f"/api/runs/{run_id}")
            if run["status"] not in ("queued", "running"):
                break
            if time.monotonic() > deadline:
                await self.api("POST", f"/api/runs/{run_id}/cancel", {})
                return f"Error: fvol timed out after {FVOL_TIMEOUT:g} seconds"
            await asyncio.sleep(0.3)

        if run["status"] != "done":
            err = run.get("error") or {}
            detail = ": ".join(x for x in (err.get("title"), err.get("message")) if x) or run["status"]
            hints = "".join(f"\n  hint: {h}" for h in err.get("hints") or [])
            return f"Error running fvol ({plugin} {run['status']}): {detail}{hints}"

        # the same text `fvol -r <renderer>` prints; fvol's caches make this quick
        query = urllib.parse.urlencode({"renderer": renderer})
        result = (await self.api("GET", f"/api/runs/{run_id}/vol?{query}", raw=True)).decode("utf-8", errors="replace")

        if dump_dir and run.get("files"):
            for f in run["files"]:
                name = f["name"]
                data = await self.api("GET", f"/api/runs/{run_id}/files/{urllib.parse.quote(name)}", raw=True)
                with open(os.path.join(dump_dir, os.path.basename(name)), "wb") as out:
                    out.write(data)
            result += f"\n\nDumped {len(run['files'])} files to {dump_dir}"
        return result

    async def web_args(self, plugin, argv):
        """Turn command line plugin options (--pid 4 8 --dump) into the web API's args object"""
        if self.plugins is None:
            self.plugins = {p["name"]: p["reqs"] for p in await self.api("GET", "/api/plugins")}
        reqs = self.plugins.get(plugin)
        if reqs is None:
            return None, f"Error: unknown plugin {plugin}. Use list_available_plugins to see them."
        flags = {r["flag"]: r for r in reqs}
        args, i = {}, 0
        while i < len(argv):
            flag, _, inline = argv[i].partition("=")
            r = flags.get(flag)
            if r is None:
                known = ", ".join(sorted(flags)) or "none"
                return None, f"Error: {plugin} has no option {argv[i]} (options: {known})"
            i += 1
            if r["kind"] == "bool":
                args[r["name"]] = True
                continue
            values = [inline] if inline else []
            if not inline:
                many = r["kind"].startswith("list_")
                while i < len(argv) and not argv[i].startswith("--") and (many or not values):
                    values.append(argv[i])
                    i += 1
            if not values:
                return None, f"Error: {plugin}: option {flag} needs a value"
            if r["kind"] == "uri" and "://" not in values[0]:
                # fvol serve resolves paths against its own working directory
                values = [os.path.abspath(os.path.expanduser(values[0]))]
            args[r["name"]] = values if r["kind"].startswith("list_") else values[0]
        return args, None


def die_with_parent():
    """In the child: get SIGTERM when this MCP server exits, so fvol serve never lingers"""
    try:
        import ctypes
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG
    except Exception:
        pass


def open_browser(url):
    for opener in ("xdg-open", "open"):
        if shutil.which(opener):
            subprocess.Popen([opener, url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
            return


web = FvolWeb()


def web_enabled():
    return bool(web.base) or FVOL_WEB not in ("", "0")


async def run_plugin(memory_dump_path: str, plugin: str, plugin_args=None, dump_dir: Optional[str] = None) -> str:
    """Validate the dump, run one plugin and optionally dump its files to dump_dir"""
    memory_dump_path, error = check_dump(memory_dump_path)
    if error:
        return error

    if web_enabled():
        return await web.run_plugin(memory_dump_path, plugin, plugin_args or [], dump_dir)

    global_args = []
    plugin_args = list(plugin_args or [])
    if dump_dir:
        dump_dir, error = prepare_dump_dir(dump_dir)
        if error:
            return error
        global_args = ["-o", dump_dir]
        plugin_args.append("--dump")

    before = set(os.listdir(dump_dir)) if dump_dir else set()
    result = await run_fvol(["-f", memory_dump_path, plugin] + plugin_args, global_args)

    if dump_dir and os.path.isdir(dump_dir):
        new_files = set(os.listdir(dump_dir)) - before
        if new_files:
            result += f"\n\nDumped {len(new_files)} files to {dump_dir}"

    return result


@mcp.tool()
async def list_available_plugins() -> str:
    """List all available fvol (Volatility 3) plugins"""
    return await run_fvol(["-h"])


@mcp.tool()
async def get_image_info(memory_dump_path: str) -> str:
    """Show OS and kernel details of a Windows memory dump (windows.info.Info)"""
    return await run_plugin(memory_dump_path, "windows.info.Info")


@mcp.tool()
async def run_pstree(memory_dump_path: str) -> str:
    """Show the process tree (parent-child relationships) of a Windows memory dump"""
    return await run_plugin(memory_dump_path, "windows.pstree.PsTree")


@mcp.tool()
async def run_pslist(memory_dump_path: str) -> str:
    """List processes from the active process list of a Windows memory dump"""
    return await run_plugin(memory_dump_path, "windows.pslist.PsList")


@mcp.tool()
async def run_psscan(memory_dump_path: str) -> str:
    """Scan for process objects, including hidden or terminated processes"""
    return await run_plugin(memory_dump_path, "windows.psscan.PsScan")


@mcp.tool()
async def run_netscan(memory_dump_path: str) -> str:
    """Scan for network connections and listening sockets"""
    return await run_plugin(memory_dump_path, "windows.netscan.NetScan")


@mcp.tool()
async def run_malfind(memory_dump_path: str, dump_dir: Optional[str] = None) -> str:
    """Find injected code and suspicious memory regions; optionally dump them to dump_dir"""
    return await run_plugin(memory_dump_path, "windows.malware.malfind.Malfind", dump_dir=dump_dir)


@mcp.tool()
async def run_cmdline(memory_dump_path: str) -> str:
    """Show the command line arguments of each process"""
    return await run_plugin(memory_dump_path, "windows.cmdline.CmdLine")


@mcp.tool()
async def run_dlllist(memory_dump_path: str, pid: Optional[int] = None) -> str:
    """List the DLLs loaded by processes, optionally for a single PID"""
    plugin_args = ["--pid", str(pid)] if pid is not None else []
    return await run_plugin(memory_dump_path, "windows.dlllist.DllList", plugin_args)


@mcp.tool()
async def run_handles(memory_dump_path: str, pid: Optional[int] = None) -> str:
    """Run the Handles plugin to list open handles for processes"""
    plugin_args = ["--pid", str(pid)] if pid is not None else []
    return await run_plugin(memory_dump_path, "windows.handles.Handles", plugin_args)


@mcp.tool()
async def run_filescan(memory_dump_path: str) -> str:
    """Scan for file objects in memory"""
    return await run_plugin(memory_dump_path, "windows.filescan.FileScan")


@mcp.tool()
async def run_memmap(memory_dump_path: str, pid: int, dump_dir: Optional[str] = None) -> str:
    """Show the memory map of a process; optionally dump its memory to dump_dir"""
    return await run_plugin(memory_dump_path, "windows.memmap.Memmap", ["--pid", str(pid)], dump_dir)


@mcp.tool()
async def run_custom_plugin(memory_dump_path: str, plugin_name: str, additional_args: str = "",
                            renderer: str = "quick") -> str:
    """Run any fvol plugin (e.g. linux.pslist.PsList, windows.registry.hivelist.HiveList) with
    optional plugin arguments. renderer is one of quick, pretty, csv, json, jsonl, mermaid."""
    memory_dump_path, error = check_dump(memory_dump_path)
    if error:
        return error

    plugin_args = shlex.split(additional_args) if additional_args else []
    if web_enabled():
        return await web.run_plugin(memory_dump_path, plugin_name, plugin_args, renderer=renderer)

    return await run_fvol(["-f", memory_dump_path, plugin_name] + plugin_args, ["-r", renderer])


@mcp.tool()
async def open_web_ui(url: str = "") -> str:
    """Show every following plugin run in the fvol serve web UI, where the user can watch it.
    Without url, start fvol serve and open it in the browser; with the URL `fvol serve` printed
    (http://127.0.0.1:8765/#token=...), use that running server. Returns the web UI's URL."""
    error = await (web.attach(url) if url else web.start())
    return error or f"fvol web UI: {web.url}\nPlugin runs now show up there under Runs."


@mcp.tool()
async def close_web_ui() -> str:
    """Stop using the web UI and run fvol on the command line again. A server started by
    open_web_ui is stopped; one the user started keeps running."""
    was = web.url
    await web.close()
    global FVOL_WEB
    FVOL_WEB = ""
    return f"Stopped using the web UI at {was}" if was else "The web UI was not in use"


@mcp.tool()
async def list_memory_dumps(search_dir: Optional[str] = None) -> str:
    """Find memory dump files in a directory (recursively)"""
    if not search_dir:
        search_dir = os.getcwd()

    search_dir = os.path.normpath(os.path.expanduser(search_dir))
    if not os.path.isdir(search_dir):
        return f"Error: Directory not found at {search_dir}"

    memory_files = []
    for root, _, files in os.walk(search_dir):
        for file in files:
            if any(file.lower().endswith(ext) for ext in MEMORY_EXTENSIONS):
                full_path = os.path.join(root, file)
                size_mb = os.path.getsize(full_path) / (1024 * 1024)
                memory_files.append(f"{full_path} (Size: {size_mb:.2f} MB)")

    if not memory_files:
        return f"No memory dump files found in {search_dir}"

    return "Found memory dump files:\n" + "\n".join(memory_files)


@mcp.resource("fvol://plugins")
async def get_fvol_plugins() -> str:
    """Get a list of all available fvol plugins"""
    output = await run_fvol(["-h"])

    plugins = []
    capture = False
    for line in output.split('\n'):
        if line.strip() == "Plugins:":
            capture = True
            continue
        # Plugin names start at a 4-space indent; wrapped descriptions are indented further.
        if capture and line.startswith("    ") and not line.startswith("     "):
            plugins.append(line.split()[0])

    return json.dumps(plugins, indent=2)


@mcp.resource("fvol://help/{plugin}")
async def get_plugin_help(plugin: str) -> str:
    """Get help for a specific fvol plugin"""
    return await run_fvol([plugin, "--help"])


if __name__ == "__main__":
    # stdout carries the MCP protocol, so diagnostics go to stderr.
    print(f"Starting FVol MCP Server using fvol at: {FVOL_PATH}", file=sys.stderr)
    try:
        mcp.run()
    finally:
        if web.proc and web.proc.returncode is None:
            web.proc.terminate()
