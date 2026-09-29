import os
import sys
import json
import shlex
import shutil
import asyncio
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


async def run_plugin(memory_dump_path: str, plugin: str, plugin_args=None, dump_dir: Optional[str] = None) -> str:
    """Validate the dump, run one plugin and optionally dump its files to dump_dir"""
    memory_dump_path, error = check_dump(memory_dump_path)
    if error:
        return error

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

    cmd_args = ["-f", memory_dump_path, plugin_name]
    if additional_args:
        cmd_args.extend(shlex.split(additional_args))

    return await run_fvol(cmd_args, ["-r", renderer])


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
    mcp.run()
