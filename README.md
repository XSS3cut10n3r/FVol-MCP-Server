# FVol MCP Server

A Model Context Protocol (MCP) server that lets Claude and other MCP-compatible LLMs run memory
forensics with [fvol](https://github.com/code-zm/fvol), a Rust port of Volatility 3.

This is a fork of [Volatility-MCP-Server](https://github.com/bornpresident/Volatility-MCP-Server)
by Vishal Chand. It exposes the same tools, but runs `fvol` instead of python volatility3.

## Why fvol

fvol reproduces all 197 plugins of volatility3 2.28.2, with the same names, options and output,
and is much faster: a common triage session on a Windows 11 image takes about 126 ms instead of
about 60 s with python ([benchmarks](https://github.com/code-zm/fvol#performance)). It is a single
static binary with no dependencies, so there is no Python environment or volatility3 checkout to
set up.

For an LLM that runs many plugins in a row, that speed is the difference between waiting minutes
for an answer and getting one almost immediately.

## Changes from the original

- Runs the `fvol` binary instead of `python vol.py`; the path comes from `FVOL_PATH` or `PATH`
  rather than a hard-coded Windows directory.
- Fixes the stray `ts` token in `run_handles` that caused an `IndentationError` and kept the
  original server from starting.
- Restores tool docstrings, which MCP clients show the LLM as tool descriptions.
- `run_malfind` uses `windows.malware.malfind.Malfind` and dumps with `-o <dir> --dump`
  (volatility3 has no `--dump-dir` option). `run_memmap` can also dump.
- Logs to stderr, since stdout carries the MCP protocol, and runs fvol with stdin closed.
- `run_custom_plugin` splits arguments with shell quoting rules and takes a `renderer`
  (`quick`, `pretty`, `csv`, `json`, `jsonl`, `mermaid`).
- Works with both the 1.x (`FastMCP`) and 2.x (`MCPServer`) MCP Python SDK.
- Per-run timeout (`FVOL_TIMEOUT`) and optional symbol directories (`FVOL_SYMBOL_DIRS`).
- The volatility3 source tree is no longer bundled.

## Requirements

- Linux (x86-64 or arm64), the platforms fvol supports
- [fvol](https://github.com/code-zm/fvol): a [release binary](https://github.com/code-zm/fvol/releases/latest),
  or built with `cargo build --release` (Rust 1.95+)
- Python 3.10 or later and the MCP Python SDK
- `curl`, which fvol uses to download Windows symbols
- Claude Desktop, Claude Code or another MCP client

## Installation

1. Install fvol and check that it runs:

   ```bash
   fvol --version
   ```

2. Clone this repository and install the Python dependency:

   ```bash
   git clone https://github.com/XSS3cut10n3r/FVol-MVP-Server.git
   cd FVol-MVP-Server
   pip install -r requirements.txt
   ```

3. Add the server to your MCP client.

   **Claude Code:**

   ```bash
   claude mcp add fvol -e FVOL_PATH=/path/to/fvol -- python3 /path/to/FVol-MVP-Server/fvol_mcp_server.py
   ```

   **Claude Desktop** (`claude_desktop_config.json`):

   ```json
   {
     "mcpServers": {
       "fvol": {
         "command": "python3",
         "args": ["/path/to/FVol-MVP-Server/fvol_mcp_server.py"],
         "env": {
           "FVOL_PATH": "/path/to/fvol"
         }
       }
     }
   }
   ```

   `FVOL_PATH` can be left out if `fvol` is on your `PATH`.

4. Restart the client.

## Configuration

| Variable           | Default          | Meaning                                                          |
| ------------------ | ---------------- | ---------------------------------------------------------------- |
| `FVOL_PATH`        | `fvol` on `PATH` | Path to the fvol binary                                          |
| `FVOL_SYMBOL_DIRS` | none             | Semicolon-separated symbol directories, passed to fvol as `-s`   |
| `FVOL_TIMEOUT`     | `600`            | Seconds before a single fvol run is stopped; `0` means no limit  |

Windows symbols are downloaded automatically. Linux and macOS images need a symbol file that
matches the kernel; see [fvol's usage guide](https://github.com/code-zm/fvol/blob/main/docs/usage.md#analyze-a-linux-image).

## Usage

Ask about your memory dumps in plain language:

- "List all processes in the memory dump at /cases/host1/memory.raw"
- "Show me the network connections in /cases/host1/memory.raw"
- "Run malfind to check for code injection and dump what it finds to /cases/host1/malfind"
- "What DLLs are loaded in process 4328?"
- "Check for hidden processes"
- "Run linux.bash.Bash on /cases/web01.lime"

## Available tools

| Tool                     | fvol plugin                        |
| ------------------------ | ---------------------------------- |
| `list_available_plugins` | `fvol -h`                          |
| `get_image_info`         | `windows.info.Info`                |
| `run_pstree`             | `windows.pstree.PsTree`            |
| `run_pslist`             | `windows.pslist.PsList`            |
| `run_psscan`             | `windows.psscan.PsScan`            |
| `run_netscan`            | `windows.netscan.NetScan`          |
| `run_malfind`            | `windows.malware.malfind.Malfind`  |
| `run_cmdline`            | `windows.cmdline.CmdLine`          |
| `run_dlllist`            | `windows.dlllist.DllList`          |
| `run_handles`            | `windows.handles.Handles`          |
| `run_filescan`           | `windows.filescan.FileScan`        |
| `run_memmap`             | `windows.memmap.Memmap`            |
| `run_custom_plugin`      | any plugin, with custom arguments  |
| `list_memory_dumps`      | finds memory images in a directory |

Resources:

- `fvol://plugins`: JSON list of every plugin name
- `fvol://help/{plugin}`: the `--help` text of one plugin

## Memory forensics workflow

1. **Triage**: "Show me the process tree", "List the network connections"
2. **Suspicious process**: "What command line started process 1234?", "Which DLLs and handles
   does process 1234 have?"
3. **Malware hunting**: "Run malfind", "Compare pslist with psscan to find hidden processes"

## Troubleshooting

- **fvol binary not found**: set `FVOL_PATH` to the absolute path of `fvol`.
- **"Unable to validate the plugin requirements"**: fvol could not find the kernel or its
  symbols. For Windows, check network access to `msdl.microsoft.com`; for Linux and macOS, set
  `FVOL_SYMBOL_DIRS`. Running `fvol -v -f <image> <plugin>` shows the reason.
- **MCP errors**: check your client's MCP logs, and that `python3 fvol_mcp_server.py` starts
  without an import error.

## License

[MIT License](LICENSE). fvol itself is a separate program under the Volatility Software License
1.0 and is not included in this repository.
