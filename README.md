# FVol MCP Server

MCP server that exposes [fvol](https://github.com/code-zm/fvol) (Rust port of Volatility 3) plugins as tools for Claude and other MCP clients. Fork of [Volatility-MCP-Server](https://github.com/bornpresident/Volatility-MCP-Server).

## Setup

Requires Linux, Python 3.10+, and the `fvol` binary ([releases](https://github.com/code-zm/fvol/releases/latest)).

```bash
git clone https://github.com/XSS3cut10n3r/FVol-MCP-Server.git
pip install -r FVol-MCP-Server/requirements.txt
claude mcp add fvol -e FVOL_PATH=/path/to/fvol -- python3 /path/to/FVol-MCP-Server/fvol_mcp_server.py
```

Environment variables:

- `FVOL_PATH`: fvol binary (default: `fvol` on `PATH`)
- `FVOL_SYMBOL_DIRS`: symbol dirs for Linux/macOS images, `;`-separated
- `FVOL_TIMEOUT`: seconds per run (default 600, `0` = none)

## Tools

`get_image_info`, `run_pstree`, `run_pslist`, `run_psscan`, `run_netscan`, `run_malfind`, `run_cmdline`, `run_dlllist`, `run_handles`, `run_filescan`, `run_memmap`, `run_custom_plugin` (any plugin, any args), `list_available_plugins`, `list_memory_dumps`.

Resources: `fvol://plugins`, `fvol://help/{plugin}`.

## Prompt

LLMs will invent PIDs, addresses and "findings" if you let them. Start with a prompt like this:

```md
Your task is to perform memory forensics on <PATH TO IMAGE> using the fvol MCP tools. Strategy:

- Start with `get_image_info` to identify the OS, then triage: `run_pstree`, `run_cmdline`, `run_netscan`, `run_malfind`
- Compare `run_pslist` against `run_psscan` to find hidden or terminated processes
- Drill into suspicious processes with `run_dlllist`, `run_handles` and `run_memmap` using their PID
- For any other plugin use `run_custom_plugin`; check `fvol://help/{plugin}` for its options first
- Only report what the tool output shows. Quote the PID, offset or row for every claim. NEVER guess values
- If a plugin errors or returns nothing, say so; don't fill the gap with assumptions
- Write a report.md at the end: timeline, suspicious processes, network indicators, IOCs, and the commands behind each finding
```

## License

MIT. fvol is separate and licensed under VSL 1.0.
