# FVol MCP Server

MCP server that exposes [fvol](https://github.com/code-zm/fvol) (Rust port of Volatility 3) plugins as tools for Claude and other MCP clients. Fork of [Volatility-MCP-Server](https://github.com/bornpresident/Volatility-MCP-Server).

## Setup

Requires Linux, Python 3.10+, and the `fvol` binary ([releases](https://github.com/code-zm/fvol/releases/latest)).

```bash
git clone https://github.com/XSS3cut10n3r/FVol-MVP-Server.git
pip install -r FVol-MVP-Server/requirements.txt
claude mcp add fvol -e FVOL_PATH=/path/to/fvol -- python3 /path/to/FVol-MVP-Server/fvol_mcp_server.py
```

Environment variables:

- `FVOL_PATH`: fvol binary (default: `fvol` on `PATH`)
- `FVOL_SYMBOL_DIRS`: symbol dirs for Linux/macOS images, `;`-separated
- `FVOL_TIMEOUT`: seconds per run (default 600, `0` = none)

## Tools

`get_image_info`, `run_pstree`, `run_pslist`, `run_psscan`, `run_netscan`, `run_malfind`, `run_cmdline`, `run_dlllist`, `run_handles`, `run_filescan`, `run_memmap`, `run_custom_plugin` (any plugin, any args), `list_available_plugins`, `list_memory_dumps`.

Resources: `fvol://plugins`, `fvol://help/{plugin}`.

## License

MIT. fvol is separate and licensed under VSL 1.0.
