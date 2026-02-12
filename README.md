# cratedex

MCP (Model Context Protocol) server for Rust documentation indexing, full-text search, and project diagnostics.

## Features

- Full-text search across Rust crate documentation (SQLite FTS5)
- Cargo metadata and workspace-aware dependency resolution
- Build diagnostics, outdated dependencies, and security advisories
- Per-project registration with background indexing
- Dual transport: stdio (per-client) or HTTP (shared daemon)

## Prerequisites

- Rust toolchain (1.93+)
- Nightly Rust (for rustdoc JSON generation)

## Installation

```bash
cargo install cratedex
```

## Usage

Start the MCP server (HTTP transport, default):

```bash
cratedex server
```

Or with stdio transport:

```bash
CRATEDEX__SERVER__TRANSPORT=stdio cratedex server
```

## Configuration

Configuration is loaded from (in priority order):
1. Environment variables (`CRATEDEX__<SECTION>__<KEY>`)
2. `~/.cratedex/cratedex.toml`
3. `cratedex.toml` in the current directory
4. Built-in defaults

See `cratedex.toml.example` for all options. Key environment variables:

| Variable | Default | Description |
|---|---|---|
| `CRATEDEX__SERVER__TRANSPORT` | `http` | Transport protocol: `http` or `stdio` |
| `CRATEDEX__SERVER__HOST` | `127.0.0.1` | HTTP bind address |
| `CRATEDEX__SERVER__PORT` | `3737` | HTTP bind port |
| `CRATEDEX__SERVER__ALLOW_REMOTE` | `false` | Allow non-loopback bind (`false` strongly recommended) |
| `CRATEDEX__SERVER__AUTH_TOKEN` | unset | Optional HTTP bearer token |
| `CRATEDEX__SERVER__MAX_SEARCH_RESULTS` | `10` | Max results per search query |
| `CRATEDEX__SERVER__MAX_PROJECTS` | `32` | Max simultaneously registered projects |
| `CRATEDEX__SERVER__MAX_CONCURRENT_REQUESTS` | `64` | HTTP concurrency limit |
| `CRATEDEX__SERVER__RATE_LIMIT_PER_SEC` | `30` | HTTP request rate cap |
| `CRATEDEX__SERVER__MAX_REQUEST_BODY_BYTES` | `262144` | Max HTTP request body size |
| `CRATEDEX__DATABASE__PATH` | `~/.cratedex/cratedex.db` | Database file path |

### HTTP Security Model

- By default, cratedex only allows loopback binds (`127.0.0.1` / `localhost`).
- Binding to non-loopback interfaces requires explicit opt-in via `CRATEDEX__SERVER__ALLOW_REMOTE=true` (or `install-service --allow-remote`).
- If you expose the service beyond localhost, place it behind a reverse proxy that enforces TLS and authentication.
- For additional local protection (multi-user hosts), set `CRATEDEX__SERVER__AUTH_TOKEN` and send `Authorization: Bearer <token>`.

## MCP Tools

| Tool | Description |
|---|---|
| `register_project` | Register a Rust project for indexing and diagnostics |
| `list_projects` | List all registered projects and their indexing status |
| `list_crates` | List all crates in a project's workspace |
| `get_diagnostics` | Get build diagnostics, outdated deps, and security advisories |
| `search_docs` | Search Rust documentation across the global index |
| `unregister_project` | Remove a registered project from the server |

## MCP Resources

| URI | Description |
|---|---|
| `cratedex://logs` | Recent log entries from the server (last 500 lines) |

## Deployment Models

### stdio -- per-client process

Each MCP client spawns its own `cratedex` process. Simple to configure, but concurrent clients may contend on the shared database file. Best for single-client setups.

### HTTP -- shared daemon

A single `cratedex` process serves all clients over HTTP. Avoids database lock contention and shares the documentation index across all sessions. Recommended for multi-client environments.

Endpoint: `http://<host>:<port>/mcp` (default `http://127.0.0.1:3737/mcp`)

## Running as a systemd User Service

For a persistent shared HTTP daemon, install cratedex as a systemd user service:

```bash
cratedex install-service
```

This writes a service unit to `~/.config/systemd/user/cratedex.service`, runs `daemon-reload`, and enables + starts the service. The command is idempotent — re-running it restarts the service with the latest binary.

Options:

| Flag | Default | Description |
|---|---|---|
| `--host` | `127.0.0.1` | HTTP bind address |
| `--port` | `3737` | HTTP bind port |
| `--linger` | off | Enable `loginctl enable-linger` so the service survives logout |
| `--allow-remote` | off | Allow non-loopback bind (use only behind TLS+auth reverse proxy) |
| `--system` | off | Install as a system-level service in `/etc/systemd/system`, managed with plain `systemctl` |
| `--run-as` | `$SUDO_USER` | User account the system service runs as (requires `--system`) |

To verify:

```bash
systemctl --user status cratedex
journalctl --user -u cratedex -f
```

### Install as a System Service (recommended for servers/headless)

A system-level service runs a single shared daemon under `/etc/systemd/system`, managed with plain `systemctl` (no `--user`). This is the most reliable option for headless machines, SSH-only setups, or environments where `systemctl --user` is broken (e.g. missing D-Bus user session).

```bash
cargo build --release
sudo install -m 0755 target/release/cratedex /usr/local/bin/cratedex
sudo cratedex install-service --system
```

The service runs as `User=<your-user>` (defaults to `$SUDO_USER`) so it reuses your existing Rust toolchains, cargo cache, and database at `~/.cratedex/`. This means no separate setup is needed — the daemon has access to everything your user account already has.

To verify:

```bash
systemctl status cratedex
journalctl -u cratedex -f
```

To remove:

```bash
sudo cratedex remove-service --system
```

To remove the per-user service:

```bash
cratedex remove-service
```

## Client Configuration

### Claude Code

```bash
claude mcp add --scope user --transport http cratedex http://127.0.0.1:3737/mcp
```

### Codex

```bash
codex mcp add cratedex --url http://127.0.0.1:3737/mcp
```

### stdio (any MCP client)

Configure the client to spawn the server directly:

```json
{
  "command": "cratedex",
  "args": ["server"],
  "env": {
    "CRATEDEX__SERVER__TRANSPORT": "stdio"
  }
}
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
