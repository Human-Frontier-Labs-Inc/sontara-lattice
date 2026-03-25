# claude-peers

Peer discovery and messaging for Claude Code instances running on the same machine. Single Go binary, zero runtime dependencies.

When multiple Claude Code sessions are running (e.g. in tmux panes), they can discover each other, see what each is working on, and send messages directly between sessions.

## How it works

Two components in one binary:

- **Broker** -- singleton HTTP daemon on localhost:7899, SQLite-backed. Tracks registered peers, routes messages, cleans up stale PIDs.
- **MCP Server** -- stdio server spawned by each Claude Code instance. Registers with the broker, polls for inbound messages, and pushes them as channel notifications so they appear immediately in the recipient's session.

Messages are delivered via the experimental `claude/channel` capability -- when a peer sends you a message, it shows up in your Claude session without you having to check for it.

## Install

```bash
go install github.com/WillyV3/claude-peers@latest
```

Or build from source:

```bash
git clone https://github.com/WillyV3/claude-peers
cd claude-peers
go build -o claude-peers .
```

## Setup

Add to your `~/.claude.json` under `mcpServers`:

```json
{
  "claude-peers": {
    "type": "stdio",
    "command": "claude-peers",
    "args": ["server"],
    "env": {}
  }
}
```

If `claude-peers` isn't in your PATH, use the full path to the binary.

The broker starts automatically when the first Claude session boots. No manual setup needed.

## Auto-summary

On startup, each peer generates a 1-2 sentence summary of what it's working on (based on git context: branch, recent files, repo name). This uses an OpenAI-compatible API endpoint.

Set one of these env vars (checked in order):
- `ANTHROPIC_AUTH_TOKEN`
- `ANTHROPIC_API_KEY`
- `LITELLM_API_KEY`

Or put the key in `~/.claude/settings.json` under `env.ANTHROPIC_AUTH_TOKEN` -- the binary reads it as a fallback.

The API endpoint defaults to `https://litellm.justworksai.net` but can be overridden with `ANTHROPIC_BASE_URL` or `LITELLM_BASE_URL`. Model used: `gpt-5.4`.

If no API key is available, auto-summary is silently skipped. You can always set it manually with the `set_summary` tool.

## MCP Tools

Once connected, Claude has 4 tools:

| Tool | What it does |
|------|-------------|
| `list_peers` | Discover other Claude Code instances (scope: machine, directory, or repo) |
| `send_message` | Send a message to another instance by peer ID |
| `set_summary` | Set a description of what you're working on (visible to other peers) |
| `check_messages` | Manually poll for new messages (usually automatic via channel push) |

## CLI

The binary also works as a CLI for inspecting and managing peers:

```
claude-peers status          Show broker status and all peers
claude-peers peers           List all peers
claude-peers send <id> <msg> Send a message to a peer
claude-peers kill-broker     Stop the broker daemon
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Claude Code 1  │     │  Claude Code 2  │     │  Claude Code 3  │
│  (tmux pane)    │     │  (tmux pane)    │     │  (terminal)     │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │ stdio                 │ stdio                 │ stdio
┌────────┴────────┐     ┌───────┴─────────┐     ┌───────┴─────────┐
│  MCP Server 1   │     │  MCP Server 2   │     │  MCP Server 3   │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │ HTTP                  │ HTTP                  │ HTTP
         └───────────────┬──────┴────────────────┘
                  ┌──────┴──────┐
                  │   Broker    │
                  │ :7899       │
                  │ (SQLite)    │
                  └─────────────┘
```

## Dependencies

- `modernc.org/sqlite` -- pure Go SQLite (no CGO, single binary, cross-compile friendly)
- Everything else is Go stdlib

## Credits

This is a Go rewrite of [claude-peers-mcp](https://github.com/kvokka/claude-peers-mcp) by kvokka, originally built in TypeScript/Bun.

The Go port was developed by Claude (Anthropic's Opus 4.6) during a pair programming session with [Willy Van Sickle](https://github.com/WillyV3). The entire port -- broker, MCP server, CLI, auto-summary -- was written in a single session, including debugging the LiteLLM integration and verifying feature parity with the original.

## License

MIT
