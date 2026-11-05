# wacli-mcp

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server that lets an AI assistant search and
read a WhatsApp archive mirrored locally by [wacli](https://github.com/openclaw/wacli).

It cannot send, edit, delete, react, mark as read, download media, back-fill history, or link an account. Those
code paths do not exist here. Keeping the archive current is left to `wacli sync --follow`, running as a separate
process you control.

The design follows the MCP guidance in wacli's own
[companion integrations guide](https://github.com/openclaw/wacli/blob/main/docs/integrations.md#model-context-protocol-mcp):
wrap the JSON CLI, fix the store, allowlist a few read commands, pass arguments without a shell, bound everything,
and treat retrieved content as untrusted. [docs/assessment.md](docs/assessment.md) explains why this wraps wacli
instead of using whatsmeow directly, and what was evaluated.

> wacli and whatsmeow use WhatsApp's unofficial multi-device web protocol. They are not affiliated with WhatsApp or
> Meta, and WhatsApp's help center says linking an account to unofficial apps
> [may result in a temporary or permanent ban](https://faq.whatsapp.com/1848531392146538). This project never
> links an account itself, but it is only useful with one that wacli has linked.

## Tools

| Tool | wacli command (always prefixed with `--read-only --json`) |
| --- | --- |
| `list_chats` | `chats list` |
| `list_messages` | `messages list` (optional chat, sender, time window, cursor) |
| `search_messages` | `messages search` (full-text, optional filters and up to 5 neighbouring messages) |
| `search_contacts` | `contacts search` |
| `history_coverage` | `history coverage` |
| `archive_health` | `doctor` (never with `--connect`) |

Every tool carries `readOnlyHint: true` and `openWorldHint: false`. Results are wrapped with
`untrusted_content: true` and a notice telling the model not to follow instructions found in messages.

## Security model

Read-only access still exposes private conversations, and a model that reads attacker-controlled text can be
steered by it ([Invariant Labs showed exactly this against a WhatsApp MCP server](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)).
The layers, from outside in:

1. **No write tools.** The exfiltration path in the Invariant Labs research was a `send_message` tool. There is none
   here. Pair this server with other tools that can send data out (email, web requests, shell) only with care,
   since a prompt injection read through this server could use them.
2. **No network for wacli.** By default every wacli call runs inside an empty network namespace
   (`unshare -rn`), so even a bug in a read path cannot talk to WhatsApp. The server refuses to start if that is
   unavailable, unless you set `WACLI_MCP_NETWORK_ISOLATION=auto` or `off`.
3. **wacli read-only mode.** Every call passes `--read-only` and `WACLI_READONLY=1`.
4. **Fixed command shape.** The executable, store or account, and command allowlist are set by the operator.
   Arguments are single `--flag=value` tokens, free text goes after `--`, there is no shell, and the child gets a
   minimal environment (your API keys and tokens are not inherited).
5. **Bounds.** Per-call timeout with process-group kill, stdout cap, concurrency cap, a per-minute rate limit,
   result limits, and per-field text truncation.
6. **Chat policy.** Optional allowlist or denylist of chat JIDs, enforced on explicit filters and again on every
   result row.
7. **Output shaping.** Only known fields are returned. Local media paths and WhatsApp CDN paths are dropped.
   Bidirectional-override, zero-width and control characters are stripped so text cannot disguise itself.
8. **Executable vetting.** The wacli binary and its directory must not be writable by group or others; you can also
   pin its SHA-256.
9. **Audit log.** Optional JSON-lines log (mode 0600) with tool name, outcome, duration and result counts. It never
   records arguments, because queries and names are personal data.
10. **HTTP transport (optional).** Bearer token from a mode-0600 file, constant-time comparison, binding limited to
    loopback or Tailscale addresses, Host header allowlist (DNS rebinding protection), and browser `Origin`
    requests refused.

Things this server cannot protect against: an MCP client that shows results to someone else, other tools in the
same agent session, and anyone who can read the wacli store directly (it is plain SQLite, protected only by file
permissions).

## Requirements

- Linux with unprivileged user namespaces (for network isolation). Debian 13 works out of the box; Ubuntu 24.04
  needs `kernel.apparmor_restrict_unprivileged_userns=0`.
- Python 3.12+ and [uv](https://docs.astral.sh/uv/).
- wacli 0.22 or newer (tested with 0.25.1), already authenticated by you with `wacli auth`, and ideally kept fresh
  with `wacli sync --follow`.

## Install

```sh
git clone https://github.com/viniciusbregoli/wacli-mcp.git
cd wacli-mcp
uv tool install .
wacli-mcp check   # validates the configuration and runs a local `wacli doctor`
```

## Configuration

All settings are environment variables read once at startup. None can be changed by the model.

| Variable | Default | Meaning |
| --- | --- | --- |
| `WACLI_MCP_BIN` | `~/.local/bin/wacli`, else `wacli` on `PATH` | Absolute path to wacli |
| `WACLI_MCP_BIN_SHA256` | unset | Refuse to start unless the binary matches |
| `WACLI_MCP_STORE` | wacli's default | Store directory (exclusive with `WACLI_MCP_ACCOUNT`) |
| `WACLI_MCP_ACCOUNT` | unset | Named wacli account |
| `WACLI_MCP_NETWORK_ISOLATION` | `require` | `require`, `auto` or `off` |
| `WACLI_MCP_ALLOWED_CHATS` | unset | Comma-separated JIDs; when set, only these chats are visible |
| `WACLI_MCP_DENIED_CHATS` | unset | Comma-separated JIDs that are never visible |
| `WACLI_MCP_TIMEOUT_S` | `20` | Per-call timeout (1 to 120) |
| `WACLI_MCP_MAX_OUTPUT_BYTES` | `2097152` | Cap on wacli stdout per call |
| `WACLI_MCP_MAX_CONCURRENCY` | `2` | Parallel wacli processes |
| `WACLI_MCP_RATE_LIMIT_PER_MIN` | `60` | Tool calls per minute |
| `WACLI_MCP_MAX_TEXT_CHARS` | `4000` | Truncation length for each text field |
| `WACLI_MCP_AUDIT_LOG` | unset | Absolute path of the JSON-lines audit log |
| `WACLI_MCP_HOME` | `$HOME` | `HOME` passed to wacli |

HTTP transport only:

| Variable | Default | Meaning |
| --- | --- | --- |
| `WACLI_MCP_HTTP_HOST` | `127.0.0.1` | Loopback or a Tailscale address; anything else is refused |
| `WACLI_MCP_HTTP_PORT` | `8765` | Port |
| `WACLI_MCP_TOKEN_FILE` | required | Mode-0600 file holding a bearer token of at least 32 characters |
| `WACLI_MCP_ALLOWED_HOSTNAMES` | unset | Extra `Host` names to accept, such as a MagicDNS name |

Policy notes: with an allowlist, explicit `chat` filters must be exact JIDs, because names are resolved inside
wacli. wacli may return rows for a chat's `@lid` identity when you ask for its phone-number JID, so list both forms
if you use an allowlist. Rows are filtered after wacli applies `limit`, so a page can come back shorter than
requested; `hidden_by_policy` reports how many rows were removed.

## Connecting a client

Local clients should spawn the server over stdio. For Claude Code:

```sh
claude mcp add whatsapp-archive --scope user \
  --env WACLI_MCP_AUDIT_LOG="$HOME/.local/state/wacli-mcp/audit.jsonl" \
  -- wacli-mcp stdio
```

Any client that accepts a JSON server definition:

```json
{
  "mcpServers": {
    "whatsapp-archive": {
      "command": "wacli-mcp",
      "args": ["stdio"],
      "env": { "WACLI_MCP_DENIED_CHATS": "15551234567@s.whatsapp.net" }
    }
  }
}
```

### Remote clients over Tailscale

```sh
install -d -m 700 ~/.config/wacli-mcp ~/.local/state/wacli-mcp
(umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > ~/.config/wacli-mcp/token)
WACLI_MCP_HTTP_HOST="$(tailscale ip -4)" WACLI_MCP_TOKEN_FILE=~/.config/wacli-mcp/token wacli-mcp http
```

Clients connect to `http://<tailscale-ip>:8765/mcp` with `Authorization: Bearer <token>`. Traffic is plain HTTP
inside the Tailscale tunnel, which WireGuard already encrypts. A hardened systemd unit is in
[deploy/wacli-mcp-http.service](deploy/wacli-mcp-http.service).

## Keeping the archive fresh

This server only reads. Results describe what wacli has stored; message results (`list_messages`,
`search_messages`) and `archive_health` include `last_sync_at`, which says when a sync last completed. Run the
sync yourself, for example as a service:

```sh
wacli sync --follow
```

wacli's read commands work while `sync --follow` holds the store lock.

## Limitations

- WhatsApp gives linked devices history on a best-effort basis; see `history_coverage`.
- Message content is returned to the model, which is the point of the tool. Use the chat policy for chats that
  should never leave the machine.
- wacli's JSON fields are not a formal API. Integration tests pin the behaviour of the tested version; run them
  after upgrading wacli.
- Media is not available: there is no download tool, by design.

## Development

```sh
uv sync
uv run ruff check . && uv run ruff format --check .
uv run pytest
```

Unit tests use a fake wacli executable. Integration tests (`-m integration`) run the real wacli binary
(`WACLI_MCP_TEST_BIN`, default `~/.local/bin/wacli`) against a throwaway store created in a temp directory with
synthetic data, inside an empty network namespace. They never open your real store. CI downloads the pinned
official wacli release and verifies its checksum before running them.

## License

MIT. See [LICENSE](LICENSE).
