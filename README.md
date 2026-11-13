# wacli-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that lets an AI assistant search and read a
WhatsApp archive mirrored locally by [wacli](https://github.com/openclaw/wacli), and, only if you opt in, send plain
text to a short list of recipients you name.

By default it is read-only. It never edits, deletes, reacts, marks as read, back-fills history, or links an
account; those code paths do not exist here. Photos and videos from group chats can be returned in two ways:
`get_group_media` reads copies wacli already has on disk, and the opt-in `download_group_media` fetches one file
from WhatsApp's media servers through wacli's read-only download (no WhatsApp session, nothing sent). Direct-chat
media is never returned. Keeping the archive current, and owning the WhatsApp connection, is left to
`wacli sync --follow`, running as a separate process you control.

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
| `get_group_media` | `messages show --chat=<group JID> --id=<msg_id>`, then reads the already-downloaded file |
| `download_group_media` (opt-in) | `messages show` offline, then `media download --chat --id --output=<private temp dir>` |

Both media tools only accept an exact group JID (ending in `@g.us`) that the chat policy allows; direct chats,
names and phone numbers are refused. The other tools are unchanged and still cover direct chats and contacts.
Message results carry `media_available_locally: true` when a local copy exists, never the path itself.

Every tool except `download_group_media` carries `readOnlyHint: true` and `openWorldHint: false`;
`download_group_media` carries `readOnlyHint: false`, `idempotentHint: true` and `openWorldHint: true`. Results are wrapped with
`untrusted_content: true` and a notice telling the model not to follow instructions found in messages.

With sending enabled (see [Sending](#sending)) one more tool appears:

| Tool | wacli command |
| --- | --- |
| `send_message` | `send text --to=<configured JID> --message=<text> --no-preview`, delegated to `wacli sync --follow` |

It carries `readOnlyHint: false`, `idempotentHint: false` and `openWorldHint: true`.

File sending (see [Sending files](#sending-files)) is a second opt-in that adds `send_file`, which sends one file
from a directory you set aside (the outbox) with `send file --to=<configured JID> --file=<staged copy>`. It carries
the same hints as `send_message`.

With several accounts configured (see [Multiple accounts](#multiple-accounts)), every tool takes a required
`account` argument limited to the configured aliases. With one account, tool signatures are unchanged.

## Security model

Read-only access still exposes private conversations, and a model that reads attacker-controlled text can be
steered by it ([Invariant Labs showed exactly this against a WhatsApp MCP server](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)).
The layers, from outside in:

1. **No write tools by default.** The exfiltration path in the Invariant Labs research was a `send_message` tool.
   It does not exist unless you enable it, and then only reaches recipients you listed (see [Sending](#sending)).
   Pair this server with other tools that can send data out (email, web requests, shell) only with care, since a
   prompt injection read through this server could use them.
2. **No network for wacli.** By default every wacli call runs inside an empty network namespace
   (`unshare -rn`), so even a bug in a read path cannot talk to WhatsApp. The server refuses to start if that is
   unavailable, unless you set `WACLI_MCP_NETWORK_ISOLATION=auto` or `off`.
3. **wacli read-only mode.** Every read call passes `--read-only` and `WACLI_READONLY=1`. The one exception is
   `send_message`, which still runs without network and can only hand a message to the sync daemon.
4. **Fixed command shape.** The executable, store or account, and command allowlist are set by the operator.
   Arguments are single `--flag=value` tokens, free text goes after `--`, there is no shell, and the child gets a
   minimal environment (your API keys and tokens are not inherited).
5. **Bounds.** Per-call timeout with process-group kill, stdout cap, concurrency cap, a per-minute rate limit,
   result limits, and per-field text truncation.
6. **Chat policy.** Optional allowlist or denylist of chat JIDs, enforced on explicit filters and again on every
   result row.
7. **Output shaping.** Only known fields are returned. Local media paths and WhatsApp CDN paths are dropped.
   Bidirectional-override, zero-width and control characters are stripped so text cannot disguise itself.
8. **Group media reads.** `get_group_media` never runs `wacli media download`, which contacts the WhatsApp CDN
   even under `--read-only`. It asks wacli for one message of the named group, checks that the returned chat and
   message ID match, and only accepts `MediaType` `image` or `video`. The recorded file must sit lexically under the
   media directory (no `..`), and every path component is opened relative to the previous directory with
   `O_NOFOLLOW`, so no symlink is followed at any level and nothing can be swapped between check and open. The file
   must be a regular, single-link file owned by the server's user and within `WACLI_MCP_MAX_MEDIA_BYTES`, and its
   magic bytes must identify a JPEG, PNG, WebP or GIF photo, or an MP4, 3GP or QuickTime video matching the
   message's media type. The sniffed type is reported, not the sender's declared one. Photos are returned as image
   content, videos as an embedded blob resource; the model never supplies a path. Media calls run one at a time.
9. **Opt-in media download.** `download_group_media` exists only with `WACLI_MCP_ALLOW_MEDIA_DOWNLOAD=1` and a
   private `WACLI_MCP_DOWNLOAD_DIR`. Every call first checks the message offline: it must be in the named group, a
   photo or video, not deleted, within the declared size limit, and carry a well-formed WhatsApp direct path
   (`/v/...` or `/o1/v/...`, with no `..`, `//`, `%2e` or `%2f`), so the download URL cannot point anywhere but
   WhatsApp's CDN host. `media download`
   is then the only wacli command that runs outside the empty network namespace, still with `--read-only` and
   `WACLI_READONLY=1`; in that mode wacli 0.25.1 fetches the encrypted file from the WhatsApp CDN and decrypts it
   without opening a WhatsApp session, and leaves `wacli.db` and `session.db` untouched. `--retry-on-phone` is never
   passed. The child runs under `prlimit` with `RLIMIT_FSIZE` just above the size limit, writes into a fresh private temporary
   directory, and the server accepts exactly one regular file there, validates it like any other media file, and
   writes the validated bytes as `<group digits>.<msg_id>.<ext>` (mode 0600, never replacing or following an
   existing entry). New downloads are refused once the directory holds `WACLI_MCP_MAX_DOWNLOAD_DIR_BYTES`. A saved
   copy is served again after the same offline check, without network access. Failed downloads report only an HTTP
   status, never wacli's text (which can contain the CDN URL with its access tokens). Leftovers of interrupted
   downloads older than ten minutes (or four times the timeout) are removed at startup; younger ones may belong to
   another server process sharing the directory.
10. **Executable vetting.** The wacli binary and its directory must not be writable by group or others; you can also
   pin its SHA-256.
11. **Audit log.** Optional JSON-lines log (mode 0600) with tool name, outcome, duration and result counts. It never
   records arguments, because queries and names are personal data.
12. **HTTP transport (optional).** Bearer token from a mode-0600 file, constant-time comparison, binding limited to
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
| `WACLI_MCP_MEDIA_DIR` | `<WACLI_MCP_STORE>/media` if it exists and is private, else unset | Directory group media is served from; unset disables `get_group_media`. Not allowed with `WACLI_MCP_ACCOUNTS_FILE`, where each account uses its own `<store>/media`. An unsafe auto-detected directory only disables media; an unsafe explicit one stops startup |
| `WACLI_MCP_MAX_MEDIA_BYTES` | `3145728` | Largest photo or video returned or downloaded (64 KiB to 64 MiB). The default keeps base64 below the 5 MB per-image limit of common model APIs |
| `WACLI_MCP_ALLOW_MEDIA_DOWNLOAD` | `0` | `1` registers `download_group_media` |
| `WACLI_MCP_DOWNLOAD_DIR` | required with downloads | Private directory (not group- or world-writable) for downloaded copies |
| `WACLI_MCP_MAX_DOWNLOAD_DIR_BYTES` | `1073741824` | Total size of the download directory after which new downloads are refused |
| `WACLI_MCP_PRLIMIT` | `/usr/bin/prlimit` | util-linux `prlimit`, required with downloads; caps the size of the file the download child writes |
| `WACLI_MCP_ALLOWED_CHATS` | unset | Comma-separated JIDs; when set, only these chats are visible |
| `WACLI_MCP_DENIED_CHATS` | unset | Comma-separated JIDs that are never visible |
| `WACLI_MCP_TIMEOUT_S` | `20` | Per-call timeout (1 to 120) |
| `WACLI_MCP_MAX_OUTPUT_BYTES` | `2097152` | Cap on wacli stdout per call |
| `WACLI_MCP_MAX_CONCURRENCY` | `2` | Parallel wacli processes |
| `WACLI_MCP_RATE_LIMIT_PER_MIN` | `60` | Tool calls per minute |
| `WACLI_MCP_MAX_TEXT_CHARS` | `4000` | Truncation length for each text field |
| `WACLI_MCP_AUDIT_LOG` | unset | Absolute path of the JSON-lines audit log |
| `WACLI_MCP_HOME` | `$HOME` | `HOME` passed to wacli |
| `WACLI_MCP_ACCOUNTS_FILE` | unset | TOML file defining several accounts (see [Multiple accounts](#multiple-accounts)) |

Sending only (see [Sending](#sending)):

| Variable | Default | Meaning |
| --- | --- | --- |
| `WACLI_MCP_ENABLE_SEND` | unset | `1` registers `send_message`; requires the two settings below |
| `WACLI_MCP_SEND_RECIPIENTS` | unset | Comma-separated `alias=JID` pairs, the only possible recipients |
| `WACLI_MCP_STORE` | | Required with sending, so the daemon check looks at the right store |
| `WACLI_MCP_SEND_CONFIRMATION` | `elicit` | `elicit` asks the user to approve each message; `none` skips that |
| `WACLI_MCP_SEND_MAX_CHARS` | `1000` | Longest message accepted (1 to 4096) |
| `WACLI_MCP_SEND_PER_HOUR` | `10` | Sends per rolling hour (1 to 60) |
| `WACLI_MCP_SEND_TIMEOUT_S` | `60` | Time allowed for one send (10 to 300) |

File sending only (see [Sending files](#sending-files)):

| Variable | Default | Meaning |
| --- | --- | --- |
| `WACLI_MCP_ENABLE_SEND_FILES` | unset | `1` registers `send_file`; requires sending and the two directories below |
| `WACLI_MCP_SEND_FILE_DIR` | | The outbox: an absolute, existing directory owned by you or root and not writable by group or others. The only place files can be sent from |
| `WACLI_MCP_SEND_STAGING_DIR` | | An absolute, existing directory owned by you with mode 700, outside the outbox. The server writes the approved copy here and the sync daemon reads it from here |
| `WACLI_MCP_SEND_FILE_MAX_BYTES` | `16777216` | Largest file accepted (1024 to 104857600) |

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

## Multiple accounts

One server can serve several WhatsApp accounts, each a separate wacli store. Point `WACLI_MCP_ACCOUNTS_FILE` at a
TOML file (owned by you, mode 600) with one table per account; [deploy/accounts.example.toml](deploy/accounts.example.toml)
is a starting point:

```toml
[accounts.personal]
store = "/home/me/.local/state/wacli"   # an existing store, by absolute path
label = "Personal phone"
denied_chats = ["15550000002@s.whatsapp.net"]

[accounts.personal.send]                # optional, needs WACLI_MCP_ENABLE_SEND=1
recipients = { me = "15550000001@s.whatsapp.net" }

[accounts.work]
wacli_account = "work"                  # a named wacli account
allowed_chats = ["120363000000000001@g.us"]
```

| Key | Meaning |
| --- | --- |
| `store` | Absolute store directory. Exactly one of `store` or `wacli_account` |
| `wacli_account` | A name from `wacli accounts list` |
| `label` | Optional text shown to the model next to the alias |
| `allowed_chats`, `denied_chats` | This account's chat policy (lists of JIDs) |
| `send.recipients` | This account's only possible recipients, `alias = "JID"` |

How accounts are kept apart:

- **Explicit selection.** Every tool requires `account`, an enum of the aliases. There is no default account, so a
  call can never land on an archive the model did not name.
- **Pinned stores.** `wacli_account` names are resolved once at startup with `wacli accounts show` (read-only,
  inside the empty network namespace) and every call then uses `--store=<that directory>`. Changing wacli's
  `config.yaml` or default account later cannot redirect an alias; restart the server to pick up changes. Two
  aliases on the same store are refused.
- **Per-account policy.** Chat allowlists and denylists, send recipients, the hourly send limit, the duplicate
  guard and the sync daemon check all belong to one account. A recipient alias or JID configured for one
  account is refused when sending from another.
- **Two switches for sending.** The file says who each account may message, and `WACLI_MCP_ENABLE_SEND=1` in the
  environment turns sending on. `send_message` only lists accounts that have recipients.
- **Files.** `WACLI_MCP_ENABLE_SEND_FILES=1` and its directories are global: one outbox and one staging directory
  serve every account that can send. Recipients, the hourly limit and the duplicate guard stay per account.
- **Labelled results and audit.** Results and audit entries carry the account alias.

`WACLI_MCP_STORE`, `WACLI_MCP_ACCOUNT`, `WACLI_MCP_ALLOWED_CHATS`, `WACLI_MCP_DENIED_CHATS`,
`WACLI_MCP_SEND_RECIPIENTS` and `WACLI_MCP_MEDIA_DIR` cannot be combined with the file; everything else (limits, audit log, isolation, send
confirmation) still comes from the environment and applies to all accounts. The global per-minute rate limit and
concurrency cap are shared, while send limits are per account. Each account needs its own
`wacli --store=<dir> sync --follow` running for fresh data and for sending.

Media in multi-account mode: both media tools take `account`. Each account serves group media only from its own
`<store>/media` directory, detected at startup like the single-account default (an unsafe one disables media for that
account only), and applies its own chat policy. The download settings (`WACLI_MCP_ALLOW_MEDIA_DOWNLOAD`,
`WACLI_MCP_DOWNLOAD_DIR`, size limits, `WACLI_MCP_PRLIMIT`) stay global. Saved copies are named
`<alias>.<group digits>.<msg_id>.<ext>`, so one account is never served another account's copy of a message; the
single-account name has no alias prefix.

Adding a second wacli account without breaking the first: `wacli accounts add <name>` makes the first account it
adds the **default**, so every wacli command run without `--store` or `--account` (including a single-account
wacli-mcp without `WACLI_MCP_STORE`) switches to the new, empty store. Pin the existing archive by absolute path,
as in the example above, before adding accounts; `wacli-mcp check` warns when a single-account setup is unpinned.

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

## Sending

Sending is off unless you set `WACLI_MCP_ENABLE_SEND=1`. It exists for one job: letting an assistant send a short
text you asked for to someone you named in advance. It is the one capability that can move data out of the
archive, so a message passes all of these, in order, before wacli is run:

1. **Recipient allowlist.** `recipient` must be an alias from `WACLI_MCP_SEND_RECIPIENTS` or one of its exact
   JIDs. Names, phone numbers and other JIDs are refused, so a model (or a message it read) cannot pick a new
   destination. Recipients must also be visible under the chat policy, or the server will not start.
2. **Message checks.** Plain text up to `WACLI_MCP_SEND_MAX_CHARS`. Text with control or invisible characters
   (bidi overrides, zero-width spaces) is refused rather than cleaned, so what you approve is exactly what is sent.
   Lines starting with `-----` are refused because the confirmation prompt uses that frame.
3. **Rate and duplicates.** At most `WACLI_MCP_SEND_PER_HOUR` sends per hour, one at a time, and the same text to
   the same recipient is refused for 10 minutes.
4. **Daemon check.** The server confirms that `wacli sync --follow` holds the store lock and its `.send.sock`
   exists. wacli then hands the message to that daemon over the Unix socket; the wacli child still runs in the
   empty network namespace. Without the daemon nothing is run, so this server never opens a second WhatsApp
   connection.
5. **User confirmation.** With the default `WACLI_MCP_SEND_CONFIRMATION=elicit`, the client shows the user the
   recipient and the exact text (MCP elicitation) and nothing is sent unless they approve. Clients without
   elicitation support get an error and nothing is sent.

Outcomes are reported honestly. If wacli times out or says the message may still have gone through, the tool
says the outcome is unknown, tells the model not to retry, and blocks the same text for 10 minutes. The audit log
records the recipient alias, character count and outcome of every attempt, including refused ones, and never the
text.

`WACLI_MCP_SEND_CONFIRMATION=none` removes step 5. Use it only for a client without elicitation, with a recipient
list you would be comfortable with a prompt injection writing to (for example, only yourself): anything the model
reads can then influence what it sends to those recipients.

Example, sending only to your own number and one group:

```sh
claude mcp add whatsapp --scope user \
  --env WACLI_MCP_STORE="$HOME/.local/state/wacli" \
  --env WACLI_MCP_ENABLE_SEND=1 \
  --env WACLI_MCP_SEND_RECIPIENTS="me=15551234567@s.whatsapp.net,family=120363000000000000@g.us" \
  --env WACLI_MCP_AUDIT_LOG="$HOME/.local/state/wacli-mcp/audit.jsonl" \
  -- wacli-mcp stdio
```

`archive_health` reports `send_ready: true` once the daemon is running for that store.

## Sending files

`send_file` sends one file to a recipient from the same allowlist as `send_message`. It is off unless you also set
`WACLI_MCP_ENABLE_SEND_FILES=1` on top of `WACLI_MCP_ENABLE_SEND=1` (with recipients). It adds two pieces of design
to the checks that apply to text:

- **An outbox.** `file` is a path relative to `WACLI_MCP_SEND_FILE_DIR`, and nothing outside that directory can be
  sent. Absolute paths, `..`, hidden names (starting with `.`), control or invisible characters and look-alike
  blanks (line separators, no-break spaces, Hangul fillers, braille blank) are refused before the filesystem is
  touched, and each directory level is opened without following symlinks. The file must be a regular, non-empty
  file within `WACLI_MCP_SEND_FILE_MAX_BYTES`, with a single hard link and owned by the server's user or root (so
  a hard link to a file from elsewhere is refused). Whoever can write to the outbox chooses what can be sent, so
  keep it dedicated to this and do not point it at a home directory. The outbox and staging directories must also
  stay apart from every store, media and download directory and the audit log, or startup fails.
- **A staging directory.** The server reads the file once, shows you its checksum, and writes exactly those bytes to
  a random name in `WACLI_MCP_SEND_STAGING_DIR`. wacli is then pointed at that copy, not at the outbox, so the file
  cannot change between the approval and the send. The copy is removed after every attempt, whatever the outcome;
  a copy left by a call cancelled mid-write is removed at the next startup once it is older than ten minutes (or
  four send timeouts, if longer). The server also sets `WACLI_MEDIA_ROOTS` to the staging directory for that one wacli call, so wacli's own check
  refuses any `--file` outside it.

Allowed types are decided by the file's content, and the extension must agree with it (case does not matter):
JPEG (`.jpg`, `.jpeg`), PNG, WebP, MP4, MP3, OGG and Opus (`.ogg`, `.opus`), M4A, PDF, plain text (`.txt`, `.csv`,
`.md`, which must be valid UTF-8 without NUL bytes), and Word, Excel and PowerPoint files (`.docx`, `.xlsx`,
`.pptx`). Anything else is refused with the list of allowed types. The server always passes `--mime` and `--as`
explicitly, so wacli does not guess. An optional `caption` follows the same rules as a text message and is not
accepted for audio.

With the default `WACLI_MCP_SEND_CONFIRMATION=elicit`, the client shows you the recipient, the file name, its type,
its size in bytes, its full SHA-256 and the caption. You do not see the content itself, so approve only a file you
asked for. If the file changes after the prompt was built, the server asks again with the new checksum, or refuses
with "the file changed after it was shown for confirmation" and sends nothing. Each approval is tied to the one
call it was shown for, so another call with the same arguments cannot reuse it.

Files share the hourly limit (`WACLI_MCP_SEND_PER_HOUR`) and the duplicate guard with `send_message`. The duplicate
guard keys on the recipient, the file's checksum and the caption, so a renamed copy of a file that was just sent is
refused too. The audit log records the recipient alias, the byte count, the MIME type and the outcome, and never
the path, file name, caption or checksum.

Daemon requirements: the sync daemon reads the staged copy itself, as the same user that runs this server, so it
must be able to read `WACLI_MCP_SEND_STAGING_DIR`. If the daemon runs with `WACLI_MEDIA_ROOTS` set, the staging
directory must be inside one of its roots. Without a running `wacli sync --follow` nothing is staged or sent.

Example, adding files to the setup above:

```sh
mkdir -p "$HOME/whatsapp-outbox" && chmod 700 "$HOME/whatsapp-outbox"
mkdir -p "$HOME/.local/state/wacli-mcp/staging" && chmod 700 "$HOME/.local/state/wacli-mcp/staging"
claude mcp add whatsapp --scope user \
  --env WACLI_MCP_STORE="$HOME/.local/state/wacli" \
  --env WACLI_MCP_ENABLE_SEND=1 \
  --env WACLI_MCP_SEND_RECIPIENTS="me=15551234567@s.whatsapp.net" \
  --env WACLI_MCP_ENABLE_SEND_FILES=1 \
  --env WACLI_MCP_SEND_FILE_DIR="$HOME/whatsapp-outbox" \
  --env WACLI_MCP_SEND_STAGING_DIR="$HOME/.local/state/wacli-mcp/staging" \
  -- wacli-mcp stdio
```

`archive_health` reports `send_files_enabled` and `send_file_max_bytes` next to the other send settings.

## Keeping the archive fresh

This server never syncs. Results describe what wacli has stored; message results (`list_messages`,
`search_messages`) and `archive_health` include `last_sync_at`, which says when a sync last completed. Run the
sync yourself, for example as a service (sending also needs it running):

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
- `send_message` is plain text only: no replies, mentions or link previews. `send_file` sends one file per call
  with an optional caption; it does not send voice notes, stickers, replies or link previews.
- A file is held in memory while it is checked and sent, so `WACLI_MCP_SEND_FILE_MAX_BYTES` bounds the memory
  one call needs (at most 100 MiB).
- The type check looks at the first bytes and, for text, the whole file. An Office document must be a zip archive
  with `[Content_Types].xml` and at least one member under `word/`, `xl/` or `ppt/` (matching its extension) and at
  most 10000 entries; only the zip directory is read, nothing is extracted. Its content is not otherwise inspected.
- The server checks the outbox and staging directories themselves at startup, not their parents. A parent that
  another local user can write to lets them swap either directory afterwards, so the parents must be trusted too.
- Error text from wacli is cleaned of the staging path, the staged name and the file name before the model sees it.
- If wacli times out, or says the file may still have gone through, `send_file` reports that the outcome is unknown,
  tells the model not to retry and blocks the same file and caption for 10 minutes, as for text.
- Delivery is not confirmed. A successful `send_message` means WhatsApp accepted the message, not that the
  recipient's phone received it.
- Without `WACLI_MCP_ALLOW_MEDIA_DOWNLOAD=1`, media is served only if it is already in the store's media
  directory. Files saved elsewhere (for example with `media download --output`) are refused by `get_group_media`.
- A download needs outbound HTTPS from wacli to WhatsApp's media servers. The server cannot restrict that process
  to those hosts; it relies on wacli's read-only download path, which was verified with wacli 0.25.1. Re-check after
  upgrading wacli. Media older than WhatsApp's retention may fail with an HTTP error; recovering it would need
  `--retry-on-phone`, which contacts the phone and is deliberately not offered.
- The declared size is the sender's claim. If it understates the file, wacli still fetches until `RLIMIT_FSIZE`
  stops it, so at most about 1 MiB over the limit is transferred and written before the call fails.
- Saved copies stay until removed by hand, even after the original message is deleted; they are only no longer
  served. Delete files from `WACLI_MCP_DOWNLOAD_DIR` to get rid of them.
- The server cannot prove that the bytes wacli downloads belong to the checked message (wacli's JSON has no content
  hash to compare against). It relies on wacli looking the message up by chat and ID, which could not be verified
  without a real conflicting message.
- When the store is wacli's default rather than `WACLI_MCP_STORE`, set `WACLI_MCP_MEDIA_DIR` explicitly.
- The server checks that a media file sits in the media directory, not that the file belongs to that message; it
  relies on wacli recording the right `local_path`.
- A media file with a second hard link is refused. If wacli ever deduplicates media with hard links, those files
  will not be served.
- Videos come back as an embedded blob resource; whether a client can show or forward them depends on the client.
  Base64 makes each response about a third larger than the file.

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
