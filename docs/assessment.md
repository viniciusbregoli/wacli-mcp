# Assessment: wacli, whatsmeow, and existing WhatsApp MCP servers

Evidence collected on 2026-11-05 from the upstream repositories, release pages and documentation linked below.
Numbers come from the GitHub API on that date.

## The question

The goal is an MCP server that lets an assistant read and search a personal WhatsApp account on an always-on Linux
home server, reachable locally or over a tailnet, without putting the account at risk. Three options were
considered:

1. Build directly on [whatsmeow](https://github.com/tulir/whatsmeow), the Go library that implements WhatsApp's
   multi-device web protocol.
2. Wrap [wacli](https://github.com/openclaw/wacli), a CLI built on whatsmeow that mirrors the account into a local
   SQLite archive.
3. Reuse an existing WhatsApp MCP server, the most popular being
   [lharries/whatsapp-mcp](https://github.com/lharries/whatsapp-mcp).

## Maintenance

| | whatsmeow | wacli | lharries/whatsapp-mcp |
| --- | --- | --- | --- |
| Created | 2021-10 | 2025-12 | 2025-03 |
| Last commit | 2026-11-02 | 2026-11-03 | 2025-07-13 |
| Commits in last 90 days | 74 | 119 | 0 |
| Tagged releases | 0 (Go pseudo-versions only) | 36 (latest v0.25.1, 2026-10-27) | 1 |
| Open issues / PRs | 39 / 54 | 14 / 24 | 96 / 173 |
| Contributors | 81 | 65 | 5 |
| License | MPL-2.0 | MIT | MIT |
| Changelog | commit log only | [CHANGELOG.md](https://github.com/openclaw/wacli/blob/main/CHANGELOG.md) per release | none |

whatsmeow is the most established piece and the base of the other two. It is maintained by the author of the
mautrix WhatsApp bridge and moves with the protocol, but it publishes no releases, so consumers pin commits and
absorb API changes themselves. wacli pins a recent whatsmeow commit (v0.25.1 uses `v0.0.0-20261017175727`), ships
frequent tagged releases with notes, applies a 48-hour cooldown before taking dependency updates, runs CodeQL, and
rebuilt its releases with Go 1.27.3 to fix GO-2026-6809 (CHANGELOG 0.23.0). lharries/whatsapp-mcp has had no
commits for about 16 months and its pinned whatsmeow is from 2025-03.

## Capabilities

whatsmeow covers the protocol: sending and receiving messages and media, groups, receipts, presence, app state,
retry receipts and status ([README](https://github.com/tulir/whatsmeow#features)). It is a library: storage of
messages, history-sync handling, search, identity mapping and recovery are left to the application.

wacli adds exactly that application layer: a local `wacli.db` archive kept apart from the whatsmeow `session.db`,
SQLite FTS5 search, cursor pagination, a content-free change journal, phone-number/LID identity merging,
history-coverage reporting, a daemon (`sync --follow`) that owns the session while other commands read the archive
concurrently, JSON output with a stable envelope, and a global `--read-only` mode
([README](https://github.com/openclaw/wacli#readme), [messages](https://github.com/openclaw/wacli/blob/main/docs/messages.md)).
Its changelog shows how much ongoing work that layer needs: receipt batches, archive-state recovery, wrapped
history payloads, LID migrations and more in the last month alone.

lharries/whatsapp-mcp pairs a small whatsmeow bridge with a Python MCP server exposing search plus `send_message`,
`send_file` and `send_audio_message`.

## Security

- **Where the session keys live.** An MCP server built directly on whatsmeow must hold the linked-device keys in
  its own process and be able to send. Wrapping wacli lets the MCP process run without any network access and with
  wacli in read-only mode, while a separate `wacli sync --follow` owns the session. A bug or prompt injection in
  the MCP layer then has no path to the WhatsApp account.
- **Exfiltration.** Invariant Labs showed that an agent connected to a WhatsApp MCP server with a send tool can be
  manipulated, either by a malicious companion server or by a crafted incoming message, into sending chat history
  to an attacker ([write-up](https://invariantlabs.ai/blog/whatsapp-mcp-exploited),
  [Simon Willison's summary](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/),
  [Docker's analysis](https://www.docker.com/blog/mcp-horror-stories-whatsapp-data-exfiltration-issue/)). The
  target was lharries/whatsapp-mcp. This server ships without a send tool by default. Its optional
  `send_message` narrows that channel instead of closing it: an operator-defined recipient allowlist, per-message
  user confirmation by default, refusal of invisible characters, rate and duplicate limits, and delegation to
  the separately run sync daemon. The residual risks are a user approving a message they did not read, the
  `none` confirmation mode, and other egress-capable tools in the same agent session.
- **Upstream guidance.** wacli documents how an MCP wrapper should be built: fixed store, small allowlist of read
  commands, no shell, bounded inputs and outputs, untrusted-content handling, private logs, and no send, delete,
  account or backfill commands ([integrations guide](https://github.com/openclaw/wacli/blob/main/docs/integrations.md#model-context-protocol-mcp)).
  whatsmeow, as a library, offers no such guidance or read-only switch.
- **Supply chain.** wacli releases publish `checksums.txt`; macOS binaries are codesigned and notarized
  (`SIGNING-MANIFEST.json`), while Linux archives rely on the checksums alone, which come from the same GitHub
  release. A locally installed binary can be checked against the release archive:

  ```sh
  gh release download v0.25.1 -R openclaw/wacli -p 'wacli_0.25.1_linux_amd64.tar.gz' -p checksums.txt
  sha256sum -c --ignore-missing checksums.txt
  tar -xzf wacli_0.25.1_linux_amd64.tar.gz && sha256sum wacli ~/.local/bin/wacli
  ```

  `go version -m $(command -v wacli)` also prints the module path, version and VCS revision embedded at build time.
- **Account risk.** Every option here uses the unofficial protocol. WhatsApp's help center says unofficial apps
  violate its terms and that linking an account to them may lead to a temporary or permanent ban
  ([temporarily banned accounts](https://faq.whatsapp.com/1848531392146538), [account bans](https://faq.whatsapp.com/465883178708358)).
  Read-only use with a single linked device and little or no automated sending keeps the footprint small (the
  send rate limit defaults to 10 per hour), but the risk is not
  zero and cannot be removed by this project. The official WhatsApp Business Platform cannot read a personal
  account's chats, so it does not fit this use case.
- **Data at rest.** Both wacli databases are unencrypted SQLite files protected by file permissions (wacli creates
  them mode 0600). Anyone with access to the user account can read them, with or without this server.

## Suitability and decision

| Criterion | whatsmeow directly | wacli wrapper (chosen) | lharries/whatsapp-mcp |
| --- | --- | --- | --- |
| Effort to reach a searchable archive | High: storage, history sync, FTS, LID mapping, recovery | Low: already built | Low |
| Ongoing maintenance for us | High: track an unversioned API | Low: follow tagged releases | Fork required |
| Blast radius of an MCP bug | Session keys and send capability in-process | No network, read-only child | Send tools exposed |
| Fit for a headless server | Good | Good (`sync --follow` as a service) | Bridge plus server |
| Protocol fixes latency | Immediate | One wacli release behind whatsmeow | Stale |

Wrapping wacli is the appropriate approach: it reuses a maintained, versioned implementation of the hard parts, it
is the integration path its maintainers document, and it lets the MCP process be read-only and offline by
construction. Building on whatsmeow directly would only pay off for features wacli lacks and that need live
protocol access, such as real-time event streaming into the assistant or write actions, and those are the features
with the largest security cost. lharries/whatsapp-mcp should not be used: it is unmaintained and exposes the send
tools that made the published exfiltration attack possible.

Residual trade-offs of the choice:

- The archive is only as fresh as the last `wacli sync`; results expose `last_sync_at`.
- wacli's JSON field names are not a formal API, so wacli upgrades should be gated on the integration tests.
- wacli currently lists one maintainer (with its creator still credited), which is a bus-factor risk; the code is
  MIT licensed and small enough to fork if needed.
