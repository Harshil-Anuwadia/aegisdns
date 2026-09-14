# Architecture

AegisDNS is a local DNS policy layer in front of an Unbound recursive resolver. A Rust daemon serves DNS, the authenticated administration API, and the compiled dashboard. State remains on the host in configuration files and a Compose-managed data volume.

```text
Clients
  │ UDP/TCP 53
  ▼
AegisDNS daemon
  ├─ policy, blocklists, risk checks, rate containment
  ├─ local-zone lookup ───────────────► Openroot :5354
  ├─ recursive or forwarded lookup ──► Unbound :5353
  ├─ SQLite analytics and relationship observations
  └─ authenticated dashboard/API ─────► 127.0.0.1:5380
```

## Components

| Path                 | Responsibility                                                                                |
| -------------------- | --------------------------------------------------------------------------------------------- |
| `crates/daemon`      | DNS proxy, HTTP API, authentication, actions, device discovery, and service orchestration.    |
| `crates/resolver`    | Generates secure Unbound configuration and manages the resolver process.                      |
| `crates/openroot`    | Answers configured local-zone records.                                                        |
| `crates/policy`      | Applies global and device-specific allow and deny rules.                                      |
| `crates/risk`        | Computes bounded heuristic risk signals and tracks suspicious IP rotation.                    |
| `crates/blocklist`   | Downloads, validates, compiles, and retains blocklist snapshots.                              |
| `crates/analytics`   | Persists queries, device metrics, privacy summaries, and relationship observations in SQLite. |
| `crates/config`      | Loads configuration and provides shared DNS message helpers.                                  |
| `crates/diagnostics` | Produces configuration and policy diagnostics.                                                |
| `ui`                 | React dashboard compiled into static files served by the daemon.                              |
| `scripts/setup.py`   | Shared interactive installer and uninstaller implementation.                                  |

## Request flow

The daemon validates each DNS message, identifies the client, and applies explicit policy before forwarding. It asks Openroot for configured local names and Unbound for external names. Returned CNAME and address records are inspected before the response reaches the client. Analytics are recorded asynchronously so normal logging work does not delay a DNS reply.

Unbound performs DNSSEC validation, QNAME minimization, caching, and either recursive resolution or configured forwarding. The daemon does not replace Unbound's validation logic.

## Trust boundaries

- The dashboard binds to loopback by default and every administration route requires authentication.
- Mutating API calls require the expected same-origin request marker in addition to credentials.
- Custom actions use a separate authenticated listener and an explicit executable allowlist.
- Configuration and analytics stay local. Remote favicon lookup is disabled by default because enabling it reveals displayed domain names to the configured favicon provider.
- Tailscale peer discovery is optional because its LocalAPI socket grants broader access than ordinary DNS service.
- Installation may change host DNS only after configuration and image validation. Recovery data is retained until restoration succeeds.

## Persistent data

The Compose volume contains SQLite data, generated credentials, compiled blocklist state, and resolver runtime data. Repository-side `.env`, `config.json`, `openroot.json`, and custom blocklists are bind-mounted configuration. Uninstallation preserves both categories unless the user explicitly requests a data purge.

Relationship graphs and privacy budgets describe observed DNS behavior. They are bounded views and estimates, not proof of application identity, ownership, compromise, or a device being online.
