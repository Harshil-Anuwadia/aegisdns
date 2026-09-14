# Development

## Prerequisites

- stable Rust and Cargo;
- Python 3.10 or later;
- Node.js 22 or later for dashboard work;
- Docker Engine with Compose for image and integration testing;
- `pkg-config`, OpenSSL development headers, and Clang on Linux.

## Backend

Run the workspace checks from the repository root:

```sh
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
```

When `rustfmt` and Clippy are installed:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

## Installer and CLI

```sh
python3 -m unittest discover -s tests -v
bash -n aegis install.sh uninstall.sh docker-entrypoint.sh
python3 -m py_compile scripts/setup.py scripts/launch-smoke.py
```

These tests mock administrative and Docker commands. They must not alter the developer's host resolver or running installation.

## Dashboard

```sh
cd ui
npm ci
npm run build
npx prettier --check src tests playwright.config.ts vite.config.ts
npx playwright install chromium
npm test
```

Playwright serves the compiled dashboard with API fixtures. It checks both themes, desktop and mobile viewports, keyboard behavior, forms, request contracts, and accessibility. See the dashboard's [README](../ui/README.md) for more detail.

## Production image smoke test

Build a release image, then test it in an isolated temporary container:

```sh
docker build -t aegisdns:smoke .
python3 scripts/launch-smoke.py --image aegisdns:smoke --resolve
```

The smoke test selects temporary host ports and does not change host DNS. It verifies startup, authentication, mutation protection, stored policy, DNS over UDP and TCP, analytics APIs, and optional external recursion. It removes its container and temporary files when complete.

## Repository layout

```text
.github/       GitHub workflows, templates, and community policy
assets/        README images and project media
crates/        Rust workspace packages
docs/          Architecture, development, and installation guides
scripts/       Installer implementation and integration helpers
tests/         Installer and CLI tests
ui/            Dashboard source and browser tests
```

Root-level shell and batch files are public installation entry points and remain at the root so documented commands and downloaded release artifacts continue to work.

## Data and privacy

Never commit `.env`, `config.json`, `openroot.json`, `.dns-backup`, SQLite files, query exports, real DNS logs, tokens, or generated passwords. Use reserved example domains and documentation address ranges in fixtures.

Tests that fetch mutable public blocklists or depend on a public resolver are unsuitable for the regular unit suite. Put network behavior behind deterministic local fixtures; reserve real recursion for the explicit smoke-test flag.
