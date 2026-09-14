# Contributing to AegisDNS

Thank you for helping improve AegisDNS. Contributions may be code, tests, documentation, issue triage, or reproducible bug reports.

## Before you start

- Search existing issues and pull requests before opening a duplicate.
- Use a public issue for bugs and proposals that contain no sensitive information.
- Report security vulnerabilities privately through [GitHub Security Advisories](https://github.com/Harshil-Anuwadia/aegisdns/security/advisories/new).
- Discuss large behavior changes before investing in a substantial implementation.

DNS logs can reveal browsing activity and private network details. Replace real domains, client addresses, credentials, tokens, and configuration secrets with synthetic examples before sharing evidence.

## Development setup

The backend uses stable Rust. The dashboard uses Node.js 22 or later.

```sh
cargo test --workspace --locked

cd ui
npm ci
npm run build
npx playwright install chromium
npm test
```

Installer tests are safe to run on a development machine because they use temporary files and mocked commands:

```sh
python3 -m unittest discover -s tests -v
bash -n aegis install.sh uninstall.sh docker-entrypoint.sh
```

See [Development](../docs/DEVELOPMENT.md) for the repository layout and focused commands.

## Making a change

1. Create a focused branch from the current `main` branch.
2. Add a regression test when fixing behavior that can reasonably be reproduced in automation.
3. Preserve existing configuration by default. Treat host DNS, Docker volumes, and credentials as user data.
4. Keep network requests bounded by timeouts and avoid adding telemetry or remote assets to the dashboard.
5. Update user documentation when behavior, configuration, or installation changes.
6. Run the checks relevant to your change before opening a pull request.

Avoid tests that depend on public DNS services, changing third-party blocklists, or the developer's installed AegisDNS instance. The release smoke test creates a disposable container and is documented in [Development](../docs/DEVELOPMENT.md).

## Pull requests

Keep each pull request small enough to review as one change. Explain the problem, the resulting behavior, and how you verified it. Include screenshots for visible dashboard changes at desktop and mobile widths.

By submitting a contribution, you agree that it may be distributed under the repository's [MIT license](../LICENSE).

All participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md).
