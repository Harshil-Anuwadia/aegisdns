# Dashboard development

The dashboard is a React/TypeScript application built by Vite. It is served by the existing authenticated AegisDNS listener; it does not require a separate hosted service. Fonts and application assets are bundled locally.

Use Node.js 22 or later:

```sh
cd ui
npm ci
npm run dev
```

The development server listens on `127.0.0.1:5173` and proxies `/api` to the daemon on `127.0.0.1:5380`. Authenticate with the existing admin credentials. The production Docker build compiles the dashboard automatically and copies only `dist` into the runtime image. Rebuild the image to install frontend changes; do not serve the source `index.html` directly.

```sh
npm run build
npx playwright install chromium
npm test
```

Browser tests launch the compiled application, apply the daemon's Content Security Policy, and intercept API requests using fixtures in `tests/fixtures.ts`. They never change a running DNS installation. Screenshots and failure traces are written to `test-results/`. These tests verify UI behavior and request contracts; Rust tests cover server behavior. Real resolver, DHCP, and Telegram operation still depends on the host's configuration.

## Source layout

- `src/components`: shell, navigation, accessible dialogs/forms, tables and chart.
- `src/pages`: each functional area, lazily loaded when opened.
- `src/api.ts`: authenticated requests, cancellation, timeouts and server errors.
- `src/live.tsx`: one shared SSE connection, batched updates, bounded event retention.
- `src/styles.css`: semantic theme tokens, layouts, responsive rules and reduced motion.

The query log starts with the latest 50 persisted events and retains up to 500 events in the current session. Older history is available through export. The traffic chart uses the API's 60-second window. Device activity reflects DNS observations, not online presence. Privacy scores are DNS exposure estimates, and relationship nodes describe observations rather than verified ownership. The UI does not invent historical trends, resolver health, application identity or per-query fields absent from the API.

Both themes support keyboard navigation, visible focus, descriptive status labels and reduced motion. Use Ctrl/Command+K for page commands and domain investigation. Arrow keys navigate command results; Escape closes dialogs. Destructive operations require an explicit confirmation.
