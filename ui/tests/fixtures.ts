import type { Page } from "@playwright/test";

// Deterministic test responses only. The application always calls the real API.
const events = Array.from({ length: 50 }, (_, i) => ({
  domain: i % 3 ? `service-${i}.example.com` : "tracker.example.com",
  timestamp: `2026-09-09 12:00:${String(59 - i).padStart(2, "0")}`,
  status: ["blocked", "allowed", "cache_hit"][i % 3],
  client_ip: i % 2 ? "192.168.1.20" : "192.168.1.30",
}));
export const responses: Record<string, unknown> = {
  "/stats": {
    queries_today: 14832,
    blocked_today: 3260,
    allowed_today: 9272,
    cache_hits: 2300,
    avg_latency_ms: 18.7,
  },
  "/telemetry": {
    queries: Array.from({ length: 60 }, (_, i) => 15 + (i % 19)),
    blocked: Array.from({ length: 60 }, (_, i) => i % 7),
    cache: Array.from({ length: 60 }, (_, i) => i % 9),
    latency: Array(60).fill(18),
  },
  "/recent": events,
  "/devices": [
    { ip: "192.168.1.20", name: "Work laptop", profile: "default" },
    { ip: "192.168.1.30", name: "Living room TV", profile: "strict" },
  ],
  "/top-domains": {
    top_domains: [
      { domain: "example.com", count: 1390 },
      { domain: "github.com", count: 640 },
    ],
    infrastructure: [{ domain: "cdn.example.com", count: 190 }],
    unknown: [{ domain: "new.example.com", count: 20 }],
  },
  "/top-blocked": [
    { domain: "tracker.example.com", count: 720 },
    { domain: "ads.example.com", count: 180 },
  ],
  "/policy": {
    allowed: ["example.com"],
    denied: ["ads.example.com"],
    device_allowed: {},
    device_denied: { "192.168.1.30": ["video.example.com"] },
  },
  "/lists": [{ name: "Local protection", enabled: true, rule_count: 180000 }],
  "/schedules": [
    {
      id: "evening",
      label: "Evening break",
      domain: "video.example.com",
      action: "Block",
      days: [1, 2, 3, 4, 5],
      start_minutes: 1320,
      end_minutes: 420,
      device_id: "192.168.1.30",
      enabled: true,
    },
  ],
  "/timezone": { timezone: "Asia/Kolkata" },
  "/safesearch": { enabled: true },
  "/upstream": { enabled: false, mode: "fallback", resolvers: ["9.9.9.9:53"] },
  "/privacy": {
    config: {
      enabled: false,
      default_budget: 75,
      device_budgets: { "192.168.1.30": 50, "192.168.1.99": 30 },
    },
    devices: [
      {
        device: "192.168.1.30",
        score: 54,
        total_queries: 830,
        blocked_queries: 230,
        unique_domains: 120,
        tracking_companies: 4,
        advertising_identifiers: 3,
        applications: 2,
        network_spread: 5,
        country_spread: 2,
        quiet_hour_queries: 45,
      },
    ],
  },
  "/graph": {
    hours: 24,
    nodes: [
      { id: "device:tv", kind: "device", label: "192.168.1.30" },
      { id: "domain:tracker", kind: "domain", label: "tracker.example.com" },
      { id: "ip:public", kind: "ip", label: "93.184.216.34" },
      { id: "company:ad", kind: "company", label: "Example tracker" },
    ],
    edges: [
      {
        source: "device:tv",
        target: "domain:tracker",
        relation: "requested",
        count: 140,
        first_seen: "2026-09-09 09:00:00",
        last_seen: "2026-09-09 12:00:00",
      },
      {
        source: "domain:tracker",
        target: "ip:public",
        relation: "resolves_to",
        count: 90,
        first_seen: "2026-09-09 09:00:00",
        last_seen: "2026-09-09 12:00:00",
      },
    ],
  },
  "/actions": [
    {
      domain: "desk.lan",
      action_type: "webhook",
      payload_url: "https://example.com/hook",
      method: "POST",
      success_msg: "Completed",
      token: null,
    },
  ],
  "/actions/logs": [
    {
      id: 1,
      domain: "desk.lan",
      outcome: "success",
      detail: "Webhook completed",
      triggered_at: "2026-09-09 12:00:00",
    },
  ],
  "/quarantine": ["192.168.1.30"],
  "/telegram": {
    enabled: true,
    bot_token: "",
    bot_token_configured: true,
    chat_id: "12345",
    threat_threshold: 70,
    notify_on_block: false,
  },
  "/dhcp": {
    enabled: false,
    server_ip: "192.168.1.2",
    router_ip: "192.168.1.1",
    subnet_mask: "255.255.255.0",
    start_ip: "192.168.1.100",
    end_ip: "192.168.1.200",
    lease_duration_secs: 86400,
  },
};
export async function mockApi(
  page: Page,
  overrides: Record<string, unknown> = {},
) {
  // Match the daemon's production CSP, including same-origin scripts and fonts.
  await page.route("**/*", async (route) => {
    if (route.request().resourceType() !== "document") return route.fallback();
    const response = await route.fetch();
    await route.fulfill({
      response,
      headers: {
        ...response.headers(),
        "Content-Security-Policy":
          "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
      },
    });
  });
  const writes: {
    path: string;
    method: string;
    body: any;
    header: string | undefined;
  }[] = [];
  await page.route("**/api/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname.replace("/api", "");
    if (path === "/live-feed")
      return route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: ": connected\n\n",
      });
    if (request.method() !== "GET") {
      writes.push({
        path,
        method: request.method(),
        body: request.postData() ? request.postDataJSON() : null,
        header: request.headers()["x-aegis-request"],
      });
      return route.fulfill({
        json:
          path === "/diagnose"
            ? {
                domain: "example.com",
                decision: "allowed",
                reason: "Explicit allow rule",
              }
            : { success: true, message: "Saved" },
      });
    }
    if (path === "/export/logs")
      return route.fulfill({
        contentType: "text/csv",
        body: "domain,status\nexample.com,allowed\n",
      });
    const data = path in overrides ? overrides[path] : responses[path];
    if (data === undefined)
      return route.fulfill({
        status: 404,
        json: { message: `Missing fixture: ${path}` },
      });
    return route.fulfill({ json: data });
  });
  return writes;
}
