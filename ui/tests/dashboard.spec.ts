import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { mockApi } from "./fixtures";

const pages = [
  "overview",
  "traffic",
  "network",
  "threats",
  "privacy",
  "rules",
  "blocklists",
  "schedules",
  "devices",
  "upstream",
  "actions",
  "diagnostics",
  "alerts",
  "settings",
  "support",
];
for (const theme of ["dark", "light"]) {
  for (const route of pages) {
    test(`${route}: ${theme} layout and accessibility`, async ({
      page,
    }, testInfo) => {
      const errors: string[] = [];
      page.on("pageerror", (error) => errors.push(error.message));
      await mockApi(page);
      await page.addInitScript(
        (theme) => localStorage.setItem("aegis-theme", theme),
        theme,
      );
      await page.goto(`/#${route}`);
      await expect(page.locator("main h1")).toBeVisible();
      await expect(
        page.getByRole("status", { name: "Fetching data" }),
      ).toHaveCount(0);
      if (route === "network")
        await expect(page.locator(".react-flow__node").first()).toBeVisible();
      if (route === "overview")
        await expect(page.locator(".recharts-surface").first()).toBeVisible();
      await expect(page.locator("main [role=alert]")).toHaveCount(0);
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
      ).toBe(true);
      const audit = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze();
      expect(
        audit.violations.map((v) => ({
          id: v.id,
          nodes: v.nodes.map((n) => ({
            target: n.target,
            summary: n.failureSummary,
          })),
        })),
      ).toEqual([]);
      expect(errors).toEqual([]);
      await page.screenshot({
        path: testInfo.outputPath(`${route}-${theme}.png`),
        fullPage: true,
      });
    });
  }
}
test("navigation, command search, themes, and keyboard dismissal", async ({
  page,
}, testInfo) => {
  await mockApi(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Search and commands" }).click();
  await page.getByRole("textbox", { name: "Search commands" }).fill("privacy");
  await page.getByRole("button", { name: "Open Privacy budgets" }).click();
  await expect(page).toHaveURL(/#privacy$/);
  await page.getByRole("button", { name: "Switch to light mode" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.keyboard.press("Control+k");
  await expect(
    page.getByRole("dialog", { name: "Command center" }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  if (testInfo.project.name === "mobile") {
    await page.getByRole("button", { name: "Open navigation" }).click();
    await page
      .getByRole("dialog")
      .getByRole("link", { name: "Devices", exact: true })
      .click();
    await expect(page).toHaveURL(/#devices$/);
    await expect(page.getByRole("dialog")).toHaveCount(0);
  }
});
test("query filtering, pause, detail rule and export", async ({ page }) => {
  const writes = await mockApi(page);
  await page.goto("/#traffic");
  await page
    .getByRole("combobox", { name: "Query status" })
    .selectOption("blocked");
  await expect(page.locator("tbody tr")).toHaveCount(17);
  await page.getByRole("button", { name: "Pause stream" }).click();
  await expect(
    page.getByRole("button", { name: "Resume stream" }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Inspect tracker.example.com", exact: true })
    .first()
    .click();
  await page.getByRole("button", { name: "Apply rule" }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]).toMatchObject({
    path: "/deny",
    header: "1",
    body: { domain: "tracker.example.com", device_id: "192.168.1.30" },
  });
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Export history" }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download export" }).click();
  expect((await download).suggestedFilename()).toBe("aegisdns-queries.csv");
});
test("new rule uses the selected device and closes only after save", async ({
  page,
}) => {
  const writes = await mockApi(page);
  await page.goto("/#rules");
  await page.getByRole("button", { name: "Add rule" }).click();
  await page
    .getByRole("dialog")
    .getByLabel("Domain", { exact: true })
    .fill("test.example.com");
  await page.getByLabel("Decision", { exact: true }).selectOption("allow");
  await page.getByLabel("Applies to").selectOption("192.168.1.20");
  await page.getByRole("button", { name: "Create rule" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(writes[0]).toMatchObject({
    path: "/allow",
    body: { domain: "test.example.com", device_id: "192.168.1.20" },
  });
});
test("privacy overrides survive saving and in-progress edits survive refresh", async ({
  page,
}) => {
  const writes = await mockApi(page);
  await page.goto("/#privacy");
  await page.getByRole("button", { name: "Configure budgets" }).click();
  await page.getByLabel("Default budget", { exact: false }).fill("65");
  await page.getByRole("switch").check();
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(writes[0].body).toEqual({
    enabled: true,
    default_budget: 65,
    device_budgets: { "192.168.1.30": 50, "192.168.1.99": 30 },
  });
  await page.goto("/#upstream");
  await page
    .getByLabel("Resolver endpoints", { exact: false })
    .fill("1.1.1.1:53");
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
  await expect(
    page.getByLabel("Resolver endpoints", { exact: false }),
  ).toHaveValue("1.1.1.1:53");
});
test("graph node inspection and history filter", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#network");
  await page
    .locator(".react-flow__node")
    .filter({ hasText: "tracker.example.com" })
    .click();
  await expect(
    page.getByRole("heading", { name: "Entity details" }),
  ).toBeVisible();
  await expect(page.locator(".connection-list")).toContainText(
    "140 observations",
  );
  const request = page.waitForRequest((r) =>
    r.url().includes("/api/graph?hours=168"),
  );
  await page.getByLabel("Relationship history").selectOption("168");
  await request;
});
test("failed saves stay open with an actionable error", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/deny", (route) =>
    route.fulfill({ json: { success: false, message: "Invalid domain name" } }),
  );
  await page.goto("/#rules");
  await page.getByRole("button", { name: "Add rule" }).click();
  await page
    .getByRole("dialog")
    .getByLabel("Domain", { exact: true })
    .fill("invalid");
  await page.getByRole("button", { name: "Create rule" }).click();
  await expect(page.getByRole("alert")).toContainText("Invalid domain name");
  await expect(page.getByRole("dialog")).toBeVisible();
});
test("empty and disconnected data do not claim healthy metrics", async ({
  page,
}) => {
  await mockApi(page, { "/devices": [] });
  await page.goto("/#devices");
  await expect(
    page.getByText("No registered devices in this view"),
  ).toBeVisible();
  await page.route("**/api/stats", (route) =>
    route.fulfill({ status: 503, json: {} }),
  );
  await page.goto("/#overview");
  await expect(page.getByRole("alert")).toContainText("503");
  await expect(page.locator(".primary-metric strong")).toHaveText("—");
});

test("settings save their real contracts without restarting DNS", async ({
  page,
}) => {
  const writes = await mockApi(page);
  await page.goto("/#upstream");
  await page.getByRole("switch").check();
  await page.getByLabel("Forwarding behavior").selectOption("always");
  await page.getByLabel("Resolver endpoints").fill("1.1.1.1:53\n9.9.9.9:53");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0].body).toEqual({
    enabled: true,
    mode: "always",
    resolvers: ["1.1.1.1:53", "9.9.9.9:53"],
  });
  await page.goto("/#alerts");
  await page.getByLabel("Risk threshold").fill("80");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1].body).toEqual({
    enabled: true,
    bot_token: "",
    chat_id: "12345",
    threat_threshold: 80,
    notify_on_block: false,
  });
  await page.goto("/#settings");
  await page.getByLabel("Lease duration (seconds)").fill("7200");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect.poll(() => writes.length).toBe(3);
  expect(writes[2].body.lease_duration_secs).toBe(7200);
  expect(writes.some((w) => w.path === "/restart")).toBe(false);
  expect(writes.every((w) => w.header === "1")).toBe(true);
});

test("schedule creation, pause, and confirmed removal", async ({ page }) => {
  const writes = await mockApi(page);
  await page.goto("/#schedules");
  await page
    .getByRole("button", { name: "Create schedule", exact: true })
    .click();
  await page.getByLabel("Name", { exact: true }).fill("Weekend break");
  await page.getByLabel("Domain", { exact: true }).fill("video.example.com");
  await page.getByLabel("Applies to").selectOption("192.168.1.30");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Create schedule" })
    .click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(writes[0].body).toEqual({
    label: "Weekend break",
    domain: "video.example.com",
    action: "block",
    days: [0, 1, 2, 3, 4, 5, 6],
    start_hour: 22,
    start_min: 0,
    end_hour: 7,
    end_min: 0,
    device_id: "192.168.1.30",
  });
  await page.getByRole("button", { name: "Pause schedule" }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1]).toMatchObject({
    path: "/schedules/evening/toggle",
    method: "PUT",
    body: { enabled: false },
  });
  await page
    .getByRole("button", { name: "Delete schedule Evening break" })
    .click();
  expect(writes.length).toBe(2);
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect.poll(() => writes.length).toBe(3);
  expect(writes[2]).toMatchObject({
    path: "/schedules/evening",
    method: "DELETE",
  });
});

test("blocklist, device, and action creation", async ({ page }) => {
  const writes = await mockApi(page);
  await page.goto("/#blocklists");
  await page.getByRole("button", { name: "Add source" }).click();
  await page.getByLabel("Source name").fill("Test source");
  await page.getByLabel("HTTPS URL").fill("https://example.com/hosts");
  await page.getByRole("button", { name: "Add and download" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(writes[0].body).toEqual({
    name: "Test source",
    source_url: "https://example.com/hosts",
  });
  await page.goto("/#devices");
  await page.getByRole("button", { name: "Add device", exact: true }).click();
  await page.getByLabel("Device name").fill("Tablet");
  await page.getByLabel("IP address", { exact: true }).fill("192.168.1.40");
  await page.getByRole("button", { name: "Save device" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(writes[1].body).toEqual({ name: "Tablet", ip: "192.168.1.40" });
  await page.goto("/#actions");
  await expect(
    page.getByRole("cell", { name: "Webhook completed" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Create action" }).click();
  await page.getByLabel("Local domain").fill("tablet.lan");
  await page.getByLabel("Action type").selectOption("html");
  await page.getByLabel("HTML response", { exact: true }).fill("<p>Ready</p>");
  await page
    .getByLabel("Bearer token", { exact: true })
    .fill("test-bearer-token-longer-than-32-characters");
  await page.getByRole("button", { name: "Save action" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(writes[2]).toMatchObject({
    path: "/actions",
    body: {
      domain: "tablet.lan",
      action_type: "html",
      html_content: "<p>Ready</p>",
    },
  });
});

test("SSE events arrive and the session buffer remains bounded", async ({
  page,
}) => {
  await mockApi(page, { "/recent": [] });
  const event = {
    domain: "stream.example.com",
    client_ip: "192.168.1.30",
    timestamp: "2026-09-09 12:00:00",
    status: "allowed",
  };
  await page.route("**/api/live-feed", (route) =>
    route.fulfill({
      contentType: "text/event-stream",
      body:
        "retry: 600000\n\n" +
        Array.from(
          { length: 510 },
          (_, i) =>
            `data: ${JSON.stringify({ ...event, domain: `stream-${i}.example.com` })}\n\n`,
        ).join(""),
    }),
  );
  await page.goto("/#traffic");
  await expect(page.getByText("500 matching events")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(30);
  await expect(page.getByText("Page 1 of 17")).toBeVisible();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await expect(page.getByText("Page 2 of 17")).toBeVisible();
});

test("loading, history errors and keyboard focus remain usable", async ({
  page,
}) => {
  await mockApi(page);
  let unblock: () => void = () => {};
  const pending = new Promise<void>((resolve) => {
    unblock = resolve;
  });
  await page.route("**/api/devices", async (route) => {
    await pending;
    await route.fulfill({ json: [] });
  });
  await page.goto("/#devices");
  await expect(
    page.getByRole("status", { name: "Fetching data" }),
  ).toBeVisible();
  unblock();
  await expect(
    page.getByText("No registered devices in this view"),
  ).toBeVisible();
  await page.route("**/api/recent", (route) =>
    route.fulfill({ status: 503, json: {} }),
  );
  await page.goto("/#traffic");
  await page.reload();
  await expect(page.getByRole("alert")).toContainText("503");
  await page.keyboard.press("Tab");
  await page.getByRole("link", { name: "Skip to content" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();
  await expect(page).toHaveURL(/#traffic$/);
});
