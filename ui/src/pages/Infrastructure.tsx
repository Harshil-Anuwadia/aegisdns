import { useState } from "react";
import {
  ArrowRight,
  Globe2,
  Radio,
  Server,
  Shield,
  Trash2,
  RefreshCw,
} from "lucide-react";
import { api, send, useApi } from "../api";
import type {
  Device,
  Dhcp,
  Result,
  Telegram,
  Upstream as UpstreamData,
} from "../types";
import {
  AsyncForm,
  Badge,
  Button,
  ConfirmButton,
  Empty,
  ErrorState,
  Field,
  PageHeader,
  Panel,
  Skeleton,
  Table,
  Toggle,
} from "../components/ui";

export function Upstream() {
  const query = useApi<UpstreamData>("/upstream");
  return (
    <>
      <PageHeader
        eyebrow="INFRASTRUCTURE / UPSTREAM DNS"
        title="Choose the way out."
        description="Keep recursive resolution local, or forward queries through your preferred resolvers."
      />
      {query.error ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : query.data ? (
        <div className="settings-layout">
          <Panel
            title="Resolution strategy"
            subtitle="Unbound remains the validating resolver"
          >
            <div className="panel-body">
              <UpstreamForm initial={query.data} />
            </div>
          </Panel>
          <aside className="settings-aside">
            <div className="route-diagram">
              <Server size={27} />
              <span>AegisDNS</span>
              <ArrowRight size={18} />
              <Shield size={27} />
              <span>Unbound</span>
              <ArrowRight size={18} />
              <Globe2 size={27} />
            </div>
            <h2>Validation stays in the path.</h2>
            <p>
              Queries continue through Unbound for DNSSEC validation. Forwarding
              changes where it asks for an answer.
            </p>
            <dl className="detail-list">
              <div>
                <dt>Recursive</dt>
                <dd>Unbound queries authoritative servers.</dd>
              </div>
              <div>
                <dt>Forward first</dt>
                <dd>Try forwarders, then recurse if needed.</dd>
              </div>
              <div>
                <dt>Forward only</dt>
                <dd>Use configured forwarders exclusively.</dd>
              </div>
            </dl>
            <p className="note">
              This view shows configuration, not a resolver health probe.
            </p>
          </aside>
        </div>
      ) : (
        <Skeleton rows={7} />
      )}
    </>
  );
}
function UpstreamForm({ initial }: { initial: UpstreamData }) {
  const [enabled, setEnabled] = useState(initial.enabled);
  return (
    <AsyncForm
      submit={(d) =>
        send("/upstream", {
          enabled,
          mode: d.get("mode"),
          resolvers: String(d.get("resolvers"))
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean),
        })
      }
    >
      <Toggle
        label="Use upstream forwarders"
        description="Disable to use local recursive resolution."
        checked={enabled}
        onChange={setEnabled}
      />
      <Field label="Forwarding behavior">
        <select name="mode" defaultValue={initial.mode}>
          <option value="fallback">Forward first, recurse on failure</option>
          <option value="always">Forward only</option>
        </select>
      </Field>
      <Field
        label="Resolver endpoints"
        hint="One endpoint per line; at most eight. Use public IP addresses and a port. Do not mix plain DNS and TLS."
      >
        <textarea
          className="mono"
          name="resolvers"
          rows={5}
          defaultValue={initial.resolvers.join("\n")}
          placeholder={"9.9.9.9:53\ntls://9.9.9.9:853#dns.quad9.net"}
        />
      </Field>
      <p className="note">
        DNS over TLS uses tls://IP:853#certificate-hostname. DoH URLs are not
        supported by this forwarding configuration.
      </p>
    </AsyncForm>
  );
}

export function Diagnostics() {
  const devices = useApi<Device[]>("/devices"),
    quarantine = useApi<string[]>("/quarantine", 15000),
    [report, setReport] = useState<Record<string, unknown> | null>(null),
    [kind, setKind] = useState("policy");
  const domain =
    new URLSearchParams(location.hash.split("?")[1]).get("domain") || "";
  return (
    <>
      <PageHeader
        eyebrow="UTILITIES / DIAGNOSTICS"
        title="Get to the reason."
        description="Check a domain's current policy decision or inspect its heuristic risk factors."
      />
      <div className="two-columns">
        <Panel title="Domain inspection">
          <div className="panel-body">
            <AsyncForm
              label="Run inspection"
              submit={async (d) => {
                setReport(null);
                setReport(
                  await send<Record<string, unknown>>(
                    kind === "policy" ? "/diagnose" : "/risk",
                    {
                      domain: String(d.get("domain")).trim(),
                      ...(d.get("device")
                        ? { device_id: d.get("device") }
                        : {}),
                    },
                  ),
                );
              }}
            >
              <Field label="Domain">
                <input
                  name="domain"
                  required
                  defaultValue={domain}
                  placeholder="example.com"
                />
              </Field>
              <Field label="Inspection">
                <select
                  value={kind}
                  onChange={(e) => {
                    setKind(e.target.value);
                    setReport(null);
                  }}
                >
                  <option value="policy">Current filtering policy</option>
                  <option value="risk">Domain risk factors</option>
                </select>
              </Field>
              {kind === "policy" && (
                <Field label="Device context">
                  <select name="device">
                    <option value="">Network defaults</option>
                    {devices.data?.map((d) => (
                      <option value={d.ip} key={d.ip}>
                        {d.name}
                      </option>
                    ))}
                  </select>
                </Field>
              )}
            </AsyncForm>
          </div>
        </Panel>
        <Panel
          title="Inspection result"
          subtitle="Reflects current rules, not a historical query"
        >
          {report ? (
            <dl className="detail-list report">
              {Object.entries(report).map(([key, value]) => (
                <div key={key}>
                  <dt>{key.replaceAll("_", " ")}</dt>
                  <dd>
                    {Array.isArray(value) ? (
                      <ul>
                        {value.map((v, i) => (
                          <li key={i}>{String(v)}</li>
                        ))}
                      </ul>
                    ) : typeof value === "object" ? (
                      JSON.stringify(value)
                    ) : (
                      String(value)
                    )}
                  </dd>
                </div>
              ))}
            </dl>
          ) : (
            <Empty title="Ready to investigate">
              Enter a domain and choose an inspection.
            </Empty>
          )}
        </Panel>
      </div>
      <Panel
        title="Rate guard"
        subtitle="Devices currently restricted by the DNS request rate guard"
      >
        {quarantine.error ? (
          <ErrorState error={quarantine.error} />
        ) : !quarantine.data ? (
          <Skeleton rows={2} />
        ) : !quarantine.data.length ? (
          <Empty title="No devices in quarantine">
            Rate containment is applied automatically when a device exceeds the
            query threshold.
          </Empty>
        ) : (
          <Table headers={["Device", "Address", "Action"]}>
            {quarantine.data.map((ip) => (
              <tr key={ip}>
                <td>
                  {devices.data?.find((d) => d.ip === ip)?.name ||
                    "Unregistered"}
                </td>
                <td className="mono">{ip}</td>
                <td>
                  <AsyncForm
                    label="Release device"
                    submit={() =>
                      send(
                        `/quarantine/${encodeURIComponent(ip)}`,
                        undefined,
                        "DELETE",
                      )
                    }
                  >
                    {null}
                  </AsyncForm>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}

export function Alerts() {
  const query = useApi<Telegram>("/telegram");
  return (
    <>
      <PageHeader
        eyebrow="UTILITIES / ALERTS"
        title="Only what needs your attention."
        description="Send DNS security notifications to your Telegram chat."
      />
      {query.error ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : query.data ? (
        <div className="settings-layout">
          <Panel title="Telegram notifications">
            <div className="panel-body">
              <TelegramForm initial={query.data} />
            </div>
          </Panel>
          <aside className="settings-aside">
            <Radio size={32} strokeWidth={1.2} />
            <h2>Keep an eye on DNS activity.</h2>
            <p>
              Alerts use the configured domain risk threshold. You can also
              request notifications when queries are blocked.
            </p>
            <Badge
              tone={
                query.data.enabled && query.data.bot_token_configured
                  ? "success"
                  : "neutral"
              }
            >
              {query.data.enabled && query.data.bot_token_configured
                ? "Configured and enabled"
                : "Notifications inactive"}
            </Badge>
            <p>
              Save your settings before sending a test. This sends a real
              message to the configured chat.
            </p>
            <AsyncForm
              label="Send test message"
              submit={() => send("/telegram/test")}
            >
              {null}
            </AsyncForm>
          </aside>
        </div>
      ) : (
        <Skeleton rows={7} />
      )}
    </>
  );
}
function TelegramForm({ initial }: { initial: Telegram }) {
  const [enabled, setEnabled] = useState(initial.enabled),
    [blocked, setBlocked] = useState(initial.notify_on_block),
    [token, setToken] = useState(""),
    [chat, setChat] = useState(initial.chat_id),
    [detectError, setDetectError] = useState(""),
    [detectBusy, setDetectBusy] = useState(false);
  async function detect() {
    setDetectBusy(true);
    setDetectError("");
    try {
      const data = await send<{
        ok: boolean;
        description?: string;
        result?: {
          message?: { chat?: { id: number } };
          channel_post?: { chat?: { id: number } };
          my_chat_member?: { chat?: { id: number } };
        }[];
      }>("/telegram/detect", { token });
      if (!data.ok)
        throw new Error(
          data.description || "Telegram could not read recent messages.",
        );
      const update = [...(data.result || [])]
        .reverse()
        .find(
          (x) =>
            x.message?.chat || x.channel_post?.chat || x.my_chat_member?.chat,
        );
      const id =
        update?.message?.chat?.id ??
        update?.channel_post?.chat?.id ??
        update?.my_chat_member?.chat?.id;
      if (id === undefined)
        throw new Error("Send a message to your bot, then try again.");
      setChat(String(id));
    } catch (e) {
      setDetectError((e as Error).message);
    } finally {
      setDetectBusy(false);
    }
  }
  return (
    <AsyncForm
      submit={(d) =>
        send("/telegram", {
          enabled,
          bot_token: token.trim(),
          chat_id: chat.trim(),
          threat_threshold: Number(d.get("threshold")),
          notify_on_block: blocked,
        })
      }
    >
      <Toggle
        label="Enable notifications"
        checked={enabled}
        onChange={setEnabled}
      />
      <Field
        label="Bot token"
        hint={
          initial.bot_token_configured
            ? "A token is saved. Leave blank to keep it."
            : "Create a bot in Telegram and use its API token."
        }
      >
        <input
          type="password"
          autoComplete="new-password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder={
            initial.bot_token_configured
              ? "Saved token · enter to replace"
              : "Enter bot token"
          }
        />
      </Field>
      <Field label="Chat ID">
        <input
          value={chat}
          onChange={(e) => setChat(e.target.value)}
          placeholder="Your Telegram chat ID"
        />
      </Field>
      <Button onClick={() => void detect()} disabled={!token || detectBusy}>
        {detectBusy
          ? "Checking messages…"
          : "Find chat ID from recent messages"}
      </Button>
      {detectError && (
        <p className="form-error" role="alert">
          {detectError}
        </p>
      )}
      <Field
        label="Risk threshold"
        hint="Send domain alerts at or above this heuristic score."
      >
        <input
          name="threshold"
          type="number"
          min={1}
          max={100}
          required
          defaultValue={initial.threat_threshold}
        />
      </Field>
      <Toggle
        label="Notify on blocked queries"
        description="Can produce frequent messages on busy networks."
        checked={blocked}
        onChange={setBlocked}
      />
    </AsyncForm>
  );
}

export function Settings() {
  const dhcp = useApi<Dhcp>("/dhcp");
  return (
    <>
      <PageHeader
        eyebrow="INFRASTRUCTURE / SETTINGS"
        title="Built for your network."
        description="Configure address assignment and manage the local service."
      />
      <div className="settings-layout">
        <Panel
          title="DHCP address assignment"
          subtitle="Changes require a server restart"
        >
          <div className="panel-body">
            {dhcp.error ? (
              <ErrorState
                error={dhcp.error}
                retry={() => void dhcp.refetch()}
              />
            ) : dhcp.data ? (
              <DhcpForm initial={dhcp.data} />
            ) : (
              <Skeleton rows={6} />
            )}
          </div>
        </Panel>
        <aside className="settings-aside">
          <Server size={32} strokeWidth={1.2} />
          <h2>Service controls</h2>
          <p>
            Restart AegisDNS to apply DHCP changes. DNS will be briefly
            unavailable while the service returns.
          </p>
          <ConfirmButton
            variant="secondary"
            title="Restart AegisDNS?"
            description="DNS resolution will be interrupted briefly. Your settings will be preserved."
            onConfirm={() => send("/restart")}
          >
            <RefreshCw size={16} />
            Restart service
          </ConfirmButton>
          <div className="aside-divider" />
          <h2>Query retention</h2>
          <p>
            Delete recorded query history and its associated relationship
            observations.
          </p>
          <AsyncForm
            danger
            label="Delete selected history"
            submit={(d) => {
              if (d.get("confirm") !== "on")
                throw new Error("Confirm deletion before continuing.");
              return send("/logs", { timeframe: d.get("timeframe") }, "DELETE");
            }}
          >
            <Field label="Delete history">
              <select name="timeframe">
                <option value="1h">Last hour</option>
                <option value="24h">Last day</option>
                <option value="7d">Last 7 days</option>
                <option value="all">All recorded history</option>
              </select>
            </Field>
            <label className="checkbox-label">
              <input name="confirm" type="checkbox" required />
              <span>I understand this cannot be undone.</span>
            </label>
          </AsyncForm>
        </aside>
      </div>
    </>
  );
}
function DhcpForm({ initial }: { initial: Dhcp }) {
  const [enabled, setEnabled] = useState(initial.enabled);
  return (
    <AsyncForm
      submit={(d) =>
        send("/dhcp", {
          enabled,
          server_ip: d.get("server_ip"),
          router_ip: d.get("router_ip"),
          subnet_mask: d.get("subnet_mask"),
          start_ip: d.get("start_ip"),
          end_ip: d.get("end_ip"),
          lease_duration_secs: Number(d.get("lease_duration_secs")),
        })
      }
    >
      <Toggle
        label="Enable DHCP server"
        description="Use only when this is the intended DHCP server on your network."
        checked={enabled}
        onChange={setEnabled}
      />
      <div className="form-grid">
        {[
          ["server_ip", "Server IP"],
          ["router_ip", "Router IP"],
          ["subnet_mask", "Subnet mask"],
          ["start_ip", "Pool start"],
          ["end_ip", "Pool end"],
        ].map(([name, label]) => (
          <Field key={name} label={label}>
            <input
              name={name}
              required
              defaultValue={String(initial[name as keyof Dhcp])}
            />
          </Field>
        ))}
        <Field label="Lease duration (seconds)">
          <input
            type="number"
            name="lease_duration_secs"
            min={60}
            max={2592000}
            required
            defaultValue={initial.lease_duration_secs}
          />
        </Field>
      </div>
      <p className="note">
        Save first, then restart the service when you are ready. Saving does not
        restart DNS automatically.
      </p>
    </AsyncForm>
  );
}
