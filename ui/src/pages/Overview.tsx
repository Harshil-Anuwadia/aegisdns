import { lazy, Suspense } from "react";
import {
  ArrowDownLeft,
  ArrowUpRight,
  Globe2,
  Monitor,
  ShieldCheck,
  Waypoints,
} from "lucide-react";
import { number, rate, time, timestamp, useApi } from "../api";
import type {
  Device,
  Domains,
  Stats,
  DomainCount,
  Upstream,
  Policy,
} from "../types";
import { useLive } from "../live";
import {
  Badge,
  Empty,
  ErrorState,
  PageHeader,
  PageLink,
  Panel,
  Skeleton,
  Status,
  Table,
} from "../components/ui";
const ActivityChart = lazy(() => import("../components/ActivityChart"));

export default function Overview() {
  const stats = useApi<Stats>("/stats", 5000),
    devices = useApi<Device[]>("/devices", 15000),
    domains = useApi<Domains>("/top-domains", 15000),
    blocked = useApi<DomainCount[]>("/top-blocked", 15000),
    upstream = useApi<Upstream>("/upstream"),
    policy = useApi<Policy>("/policy");
  const live = useLive();
  const s = stats.data;
  const active = new Set(live.events.map((e) => e.client_ip)).size;
  const lastActivityAge = live.events[0]
    ? Date.now() - timestamp(live.events[0].timestamp).getTime()
    : Infinity;
  return (
    <>
      <PageHeader
        eyebrow="NETWORK / OVERVIEW"
        title="Your network, in focus."
        description="A live view of DNS activity, filtering, and the devices behind it."
        action={
          <span className="period-label">
            <span className="status-dot" /> Today · UTC
          </span>
        }
      />
      {stats.error && (
        <ErrorState error={stats.error} retry={() => void stats.refetch()} />
      )}
      <section className="overview-band">
        <div className="network-identity">
          <div className="eyebrow">AEGISDNS / LOCAL NETWORK</div>
          <h2>
            Visibility.
            <br />
            <span>Without the noise.</span>
          </h2>
          <div className="identity-state">
            <ShieldCheck size={18} />
            <span>
              {s ? "Query analytics available" : "Connecting to your server"}
            </span>
          </div>
          <p>
            {s
              ? `${number(s.blocked_today)} DNS requests blocked today.`
              : "Waiting for AegisDNS to report activity."}
          </p>
        </div>
        <div className="metrics">
          <div className="metric primary-metric">
            <label>Total queries</label>
            <strong>{number(s?.queries_today)}</strong>
            <small>
              <ArrowUpRight size={14} /> Requests received today
            </small>
          </div>
          <div className="metric">
            <label>Blocked</label>
            <strong className="danger-text">{number(s?.blocked_today)}</strong>
            <small>
              {s ? rate(s.blocked_today, s.queries_today) : "—"}% of total
              queries
            </small>
          </div>
          <div className="metric">
            <label>Allowed</label>
            <strong>{number(s?.allowed_today)}</strong>
            <small>Passed through filtering</small>
          </div>
          <div className="metric">
            <label>Avg. response</label>
            <strong>
              {s?.avg_latency_ms ? s.avg_latency_ms.toFixed(1) : "—"}
              <em>ms</em>
            </strong>
            <small>Allowed queries · last 5 min</small>
          </div>
        </div>
      </section>
      <div className="overview-grid">
        <Panel
          title="Traffic pulse"
          subtitle="Queries per second · entire network"
          action={
            <Badge tone={live.state === "live" ? "info" : "neutral"}>
              Last 60 seconds
            </Badge>
          }
        >
          <div className="chart-legend">
            <span>
              <i className="info-dot" />
              Queries
            </span>
            <span>
              <i className="danger-dot" />
              Blocked
            </span>
            <span>
              <i className="violet-dot" />
              Cached
            </span>
          </div>
          <Suspense fallback={<Skeleton />}>
            <ActivityChart />
          </Suspense>
        </Panel>
        <Panel
          title="Resolution path"
          subtitle="How this network handles DNS"
          className="path-panel"
        >
          <div className="resolution-step">
            <span className="path-node">
              <Monitor size={20} />
            </span>
            <div>
              <strong>Devices</strong>
              <small>
                {devices.data
                  ? `${devices.data.length} registered · ${active} in recent events`
                  : "Reading devices…"}
              </small>
            </div>
          </div>
          <div
            className={`path-connector ${live.state === "live" && lastActivityAge >= 0 && lastActivityAge < 10000 ? "has-traffic" : ""}`}
          />
          <div className="resolution-step aegis-step">
            <span className="path-node">
              <ShieldCheck size={22} />
            </span>
            <div>
              <strong>AegisDNS</strong>
              <small>
                {policy.data
                  ? `${policy.data.allowed.length + policy.data.denied.length} global rules`
                  : "Policy engine"}
              </small>
            </div>
            <Badge tone="success">Filter</Badge>
          </div>
          <div className="path-branches">
            <div>
              <span className="branch-count danger-text">
                {number(s?.blocked_today)}
              </span>
              <small>Blocked here</small>
            </div>
            <div>
              <span className="branch-count">
                {number(s ? s.allowed_today + s.cache_hits : undefined)}
              </span>
              <small>Allowed / cached</small>
            </div>
          </div>
          <div className="resolution-step">
            <span className="path-node">
              <Globe2 size={20} />
            </span>
            <div>
              <strong>
                {upstream.data
                  ? upstream.data.enabled
                    ? "Configured forwarders"
                    : "Recursive resolution"
                  : "Resolver configuration unavailable"}
              </strong>
              <small>
                {upstream.data
                  ? upstream.data.enabled
                    ? `${upstream.data.resolvers.length} resolver endpoints`
                    : "Unbound · DNSSEC validation"
                  : "Open upstream settings to retry"}
              </small>
            </div>
          </div>
          <PageLink to="network">Explore domain relationships</PageLink>
        </Panel>
        <Panel
          title="Query stream"
          subtitle="Most recent DNS requests"
          action={<PageLink to="traffic">Open query log</PageLink>}
        >
          {live.historyError && !live.events.length ? (
            <ErrorState
              error={live.historyError}
              retry={() => location.reload()}
            />
          ) : live.historyLoading && !live.events.length ? (
            <Skeleton rows={4} />
          ) : !live.events.length ? (
            <Empty title="Waiting for query activity">
              Point a device at AegisDNS to see its requests.
            </Empty>
          ) : (
            <Table headers={["Time", "Domain", "Device", "Result"]}>
              {live.events.slice(0, 6).map((q, i) => (
                <tr key={`${q.timestamp}-${q.domain}-${i}`}>
                  <td className="mono muted">{time(q.timestamp)}</td>
                  <td>
                    <a
                      className="domain-link"
                      href={`#traffic?domain=${encodeURIComponent(q.domain)}`}
                    >
                      {q.domain}
                    </a>
                  </td>
                  <td className="muted">
                    {devices.data?.find((d) => d.ip === q.client_ip)?.name ||
                      q.client_ip}
                  </td>
                  <td>
                    <Status value={q.status} />
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </Panel>
        <Panel
          title="Most blocked"
          subtitle="Domains with the most blocked requests today"
          action={<ArrowDownLeft size={18} className="danger-text" />}
        >
          {blocked.error ? (
            <ErrorState error={blocked.error} />
          ) : !blocked.data ? (
            <Skeleton rows={3} />
          ) : (
            <DomainRanking rows={blocked.data.slice(0, 5)} danger />
          )}
        </Panel>
      </div>
      <Panel
        title="Where queries go"
        subtitle="Top destination domains today"
        action={<PageLink to="threats">View domain activity</PageLink>}
      >
        {domains.error ? (
          <ErrorState error={domains.error} />
        ) : !domains.data ? (
          <Skeleton rows={3} />
        ) : (
          <div className="destination-grid">
            {domains.data.top_domains.slice(0, 6).map((d) => (
              <a
                key={d.domain}
                href={`#network?domain=${encodeURIComponent(d.domain)}`}
                className="destination"
              >
                <span className="domain-monogram">
                  {d.domain?.charAt(0).toUpperCase()}
                </span>
                <div>
                  <strong>{d.domain}</strong>
                  <small>{number(d.count)} queries</small>
                </div>
                <ArrowUpRight size={17} />
              </a>
            ))}
            {!domains.data.top_domains.length && (
              <Empty title="No destination activity yet" />
            )}
          </div>
        )}
      </Panel>
    </>
  );
}
export function DomainRanking({
  rows,
  danger = false,
}: {
  rows: DomainCount[];
  danger?: boolean;
}) {
  const max = Math.max(...rows.map((d) => d.count), 1);
  return rows.length ? (
    <div className="domain-ranking">
      {rows.map((d, i) => (
        <a
          className="rank-row"
          key={d.domain}
          href={`#network?domain=${encodeURIComponent(d.domain)}`}
        >
          <span className="rank-index">{String(i + 1).padStart(2, "0")}</span>
          <div>
            <strong>{d.domain}</strong>
            <span className="rank-track">
              <i
                className={danger ? "danger-fill" : ""}
                style={{ width: `${(d.count / max) * 100}%` }}
              />
            </span>
          </div>
          <span className="mono">{number(d.count)}</span>
        </a>
      ))}
    </div>
  ) : (
    <Empty
      title={danger ? "No blocked domains today" : "No domains recorded yet"}
    />
  );
}
