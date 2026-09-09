import { useState } from "react";
import { ShieldCheck, ShieldOff } from "lucide-react";
import { number, send, useApi } from "../api";
import type { DomainCount, Domains, Stats } from "../types";
import {
  AsyncForm,
  Badge,
  Empty,
  ErrorState,
  Field,
  PageHeader,
  Panel,
  Skeleton,
  Table,
  Toggle,
} from "../components/ui";
import { DomainRanking } from "./Overview";

export default function Blocking() {
  const stats = useApi<Stats>("/stats", 10000),
    blocked = useApi<DomainCount[]>("/top-blocked", 15000),
    domains = useApi<Domains>("/top-domains", 15000),
    safe = useApi<{ enabled: boolean }>("/safesearch"),
    [kind, setKind] = useState("top_domains");
  return (
    <>
      <PageHeader
        eyebrow="OBSERVE / BLOCKING"
        title="Less noise. More control."
        description="Understand what was filtered and fine-tune the domains your network can reach."
      />
      <div className="blocking-banner">
        <ShieldCheck size={32} strokeWidth={1.3} />
        <div>
          <span className="eyebrow">BLOCKED TODAY</span>
          <strong>{number(stats.data?.blocked_today)}</strong>
        </div>
        <p>
          DNS requests stopped by filtering.
          <small>
            Request logs do not distinguish malware, advertising, and policy
            blocks.
          </small>
        </p>
      </div>
      <div className="two-columns">
        <Panel
          title="Most blocked domains"
          subtitle="Today's requests, ranked by count"
        >
          {blocked.error ? (
            <ErrorState error={blocked.error} />
          ) : blocked.data ? (
            <DomainRanking rows={blocked.data} danger />
          ) : (
            <Skeleton />
          )}
        </Panel>
        <Panel
          title="SafeSearch"
          subtitle="Restrict supported search and video results"
        >
          <div className="panel-body">
            {safe.error ? (
              <ErrorState error={safe.error} />
            ) : safe.data ? (
              <SafeSearch initial={safe.data.enabled} />
            ) : (
              <Skeleton rows={2} />
            )}
          </div>
        </Panel>
      </div>
      <Panel
        title="Domain activity"
        subtitle="Classification is a browsing aid, not a security verdict"
        action={
          <select
            aria-label="Domain classification"
            value={kind}
            onChange={(e) => setKind(e.target.value)}
          >
            <option value="top_domains">Destinations</option>
            <option value="infrastructure">Infrastructure</option>
            <option value="unknown">Unclassified</option>
          </select>
        }
      >
        {domains.error ? (
          <ErrorState error={domains.error} />
        ) : !domains.data ? (
          <Skeleton />
        ) : (domains.data[kind as keyof Domains] || []).length ? (
          <Table headers={["Domain", "Queries today", "Classification"]}>
            {domains.data[kind as keyof Domains].map((d) => (
              <tr key={d.domain}>
                <td>
                  <a href={`#network?domain=${encodeURIComponent(d.domain)}`}>
                    {d.domain}
                  </a>
                </td>
                <td className="mono">{number(d.count)}</td>
                <td>
                  <AsyncForm
                    label="Apply"
                    submit={(data) =>
                      send("/classify", {
                        domain: d.domain,
                        category: data.get("category"),
                      })
                    }
                  >
                    <select
                      name="category"
                      aria-label={`Classify ${d.domain}`}
                      defaultValue={
                        kind === "top_domains" ? "destination" : kind
                      }
                    >
                      <option value="destination">Destination</option>
                      <option value="infrastructure">Infrastructure</option>
                      <option value="unknown">Automatic / unknown</option>
                    </select>
                  </AsyncForm>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No domains in this category" />
        )}
      </Panel>
    </>
  );
}
function SafeSearch({ initial }: { initial: boolean }) {
  const [enabled, setEnabled] = useState(initial);
  return (
    <AsyncForm submit={() => send("/safesearch", { enabled })}>
      <Toggle
        label="Enforce SafeSearch"
        description="Google, Bing, DuckDuckGo, and YouTube on supported hostnames."
        checked={enabled}
        onChange={setEnabled}
      />
      <div className="note">
        Explicit allow rules and bypass profiles take precedence. DNS filtering
        cannot control traffic using another DNS service.
      </div>
    </AsyncForm>
  );
}
