import { useMemo, useState } from "react";
import { Download, Pause, Play, Search, SlidersHorizontal } from "lucide-react";
import { useLive } from "../live";
import { api, number, send, time, useApi } from "../api";
import { DomainIcon } from "../components/DomainIcon";
import type { Device, QueryEvent } from "../types";
import {
  AsyncForm,
  Badge,
  Button,
  Dialog,
  Empty,
  ErrorState,
  Skeleton,
  Field,
  PageHeader,
  Panel,
  Status,
  Table,
} from "../components/ui";

export default function Traffic() {
  const live = useLive(),
    devices = useApi<Device[]>("/devices");
  const params = new URLSearchParams(location.hash.split("?")[1]);
  const [search, setSearch] = useState(params.get("domain") || ""),
    [status, setStatus] = useState(params.get("status") || ""),
    [device, setDevice] = useState(params.get("device") || ""),
    [paused, setPaused] = useState<QueryEvent[] | null>(null),
    [page, setPage] = useState(0),
    [selected, setSelected] = useState<QueryEvent | null>(null),
    [exportOpen, setExportOpen] = useState(false),
    [sort, setSort] = useState("newest");
  const events = paused || live.events;
  const filtered = useMemo(() => {
    const rows = events.filter(
      (q) =>
        q.domain.toLowerCase().includes(search.toLowerCase()) &&
        (!status || q.status === status) &&
        (!device || q.client_ip === device),
    );
    return sort === "domain"
      ? [...rows].sort((a, b) => a.domain.localeCompare(b.domain))
      : sort === "oldest"
        ? [...rows].reverse()
        : rows;
  }, [events, search, status, device, sort]);
  const pages = Math.max(1, Math.ceil(filtered.length / 30)),
    safePage = Math.min(page, pages - 1);
  return (
    <>
      <PageHeader
        eyebrow="OBSERVE / TRAFFIC"
        title="Every query has a story."
        description="Inspect live requests and the latest 50 persisted queries. This session retains up to 500 events."
        action={
          <>
            <Button onClick={() => setPaused(paused ? null : [...live.events])}>
              {paused ? <Play size={15} /> : <Pause size={15} />}
              {paused ? "Resume stream" : "Pause stream"}
            </Button>
            <Button onClick={() => setExportOpen(true)}>
              <Download size={16} />
              Export history
            </Button>
          </>
        }
      />
      <Panel>
        <div className="filter-bar">
          <div className="search-field">
            <Search size={17} />
            <input
              aria-label="Search domains"
              placeholder="Filter by domain…"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(0);
              }}
            />
          </div>
          <select
            aria-label="Query status"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(0);
            }}
          >
            <option value="">All results</option>
            <option value="allowed">Allowed</option>
            <option value="blocked">Blocked</option>
            <option value="cache_hit">Cached</option>
            <option value="failed">Failed</option>
          </select>
          <select
            aria-label="Query device"
            value={device}
            onChange={(e) => {
              setDevice(e.target.value);
              setPage(0);
            }}
          >
            <option value="">All devices</option>
            {Array.from(
              new Set([
                ...events.map((q) => q.client_ip),
                ...(devices.data || []).map((d) => d.ip),
              ]),
            ).map((ip) => (
              <option key={ip} value={ip}>
                {devices.data?.find((d) => d.ip === ip)?.name || ip}
              </option>
            ))}
          </select>
          <select
            aria-label="Sort queries"
            value={sort}
            onChange={(e) => setSort(e.target.value)}
          >
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
            <option value="domain">Domain A–Z</option>
          </select>
        </div>
        <div className="stream-summary">
          <Badge
            tone={
              paused ? "warning" : live.state === "live" ? "info" : "warning"
            }
          >
            {paused
              ? "Paused"
              : live.state === "live"
                ? "Live stream"
                : "Reconnecting"}
          </Badge>
          <span>{number(filtered.length)} matching events</span>
          <span className="muted">Times shown in your local timezone</span>
        </div>
        {live.historyError && !events.length ? (
          <ErrorState
            error={live.historyError}
            retry={() => location.reload()}
          />
        ) : live.historyLoading && !events.length ? (
          <Skeleton rows={6} />
        ) : filtered.length ? (
          <Table
            headers={[
              "Time",
              "Domain",
              "Device",
              "IP address",
              "Result",
              "Details",
            ]}
          >
            {filtered.slice(safePage * 30, (safePage + 1) * 30).map((q, i) => (
              <tr key={`${q.timestamp}-${q.domain}-${i}`}>
                <td className="mono muted">{time(q.timestamp)}</td>
                <td>
                  <button
                    className="plain-button domain-link"
                    onClick={() => setSelected(q)}
                  >
                    <DomainIcon domain={q.domain} size="compact" />
                    {q.domain}
                  </button>
                </td>
                <td>
                  {devices.data?.find((d) => d.ip === q.client_ip)?.name ||
                    "Unregistered"}
                </td>
                <td className="mono muted">{q.client_ip}</td>
                <td>
                  <Status value={q.status} />
                </td>
                <td>
                  <Button
                    variant="ghost"
                    aria-label={`Inspect ${q.domain}`}
                    onClick={() => setSelected(q)}
                  >
                    <SlidersHorizontal size={15} />
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty
            title={
              search || status || device
                ? "No queries match these filters"
                : "Waiting for DNS activity"
            }
          >
            Try a different domain or device, or leave the stream open for new
            requests.
          </Empty>
        )}
        <div className="pagination">
          <span>
            Page {safePage + 1} of {pages}
          </span>
          <div>
            <Button disabled={!safePage} onClick={() => setPage(safePage - 1)}>
              Previous
            </Button>
            <Button
              disabled={safePage === pages - 1}
              onClick={() => setPage(safePage + 1)}
            >
              Next
            </Button>
          </div>
        </div>
      </Panel>
      <Dialog
        drawer
        open={!!selected}
        onClose={() => setSelected(null)}
        title={selected?.domain || "Query details"}
        description="Recorded request details."
      >
        {selected && (
          <>
            <dl className="detail-list">
              <div>
                <dt>Result</dt>
                <dd>
                  <Status value={selected.status} />
                </dd>
              </div>
              <div>
                <dt>Timestamp (UTC)</dt>
                <dd className="mono">{selected.timestamp}</dd>
              </div>
              <div>
                <dt>Device</dt>
                <dd>
                  {devices.data?.find((d) => d.ip === selected.client_ip)
                    ?.name || "Unregistered"}
                </dd>
              </div>
              <div>
                <dt>Client address</dt>
                <dd className="mono">{selected.client_ip}</dd>
              </div>
            </dl>
            <p className="note">
              Per-query latency, matching rule, and blocklist source are not
              included in this event.
            </p>
            <div className="drawer-links">
              <a
                className="button secondary"
                href={`#network?domain=${encodeURIComponent(selected.domain)}`}
                onClick={() => setSelected(null)}
              >
                Explore relationships
              </a>
              <a
                className="button secondary"
                href={`#diagnostics?domain=${encodeURIComponent(selected.domain)}`}
                onClick={() => setSelected(null)}
              >
                Check current policy
              </a>
            </div>
            <AsyncForm
              label="Apply rule"
              submit={(d) =>
                send(`/${d.get("action")}`, {
                  domain: selected.domain,
                  ...(d.get("scope") === "device"
                    ? { device_id: selected.client_ip }
                    : {}),
                })
              }
            >
              <Field label="New rule">
                <select name="action">
                  <option value="deny">Block this domain</option>
                  <option value="allow">Allow this domain</option>
                </select>
              </Field>
              <Field label="Scope">
                <select name="scope">
                  <option value="device">This device only</option>
                  <option value="global">All devices</option>
                </select>
              </Field>
            </AsyncForm>
          </>
        )}
      </Dialog>
      <Dialog
        open={exportOpen}
        onClose={() => setExportOpen(false)}
        title="Export query history"
        description="Download persisted DNS logs with the selected filters."
      >
        <AsyncForm
          label="Download export"
          submit={async (d) => {
            const q = new URLSearchParams({
              days: String(d.get("days")),
              format: String(d.get("format")),
              status,
              ip: device,
            });
            const response = await fetch(`/api/export/logs?${q}`, {
              credentials: "same-origin",
              headers: { "X-Aegis-Request": "1" },
            });
            if (!response.ok)
              throw new Error(`Export failed (${response.status})`);
            const url = URL.createObjectURL(await response.blob());
            const a = document.createElement("a");
            a.href = url;
            a.download = `aegisdns-queries.${d.get("format")}`;
            a.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
            setExportOpen(false);
          }}
        >
          <Field label="History">
            <select name="days">
              <option value="1">Last day</option>
              <option value="7">Last 7 days</option>
              <option value="30">Last 30 days</option>
            </select>
          </Field>
          <Field label="File format">
            <select name="format">
              <option value="csv">CSV</option>
              <option value="json">JSON</option>
            </select>
          </Field>
          <p className="note">
            Current device and status filters apply. Availability depends on
            retained logs.
          </p>
        </AsyncForm>
      </Dialog>
    </>
  );
}
