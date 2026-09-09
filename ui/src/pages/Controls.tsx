import { useState } from "react";
import { Clock3, ListFilter, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { number, send, useApi } from "../api";
import type { Blocklist, Device, Policy, Schedule } from "../types";
import {
  AsyncForm,
  Badge,
  Button,
  ConfirmButton,
  Dialog,
  Empty,
  ErrorState,
  Field,
  PageHeader,
  Panel,
  Skeleton,
  Table,
} from "../components/ui";

function DeviceSelect({
  devices,
  name = "device",
  value,
  id,
}: {
  devices: Device[];
  name?: string;
  value?: string;
  id?: string;
}) {
  return (
    <select id={id} name={name} defaultValue={value || ""}>
      <option value="">All devices</option>
      {devices.map((d) => (
        <option key={d.ip} value={d.ip}>
          {d.name} · {d.ip}
        </option>
      ))}
    </select>
  );
}
export function Rules() {
  const query = useApi<Policy>("/policy"),
    devices = useApi<Device[]>("/devices"),
    [open, setOpen] = useState(false),
    [search, setSearch] = useState(""),
    [scope, setScope] = useState("all");
  const rows = query.data
    ? [
        ...query.data.allowed.map((domain) => ({
          domain,
          action: "Allowed",
          ip: "",
        })),
        ...query.data.denied.map((domain) => ({
          domain,
          action: "Blocked",
          ip: "",
        })),
        ...Object.entries(query.data.device_allowed).flatMap(([ip, domains]) =>
          domains.map((domain) => ({ domain, action: "Allowed", ip })),
        ),
        ...Object.entries(query.data.device_denied).flatMap(([ip, domains]) =>
          domains.map((domain) => ({ domain, action: "Blocked", ip })),
        ),
      ].filter(
        (r) =>
          r.domain.includes(search.toLowerCase()) &&
          (scope === "all" || (scope === "global" ? !r.ip : !!r.ip)),
      )
    : [];
  return (
    <>
      <PageHeader
        eyebrow="CONTROL / RULES"
        title="Decide what gets through."
        description="Explicit domain rules for your whole network or a single device."
        action={
          <Button variant="primary" onClick={() => setOpen(true)}>
            <Plus size={16} />
            Add rule
          </Button>
        }
      />
      <Panel>
        <div className="filter-bar">
          <input
            aria-label="Search rules"
            placeholder="Search domains…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            aria-label="Rule scope"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
          >
            <option value="all">All scopes</option>
            <option value="global">Network rules</option>
            <option value="device">Device rules</option>
          </select>
          <span className="filter-count">{rows.length} rules</span>
        </div>
        {query.error ? (
          <ErrorState error={query.error} retry={() => void query.refetch()} />
        ) : !query.data ? (
          <Skeleton />
        ) : !rows.length ? (
          <Empty title="No rules match this view">
            Add a domain rule to make an explicit allow or block decision.
          </Empty>
        ) : (
          <Table headers={["Domain", "Decision", "Applies to", ""]}>
            {rows.map((r) => (
              <tr key={`${r.domain}-${r.ip}-${r.action}`}>
                <td className="mono">{r.domain}</td>
                <td>
                  <Badge tone={r.action === "Allowed" ? "success" : "danger"}>
                    {r.action}
                  </Badge>
                </td>
                <td>
                  {r.ip
                    ? devices.data?.find((d) => d.ip === r.ip)?.name || r.ip
                    : "All devices"}
                </td>
                <td>
                  <ConfirmButton
                    title="Remove domain rule?"
                    description={`${r.domain} will return to the remaining policy and blocklist rules.`}
                    onConfirm={() =>
                      send("/policy/remove", {
                        domain: r.domain,
                        ...(r.ip ? { device_id: r.ip } : {}),
                      })
                    }
                  >
                    <Trash2 size={16} />
                    <span className="sr-only">Remove {r.domain}</span>
                  </ConfirmButton>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
      <p className="footnote">
        Active schedules take precedence. A device rule takes precedence over a
        network rule; explicit allow rules bypass content filtering.
      </p>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title="Add a domain rule"
        description="The rule includes the domain and its subdomains."
      >
        <AsyncForm
          label="Create rule"
          onSuccess={() => setOpen(false)}
          submit={(d) =>
            send(`/${d.get("action")}`, {
              domain: String(d.get("domain")).trim(),
              ...(d.get("device") ? { device_id: d.get("device") } : {}),
            })
          }
        >
          <Field label="Domain">
            <input
              name="domain"
              required
              placeholder="example.com"
              autoComplete="off"
              maxLength={253}
            />
          </Field>
          <Field label="Decision">
            <select name="action">
              <option value="deny">Block</option>
              <option value="allow">Allow</option>
            </select>
          </Field>
          <Field label="Applies to">
            <DeviceSelect devices={devices.data || []} />
          </Field>
        </AsyncForm>
      </Dialog>
    </>
  );
}
export function Blocklists() {
  const query = useApi<Blocklist[]>("/lists"),
    [open, setOpen] = useState(false);
  return (
    <>
      <PageHeader
        eyebrow="CONTROL / BLOCKLISTS"
        title="Protection, from your sources."
        description="Manage the lists that supply domain filtering rules."
        action={
          <Button variant="primary" onClick={() => setOpen(true)}>
            <Plus size={16} />
            Add source
          </Button>
        }
      />
      <div className="summary-line">
        <ListFilter size={20} />
        <strong>
          {query.data
            ? number(
                query.data.reduce(
                  (sum, l) => sum + (l.enabled ? l.rule_count : 0),
                  0,
                ),
              )
            : "—"}
        </strong>
        <span>
          rules across {query.data?.filter((l) => l.enabled).length ?? "—"}{" "}
          enabled sources
        </span>
        <small>Sources can overlap.</small>
      </div>
      {query.error ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : !query.data ? (
        <Skeleton />
      ) : !query.data.length ? (
        <Panel>
          <Empty title="No blocklist sources">
            Add an HTTPS blocklist to start filtering domains.
          </Empty>
        </Panel>
      ) : (
        <div className="source-list">
          {query.data.map((list, i) => (
            <Panel key={list.name}>
              <div className="source-row">
                <span className="source-number">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <div className="source-name">
                  <h2>{list.name}</h2>
                  <span>Domain filtering source</span>
                </div>
                <Badge tone={list.enabled ? "success" : "neutral"}>
                  {list.enabled ? "Enabled" : "Disabled"}
                </Badge>
                <div className="source-total">
                  <strong>{number(list.rule_count)}</strong>
                  <small>rules</small>
                </div>
                <ConfirmButton
                  title="Remove this source?"
                  description={`Remove ${list.name} from active filtering. Local file sources are disabled.`}
                  onConfirm={() =>
                    send(
                      `/blocklists/${encodeURIComponent(list.name)}`,
                      undefined,
                      "DELETE",
                    )
                  }
                >
                  <Trash2 size={17} />
                  <span className="sr-only">Remove {list.name}</span>
                </ConfirmButton>
              </div>
            </Panel>
          ))}
        </div>
      )}
      <p className="footnote">
        AegisDNS refreshes sources at startup and every six hours. A failed
        download keeps the previous active snapshot.
      </p>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title="Add a blocklist source"
        description="Use an HTTPS URL that serves a supported domain or hosts list."
      >
        <AsyncForm
          label="Add and download"
          onSuccess={() => setOpen(false)}
          submit={(d) =>
            send("/blocklists", {
              name: d.get("name"),
              source_url: d.get("url"),
            })
          }
        >
          <Field label="Source name">
            <input
              name="name"
              required
              maxLength={128}
              placeholder="My filtering list"
            />
          </Field>
          <Field label="HTTPS URL">
            <input
              name="url"
              type="url"
              pattern="https://.*"
              required
              placeholder="https://example.com/blocklist.txt"
            />
          </Field>
          <p className="note">
            Downloading and validating a source may take a moment.
          </p>
        </AsyncForm>
      </Dialog>
    </>
  );
}
const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const clock = (minutes: number) =>
  `${String(Math.floor(minutes / 60)).padStart(2, "0")}:${String(minutes % 60).padStart(2, "0")}`;
export function Schedules() {
  const query = useApi<Schedule[]>("/schedules"),
    devices = useApi<Device[]>("/devices"),
    tz = useApi<{ timezone: string }>("/timezone"),
    [open, setOpen] = useState(false);
  return (
    <>
      <PageHeader
        eyebrow="CONTROL / SCHEDULES"
        title="Make room for offline."
        description="Set predictable hours for domain access, for everyone or a single device."
        action={
          <Button variant="primary" onClick={() => setOpen(true)}>
            <Plus size={16} />
            Create schedule
          </Button>
        }
      />
      <div className="timezone-note">
        <Clock3 size={16} />
        <span>Server timezone: {tz.data?.timezone || "Checking…"}</span>
      </div>
      {query.error ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : !query.data ? (
        <Skeleton />
      ) : !query.data.length ? (
        <Panel>
          <Empty title="No schedules yet">
            Create a schedule to control domain access by time.
          </Empty>
        </Panel>
      ) : (
        <div className="schedule-grid">
          {query.data.map((s) => (
            <Panel key={s.id}>
              <div className="schedule-top">
                <Clock3 size={22} />
                <Badge tone={s.enabled ? "success" : "neutral"}>
                  {s.enabled ? "Enabled" : "Paused"}
                </Badge>
              </div>
              <div className="schedule-content">
                <h2>{s.label || s.domain}</h2>
                <p className="mono">{s.domain}</p>
                <div className="schedule-time">
                  {s.start_minutes === s.end_minutes
                    ? "All day"
                    : `${clock(s.start_minutes)} — ${clock(s.end_minutes)}`}
                </div>
                <div className="days-display">
                  {dayNames.map((day, index) => (
                    <span
                      key={day}
                      className={s.days.includes(index) ? "selected" : ""}
                    >
                      {day}
                    </span>
                  ))}
                </div>
                <p>
                  {s.action} ·{" "}
                  {s.device_id
                    ? devices.data?.find((d) => d.ip === s.device_id)?.name ||
                      s.device_id
                    : "All devices"}
                </p>
              </div>
              <div className="schedule-footer">
                <AsyncForm
                  label={s.enabled ? "Pause schedule" : "Enable schedule"}
                  submit={() =>
                    send(
                      `/schedules/${encodeURIComponent(s.id)}/toggle`,
                      { enabled: !s.enabled },
                      "PUT",
                    )
                  }
                >
                  {null}
                </AsyncForm>
                <ConfirmButton
                  title="Delete schedule?"
                  description={`Remove ${s.label || s.domain} permanently.`}
                  onConfirm={() =>
                    send(
                      `/schedules/${encodeURIComponent(s.id)}`,
                      undefined,
                      "DELETE",
                    )
                  }
                >
                  <Trash2 size={16} />
                  <span className="sr-only">Delete schedule {s.label}</span>
                </ConfirmButton>
              </div>
            </Panel>
          ))}
        </div>
      )}
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title="Create a schedule"
        description="Overnight schedules belong to their starting day. Equal start and end times mean all day."
      >
        <AsyncForm
          label="Create schedule"
          onSuccess={() => setOpen(false)}
          submit={(d) => {
            const days = d.getAll("days").map(Number);
            if (!days.length) throw new Error("Choose at least one day.");
            const [start_hour, start_min] = String(d.get("start"))
              .split(":")
              .map(Number);
            const [end_hour, end_min] = String(d.get("end"))
              .split(":")
              .map(Number);
            return send("/schedules", {
              label: d.get("label"),
              domain: d.get("domain"),
              action: d.get("action"),
              days,
              start_hour,
              start_min,
              end_hour,
              end_min,
              device_id: d.get("device") || null,
            });
          }}
        >
          <Field label="Name">
            <input
              name="label"
              required
              maxLength={256}
              placeholder="Evening screen break"
            />
          </Field>
          <Field label="Domain">
            <input name="domain" required placeholder="youtube.com" />
          </Field>
          <div className="form-grid">
            <Field label="Decision">
              <select name="action">
                <option value="block">Block</option>
                <option value="allow">Allow</option>
              </select>
            </Field>
            <Field label="Applies to">
              <DeviceSelect devices={devices.data || []} />
            </Field>
            <Field label="From">
              <input type="time" name="start" defaultValue="22:00" required />
            </Field>
            <Field label="Until">
              <input type="time" name="end" defaultValue="07:00" required />
            </Field>
          </div>
          <div className="day-selector" role="group" aria-label="Days of week">
            {dayNames.map((day, i) => (
              <label key={day}>
                <input type="checkbox" name="days" value={i} defaultChecked />
                <span>{day}</span>
              </label>
            ))}
          </div>
        </AsyncForm>
      </Dialog>
    </>
  );
}
