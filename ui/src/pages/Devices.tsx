import { useState } from "react";
import { Monitor, Plus, ArrowUpRight, Trash2, Search } from "lucide-react";
import { number, rate, send, useApi } from "../api";
import type { Device, Privacy } from "../types";
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
} from "../components/ui";
import { useLive } from "../live";

export default function Devices() {
  const query = useApi<Device[]>("/devices", 15000),
    privacy = useApi<Privacy>("/privacy", 15000),
    live = useLive();
  const [open, setOpen] = useState(false),
    [search, setSearch] = useState("");
  const devices =
    query.data?.filter((d) =>
      `${d.name} ${d.ip}`.toLowerCase().includes(search.toLowerCase()),
    ) || [];
  return (
    <>
      <PageHeader
        eyebrow="INFRASTRUCTURE / DEVICES"
        title="Know your network."
        description="Name your devices, inspect their DNS activity, and choose how each is filtered."
        action={
          <Button variant="primary" onClick={() => setOpen(true)}>
            <Plus size={16} />
            Add device
          </Button>
        }
      />
      <div className="filter-bar standalone">
        <div className="search-field">
          <Search size={17} />
          <input
            aria-label="Search devices"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name or IP address…"
          />
        </div>
        <span className="filter-count">
          {devices.length} registered devices
        </span>
      </div>
      {query.error ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : !query.data ? (
        <Skeleton />
      ) : !devices.length ? (
        <Panel>
          <Empty title="No registered devices in this view">
            Register an IP address to give it a friendly name and filtering
            profile.
          </Empty>
        </Panel>
      ) : (
        <div className="device-grid">
          {devices.map((d) => {
            const usage = privacy.data?.devices.find((p) => p.device === d.ip);
            const recent = live.events.some((q) => q.client_ip === d.ip);
            return (
              <Panel key={d.ip}>
                <div className="device-top">
                  <span className="device-icon">
                    <Monitor size={25} strokeWidth={1.4} />
                  </span>
                  <Badge tone={recent ? "info" : "neutral"}>
                    {recent ? "In recent events" : "No recent events"}
                  </Badge>
                </div>
                <div className="device-content">
                  <h2>{d.name}</h2>
                  <p className="mono">{d.ip}</p>
                  <div className="device-metrics">
                    <div>
                      <strong>{number(usage?.total_queries)}</strong>
                      <small>queries today</small>
                    </div>
                    <div>
                      <strong className="danger-text">
                        {number(usage?.blocked_queries)}
                      </strong>
                      <small>blocked</small>
                    </div>
                    <div>
                      <strong>
                        {usage
                          ? rate(usage.blocked_queries, usage.total_queries)
                          : "—"}
                        <em>%</em>
                      </strong>
                      <small>block rate</small>
                    </div>
                  </div>
                  <AsyncForm
                    label="Update profile"
                    submit={(data) =>
                      send(
                        `/devices/${encodeURIComponent(d.ip)}/profile`,
                        { profile: data.get("profile") },
                        "PUT",
                      )
                    }
                  >
                    <Field label="Filtering profile">
                      <select name="profile" defaultValue={d.profile}>
                        <option value="default">Default protection</option>
                        <option value="strict">
                          Strict · includes risk heuristics
                        </option>
                        <option value="bypass">Bypass content filtering</option>
                      </select>
                    </Field>
                  </AsyncForm>
                </div>
                <div className="device-footer">
                  <a href={`#traffic?device=${encodeURIComponent(d.ip)}`}>
                    Inspect queries <ArrowUpRight size={15} />
                  </a>
                  <ConfirmButton
                    title="Remove device registration?"
                    description={`Remove the name and profile for ${d.name}. This does not disconnect it from the network.`}
                    onConfirm={() =>
                      send(
                        `/devices/${encodeURIComponent(d.ip)}`,
                        undefined,
                        "DELETE",
                      )
                    }
                  >
                    <Trash2 size={16} />
                    <span className="sr-only">Remove {d.name}</span>
                  </ConfirmButton>
                </div>
              </Panel>
            );
          })}
        </div>
      )}
      <p className="footnote">
        Recent DNS activity is not an online/offline signal. Registered devices
        and Tailscale peers are shown; per-device totals reflect today's
        persisted logs.
      </p>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title="Register a device"
        description="Use the IP address AegisDNS sees in the query log."
      >
        <AsyncForm
          label="Save device"
          onSuccess={() => setOpen(false)}
          submit={(d) =>
            send("/devices", { name: d.get("name"), ip: d.get("ip") })
          }
        >
          <Field label="Device name">
            <input
              name="name"
              required
              maxLength={128}
              placeholder="Living room TV"
            />
          </Field>
          <Field label="IP address">
            <input name="ip" required placeholder="192.168.1.24" />
          </Field>
        </AsyncForm>
      </Dialog>
    </>
  );
}
