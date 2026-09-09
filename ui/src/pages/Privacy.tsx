import { useState } from "react";
import { Shield, SlidersHorizontal } from "lucide-react";
import { number, send, useApi } from "../api";
import type { Device, Privacy as PrivacyData } from "../types";
import {
  AsyncForm,
  Badge,
  Button,
  Dialog,
  Empty,
  ErrorState,
  Field,
  PageHeader,
  Panel,
  Skeleton,
  Table,
  Toggle,
} from "../components/ui";

export default function Privacy() {
  const query = useApi<PrivacyData>("/privacy", 15000),
    devices = useApi<Device[]>("/devices"),
    [open, setOpen] = useState(false);
  const over = query.data?.devices.filter(
    (d) =>
      d.score >=
      (query.data!.config.device_budgets[d.device] ??
        query.data!.config.default_budget),
  ).length;
  return (
    <>
      <PageHeader
        eyebrow="OBSERVE / PRIVACY"
        title="Give tracking a limit."
        description="Measure DNS exposure and set a daily tracking budget for each device."
        action={
          <Button
            variant="primary"
            onClick={() => setOpen(true)}
            disabled={!query.data}
          >
            <SlidersHorizontal size={16} />
            Configure budgets
          </Button>
        }
      />
      {query.error ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : !query.data ? (
        <Skeleton rows={7} />
      ) : (
        <>
          <div className="privacy-banner">
            <div className="privacy-symbol">
              <Shield size={39} strokeWidth={1.1} />
            </div>
            <div>
              <span className="eyebrow">DAILY PRIVACY BUDGET</span>
              <h2>
                {query.data.config.enabled
                  ? "Tracking limits are enabled."
                  : "Observation comes first."}
              </h2>
              <p>
                {query.data.config.enabled
                  ? "Known tracking domains are blocked when a device reaches its budget."
                  : "Exposure is measured. Turn on budget enforcement when you are ready."}
              </p>
            </div>
            <div className="privacy-banner-metric">
              <strong>
                {over}
                <span> / {query.data.devices.length}</span>
              </strong>
              <small>devices at their limit</small>
            </div>
          </div>
          <div className="privacy-device-grid">
            {query.data.devices.map((d) => {
              const budget =
                query.data!.config.device_budgets[d.device] ??
                query.data!.config.default_budget;
              return (
                <Panel key={d.device}>
                  <div className="privacy-card-head">
                    <div>
                      <h2>
                        {devices.data?.find((x) => x.ip === d.device)?.name ||
                          d.device}
                      </h2>
                      <p className="mono">{d.device}</p>
                    </div>
                    <Badge tone={d.score >= budget ? "warning" : "violet"}>
                      {d.score >= budget ? "At limit" : "Within budget"}
                    </Badge>
                  </div>
                  <div className="budget-display">
                    <svg
                      viewBox="0 0 140 140"
                      aria-label={`Exposure score ${d.score} out of 100`}
                      role="img"
                    >
                      <circle className="ring-track" cx="70" cy="70" r="57" />
                      <circle
                        className="ring-value"
                        cx="70"
                        cy="70"
                        r="57"
                        strokeDasharray={`${(d.score / 100) * 358} 358`}
                      />
                      <text x="70" y="69">
                        {d.score}
                      </text>
                      <text className="ring-label" x="70" y="88">
                        EXPOSURE
                      </text>
                    </svg>
                    <div>
                      <strong>
                        {budget}
                        <span> / 100</span>
                      </strong>
                      <p>Daily limit</p>
                      <small>
                        Higher exposure means more
                        <br />
                        DNS tracking signals.
                      </small>
                    </div>
                  </div>
                  <dl className="privacy-factors">
                    <div>
                      <dt>Tracking companies</dt>
                      <dd>{number(d.tracking_companies)}</dd>
                    </div>
                    <div>
                      <dt>Identifier-like domains</dt>
                      <dd>{number(d.advertising_identifiers)}</dd>
                    </div>
                    <div>
                      <dt>Unique domains</dt>
                      <dd>{number(d.unique_domains)}</dd>
                    </div>
                    <div>
                      <dt>Networks / countries</dt>
                      <dd>
                        {d.network_spread} / {d.country_spread}
                      </dd>
                    </div>
                    <div>
                      <dt>Queries from 00–06 UTC</dt>
                      <dd>{number(d.quiet_hour_queries)}</dd>
                    </div>
                  </dl>
                </Panel>
              );
            })}
          </div>
          {!query.data.devices.length && (
            <Panel>
              <Empty title="No device activity recorded today">
                Privacy budgets become measurable once DNS queries are recorded.
              </Empty>
            </Panel>
          )}
          <div className="method-note">
            <Shield size={20} />
            <div>
              <h3>What this score means</h3>
              <p>
                This is a DNS-based exposure estimate, not a guarantee of
                privacy. Company and application matches are inferred from
                domain patterns. Identifier-like hostnames are not confirmed
                advertising IDs. Quiet hours are 00–06 UTC, not measured device
                idle time. Network and country counts depend on available
                enrichment.
              </p>
            </div>
          </div>
        </>
      )}
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title="Privacy budget settings"
        description="Changes apply to known tracker domains. Other DNS traffic remains available."
      >
        {query.data && (
          <BudgetForm initial={query.data} close={() => setOpen(false)} />
        )}
      </Dialog>
    </>
  );
}
function BudgetForm({
  initial,
  close,
}: {
  initial: PrivacyData;
  close: () => void;
}) {
  const [enabled, setEnabled] = useState(initial.config.enabled);
  const allDevices = Array.from(
    new Set([
      ...initial.devices.map((d) => d.device),
      ...Object.keys(initial.config.device_budgets),
    ]),
  );
  return (
    <AsyncForm
      onSuccess={close}
      submit={(d) => {
        const device_budgets = { ...initial.config.device_budgets };
        for (const ip of allDevices) {
          const v = String(d.get(`budget:${ip}`) || "");
          if (v) device_budgets[ip] = Number(v);
          else delete device_budgets[ip];
        }
        return send("/privacy", {
          enabled,
          default_budget: Number(d.get("default_budget")),
          device_budgets,
        });
      }}
    >
      <Toggle
        label="Enforce daily budgets"
        checked={enabled}
        onChange={setEnabled}
      />
      <Field
        label="Default budget"
        hint="A score from 1 to 100. Lower budgets restrict tracking sooner."
      >
        <input
          type="number"
          name="default_budget"
          min={1}
          max={100}
          required
          defaultValue={initial.config.default_budget}
        />
      </Field>
      {allDevices.map((ip) => (
        <Field
          key={ip}
          label={ip}
          hint="Leave empty to inherit the default budget."
        >
          <input
            type="number"
            min={1}
            max={100}
            name={`budget:${ip}`}
            defaultValue={initial.config.device_budgets[ip] ?? ""}
            placeholder="Use default"
          />
        </Field>
      ))}
    </AsyncForm>
  );
}
