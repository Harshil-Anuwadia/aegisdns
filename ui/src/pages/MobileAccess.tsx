import { useState } from "react";
import {
  Check,
  Copy,
  ExternalLink,
  LockKeyhole,
  Smartphone,
} from "lucide-react";
import { send, useApi } from "../api";
import type { MobileAccess as MobileAccessState } from "../types";
import {
  Badge,
  Button,
  ErrorState,
  PageHeader,
  Panel,
  Skeleton,
} from "../components/ui";

export default function MobileAccess() {
  const query = useApi<MobileAccessState>("/mobile-access", 10000);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [actionError, setActionError] = useState("");
  const status = query.data;

  async function toggle(enabled: boolean) {
    setBusy(true);
    setActionError("");
    try {
      await send<MobileAccessState>("/mobile-access", { enabled });
      await query.refetch();
    } catch (error) {
      setActionError(
        error instanceof Error
          ? error.message
          : "Mobile access could not be changed.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function copyAddress() {
    if (!status?.url) return;
    try {
      await navigator.clipboard.writeText(status.url);
      setCopied(true);
      setActionError("");
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setActionError(
        "Copy was blocked by this browser. Select the address and copy it manually.",
      );
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="INFRASTRUCTURE / MOBILE ACCESS"
        title="Take your network with you."
        description="Create a private HTTPS route to this dashboard for phones connected to your tailnet."
      />
      {query.error ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : !status ? (
        <Skeleton rows={7} />
      ) : (
        <div className="settings-layout mobile-access-layout">
          <Panel
            title="Phone connection"
            subtitle="Private to your Tailscale network"
            action={
              <Badge
                tone={
                  status.enabled
                    ? "success"
                    : status.conflict || !status.available
                      ? "warning"
                      : "neutral"
                }
              >
                {status.enabled
                  ? "Ready"
                  : status.conflict
                    ? "Port in use"
                    : status.available
                      ? "Off"
                      : "Unavailable"}
              </Badge>
            }
          >
            <div className="panel-body mobile-access-panel">
              <div className="mobile-access-mark">
                <Smartphone size={28} />
              </div>
              <div>
                <h2>
                  {status.enabled
                    ? "Mobile access is ready"
                    : "Connect the AegisDNS mobile app"}
                </h2>
                <p>{status.message}</p>
              </div>
              {status.enabled && status.url && (
                <div className="mobile-access-url">
                  <span className="mono">{status.url}</span>
                  <Button
                    variant="secondary"
                    onClick={() => void copyAddress()}
                  >
                    {copied ? <Check size={16} /> : <Copy size={16} />}
                    {copied ? "Copied" : "Copy address"}
                  </Button>
                  <a
                    className="button secondary"
                    href={status.url}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <ExternalLink size={16} /> Open
                  </a>
                </div>
              )}
              {status.available ? (
                <Button
                  variant={status.enabled ? "secondary" : "primary"}
                  disabled={busy || status.conflict}
                  onClick={() => void toggle(!status.enabled)}
                >
                  {busy
                    ? "Applying…"
                    : status.enabled
                      ? "Turn off mobile access"
                      : "Enable mobile access"}
                </Button>
              ) : (
                <p className="note">
                  Update this installation with the current installer to add
                  one-click mobile access.
                </p>
              )}
              {actionError && (
                <p className="form-error" role="alert">
                  {actionError}
                </p>
              )}
            </div>
          </Panel>
          <aside className="settings-aside">
            <LockKeyhole size={27} />
            <h2>Private by construction.</h2>
            <p>
              The route is available only inside your tailnet. It never enables
              Tailscale Funnel or makes the admin dashboard public.
            </p>
            <ol className="connection-steps">
              <li>
                <span>1</span>
                <div>
                  <strong>Join Tailscale</strong>
                  <small>Use the same tailnet on your phone.</small>
                </div>
              </li>
              <li>
                <span>2</span>
                <div>
                  <strong>Enable access</strong>
                  <small>AegisDNS configures HTTPS automatically.</small>
                </div>
              </li>
              <li>
                <span>3</span>
                <div>
                  <strong>Connect the app</strong>
                  <small>
                    Paste the address and enter your admin credentials.
                  </small>
                </div>
              </li>
            </ol>
            <p className="note">
              The address contains no password or private configuration.
            </p>
          </aside>
        </div>
      )}
    </>
  );
}
