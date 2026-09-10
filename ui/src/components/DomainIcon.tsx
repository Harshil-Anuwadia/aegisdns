import { useEffect, useState } from "react";
import { useApi } from "../api";

export function DomainIcon({ domain, size = "regular" }: { domain: string; size?: "compact" | "regular" }) {
  const status = useApi<{ enabled: boolean }>("/favicon/status");
  const [failed, setFailed] = useState(false);
  const hostname = domain.trim().replace(/\.+$/, "");

  useEffect(() => setFailed(false), [hostname]);

  if (!hostname || failed || !status.data?.enabled) return null;

  return (
    <span className={`domain-icon domain-icon-${size}`} aria-hidden="true">
      <img src={`/api/favicon?domain=${encodeURIComponent(hostname)}`} alt="" loading="lazy" decoding="async" onError={() => setFailed(true)} />
    </span>
  );
}
