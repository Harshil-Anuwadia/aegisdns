import { useEffect, useState } from "react";
import { useApi } from "../api";

export function DomainIcon({
  domain,
  size = "regular",
}: {
  domain: string;
  size?: "compact" | "regular";
}) {
  const status = useApi<{ enabled: boolean }>("/favicon/status");
  const [failed, setFailed] = useState(false);
  const hostname = domain.trim().replace(/\.+$/, "");

  useEffect(() => setFailed(false), [hostname]);

  if (!hostname || failed || !status.data?.enabled) return null;

  return (
    <span
      className={`domain-icon domain-icon-${size}`}
      aria-hidden="true"
      style={{
        transition: "transform 0.2s ease, box-shadow 0.2s ease",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform = "scale(1.1)";
        e.currentTarget.style.boxShadow = "0 2px 8px rgba(0, 0, 0, 0.15)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = "scale(1)";
        e.currentTarget.style.boxShadow = "none";
      }}
    >
      <img
        src={`/api/favicon?domain=${encodeURIComponent(hostname)}`}
        alt=""
        loading="lazy"
        decoding="async"
        onError={() => setFailed(true)}
        style={{
          transition: "opacity 0.3s ease",
        }}
      />
    </span>
  );
}
