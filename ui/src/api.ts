import { useQuery } from "@tanstack/react-query";
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    credentials: "same-origin",
    signal: init.signal
      ? AbortSignal.any([init.signal, AbortSignal.timeout(30000)])
      : AbortSignal.timeout(path === "/blocklists" ? 180000 : 30000),
    headers: {
      "X-Aegis-Request": "1",
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...init.headers,
    },
  });
  if (!response.ok)
    throw new Error(
      response.status === 401
        ? "Your admin session needs authentication. Reload to sign in."
        : `Request failed (${response.status}). Check the service and try again.`,
    );
  if (
    response.status === 204 ||
    !response.headers.get("content-type")?.includes("application/json")
  )
    return undefined as T;
  const data = await response.json();
  if (data?.success === false)
    throw new Error(data.message || "The change could not be saved.");
  return data as T;
}
export const send = <T>(path: string, body?: unknown, method = "POST") =>
  api<T>(path, {
    method,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
export function useApi<T>(path: string, interval: number | false = false) {
  return useQuery<T, Error>({
    queryKey: [path],
    queryFn: ({ signal }) => api<T>(path, { signal }),
    refetchInterval: interval,
    staleTime: 3000,
    retry: 1,
  });
}
export const number = (value: number | undefined) =>
  value === undefined ? "—" : value.toLocaleString();
// Matches a trailing ISO 8601 timezone designator: "Z", "+05:30", "-0500", "-05".
const HAS_TIMEZONE = /(?:Z|[+-]\d{2}(?::?\d{2})?)$/i;
export function timestamp(value: string) {
  if (!value) return new Date(NaN);
  // The daemon stores naive UTC ("2026-09-10 14:32:01"), so a value without a
  // timezone is normalised to ISO 8601 UTC and everything else is left alone:
  //   "2026-09-10 14:32:01"       → "2026-09-10T14:32:01Z"
  //   "2026-09-10T14:32:01"       → "2026-09-10T14:32:01Z"
  //   "2026-09-10T14:32:01.123Z"  → kept as-is
  //   "2026-09-10T14:32:01-05:00" → kept as-is
  // Appending "Z" to an offset-bearing value used to produce an Invalid Date,
  // which surfaced as a blank timestamp column. Only the date/time separator
  // is replaced; a trailing offset never contains a space.
  const s = value.trim().replace(" ", "T");
  return new Date(HAS_TIMEZONE.test(s) ? s : `${s}Z`);
}
export function time(value: string) {
  const d = timestamp(value);
  return Number.isNaN(d.getTime())
    ? value
    : d.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
}
export const rate = (blocked: number, total: number) =>
  total ? ((blocked / total) * 100).toFixed(1) : "0.0";
