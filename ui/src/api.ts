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
export function timestamp(value: string) {
  return new Date(value.includes("T") ? value : value.replace(" ", "T") + "Z");
}
export function time(value: string) {
  const d = timestamp(value);
  return Number.isNaN(d.getTime())
    ? value
    : d.toLocaleTimeString([], { hour12: false });
}
export const rate = (blocked: number, total: number) =>
  total ? ((blocked / total) * 100).toFixed(1) : "0.0";
