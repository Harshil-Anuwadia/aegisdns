import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { api } from "./api";
import type { QueryEvent } from "./types";

const LiveContext = createContext<{
  events: QueryEvent[];
  state: "connecting" | "live" | "disconnected";
  historyLoading: boolean;
  historyError: Error | null;
}>({
  events: [],
  state: "connecting",
  historyLoading: true,
  historyError: null,
});
export function LiveProvider({ children }: { children: ReactNode }) {
  const [events, setEvents] = useState<QueryEvent[]>([]),
    [state, setState] = useState<"connecting" | "live" | "disconnected">(
      "connecting",
    );
  const buffer = useRef<QueryEvent[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState<Error | null>(null);
  useEffect(() => {
    let active = true;
    void api<QueryEvent[]>("/recent")
      .then((rows) => {
        // History is older than anything already streamed, so it belongs
        // after the live events. Duplicates are possible because a query can
        // arrive on the stream and also appear in this snapshot.
        if (active)
          setEvents((current) => {
            const seen = new Set(
              current.map((e) => `${e.timestamp}|${e.client_ip}|${e.domain}`),
            );
            const history = rows.filter(
              (e) => !seen.has(`${e.timestamp}|${e.client_ip}|${e.domain}`),
            );
            return [...current, ...history].slice(0, 500);
          });
      })
      .catch((error) => {
        if (active)
          setHistoryError(
            error instanceof Error
              ? error
              : new Error("Recent query history could not be loaded."),
          );
      })
      .finally(() => {
        if (active) setHistoryLoading(false);
      });
    // The browser reconnects an EventSource automatically only when the
    // server closes the stream cleanly. A dropped connection, a restarted
    // daemon or a suspended laptop leaves it permanently closed, and the feed
    // silently stayed empty until the user reloaded the page. Reconnect
    // explicitly, backing off so a daemon that is down is not hammered.
    let stream: EventSource | null = null;
    let retry: number | undefined;
    let attempt = 0;

    const connect = () => {
      if (!active) return;
      stream = new EventSource("/api/live-feed");
      stream.onopen = () => {
        attempt = 0;
        setState("live");
      };
      stream.onerror = () => {
        setState("disconnected");
        // Drop the dead handle; a new one is created for each attempt.
        stream?.close();
        stream = null;
        if (!active) return;
        // 1s, 2s, 4s … capped at 30s.
        const delay = Math.min(1000 * 2 ** attempt++, 30000);
        retry = window.setTimeout(connect, delay);
      };
      stream.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (
            typeof data.domain === "string" &&
            typeof data.client_ip === "string" &&
            typeof data.timestamp === "string" &&
            typeof data.status === "string"
          ) {
            if (!data.timestamp) {
              data.timestamp = new Date()
                .toISOString()
                .replace("T", " ")
                .slice(0, 19);
            }
            buffer.current.unshift(data);
          }
          buffer.current = buffer.current.slice(0, 500);
        } catch {
          /* Ignore malformed events without interrupting the stream. */
        }
      };
    };
    connect();

    const timer = window.setInterval(() => {
      if (buffer.current.length) {
        const incoming = buffer.current.splice(0);
        setEvents((current) => [...incoming, ...current].slice(0, 500));
      }
    }, 750);
    return () => {
      active = false;
      stream?.close();
      clearInterval(timer);
      if (retry !== undefined) clearTimeout(retry);
      buffer.current = [];
    };
  }, []);
  return (
    <LiveContext.Provider
      value={{ events, state, historyLoading, historyError }}
    >
      {children}
    </LiveContext.Provider>
  );
}
export const useLive = () => useContext(LiveContext);
