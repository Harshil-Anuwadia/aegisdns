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
        if (active) setEvents((current) => [...current, ...rows].slice(0, 500));
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
    const stream = new EventSource("/api/live-feed");
    stream.onopen = () => setState("live");
    stream.onerror = () => setState("disconnected");
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
            data.timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
          }
          buffer.current.unshift(data);
        }
        buffer.current = buffer.current.slice(0, 500);
      } catch {
        /* Ignore malformed events without interrupting the stream. */
      }
    };
    const timer = window.setInterval(() => {
      if (buffer.current.length) {
        const incoming = buffer.current.splice(0);
        setEvents((current) => [...incoming, ...current].slice(0, 500));
      }
    }, 750);
    return () => {
      active = false;
      stream.close();
      clearInterval(timer);
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
