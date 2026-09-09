import React, {
  Component,
  Suspense,
  lazy,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "./styles.css";
import "./funding.css";
import { AppShell, allPages } from "./components/AppShell";
import { LiveProvider } from "./live";
import { ErrorState, Skeleton } from "./components/ui";
import Overview from "./pages/Overview";

const Traffic = lazy(() => import("./pages/Traffic"));
const Network = lazy(() => import("./pages/Network"));
const Blocking = lazy(() => import("./pages/Blocking"));
const Devices = lazy(() => import("./pages/Devices"));
const Privacy = lazy(() => import("./pages/Privacy"));
const Actions = lazy(() => import("./pages/Actions"));
const Support = lazy(() => import("./pages/Support"));
const Rules = lazy(() =>
  import("./pages/Controls").then((m) => ({ default: m.Rules })),
);
const Blocklists = lazy(() =>
  import("./pages/Controls").then((m) => ({ default: m.Blocklists })),
);
const Schedules = lazy(() =>
  import("./pages/Controls").then((m) => ({ default: m.Schedules })),
);
const Upstream = lazy(() =>
  import("./pages/Infrastructure").then((m) => ({ default: m.Upstream })),
);
const Diagnostics = lazy(() =>
  import("./pages/Infrastructure").then((m) => ({ default: m.Diagnostics })),
);
const Alerts = lazy(() =>
  import("./pages/Infrastructure").then((m) => ({ default: m.Alerts })),
);
const Settings = lazy(() =>
  import("./pages/Infrastructure").then((m) => ({ default: m.Settings })),
);
const pages: Record<string, React.ComponentType> = {
  overview: Overview,
  traffic: Traffic,
  network: Network,
  threats: Blocking,
  privacy: Privacy,
  rules: Rules,
  blocklists: Blocklists,
  schedules: Schedules,
  devices: Devices,
  upstream: Upstream,
  diagnostics: Diagnostics,
  alerts: Alerts,
  settings: Settings,
  actions: Actions,
  support: Support,
};

const client = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: true } },
});
class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    return this.state.error ? (
      <ErrorState error={this.state.error} retry={() => location.reload()} />
    ) : (
      this.props.children
    );
  }
}
function App() {
  const [hash, setHash] = useState(location.hash.slice(1) || "overview");
  useEffect(() => {
    const listener = () => setHash(location.hash.slice(1) || "overview");
    addEventListener("hashchange", listener);
    return () => removeEventListener("hashchange", listener);
  }, []);
  const route = hash.split("?")[0];
  const Page = pages[route];
  return (
    <AppShell route={route}>
      <ErrorBoundary key={route}>
        <Suspense fallback={<Skeleton rows={8} />}>
          {Page ? (
            <Page key={hash} />
          ) : (
            <ErrorState
              error={
                new Error(
                  "This page was not found. Choose a view from navigation.",
                )
              }
            />
          )}
        </Suspense>
      </ErrorBoundary>
    </AppShell>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={client}>
      <LiveProvider>
        <App />
      </LiveProvider>
    </QueryClientProvider>
  </React.StrictMode>,
);
