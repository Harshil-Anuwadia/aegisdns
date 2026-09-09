import {
  Activity,
  Bell,
  ChevronLeft,
  Command,
  FileText,
  Globe2,
  LayoutDashboard,
  ListFilter,
  Menu,
  Moon,
  Network,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  Terminal,
  Timer,
  Workflow,
  X,
  Monitor,
  RefreshCw,
  ArrowUpRight,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Badge, Button, Dialog } from "./ui";
import { useLive } from "../live";

export const navigation = [
  {
    group: "Observe",
    items: [
      { id: "overview", label: "Overview", icon: LayoutDashboard },
      { id: "traffic", label: "Query log", icon: Activity },
      { id: "network", label: "Relationships", icon: Network },
      { id: "threats", label: "Blocking", icon: ShieldCheck },
      { id: "privacy", label: "Privacy budgets", icon: Shield },
    ],
  },
  {
    group: "Control",
    items: [
      { id: "rules", label: "Rules", icon: SlidersHorizontal },
      { id: "blocklists", label: "Blocklists", icon: ListFilter },
      { id: "schedules", label: "Schedules", icon: Timer },
    ],
  },
  {
    group: "Infrastructure",
    items: [
      { id: "devices", label: "Devices", icon: Monitor },
      { id: "upstream", label: "Upstream DNS", icon: Globe2 },
      { id: "actions", label: "Custom actions", icon: Workflow },
      { id: "diagnostics", label: "Diagnostics", icon: Terminal },
      { id: "alerts", label: "Alerts", icon: Bell },
      { id: "settings", label: "Settings", icon: Settings2 },
    ],
  },
];
export const allPages = [
  ...navigation.flatMap((g) => g.items),
  { id: "support", label: "Support AegisDNS", icon: Globe2 },
];
export function AppShell({
  route,
  children,
}: {
  route: string;
  children: ReactNode;
}) {
  const [mobile, setMobile] = useState(false),
    [collapsed, setCollapsed] = useState(false),
    [command, setCommand] = useState(false),
    [search, setSearch] = useState(""),
    [notifications, setNotifications] = useState(false);
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("aegis-theme") || "dark";
    } catch {
      return "dark";
    }
  });
  const qc = useQueryClient();
  const live = useLive();
  const toggleTheme = () => setTheme((v) => (v === "dark" ? "light" : "dark"));
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("aegis-theme", theme);
    } catch {}
  }, [theme]);
  useEffect(() => {
    setMobile(false);
    document.title = `${allPages.find((p) => p.id === route)?.label || "Overview"} · AegisDNS`;
  }, [route]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCommand((v) => !v);
      }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, []);
  function go(id: string) {
    location.hash = id;
    setCommand(false);
    setSearch("");
  }
  const nav = (
    <>
      <a href="#overview" className="brand">
        <span className="brand-mark">
          <Shield size={24} strokeWidth={1.6} />
        </span>
        <span>
          Aegis<span className="brand-light">DNS</span>
          <small>NETWORK CONTROL</small>
        </span>
      </a>
      <nav aria-label="Main navigation">
        {navigation.map((group) => (
          <div className="nav-group" key={group.group}>
            <span className="nav-group-label">{group.group}</span>
            {group.items.map(({ id, label, icon: Icon }) => (
              <a
                key={id}
                href={`#${id}`}
                className={`nav-item ${route === id ? "active" : ""}`}
                aria-current={route === id ? "page" : undefined}
                title={collapsed ? label : undefined}
                onClick={() => setMobile(false)}
              >
                <Icon size={18} strokeWidth={1.65} />
                <span>{label}</span>
                {route === id && <i />}
              </a>
            ))}
          </div>
        ))}
      </nav>
      <footer className="sidebar-footer">
        <div className="server-avatar">
          <Terminal size={17} />
        </div>
        <span>
          Self-hosted<small>Local DNS control</small>
        </span>
        <Button
          variant="ghost"
          aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          onClick={() => setCollapsed((v) => !v)}
        >
          <ChevronLeft size={16} />
        </Button>
      </footer>
    </>
  );
  return (
    <div className={`app-shell ${collapsed ? "collapsed" : ""}`}>
      <a
        className="skip-link"
        href="#main"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById("main")?.focus();
        }}
      >
        Skip to content
      </a>
      <aside className="sidebar">{nav}</aside>
      <Dialog open={mobile} onClose={() => setMobile(false)} title="Navigation">
        <div className="mobile-navigation">{nav}</div>
      </Dialog>
      <div className="workspace">
        <header className="topbar">
          <div className="breadcrumbs">
            <Button
              className="mobile-menu"
              variant="ghost"
              aria-label="Open navigation"
              onClick={() => setMobile(true)}
            >
              <Menu size={20} />
            </Button>
            <span>Workspace</span>
            <span className="slash">/</span>
            <strong>
              {allPages.find((p) => p.id === route)?.label || "Overview"}
            </strong>
          </div>
          <div className="topbar-actions">
            <Badge tone={live.state === "live" ? "success" : "warning"}>
              {live.state === "live"
                ? "Live feed connected"
                : live.state === "connecting"
                  ? "Connecting"
                  : "Feed disconnected"}
            </Badge>
            <Button
              variant="ghost"
              className="search-trigger"
              onClick={() => setCommand(true)}
              aria-label="Search and commands"
            >
              <Search size={17} />
              <span>Search anything</span>
              <kbd>⌘ K</kbd>
            </Button>
            <Button
              variant="ghost"
              aria-label="Refresh data"
              onClick={() => void qc.invalidateQueries()}
            >
              <RefreshCw size={17} />
            </Button>
            <Button
              variant="ghost"
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
              onClick={toggleTheme}
            >
              {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            </Button>
            <Button
              variant="ghost"
              aria-label="Open notifications"
              onClick={() => setNotifications(true)}
            >
              <Bell size={18} />
            </Button>
          </div>
        </header>
        <main id="main" tabIndex={-1}>
          {children}
        </main>
        <footer className="workspace-footer">
          <span>
            AegisDNS <span className="muted">/</span> Network intelligence,
            locally.
          </span>
          <span>All daily metrics use UTC</span>
          <a className="funding-footer-link" href="#support">
            Support AegisDNS
          </a>
        </footer>
      </div>
      <Dialog
        open={command}
        onClose={() => setCommand(false)}
        title="Command center"
        description="Navigate your network workspace."
      >
        <div className="command-search">
          <Search size={20} />
          <input
            autoFocus
            aria-label="Search commands"
            placeholder="Search pages or enter a domain…"
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                document
                  .querySelector<HTMLButtonElement>(".command-results button")
                  ?.focus();
              }
            }}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div
          className="command-results"
          onKeyDown={(e) => {
            if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
            e.preventDefault();
            const buttons = Array.from(
              e.currentTarget.querySelectorAll("button"),
            );
            const index = buttons.indexOf(e.target as HTMLButtonElement);
            buttons[
              (index + (e.key === "ArrowDown" ? 1 : buttons.length - 1)) %
                buttons.length
            ]?.focus();
          }}
        >
          {allPages
            .filter((p) => p.label.toLowerCase().includes(search.toLowerCase()))
            .map(({ id, label, icon: Icon }) => (
              <button key={id} onClick={() => go(id)}>
                <Icon size={18} />
                <span>Open {label}</span>
                <ArrowUpRight size={15} />
              </button>
            ))}
          {search.includes(".") && (
            <button
              onClick={() =>
                go(`network?domain=${encodeURIComponent(search.trim())}`)
              }
            >
              <Network size={18} />
              <span>Investigate {search}</span>
              <ArrowUpRight size={15} />
            </button>
          )}
          <button
            onClick={() => {
              toggleTheme();
              setCommand(false);
            }}
          >
            <Sun size={18} />
            <span>Toggle color theme</span>
          </button>
          <button
            onClick={() => {
              void qc.invalidateQueries();
              setCommand(false);
            }}
          >
            <RefreshCw size={18} />
            <span>Refresh all data</span>
          </button>
          <button onClick={() => go("traffic?status=blocked")}>
            <ListFilter size={18} />
            <span>Filter blocked queries</span>
          </button>
        </div>
        <div className="command-hint">
          <Command size={14} /> Ctrl / ⌘ K to open <span>Esc to close</span>
        </div>
      </Dialog>
      <Dialog
        drawer
        open={notifications}
        onClose={() => setNotifications(false)}
        title="Notifications"
        description="Connection state and alert delivery."
      >
        <div className="notification-item">
          <Activity size={22} />
          <div>
            <strong>
              {live.state === "live"
                ? "Live feed connected"
                : "Live feed unavailable"}
            </strong>
            <p>
              {live.state === "live"
                ? "New query events are arriving through the server stream."
                : "AegisDNS will reconnect automatically. Check the service if this persists."}
            </p>
          </div>
        </div>
        <a
          className="button secondary"
          href="#alerts"
          onClick={() => setNotifications(false)}
        >
          Manage Telegram alerts <ArrowUpRight size={16} />
        </a>
        <p className="muted">
          Historical alert delivery is not exposed by the server.
        </p>
      </Dialog>
    </div>
  );
}
