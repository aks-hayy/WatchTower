import { Link, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  Network,
  Users,
  AlertTriangle,
  Waves,
  FlaskConical,
  FolderArchive,
  Bot,
  Settings,
  Radar,
  Crosshair,
  Radio,
  Plug,
  FileSearch,
  Search,
  ServerCog,
} from "lucide-react";
import { useEffect, useState } from "react";
import { fetchHealth, fetchSystemInfo } from "@/lib/api.functions";
import type { HealthStatus, SystemInfo } from "@/types/watchtower";

const navItems = [
  { title: "Sensor Fleet", url: "/fleet", icon: ServerCog, code: "FLT", group: "operations" },
  { title: "Command", url: "/", icon: Activity, code: "CMD", group: "operations" },
  { title: "Capture", url: "/capture", icon: Radio, code: "CAP", group: "operations" },
  { title: "Flows", url: "/flows", icon: Waves, code: "FLW", group: "operations" },
  { title: "Topology", url: "/topology", icon: Network, code: "TOP", group: "operations" },
  { title: "Entities", url: "/entities", icon: Users, code: "ENT", group: "operations" },
  { title: "Lookup", url: "/lookup", icon: Search, code: "LKP", group: "operations" },
  { title: "Alerts", url: "/alerts", icon: AlertTriangle, code: "ALT", group: "operations" },
  { title: "Hunt", url: "/hunt", icon: Crosshair, code: "HNT", group: "operations" },
  { title: "Forensics", url: "/forensics", icon: FlaskConical, code: "FOR", group: "operations" },
  { title: "Evidence", url: "/evidence", icon: FolderArchive, code: "EVD", group: "operations" },
  { title: "Plugins", url: "/plugins", icon: Plug, code: "PLG", group: "system" },
  { title: "Sigma", url: "/sigma", icon: FileSearch, code: "SIG", group: "system" },
  { title: "Analyst", url: "/ai", icon: Bot, code: "AIA", group: "system" },
  { title: "Settings", url: "/settings", icon: Settings, code: "CFG", group: "system" },
];

export function AppSidebar({
  open = false,
  onNavigate,
}: {
  open?: boolean;
  onNavigate?: () => void;
}) {
  const currentPath = useRouterState({ select: (s) => s.location.pathname });
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [system, setSystem] = useState<SystemInfo | null>(null);

  useEffect(() => {
    Promise.all([fetchHealth(), fetchSystemInfo().catch(() => null)]).then(
      ([nextHealth, nextSystem]) => {
        setHealth(nextHealth);
        setSystem(nextSystem);
      },
    );
  }, []);

  const online = health?.status === "ok";
  const uptime = system ? `${Math.floor(system.uptime / 3600)}h` : "—";

  return (
    <aside
      className={`fixed inset-y-0 left-0 z-50 flex h-screen w-[220px] shrink-0 flex-col border-r border-border bg-sidebar transition-transform md:sticky md:top-0 md:z-auto md:translate-x-0 ${open ? "translate-x-0" : "-translate-x-full"}`}
    >
      {/* Wordmark */}
      <div className="border-b border-border px-4 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid h-7 w-7 place-items-center border border-signal/60 bg-signal/10">
            <Radar className="h-3.5 w-3.5 text-signal" strokeWidth={2} />
          </div>
          <div className="min-w-0">
            <div className="text-[13px] font-medium tracking-tight text-foreground leading-none">
              Watchtower
            </div>
            <div className="mt-1 mono text-[9px] uppercase tracking-[0.18em] text-muted-foreground">
              SIG-INT · v2.0.0-rc.1
            </div>
          </div>
        </div>
      </div>

      {/* Status */}
      <div className="border-b border-border px-4 py-3 space-y-1.5">
        <div className="flex items-center justify-between mono text-[10px] uppercase tracking-wider">
          <span className="flex items-center gap-1.5 text-ok">
            <span
              className={`h-1.5 w-1.5 rounded-full ${online ? "bg-ok pulse-dot" : "bg-severity-high"}`}
            />
            {health ? health.status.toUpperCase() : "CONNECTING"}
          </span>
          <span className={health?.daemon === "online" ? "text-ok" : "text-muted-foreground"}>
            DAEMON {health?.daemon?.toUpperCase() || "—"}
          </span>
        </div>
        <div className="flex items-center justify-between mono text-[10px] uppercase tracking-wider">
          <span className="text-muted-foreground">API</span>
          <span className="text-signal">V1 · {health?.database?.toUpperCase() || "WAIT"}</span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-2">
        <div className="section-label px-4 py-2">Operations</div>
        {navItems
          .filter((item) => item.group === "operations")
          .map((item) => (
            <NavRow
              key={item.url}
              item={item}
              active={
                currentPath === item.url ||
                (item.url !== "/" && currentPath.startsWith(`${item.url}/`))
              }
              onNavigate={onNavigate}
            />
          ))}
        <div className="section-label px-4 py-2 mt-3">System</div>
        {navItems
          .filter((item) => item.group === "system")
          .map((item) => (
            <NavRow
              key={item.url}
              item={item}
              active={currentPath === item.url}
              onNavigate={onNavigate}
            />
          ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-border px-4 py-3 space-y-1">
        <div className="flex items-center justify-between mono text-[10px] uppercase tracking-wider">
          <span className="text-muted-foreground">OP</span>
          <span className="text-foreground truncate ml-2">
            {system?.hostname || "local sensor"}
          </span>
        </div>
        <div className="flex items-center justify-between mono text-[10px] uppercase tracking-wider">
          <span className="text-muted-foreground">UPTIME</span>
          <span className="text-foreground">{uptime}</span>
        </div>
      </div>
    </aside>
  );
}

function NavRow({
  item,
  active,
  onNavigate,
}: {
  item: (typeof navItems)[number];
  active: boolean;
  onNavigate?: () => void;
}) {
  return (
    <Link
      to={item.url}
      onClick={onNavigate}
      className={`group relative flex items-center gap-3 px-4 py-1.5 text-[13px] transition-colors ${
        active
          ? "bg-signal/5 text-foreground"
          : "text-sidebar-foreground hover:bg-signal/[0.03] hover:text-foreground"
      }`}
    >
      {active && <span className="absolute left-0 top-0 bottom-0 w-[2px] bg-signal" />}
      <item.icon
        className={`h-3.5 w-3.5 shrink-0 ${active ? "text-signal" : "text-muted-foreground group-hover:text-foreground"}`}
        strokeWidth={2}
      />
      <span className="tracking-tight">{item.title}</span>
      <span className="ml-auto mono text-[9px] text-muted-foreground/60">{item.code}</span>
    </Link>
  );
}
