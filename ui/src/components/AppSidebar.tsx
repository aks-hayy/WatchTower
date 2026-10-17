import { Link, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  Bot,
  ChevronDown,
  CircleHelp,
  FileSearch,
  FolderSearch,
  Network,
  Radar,
  Radio,
  Search,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  Waves,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { fetchHealth, fetchSystemInfo } from "@/lib/api.functions";
import { partitionSimpleNavigation, shouldExpandMoreTools } from "@/lib/navigation-layout";
import { describeServiceStatus } from "@/lib/service-status";
import type { ExperienceMode, HealthStatus, SystemInfo } from "@/types/watchtower";

const MODE_KEY = "watchtower.experience-mode";

type Workspace = {
  title: string;
  url: string;
  icon: LucideIcon;
  description: string;
  children?: readonly { title: string; url: string; icon: LucideIcon }[];
};

const workspaces: readonly Workspace[] = [
  { title: "Overview", url: "/", icon: Activity, description: "What needs attention now" },
  {
    title: "Monitor",
    url: "/capture",
    icon: Radio,
    description: "Live traffic, devices, and sensors",
    children: [
      { title: "Capture", url: "/capture", icon: Radio },
      { title: "Connections", url: "/flows", icon: Waves },
      { title: "Devices", url: "/entities", icon: Users },
      { title: "Network map", url: "/topology", icon: Network },
      { title: "Sensors", url: "/fleet", icon: SlidersHorizontal },
    ],
  },
  {
    title: "Alerts",
    url: "/alerts",
    icon: AlertTriangle,
    description: "Review and tune detections",
    children: [
      { title: "Alert queue", url: "/alerts", icon: AlertTriangle },
      { title: "Detection rules", url: "/sigma", icon: FileSearch },
    ],
  },
  {
    title: "Investigate",
    url: "/forensics",
    icon: FolderSearch,
    description: "Search, hunt, and preserve evidence",
    children: [
      { title: "Cases", url: "/forensics", icon: FolderSearch },
      { title: "Search", url: "/lookup", icon: Search },
      { title: "Hunts", url: "/hunt", icon: Radar },
      { title: "Evidence", url: "/evidence", icon: ShieldCheck },
    ],
  },
  {
    title: "Settings",
    url: "/settings",
    icon: Settings,
    description: "Security, storage, and integrations",
    children: [
      { title: "System settings", url: "/settings", icon: Settings },
      { title: "Extensions", url: "/plugins", icon: SlidersHorizontal },
      { title: "Analyst", url: "/ai", icon: Bot },
    ],
  },
] as const;

const simpleDestinations = [
  { title: "Overview", url: "/", icon: Activity },
  ...workspaces.flatMap((workspace) => workspace.children ?? []),
];
const { primary: simplePrimary, moreTools } = partitionSimpleNavigation(simpleDestinations);

const modes: Array<{ value: ExperienceMode; label: string; description: string }> = [
  { value: "simple", label: "Simple", description: "Guided essentials" },
  { value: "standard", label: "Standard", description: "Everyday operations" },
  { value: "analyst", label: "Analyst", description: "Full investigation depth" },
];

function readMode(): ExperienceMode {
  if (typeof window === "undefined") return "standard";
  const stored = window.localStorage.getItem(MODE_KEY);
  return stored === "simple" || stored === "analyst" ? stored : "standard";
}

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
  const [mode, setMode] = useState<ExperienceMode>(readMode);
  const [moreToolsOpen, setMoreToolsOpen] = useState(
    () => readMode() === "simple" && shouldExpandMoreTools(currentPath, false, moreTools),
  );

  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      const [nextHealth, nextSystem] = await Promise.all([
        fetchHealth(),
        fetchSystemInfo().catch(() => null),
      ]);
      if (!cancelled) {
        setHealth(nextHealth);
        setSystem(nextSystem);
      }
    };
    void refresh();
    const interval = window.setInterval(() => void refresh(), 15_000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    if (mode === "simple" && shouldExpandMoreTools(currentPath, false, moreTools)) {
      setMoreToolsOpen(true);
    }
  }, [currentPath, mode]);

  const selectMode = (nextMode: ExperienceMode) => {
    setMode(nextMode);
    setMoreToolsOpen(nextMode === "simple" && shouldExpandMoreTools(currentPath, false, moreTools));
    window.localStorage.setItem(MODE_KEY, nextMode);
    window.dispatchEvent(new CustomEvent("watchtower:mode-change", { detail: nextMode }));
  };

  const presentation = describeServiceStatus(health);
  const status = {
    label: presentation.label,
    tone:
      presentation.state === "offline"
        ? "text-severity-high"
        : presentation.state === "attention"
          ? "text-severity-medium"
          : presentation.state === "ready" && health?.capture_state === "active"
            ? "text-ok"
            : "text-signal",
    dot:
      presentation.state === "offline"
        ? "bg-severity-high"
        : presentation.state === "attention"
          ? "bg-severity-medium"
          : presentation.state === "ready" && health?.capture_state === "active"
            ? "bg-ok pulse-dot"
            : "bg-signal",
  };

  const isActive = (url: string) =>
    url === "/" ? currentPath === "/" : currentPath === url || currentPath.startsWith(`${url}/`);

  return (
    <aside
      className={`fixed inset-y-0 left-0 z-50 flex h-screen w-[252px] shrink-0 flex-col border-r border-border bg-sidebar transition-transform md:sticky md:top-0 md:z-auto md:translate-x-0 ${open ? "translate-x-0" : "-translate-x-full"}`}
    >
      <div className="border-b border-border px-5 py-4">
        <div className="flex items-center gap-3">
          <div className="grid h-8 w-8 place-items-center rounded-md border border-signal/60 bg-signal/10">
            <Radar className="h-4 w-4 text-signal" strokeWidth={2} />
          </div>
          <div className="min-w-0">
            <div className="text-[15px] font-semibold tracking-tight text-foreground">
              WatchTower
            </div>
            <div className="mt-1 text-[11px] text-muted-foreground">Local network security</div>
          </div>
        </div>
      </div>

      <div className="border-b border-border px-5 py-3">
        <div className="flex items-center gap-2 text-[12px] font-medium">
          <span className={`h-2 w-2 rounded-full ${status.dot}`} />
          <span className={status.tone}>{status.label}</span>
          <span className="ml-auto text-[11px] text-muted-foreground">
            {presentation.sourceLabel}
          </span>
        </div>
        <div className="mt-1 text-[11px] text-muted-foreground">
          {presentation.nextAction ||
            (health?.daemon === "online" ? "Ready for your next task" : "Start the local service")}
        </div>
      </div>

      <nav aria-label="Primary navigation" className="flex-1 overflow-y-auto px-3 py-3">
        {mode === "simple" ? (
          <>
            <div className="mb-2 px-2 text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
              Essentials
            </div>
            {simplePrimary.map((destination) => {
              const active = isActive(destination.url);
              return (
                <Link
                  key={destination.url}
                  to={destination.url}
                  onClick={onNavigate}
                  aria-current={active ? "page" : undefined}
                  className={`group mb-1 flex items-center gap-3 rounded-md px-3 py-2.5 text-[13px] transition-colors ${active ? "bg-signal/10 text-foreground" : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-foreground"}`}
                >
                  <destination.icon
                    className={`h-4 w-4 shrink-0 ${active ? "text-signal" : "text-muted-foreground group-hover:text-foreground"}`}
                    strokeWidth={1.8}
                  />
                  <span className="font-medium">{destination.title}</span>
                </Link>
              );
            })}
            <button
              type="button"
              aria-expanded={moreToolsOpen}
              aria-controls="simple-more-tools"
              onClick={() => setMoreToolsOpen((expanded) => !expanded)}
              className="group mt-2 flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left text-[13px] text-sidebar-foreground transition-colors hover:bg-sidebar-accent hover:text-foreground"
            >
              <SlidersHorizontal
                className="h-4 w-4 shrink-0 text-muted-foreground group-hover:text-foreground"
                strokeWidth={1.8}
              />
              <span className="font-medium">More tools</span>
              <ChevronDown
                className={`ml-auto h-3.5 w-3.5 text-muted-foreground transition-transform ${moreToolsOpen ? "rotate-180" : ""}`}
              />
            </button>
            <div
              id="simple-more-tools"
              hidden={!moreToolsOpen}
              className="ml-4 border-l border-border pl-3 pt-1"
            >
              {moreTools.map((destination) => {
                const active = isActive(destination.url);
                return (
                  <Link
                    key={destination.url}
                    to={destination.url}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={`flex items-center gap-2 rounded px-2 py-1.5 text-[12px] transition-colors ${active ? "text-signal" : "text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"}`}
                  >
                    <destination.icon className="h-3.5 w-3.5" strokeWidth={1.8} />
                    {destination.title}
                  </Link>
                );
              })}
            </div>
          </>
        ) : (
          <>
            <div className="mb-2 px-2 text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
              Workspaces
            </div>
            {workspaces.map((workspace) => {
              const active =
                isActive(workspace.url) || workspace.children?.some((child) => isActive(child.url));
              return (
                <div key={workspace.title} className="mb-1">
                  <Link
                    to={workspace.url}
                    onClick={onNavigate}
                    className={`group flex items-center gap-3 rounded-md px-3 py-2.5 text-[13px] transition-colors ${active ? "bg-signal/10 text-foreground" : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-foreground"}`}
                  >
                    <workspace.icon
                      className={`h-4 w-4 shrink-0 ${active ? "text-signal" : "text-muted-foreground group-hover:text-foreground"}`}
                      strokeWidth={1.8}
                    />
                    <span className="font-medium">{workspace.title}</span>
                    <ChevronDown className="ml-auto h-3.5 w-3.5 rotate-180 text-muted-foreground" />
                  </Link>
                  {workspace.children && (
                    <div className="ml-4 border-l border-border pl-3 pt-1">
                      {workspace.children.map((child) => (
                        <Link
                          key={child.url}
                          to={child.url}
                          onClick={onNavigate}
                          className={`flex items-center gap-2 rounded px-2 py-1.5 text-[12px] transition-colors ${isActive(child.url) ? "text-signal" : "text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"}`}
                        >
                          <child.icon className="h-3.5 w-3.5" strokeWidth={1.8} />
                          {child.title}
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </>
        )}

        <div className="mt-5 mb-2 flex items-center justify-between px-2">
          <div className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
            Experience
          </div>
          <CircleHelp
            className="h-3.5 w-3.5 text-muted-foreground"
            aria-label="Choose how much detail WatchTower shows"
          />
        </div>
        <div className="rounded-md border border-border bg-background/40 p-1">
          {modes.map((item) => (
            <button
              key={item.value}
              type="button"
              onClick={() => selectMode(item.value)}
              aria-pressed={mode === item.value}
              className={`w-full rounded px-2.5 py-2 text-left transition-colors ${mode === item.value ? "bg-signal/10 text-foreground" : "text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"}`}
            >
              <div className="flex items-center justify-between text-[12px] font-medium">
                <span>{item.label}</span>
                {mode === item.value && <span className="text-[10px] text-signal">Selected</span>}
              </div>
              <div className="mt-0.5 text-[10px] text-muted-foreground">{item.description}</div>
            </button>
          ))}
        </div>
      </nav>

      <div className="border-t border-border px-5 py-3 text-[11px] text-muted-foreground">
        <div className="flex items-center justify-between">
          <span>{system?.hostname || "This computer"}</span>
          <span>{system?.version || "—"}</span>
        </div>
        <div className="mt-1">
          {mode === "simple"
            ? "All tools remain available in More tools."
            : "Experience changes detail, not what you can access."}
        </div>
      </div>
    </aside>
  );
}
