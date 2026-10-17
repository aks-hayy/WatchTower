import { HeadContent, Outlet, Scripts, createRootRoute } from "@tanstack/react-router";
import { CheckCircle2, Menu, Radar, TriangleAlert, X } from "lucide-react";
import { useEffect, useState } from "react";
import { AppSidebar } from "@/components/AppSidebar";
import { AuthGate } from "@/components/AuthGate";
import { SensorScopeProvider, SensorScopeSelector } from "@/components/SensorScope";
import { useSensorScope } from "@/components/useSensorScope";
import { fetchHealth } from "@/lib/api.functions";
import { describeServiceStatus, resolveWorkspaceServiceState } from "@/lib/service-status";
import type { HealthStatus } from "@/types/watchtower";
import appCss from "../styles.css?url";

declare global {
  interface Window {
    __WATCHTOWER_API_URL__?: string;
  }
}

const runtimeApiUrl = "/api/v1";

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "Watchtower - Network Signal Intelligence" },
      {
        name: "description",
        content:
          "Real-time network traffic analysis, threat detection, and forensic investigation platform",
      },
      { property: "og:title", content: "Watchtower" },
      { property: "og:description", content: "Network Signal Intelligence Platform" },
      { property: "og:type", content: "website" },
    ],
    links: [{ rel: "stylesheet", href: appCss }],
  }),
  shellComponent: RootShell,
  component: RootComponent,
  notFoundComponent: NotFound,
});

function RootShell({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <head>
        <HeadContent />
      </head>
      <body>
        {children}
        <script
          dangerouslySetInnerHTML={{
            __html: `window.__WATCHTOWER_API_URL__=${JSON.stringify(runtimeApiUrl)};`,
          }}
        />
        <Scripts />
      </body>
    </html>
  );
}

function RootComponent() {
  return (
    <AuthGate>
      <SensorScopeProvider>
        <WatchTowerWorkspace />
      </SensorScopeProvider>
    </AuthGate>
  );
}

function WatchTowerWorkspace() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { selectedLabel } = useSensorScope();
  return (
    <div className="flex min-h-screen w-full min-w-0">
      {sidebarOpen && (
        <button
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
          className="fixed inset-0 z-40 bg-black/60 md:hidden"
        />
      )}
      <AppSidebar open={sidebarOpen} onNavigate={() => setSidebarOpen(false)} />
      <div className="min-w-0 flex-1">
        <div className="sticky top-0 z-30 flex h-12 items-center border-b border-border bg-sidebar px-3 md:hidden">
          <button
            onClick={() => setSidebarOpen((open) => !open)}
            title={sidebarOpen ? "Close navigation" : "Open navigation"}
            className="grid h-8 w-8 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal"
          >
            {sidebarOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
          <div className="ml-3 flex items-center gap-2">
            <Radar className="h-4 w-4 text-signal" />
            <span className="text-[13px] text-foreground">Watchtower</span>
          </div>
        </div>
        <WorkspaceStatusBar selectedLabel={selectedLabel} />
        <main className="min-w-0 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function WorkspaceStatusBar({ selectedLabel }: { selectedLabel: string }) {
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      const nextHealth = await fetchHealth();
      if (!cancelled) setHealth(nextHealth);
    };
    void refresh();
    const interval = window.setInterval(() => void refresh(), 15_000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  const serviceState = resolveWorkspaceServiceState(health);
  const servicePresentation = describeServiceStatus(health);
  const needsAttention = serviceState === "attention";
  const offline = serviceState === "offline";
  const checking = serviceState === "checking";
  return (
    <div className="sticky top-0 z-20 flex min-h-11 flex-wrap items-center gap-x-4 gap-y-2 border-b border-border bg-background/95 px-3 py-2 backdrop-blur md:px-5">
      <SensorScopeSelector />
      <div className="flex items-center gap-2 text-[12px]">
        {checking || needsAttention || offline ? (
          <TriangleAlert className="h-3.5 w-3.5 text-severity-medium" />
        ) : (
          <CheckCircle2 className="h-3.5 w-3.5 text-ok" />
        )}
        <span
          className={
            checking
              ? "text-muted-foreground"
              : offline
                ? "text-severity-high"
                : needsAttention
                  ? "text-severity-medium"
                  : "text-ok"
          }
        >
          {servicePresentation.label}
        </span>
      </div>
      <div className="hidden h-4 w-px bg-border sm:block" />
      <div className="text-[12px] text-muted-foreground">
        {checking ? "Checking capture status" : servicePresentation.nextAction}
      </div>
      <span className="ml-auto truncate text-[11px] text-muted-foreground">{selectedLabel}</span>
    </div>
  );
}

function NotFound() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="text-center">
        <div className="section-label section-label-accent">// TRACE FAILED</div>
        <h1 className="mt-2 text-6xl text-foreground tracking-tight">404 - No signal</h1>
        <p className="mt-3 mono text-sm text-muted-foreground">
          The requested endpoint does not resolve.
        </p>
      </div>
    </div>
  );
}
