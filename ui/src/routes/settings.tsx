import { createFileRoute } from "@tanstack/react-router";
import {
  AlertCircle,
  Circle,
  Cpu,
  Bot,
  KeyRound,
  Loader2,
  LockKeyhole,
  Network,
  Play,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  ShieldX,
  Square,
  Trash2,
  Wifi,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import {
  createMeshEnrollment,
  fetchHealth,
  fetchAIStatus,
  fetchInterfaces,
  fetchMeshNodes,
  fetchMeshStatus,
  fetchSystemInfo,
  initializeMeshController,
  queueMeshNodeCommand,
  resetDatabase,
  revokeMeshNode,
  startEngine,
  stopEngine,
} from "@/lib/api.functions";
import {
  fetchAuthStatus,
  lockAuth,
  setAuthEnabled,
  stepUpWithPin,
  type AuthStatus,
} from "@/lib/auth";
import {
  connectProvider,
  disconnectProvider,
  fetchProviderModels,
  fetchProviders,
  ProviderRequestError,
  setProviderModel,
  testProvider,
  type ProviderModel,
} from "@/lib/providers";
import { captureStartBackend, selectCaptureBackend } from "@/lib/capture-backend";
import type {
  AIProviderStatus,
  HealthStatus,
  NetworkInterface,
  SensorNode,
  SystemInfo,
} from "@/types/watchtower";

export const Route = createFileRoute("/settings")({
  head: () => ({ meta: [{ title: "Settings - Watchtower" }] }),
  loader: async () => {
    const [system, interfaces, health, meshStatus, nodes, aiStatus, authStatus] = await Promise.all(
      [
        fetchSystemInfo(),
        fetchInterfaces(),
        fetchHealth(),
        fetchMeshStatus(),
        fetchMeshNodes({ data: { limit: 100 } }),
        fetchAIStatus(),
        fetchAuthStatus(),
      ],
    );
    return { system, interfaces, health, meshStatus, nodes, aiStatus, authStatus } as {
      system: SystemInfo;
      interfaces: NetworkInterface[];
      health: HealthStatus;
      meshStatus: Record<string, unknown>;
      nodes: SensorNode[];
      aiStatus: { providers: AIProviderStatus[] };
      authStatus: AuthStatus;
    };
  },
  component: SettingsPage,
});

function SettingsPage() {
  const initial = Route.useLoaderData();
  const [interfaces, setInterfaces] = useState(initial.interfaces);
  const [health, setHealth] = useState(initial.health);
  const [meshStatus, setMeshStatus] = useState(initial.meshStatus);
  const [nodes, setNodes] = useState<SensorNode[]>(initial.nodes);
  const [authStatus, setAuthStatus] = useState<AuthStatus>(initial.authStatus);
  const [authPin, setAuthPin] = useState("");
  const [authRecoveryCode, setAuthRecoveryCode] = useState("");
  const [showAuthChange, setShowAuthChange] = useState(false);
  const [providers, setProviders] = useState<AIProviderStatus[]>(initial.aiStatus.providers);
  const [providerModels, setProviderModels] = useState<Record<string, ProviderModel[]>>({});
  const [openAIKey, setOpenAIKey] = useState("");
  const [providerPin, setProviderPin] = useState("");
  const [providerNeedsStepUp, setProviderNeedsStepUp] = useState<string | null>(null);
  const pendingProviderAction = useRef<(() => Promise<unknown>) | null>(null);
  const [backend, setBackend] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [showReset, setShowReset] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const [meshInterface, setMeshInterface] = useState("");
  const [enrollmentToken, setEnrollmentToken] = useState("");

  useEffect(() => {
    fetchAuthStatus()
      .then(setAuthStatus)
      .catch(() => undefined);
  }, []);

  const refreshProof = async () => {
    setBusy("auth-proof");
    setMessage(null);
    try {
      const result = await stepUpWithPin(authPin);
      setAuthStatus(result.status);
      setAuthPin("");
      setMessage({
        kind: "ok",
        text: "Operator proof refreshed for sensitive actions for five minutes.",
      });
    } catch (cause) {
      setMessage({
        kind: "error",
        text: cause instanceof Error ? cause.message : "Operator verification failed",
      });
    } finally {
      setBusy(null);
    }
  };

  const changeAuthentication = async (enabled: boolean) => {
    setBusy("auth-change");
    setMessage(null);
    try {
      const result = await setAuthEnabled(enabled, authPin);
      setAuthStatus(result);
      setAuthRecoveryCode(result.recovery_code || "");
      setAuthPin("");
      setShowAuthChange(false);
      setMessage({
        kind: "ok",
        text: `Application authentication ${enabled ? "enabled" : "disabled"}. Background services were not changed.`,
      });
      if (enabled) window.location.reload();
    } catch (cause) {
      setMessage({
        kind: "error",
        text:
          cause instanceof Error ? cause.message : "Authentication setting could not be changed",
      });
    } finally {
      setBusy(null);
    }
  };

  const lockWorkspace = async () => {
    setBusy("auth-lock");
    try {
      await lockAuth();
      window.location.reload();
    } catch (cause) {
      setMessage({
        kind: "error",
        text: cause instanceof Error ? cause.message : "Workspace could not be locked",
      });
      setBusy(null);
    }
  };

  const refreshProviders = async () => {
    const result = await fetchProviders();
    setProviders(result.providers);
  };

  const providerAction = async (provider: string, operation: () => Promise<unknown>) => {
    setBusy(`provider:${provider}`);
    setMessage(null);
    try {
      await operation();
      setProviderNeedsStepUp(null);
      setProviderPin("");
      setOpenAIKey("");
      await refreshProviders();
      setMessage({ kind: "ok", text: `${provider} provider configuration updated.` });
    } catch (cause) {
      if (cause instanceof ProviderRequestError && cause.code === "step_up_required") {
        pendingProviderAction.current = operation;
        setProviderNeedsStepUp(provider);
        setMessage({
          kind: "error",
          text: "Re-authenticate below to change provider credentials.",
        });
      } else {
        setMessage({
          kind: "error",
          text: cause instanceof Error ? cause.message : "Provider operation failed",
        });
      }
    } finally {
      setBusy(null);
    }
  };

  const retryProviderAfterStepUp = async (provider: string) => {
    setBusy(`provider:${provider}`);
    try {
      await stepUpWithPin(providerPin);
      setProviderNeedsStepUp(null);
      setProviderPin("");
      const pending = pendingProviderAction.current;
      pendingProviderAction.current = null;
      if (pending) await pending();
      setOpenAIKey("");
      await refreshProviders();
      setMessage({ kind: "ok", text: "Operator verified. Provider configuration updated." });
    } catch (cause) {
      setMessage({
        kind: "error",
        text: cause instanceof Error ? cause.message : "Re-authentication failed",
      });
    } finally {
      setBusy(null);
    }
  };

  const refresh = async () => {
    const [nextInterfaces, nextHealth, nextMeshStatus, nextNodes] = await Promise.all([
      fetchInterfaces(),
      fetchHealth(),
      fetchMeshStatus(),
      fetchMeshNodes({ data: { limit: 100 } }),
    ]);
    setInterfaces(nextInterfaces);
    setBackend((current) =>
      Object.fromEntries(
        nextInterfaces.flatMap((item) => {
          const selected = current[item.id];
          return selected &&
            item.backends.some((value) => value.toLowerCase() === selected.toLowerCase())
            ? [[item.id, selected]]
            : [];
        }),
      ),
    );
    setHealth(nextHealth);
    setMeshStatus(nextMeshStatus);
    setNodes(nextNodes);
  };

  const toggle = async (item: NetworkInterface) => {
    setBusy(item.id);
    setMessage(null);
    try {
      if (item.capturing) await stopEngine({ data: { interface_id: item.id } });
      else {
        const selectedBackend = captureStartBackend(item, backend[item.id]);
        if (selectedBackend === null) throw new Error("No supported capture backend is available");
        await startEngine({
          data: {
            interface_id: item.id,
            backend: selectedBackend,
            source_type: item.source_type,
          },
        });
      }
      await refresh();
      setMessage({
        kind: "ok",
        text: `${item.name} capture ${item.capturing ? "stopped" : "started"}`,
      });
    } catch (cause) {
      setMessage({
        kind: "error",
        text: cause instanceof Error ? cause.message : "Capture control failed",
      });
      await refresh().catch(() => undefined);
    } finally {
      setBusy(null);
    }
  };

  const reset = async () => {
    setBusy("reset");
    setMessage(null);
    try {
      const result = await resetDatabase({ data: { confirmation } });
      setMessage({ kind: "ok", text: `Database reset complete: ${JSON.stringify(result)}` });
      setShowReset(false);
      setConfirmation("");
    } catch (cause) {
      setMessage({
        kind: "error",
        text: cause instanceof Error ? cause.message : "Database reset failed",
      });
    } finally {
      setBusy(null);
    }
  };

  const initializeMesh = async () => {
    setBusy("mesh-init");
    setMessage(null);
    try {
      await initializeMeshController({ data: { host: "127.0.0.1" } });
      setMessage({
        kind: "ok",
        text: "Mesh controller initialized. Create an enrollment token for the next sensor.",
      });
      await refresh();
    } catch (cause) {
      setMessage({
        kind: "error",
        text: cause instanceof Error ? cause.message : "Mesh initialization failed",
      });
    } finally {
      setBusy(null);
    }
  };

  const enroll = async () => {
    setBusy("mesh-enroll");
    setMessage(null);
    try {
      const result = await createMeshEnrollment({ data: { ttl_seconds: 3600, max_uses: 1 } });
      setEnrollmentToken(String(result.token || ""));
      setMessage({
        kind: "ok",
        text: "One-time enrollment token created. It is shown once below.",
      });
    } catch (cause) {
      setMessage({
        kind: "error",
        text: cause instanceof Error ? cause.message : "Enrollment token creation failed",
      });
    } finally {
      setBusy(null);
    }
  };

  const commandNode = async (node: SensorNode, action: "capture.start" | "capture.stop") => {
    if (!meshInterface.trim()) {
      setMessage({
        kind: "error",
        text: "Enter the interface identifier exposed by the selected node.",
      });
      return;
    }
    setBusy(`${node.id}:${action}`);
    setMessage(null);
    try {
      await queueMeshNodeCommand({
        data: {
          node_id: node.id,
          action,
          arguments:
            action === "capture.start"
              ? { interface: meshInterface.trim(), source_type: "network" }
              : { interface: meshInterface.trim() },
        },
      });
      setMessage({
        kind: "ok",
        text: `${action === "capture.start" ? "Start" : "Stop"} queued for ${node.name}. The result will appear after the node checks in.`,
      });
    } catch (cause) {
      setMessage({
        kind: "error",
        text: cause instanceof Error ? cause.message : "Node command could not be queued",
      });
    } finally {
      setBusy(null);
    }
  };

  const revoke = async (node: SensorNode) => {
    setBusy(`revoke:${node.id}`);
    setMessage(null);
    try {
      await revokeMeshNode({ data: { node_id: node.id, reason: "Revoked by local operator" } });
      setMessage({ kind: "ok", text: `${node.name} certificate revoked.` });
      await refresh();
    } catch (cause) {
      setMessage({
        kind: "error",
        text: cause instanceof Error ? cause.message : "Node revocation failed",
      });
    } finally {
      setBusy(null);
    }
  };

  const system = initial.system;
  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-surface/60">
        <div className="flex items-center gap-6 px-6 py-3 mono text-[11px] uppercase tracking-wider">
          <span className="section-label section-label-accent">CFG</span>
          <span className="text-foreground">/ System Control</span>
          <span
            className={`ml-auto ${health.daemon === "online" ? "text-ok" : "text-severity-high"}`}
          >
            daemon {health.daemon}
          </span>
        </div>
      </header>

      <div className="space-y-5 p-6">
        {message && (
          <div
            className={`flex items-center gap-2 border px-4 py-3 mono text-[11px] ${message.kind === "ok" ? "border-ok/40 bg-ok/10 text-ok" : "border-severity-critical/40 bg-severity-critical/10 text-severity-critical"}`}
          >
            <AlertCircle className="h-3.5 w-3.5" />
            {message.text}
          </div>
        )}

        <section className="panel">
          <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
            <Cpu className="h-3.5 w-3.5 text-signal" />
            <div className="text-sm text-foreground">Host Telemetry</div>
          </div>
          <div className="grid grid-cols-2 gap-px bg-border md:grid-cols-4">
            <HostMetric label="HOSTNAME" value={system.hostname} />
            <HostMetric label="PLATFORM" value={system.platform} />
            <HostMetric label="VERSION" value={system.version} />
            <HostMetric label="UPTIME" value={`${Math.floor(system.uptime / 3600)}h`} />
          </div>
          <div className="grid grid-cols-3 gap-px border-t border-border bg-border">
            <Resource label="CPU" value={system.cpu_percent} color="bg-signal" />
            <Resource label="MEMORY" value={system.memory_percent} color="bg-chart-2" />
            <Resource label="DISK" value={system.disk_percent} color="bg-chart-3" />
          </div>
        </section>

        <section className="panel">
          <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5">
            <ShieldCheck className="h-3.5 w-3.5 text-signal" />
            <div className="text-sm text-foreground">Operator Security</div>
            <span
              className={`mono text-[10px] uppercase ${authStatus.auth_enabled ? "text-ok" : "text-severity-medium"}`}
            >
              {authStatus.auth_enabled ? "protected" : "authentication disabled"}
            </span>
          </div>
          <div className="grid gap-px bg-border md:grid-cols-3">
            <div className="bg-background p-4">
              <div className="section-label">Session deadline</div>
              <div className="mt-1 mono text-[11px] text-foreground">
                {authStatus.session
                  ? new Date(authStatus.session.expires_at * 1000).toLocaleString()
                  : authStatus.auth_enabled
                    ? "locked"
                    : "not applicable"}
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">
                Eight hours absolute. Activity never extends it.
              </div>
            </div>
            <div className="bg-background p-4">
              <div className="section-label">Authentication factors</div>
              <div className="mt-1 mono text-[11px] text-foreground">
                PIN{authStatus.credential_count ? ` + ${authStatus.credential_count} passkey` : ""}
              </div>
              <div className="mt-1 text-[11px] text-muted-foreground">
                Biometric material remains with Windows Hello.
              </div>
            </div>
            <div className="bg-background p-4">
              <div className="section-label">Sensitive actions</div>
              <div className="mt-1 mono text-[11px] text-foreground">Five-minute proof window</div>
              <div className="mt-1 text-[11px] text-muted-foreground">
                Refreshing proof does not renew the main session.
              </div>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 border-t border-border p-4">
            {authStatus.auth_enabled && (
              <>
                <input
                  type="password"
                  value={authPin}
                  onChange={(event) => setAuthPin(event.target.value)}
                  placeholder="Operator PIN"
                  className="h-8 min-w-52 border border-border bg-background px-2 mono text-[10px] text-foreground"
                />
                <button
                  onClick={refreshProof}
                  disabled={authPin.length < 6 || busy === "auth-proof"}
                  className="flex h-8 items-center gap-1.5 border border-signal/50 px-3 mono text-[10px] uppercase text-signal disabled:opacity-35"
                >
                  {busy === "auth-proof" ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <KeyRound className="h-3 w-3" />
                  )}
                  Refresh proof
                </button>
                <button
                  onClick={lockWorkspace}
                  disabled={busy === "auth-lock"}
                  className="flex h-8 items-center gap-1.5 border border-border px-3 mono text-[10px] uppercase text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-35"
                >
                  <LockKeyhole className="h-3 w-3" />
                  Lock
                </button>
              </>
            )}
            <button
              onClick={() => setShowAuthChange((current) => !current)}
              className="ml-auto flex h-8 items-center gap-1.5 border border-severity-medium/40 px-3 mono text-[10px] uppercase text-severity-medium"
            >
              <ShieldOff className="h-3 w-3" />
              {authStatus.auth_enabled ? "Disable protection" : "Enable protection"}
            </button>
          </div>
          {showAuthChange && (
            <div className="border-t border-severity-medium/30 bg-severity-medium/5 p-4">
              <div className="text-[12px] text-severity-medium">
                {authStatus.auth_enabled
                  ? "Disabling protection allows anyone with local application access to control WatchTower. Capture and background processing are unaffected."
                  : "Re-enabling protection locks the workspace immediately. Your existing PIN remains the fallback factor."}
              </div>
              <div className="mt-3 flex max-w-lg">
                <input
                  type="password"
                  value={authPin}
                  onChange={(event) => setAuthPin(event.target.value)}
                  placeholder="Confirm operator PIN"
                  className="h-8 min-w-0 flex-1 border border-severity-medium/40 bg-background px-2 mono text-[10px] text-foreground"
                />
                <button
                  onClick={() => changeAuthentication(!authStatus.auth_enabled)}
                  disabled={authPin.length < 6 || busy === "auth-change"}
                  className="h-8 border border-l-0 border-severity-medium/50 px-3 mono text-[10px] uppercase text-severity-medium disabled:opacity-35"
                >
                  Confirm
                </button>
              </div>
            </div>
          )}
          {authRecoveryCode && (
            <div className="border-t border-severity-medium/30 bg-severity-medium/5 p-4">
              <div className="section-label text-severity-medium">One-time recovery code</div>
              <code className="mt-2 block border border-border bg-background p-3 text-center text-sm tracking-wider text-signal">
                {authRecoveryCode}
              </code>
              <button
                onClick={() => setAuthRecoveryCode("")}
                className="mt-3 h-8 border border-border px-3 mono text-[10px] uppercase text-foreground hover:border-signal"
              >
                I stored the code
              </button>
            </div>
          )}
        </section>

        <section className="panel">
          <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
            <Bot className="h-3.5 w-3.5 text-signal" />
            <div className="text-sm text-foreground">AI Providers</div>
            <button
              onClick={refreshProviders}
              title="Refresh provider status"
              className="ml-auto grid h-7 w-7 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="divide-y divide-border">
            {providers.map((provider) => (
              <div key={provider.name} className="space-y-3 p-4">
                <div className="flex flex-wrap items-start gap-3">
                  <Circle
                    className={`mt-1 h-2 w-2 ${provider.available ? "fill-ok text-ok" : "fill-severity-high text-severity-high"}`}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] text-foreground">
                      {provider.label || provider.name}
                    </div>
                    <div className="mt-1 mono text-[10px] text-muted-foreground">
                      {provider.model || "no model selected"} /{" "}
                      {provider.detail || "not configured"}
                    </div>
                    {provider.name === "openai" && (
                      <div className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
                        Uses OpenAI API billing. A ChatGPT subscription does not include API usage.
                        Keys are stored only in Windows Credential Manager.
                      </div>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      onClick={() =>
                        providerAction(provider.name, async () => {
                          const result = await testProvider(provider.name);
                          setProviderModels((current) => ({
                            ...current,
                            [provider.name]: result.models,
                          }));
                        })
                      }
                      disabled={busy === `provider:${provider.name}`}
                      className="h-8 border border-border px-3 mono text-[10px] uppercase text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-35"
                    >
                      Test
                    </button>
                    {provider.configured && (
                      <button
                        onClick={() =>
                          providerAction(provider.name, () => disconnectProvider(provider.name))
                        }
                        disabled={busy === `provider:${provider.name}`}
                        className="h-8 border border-severity-high/40 px-3 mono text-[10px] uppercase text-severity-high disabled:opacity-35"
                      >
                        Disconnect
                      </button>
                    )}
                  </div>
                </div>
                {provider.name === "openai" && !provider.configured && (
                  <div className="flex flex-col gap-2 md:flex-row">
                    <input
                      type="password"
                      autoComplete="off"
                      value={openAIKey}
                      onChange={(event) => setOpenAIKey(event.target.value)}
                      placeholder="OpenAI API key"
                      className="h-9 min-w-0 flex-1 border border-border bg-background px-3 mono text-[11px] text-foreground focus:border-signal focus:outline-none"
                    />
                    <button
                      onClick={() =>
                        providerAction("openai", async () => {
                          const result = await connectProvider("openai", { secret: openAIKey });
                          setProviderModels((current) => ({ ...current, openai: result.models }));
                        })
                      }
                      disabled={!openAIKey || busy === "provider:openai"}
                      className="h-9 border border-signal px-3 mono text-[10px] uppercase text-signal hover:bg-signal hover:text-primary-foreground disabled:opacity-35"
                    >
                      Connect OpenAI API
                    </button>
                  </div>
                )}
                {provider.name === "ollama" && !provider.configured && (
                  <button
                    onClick={() =>
                      providerAction("ollama", async () => {
                        const result = await connectProvider("ollama", {});
                        setProviderModels((current) => ({ ...current, ollama: result.models }));
                      })
                    }
                    className="h-8 border border-signal/50 px-3 mono text-[10px] uppercase text-signal"
                  >
                    Connect local Ollama
                  </button>
                )}
                {provider.configured && (
                  <div className="flex flex-col gap-2 md:flex-row">
                    <select
                      value={provider.model || ""}
                      onFocus={() => {
                        if (!providerModels[provider.name]) {
                          void fetchProviderModels(provider.name).then((result) =>
                            setProviderModels((current) => ({
                              ...current,
                              [provider.name]: result.models,
                            })),
                          );
                        }
                      }}
                      onChange={(event) =>
                        providerAction(provider.name, () =>
                          setProviderModel(provider.name, event.target.value),
                        )
                      }
                      className="h-8 min-w-64 border border-border bg-background px-2 mono text-[10px] text-foreground"
                    >
                      <option value={provider.model || ""}>
                        {provider.model || "Select model"}
                      </option>
                      {(providerModels[provider.name] || []).map((model) => (
                        <option key={model.id} value={model.id}>
                          {model.label}
                        </option>
                      ))}
                    </select>
                    <button
                      onClick={() =>
                        fetchProviderModels(provider.name, true).then((result) =>
                          setProviderModels((current) => ({
                            ...current,
                            [provider.name]: result.models,
                          })),
                        )
                      }
                      className="h-8 border border-border px-3 mono text-[10px] uppercase text-muted-foreground hover:border-signal hover:text-signal"
                    >
                      Refresh models
                    </button>
                  </div>
                )}
                {providerNeedsStepUp === provider.name && (
                  <div className="flex max-w-md">
                    <input
                      type="password"
                      value={providerPin}
                      onChange={(event) => setProviderPin(event.target.value)}
                      placeholder="Confirm operator PIN"
                      className="h-8 min-w-0 flex-1 border border-severity-medium/50 bg-background px-2 mono text-[10px] text-foreground"
                    />
                    <button
                      onClick={() => retryProviderAfterStepUp(provider.name)}
                      disabled={providerPin.length < 6}
                      className="h-8 border border-l-0 border-severity-medium/60 px-3 mono text-[10px] uppercase text-severity-medium disabled:opacity-35"
                    >
                      Verify
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5">
            <Network className="h-3.5 w-3.5 text-signal" />
            <div className="text-sm text-foreground">Sensor Mesh</div>
            <span className="mono text-[10px] uppercase text-muted-foreground">
              {String(meshStatus.authority_ready) === "true"
                ? "controller ready"
                : "controller not initialized"}
            </span>
            <button
              onClick={refresh}
              title="Refresh mesh health"
              className="ml-auto grid h-7 w-7 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-3">
            <button
              onClick={initializeMesh}
              disabled={busy === "mesh-init" || String(meshStatus.authority_ready) === "true"}
              className="flex h-8 items-center gap-1.5 border border-signal/40 px-3 mono text-[10px] uppercase text-signal hover:bg-signal/10 disabled:opacity-35"
            >
              {busy === "mesh-init" ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <Network className="h-3 w-3" />
              )}
              Initialize Controller
            </button>
            <button
              onClick={enroll}
              disabled={busy === "mesh-enroll" || String(meshStatus.authority_ready) !== "true"}
              className="flex h-8 items-center gap-1.5 border border-border px-3 mono text-[10px] uppercase text-foreground hover:border-signal hover:text-signal disabled:opacity-35"
            >
              {busy === "mesh-enroll" ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <KeyRound className="h-3 w-3" />
              )}
              New Enrollment Token
            </button>
            <input
              value={meshInterface}
              onChange={(event) => setMeshInterface(event.target.value)}
              placeholder="remote interface identifier"
              className="h-8 min-w-52 flex-1 border border-border bg-background px-2 mono text-[10px] text-foreground placeholder:text-muted-foreground"
            />
          </div>
          {enrollmentToken && (
            <div className="border-b border-severity-medium/30 bg-severity-medium/5 px-4 py-3">
              <div className="section-label text-severity-medium">One-time enrollment token</div>
              <code className="mt-1 block break-all text-[11px] text-foreground">
                {enrollmentToken}
              </code>
            </div>
          )}
          <div className="divide-y divide-border">
            {nodes.map((node) => (
              <div key={node.id} className="grid gap-3 p-4 md:grid-cols-[minmax(0,1fr)_auto]">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <Circle
                      className={`h-2 w-2 ${node.status === "online" || node.status === "local" ? "fill-ok text-ok" : "fill-severity-high text-severity-high"}`}
                    />
                    <span className="truncate text-[13px] text-foreground">{node.name}</span>
                    <span className="mono text-[10px] uppercase text-muted-foreground">
                      {node.status}
                    </span>
                  </div>
                  <div className="mt-1 truncate mono text-[10px] text-muted-foreground">
                    {node.id} / {node.platform || "platform unknown"} / last check-in{" "}
                    {node.last_seen_at
                      ? new Date(node.last_seen_at * 1000).toLocaleString()
                      : "never"}
                  </div>
                </div>
                {node.status !== "local" && node.status !== "revoked" && (
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      onClick={() => commandNode(node, "capture.start")}
                      disabled={busy === `${node.id}:capture.start`}
                      className="h-8 border border-signal/40 px-3 mono text-[10px] uppercase text-signal hover:bg-signal/10 disabled:opacity-35"
                    >
                      Start
                    </button>
                    <button
                      onClick={() => commandNode(node, "capture.stop")}
                      disabled={busy === `${node.id}:capture.stop`}
                      className="h-8 border border-border px-3 mono text-[10px] uppercase text-muted-foreground hover:border-severity-high hover:text-severity-high disabled:opacity-35"
                    >
                      Stop
                    </button>
                    <button
                      onClick={() => revoke(node)}
                      disabled={busy === `revoke:${node.id}`}
                      title="Revoke sensor certificate"
                      className="grid h-8 w-8 place-items-center border border-border text-muted-foreground hover:border-severity-critical hover:text-severity-critical disabled:opacity-35"
                    >
                      <ShieldX className="h-3.5 w-3.5" />
                    </button>
                  </div>
                )}
              </div>
            ))}
            {!nodes.length && (
              <div className="px-4 py-5 mono text-[10px] uppercase text-muted-foreground">
                No sensor nodes registered
              </div>
            )}
          </div>
        </section>

        <section className="panel">
          <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
            <Wifi className="h-3.5 w-3.5 text-signal" />
            <div className="text-sm text-foreground">Capture Sources</div>
            <button
              onClick={refresh}
              title="Refresh capture sources"
              className="ml-auto grid h-7 w-7 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </div>
          {health.daemon !== "online" && (
            <div className="border-b border-severity-high/30 bg-severity-high/10 px-4 py-2.5 mono text-[10px] uppercase text-severity-high">
              Start the WatchTower daemon before controlling capture sources
            </div>
          )}
          <div className="divide-y divide-border">
            {interfaces.map((item) => (
              <div
                key={item.id}
                className="grid items-center gap-4 p-4 data-row md:grid-cols-[1fr_130px_auto]"
              >
                <div className="flex min-w-0 items-center gap-3">
                  <Circle
                    className={`h-2 w-2 shrink-0 ${item.status === "up" ? "fill-ok text-ok" : "fill-muted-foreground text-muted-foreground"}`}
                  />
                  <div className="min-w-0">
                    <div className="truncate text-[13px] text-foreground">
                      {item.name}{" "}
                      <span className="mono text-[10px] text-muted-foreground">
                        / {item.source_type}
                      </span>
                    </div>
                    <div className="truncate mono text-[10px] uppercase text-muted-foreground">
                      {item.mac || "no hardware address"}
                      {item.ipv4 ? ` / ${item.ipv4}` : ""}
                      {item.unavailable_reason
                        ? ` / ${item.unavailable_reason}`
                        : !selectCaptureBackend(item)
                          ? " / no supported capture backend"
                          : ""}
                    </div>
                  </div>
                </div>
                <select
                  aria-label={`${item.name} packet core`}
                  value={item.capturing ? selectCaptureBackend(item) || "" : backend[item.id] || ""}
                  onChange={(event) =>
                    setBackend((current) => ({ ...current, [item.id]: event.target.value }))
                  }
                  disabled={item.capturing}
                  className="h-8 border border-border bg-background px-2 mono text-[10px] uppercase text-foreground disabled:opacity-50"
                >
                  {selectCaptureBackend(item) ? (
                    <option value="">operator default</option>
                  ) : (
                    <option value="">unavailable</option>
                  )}
                  {item.backends.map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
                <button
                  onClick={() => toggle(item)}
                  disabled={
                    busy === item.id ||
                    item.status !== "up" ||
                    health.daemon !== "online" ||
                    (!item.capturing && !selectCaptureBackend(item))
                  }
                  className={`flex h-8 min-w-24 items-center justify-center gap-1.5 border px-3 mono text-[10px] uppercase ${item.capturing ? "border-severity-critical/40 text-severity-critical hover:bg-severity-critical/10" : "border-signal/40 text-signal hover:bg-signal/10"} disabled:cursor-not-allowed disabled:opacity-30`}
                >
                  {busy === item.id ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : item.capturing ? (
                    <Square className="h-3 w-3" />
                  ) : (
                    <Play className="h-3 w-3" />
                  )}
                  {item.capturing ? "Stop" : "Start"}
                </button>
              </div>
            ))}
          </div>
        </section>

        <section className="panel border-severity-critical/40">
          <div className="flex items-center gap-2 border-b border-severity-critical/30 px-4 py-2.5">
            <Trash2 className="h-3.5 w-3.5 text-severity-critical" />
            <div className="text-sm text-severity-critical">Danger Zone</div>
          </div>
          <div className="p-4">
            <p className="text-[13px] text-muted-foreground">
              Purge all captured data. The API refuses this action while capture is active.
            </p>
            {!showReset ? (
              <button
                onClick={() => setShowReset(true)}
                className="mt-3 border border-severity-critical/40 bg-severity-critical/10 px-3 py-1.5 mono text-[10px] uppercase text-severity-critical hover:bg-severity-critical hover:text-white"
              >
                Reset Database
              </button>
            ) : (
              <div className="mt-4 max-w-xl border border-severity-critical/30 p-3">
                <label className="section-label">TYPE RESET WATCHTOWER</label>
                <div className="mt-2 flex gap-2">
                  <input
                    value={confirmation}
                    onChange={(event) => setConfirmation(event.target.value)}
                    className="h-9 min-w-0 flex-1 border border-border bg-background px-3 mono text-[11px] text-foreground focus:border-severity-critical focus:outline-none"
                  />
                  <button
                    onClick={reset}
                    disabled={confirmation !== "RESET WATCHTOWER" || busy === "reset"}
                    className="h-9 border border-severity-critical bg-severity-critical/10 px-3 mono text-[10px] uppercase text-severity-critical disabled:opacity-30"
                  >
                    {busy === "reset" ? "Resetting" : "Confirm"}
                  </button>
                  <button
                    onClick={() => {
                      setShowReset(false);
                      setConfirmation("");
                    }}
                    className="h-9 border border-border px-3 mono text-[10px] uppercase text-muted-foreground"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

function HostMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 bg-background p-4">
      <div className="section-label">{label}</div>
      <div className="mt-1 truncate text-foreground">{value}</div>
    </div>
  );
}

function Resource({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-background p-4">
      <div className="flex items-baseline justify-between">
        <span className="section-label">{label}</span>
        <span className="numeral text-xl text-foreground">
          {value}
          <span className="text-xs text-muted-foreground">%</span>
        </span>
      </div>
      <div className="mt-2 h-[3px] bg-border">
        <div className={`h-full ${color}`} style={{ width: `${Math.min(100, value)}%` }} />
      </div>
    </div>
  );
}
