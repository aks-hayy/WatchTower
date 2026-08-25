import { createFileRoute } from "@tanstack/react-router";
import {
  AlertTriangle,
  Bot,
  Check,
  ChevronRight,
  Circle,
  Loader2,
  Plus,
  RefreshCw,
  Send,
  ShieldCheck,
  Sparkles,
  User,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  approveAIAction,
  createAIConversation,
  fetchAIConversation,
  fetchAIConversations,
  fetchAIRun,
  fetchAIStatus,
  fetchInterfaces,
  fetchMeshNodes,
  fetchSessions,
  rejectAIAction,
  startAIRun,
} from "@/lib/api.functions";
import type {
  AIApproval,
  AIContextScope,
  AIConversation,
  AIRun,
  AIStatus,
  CaptureSession,
  NetworkInterface,
  SensorNode,
} from "@/types/watchtower";
import { useSensorScope } from "@/components/useSensorScope";

export const Route = createFileRoute("/ai")({
  head: () => ({ meta: [{ title: "Analyst - Watchtower" }] }),
  loader: async () => {
    const [status, conversations, interfaces, sessions, nodes] = await Promise.all([
      fetchAIStatus(),
      fetchAIConversations({ data: { limit: 100 } }),
      fetchInterfaces(),
      fetchSessions({ data: { limit: 100 } }),
      fetchMeshNodes({ data: { limit: 100 } }),
    ]);
    return { status, conversations, interfaces, sessions, nodes };
  },
  component: AiPage,
});

const SUGGESTIONS = [
  "Summarize the current alert picture with evidence.",
  "Investigate the highest-priority endpoint.",
  "Show the current pipeline health and visibility limits.",
  "Prepare a historical Sigma hunt for this scope.",
];

function AiPage() {
  const initial = Route.useLoaderData();
  const { selectedNodeId } = useSensorScope();
  const [status, setStatus] = useState<AIStatus>(initial.status);
  const [conversations, setConversations] = useState<AIConversation[]>(initial.conversations);
  const [conversation, setConversation] = useState<AIConversation | null>(null);
  const [interfaces] = useState<NetworkInterface[]>(initial.interfaces);
  const [sessions] = useState<CaptureSession[]>(initial.sessions);
  const [nodes] = useState<SensorNode[]>(initial.nodes);
  const [provider, setProvider] = useState<"ollama" | "openai">("ollama");
  const [source, setSource] = useState("live");
  const [captureInterface, setCaptureInterface] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [nodeId, setNodeId] = useState(selectedNodeId || "");
  const [research, setResearch] = useState<"auto" | "off">("auto");
  const [mode, setMode] = useState<"auto" | "general" | "investigate">("auto");
  const [input, setInput] = useState("");
  const [run, setRun] = useState<AIRun | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [typedConfirmations, setTypedConfirmations] = useState<Record<string, string>>({});

  useEffect(() => {
    setNodeId(selectedNodeId || "");
    setSessionId("");
  }, [selectedNodeId]);

  const selectedProvider = status.providers.find((item) => item.name === provider);
  const activeRunId = run?.id;
  const activeRunStatus = run?.status;
  const scope = useMemo<AIContextScope>(
    () => ({
      source: source.trim() || undefined,
      interface: captureInterface || undefined,
      session_id: sessionId || undefined,
      node_id: nodeId || undefined,
      max_records: 250,
    }),
    [source, captureInterface, sessionId, nodeId],
  );

  const refreshList = useCallback(async () => {
    const [nextStatus, nextConversations] = await Promise.all([
      fetchAIStatus(),
      fetchAIConversations({ data: { limit: 100 } }),
    ]);
    setStatus(nextStatus);
    setConversations(nextConversations);
  }, []);

  const openConversation = async (id: string) => {
    setBusy(true);
    setNotice(null);
    try {
      const next = await fetchAIConversation({ data: { conversation_id: id } });
      setConversation(next);
      setProvider(next.provider === "openai" ? "openai" : "ollama");
      setSource(next.scope.source || "live");
      setCaptureInterface(next.scope.interface || "");
      setSessionId(next.scope.session_id || "");
      setNodeId(next.scope.node_id || "");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Unable to open conversation");
    } finally {
      setBusy(false);
    }
  };

  const newConversation = async () => {
    setBusy(true);
    setNotice(null);
    try {
      const next = await createAIConversation({ data: { provider, scope } });
      setConversation({ ...next, messages: [] });
      await refreshList();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Unable to create conversation");
    } finally {
      setBusy(false);
    }
  };

  const refreshConversation = useCallback(
    async (id: string) => {
      const next = await fetchAIConversation({ data: { conversation_id: id } });
      setConversation(next);
      await refreshList();
    },
    [refreshList],
  );

  const send = async (value = input) => {
    const prompt = value.trim();
    if (!prompt || busy) return;
    setBusy(true);
    setNotice(null);
    try {
      const next = await startAIRun({
        data: {
          prompt,
          conversation_id: conversation?.id,
          provider,
          scope,
          research_mode: research,
          mode,
        },
      });
      setRun(next);
      setInput("");
      if (next.conversation_id) await refreshConversation(next.conversation_id);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Unable to start analyst run");
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (
      !activeRunId ||
      ["COMPLETE", "DEGRADED", "NEEDS_SCOPE", "FAILED", "REJECTED"].includes(activeRunStatus || "")
    )
      return;
    const timer = window.setInterval(() => {
      fetchAIRun({ data: { run_id: activeRunId } })
        .then(async (next) => {
          setRun(next);
          if (["COMPLETE", "DEGRADED", "NEEDS_SCOPE", "FAILED", "REJECTED"].includes(next.status)) {
            await refreshConversation(next.conversation_id);
          }
        })
        .catch((error) =>
          setNotice(error instanceof Error ? error.message : "Analyst status unavailable"),
        );
    }, 700);
    return () => window.clearInterval(timer);
  }, [activeRunId, activeRunStatus, refreshConversation]);

  const decideApproval = async (approval: AIApproval, approved: boolean) => {
    setBusy(true);
    setNotice(null);
    try {
      const next = approved
        ? await approveAIAction({
            data: { approval_id: approval.id, confirmation: typedConfirmations[approval.id] || "" },
          })
        : await rejectAIAction({
            data: { approval_id: approval.id, reason: "Operator rejected this proposal" },
          });
      setRun(next);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Approval could not be recorded");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <header className="flex flex-wrap items-center gap-3 border-b border-border bg-surface/60 px-4 py-3 md:px-6">
        <span className="section-label section-label-accent">AIA</span>
        <span className="mono text-[11px] uppercase text-foreground">/ Analyst</span>
        <span className="mono text-[10px] uppercase text-muted-foreground">
          local control plane
        </span>
        <span className="ml-auto flex items-center gap-1.5 mono text-[10px] uppercase text-muted-foreground">
          <Circle
            className={`h-2 w-2 ${selectedProvider?.available ? "fill-ok text-ok" : "fill-severity-high text-severity-high"}`}
          />
          {provider} {selectedProvider?.available ? "ready" : "unavailable"}
          {selectedProvider?.available && (
            <span className={selectedProvider.agentic_ready ? "text-ok" : "text-severity-medium"}>
              / {selectedProvider.agentic_ready ? "agentic" : "chat-only"}
            </span>
          )}
        </span>
        <button
          onClick={() => refreshList()}
          title="Refresh analyst state"
          className="grid h-7 w-7 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal"
        >
          <RefreshCw className="h-3.5 w-3.5" />
        </button>
      </header>

      <div className="grid min-h-[calc(100vh-49px)] grid-cols-1 xl:grid-cols-[260px_minmax(0,1fr)_300px]">
        <aside className="border-b border-border bg-surface/30 xl:border-b-0 xl:border-r">
          <div className="flex items-center border-b border-border px-3 py-2.5">
            <span className="section-label">Conversations</span>
            <button
              onClick={newConversation}
              disabled={busy}
              title="New analyst conversation"
              className="ml-auto grid h-6 w-6 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-40"
            >
              <Plus className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="max-h-52 overflow-y-auto xl:max-h-[calc(100vh-240px)]">
            {conversations.map((item) => (
              <button
                key={item.id}
                onClick={() => openConversation(item.id)}
                className={`block w-full border-b border-border px-3 py-3 text-left hover:bg-signal/[0.03] ${conversation?.id === item.id ? "bg-signal/5" : ""}`}
              >
                <div className="truncate text-[12px] text-foreground">{item.title}</div>
                <div className="mt-1 flex gap-2 mono text-[9px] uppercase text-muted-foreground">
                  <span>{item.provider}</span>
                  <span>{formatTime(item.updated_at)}</span>
                </div>
              </button>
            ))}
            {!conversations.length && (
              <div className="px-3 py-5 mono text-[10px] uppercase text-muted-foreground">
                No stored conversations
              </div>
            )}
          </div>
          <div className="hidden space-y-3 p-3 xl:block">
            <ScopeControls
              provider={provider}
              setProvider={setProvider}
              source={source}
              setSource={setSource}
              captureInterface={captureInterface}
              setCaptureInterface={setCaptureInterface}
              sessionId={sessionId}
              setSessionId={setSessionId}
              nodeId={nodeId}
              setNodeId={setNodeId}
              research={research}
              setResearch={setResearch}
              mode={mode}
              setMode={setMode}
              interfaces={interfaces}
              sessions={sessions}
              nodes={nodes}
              providers={status.providers}
            />
          </div>
        </aside>

        <section className="flex min-h-[560px] min-w-0 flex-col grid-bg-fine">
          <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
            <Bot className="h-3.5 w-3.5 text-signal" />
            <span className="section-label">Evidence Conversation</span>
            {run && (
              <span className="ml-auto mono text-[10px] uppercase text-muted-foreground">
                {run.status}
              </span>
            )}
          </div>
          {notice && (
            <div className="m-3 border border-severity-high/40 bg-severity-high/10 px-3 py-2 mono text-[10px] text-severity-high">
              {notice}
            </div>
          )}
          <div className="flex-1 space-y-4 overflow-auto px-4 py-5 md:px-6">
            {(conversation?.messages || []).map((message) => (
              <MessageRow key={message.id} message={message} />
            ))}
            {run &&
              !["COMPLETE", "DEGRADED", "NEEDS_SCOPE", "FAILED", "REJECTED"].includes(
                run.status,
              ) && (
                <div className="flex items-center gap-2 mono text-[10px] uppercase text-muted-foreground">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-signal" /> Analyst processing
                </div>
              )}
            {run?.error && (
              <div className="border border-severity-critical/40 bg-severity-critical/10 p-3 mono text-[11px] text-severity-critical">
                {run.error}
              </div>
            )}
            {run?.approvals
              .filter((item) => item.status === "PENDING")
              .map((approval) => (
                <ApprovalCard
                  key={approval.id}
                  approval={approval}
                  run={run}
                  value={typedConfirmations[approval.id] || ""}
                  onChange={(value) =>
                    setTypedConfirmations((current) => ({ ...current, [approval.id]: value }))
                  }
                  onApprove={() => decideApproval(approval, true)}
                  onReject={() => decideApproval(approval, false)}
                  busy={busy}
                />
              ))}
            {!conversation?.messages?.length && !run && (
              <div className="grid h-full min-h-72 place-items-center text-center">
                <Sparkles className="h-7 w-7 text-muted-foreground" />
              </div>
            )}
          </div>
          <div className="border-t border-border bg-surface/60 p-3">
            <div className="mx-auto max-w-4xl space-y-2">
              <div className="flex flex-wrap gap-1.5">
                {SUGGESTIONS.map((suggestion) => (
                  <button
                    key={suggestion}
                    onClick={() => send(suggestion)}
                    disabled={busy}
                    className="border border-border px-2 py-1 mono text-[9px] uppercase text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-40"
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
              <div className="flex">
                <textarea
                  value={input}
                  onChange={(event) => setInput(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && !event.shiftKey) {
                      event.preventDefault();
                      send();
                    }
                  }}
                  placeholder="Ask WatchTower"
                  rows={2}
                  className="min-h-11 flex-1 resize-none border border-border bg-background px-3 py-2 mono text-[12px] text-foreground placeholder:text-muted-foreground focus:border-signal focus:outline-none"
                />
                <button
                  onClick={() => send()}
                  disabled={!input.trim() || busy}
                  title="Send analyst prompt"
                  className="grid w-11 place-items-center border border-l-0 border-signal bg-signal/10 text-signal hover:bg-signal hover:text-primary-foreground disabled:opacity-30"
                >
                  <Send className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          </div>
        </section>

        <aside className="border-t border-border bg-surface/30 xl:border-l xl:border-t-0">
          <div className="p-3 xl:hidden">
            <ScopeControls
              provider={provider}
              setProvider={setProvider}
              source={source}
              setSource={setSource}
              captureInterface={captureInterface}
              setCaptureInterface={setCaptureInterface}
              sessionId={sessionId}
              setSessionId={setSessionId}
              nodeId={nodeId}
              setNodeId={setNodeId}
              research={research}
              setResearch={setResearch}
              mode={mode}
              setMode={setMode}
              interfaces={interfaces}
              sessions={sessions}
              nodes={nodes}
              providers={status.providers}
            />
          </div>
          <div className="border-y border-border px-3 py-2.5 xl:border-t-0">
            <span className="section-label">Run Ledger</span>
          </div>
          {run && (
            <div className="grid grid-cols-2 gap-px border-b border-border bg-border mono text-[10px] uppercase">
              <div className="bg-surface px-3 py-2 text-muted-foreground">
                Rounds <span className="text-foreground">{run.rounds ?? "-"}</span>
              </div>
              <div className="bg-surface px-3 py-2 text-muted-foreground">
                Tools{" "}
                <span className="text-foreground">
                  {run.tool_call_count ?? run.tool_calls?.length ?? 0}
                </span>
              </div>
              <div className="bg-surface px-3 py-2 text-muted-foreground">
                Context{" "}
                <span className="text-foreground">
                  {run.context_chars ? `${Math.round(run.context_chars / 1000)}k` : "-"}
                </span>
              </div>
              <div className="bg-surface px-3 py-2 text-muted-foreground">
                Citations{" "}
                <span className="text-foreground">
                  {run.citation_coverage != null
                    ? `${Math.round(run.citation_coverage * 100)}%`
                    : "-"}
                </span>
              </div>
              <div className="bg-surface px-3 py-2 text-muted-foreground">
                Validation{" "}
                <span
                  className={
                    run.validation_status === "degraded" ? "text-severity-high" : "text-foreground"
                  }
                >
                  {run.validation_status || "-"}
                </span>
              </div>
              <div className="bg-surface px-3 py-2 text-muted-foreground">
                Blocked <span className="text-foreground">{run.blocked_claims ?? 0}</span>
              </div>
            </div>
          )}
          <div className="divide-y divide-border">
            {(run?.tool_calls || []).map((call) => (
              <div key={call.id} className="px-3 py-2.5">
                <div className="flex items-center gap-2 mono text-[10px] uppercase">
                  <ChevronRight className="h-3 w-3 text-signal" />
                  <span className="text-foreground">{call.tool_name}</span>
                  <span className="ml-auto text-muted-foreground">{call.status}</span>
                </div>
              </div>
            ))}
            {!run?.tool_calls?.length && (
              <div className="px-3 py-5 mono text-[10px] uppercase text-muted-foreground">
                No tool activity
              </div>
            )}
          </div>
          <div className="border-y border-border px-3 py-2.5">
            <span className="section-label">Sources</span>
          </div>
          <div className="max-h-64 divide-y divide-border overflow-y-auto">
            {(run?.citations || []).map((citation, index) => (
              <CitationRow key={`${citation.reference}-${index}`} citation={citation} />
            ))}
            {!run?.citations?.length && (
              <div className="px-3 py-5 mono text-[10px] uppercase text-muted-foreground">
                No citations
              </div>
            )}
          </div>
        </aside>
      </div>
    </div>
  );
}

function ScopeControls(props: {
  provider: "ollama" | "openai";
  setProvider: (value: "ollama" | "openai") => void;
  source: string;
  setSource: (value: string) => void;
  captureInterface: string;
  setCaptureInterface: (value: string) => void;
  sessionId: string;
  setSessionId: (value: string) => void;
  nodeId: string;
  setNodeId: (value: string) => void;
  research: "auto" | "off";
  setResearch: (value: "auto" | "off") => void;
  mode: "auto" | "general" | "investigate";
  setMode: (value: "auto" | "general" | "investigate") => void;
  interfaces: NetworkInterface[];
  sessions: CaptureSession[];
  nodes: SensorNode[];
  providers: AIStatus["providers"];
}) {
  return (
    <div className="space-y-3">
      <label className="block">
        <span className="section-label">Provider</span>
        <select
          value={props.provider}
          onChange={(event) => props.setProvider(event.target.value as "ollama" | "openai")}
          className="mt-1.5 h-8 w-full border border-border bg-background px-2 mono text-[10px] uppercase text-foreground"
        >
          <option value="ollama">Ollama</option>
          <option value="openai">OpenAI</option>
        </select>
      </label>
      <label className="block">
        <span className="section-label">Analyst mode</span>
        <select
          value={props.mode}
          onChange={(event) =>
            props.setMode(event.target.value as "auto" | "general" | "investigate")
          }
          className="mt-1.5 h-8 w-full border border-border bg-background px-2 mono text-[10px] uppercase text-foreground"
        >
          <option value="auto">Auto by scope</option>
          <option value="general">General chat</option>
          <option value="investigate">Scoped investigation</option>
        </select>
      </label>
      <label className="block">
        <span className="section-label">Source</span>
        <input
          value={props.source}
          onChange={(event) => props.setSource(event.target.value)}
          className="mt-1.5 h-8 w-full border border-border bg-background px-2 mono text-[10px] text-foreground"
        />
      </label>
      <label className="block">
        <span className="section-label">Interface</span>
        <select
          value={props.captureInterface}
          onChange={(event) => props.setCaptureInterface(event.target.value)}
          className="mt-1.5 h-8 w-full border border-border bg-background px-2 mono text-[10px] text-foreground"
        >
          <option value="">All interfaces</option>
          {props.interfaces.map((item) => (
            <option key={item.id} value={item.name}>
              {item.name}
            </option>
          ))}
        </select>
      </label>
      <label className="block">
        <span className="section-label">Session</span>
        <select
          value={props.sessionId}
          onChange={(event) => props.setSessionId(event.target.value)}
          className="mt-1.5 h-8 w-full border border-border bg-background px-2 mono text-[10px] text-foreground"
        >
          <option value="">All sessions</option>
          {props.sessions.map((item) => (
            <option key={item.id} value={item.id}>
              {item.interface || item.device_id} / {item.id.slice(0, 8)}
            </option>
          ))}
        </select>
      </label>
      <label className="block">
        <span className="section-label">Sensor Node</span>
        <select
          value={props.nodeId}
          onChange={(event) => {
            const value = event.target.value;
            props.setNodeId(value);
            if (value) props.setSource("");
          }}
          className="mt-1.5 h-8 w-full border border-border bg-background px-2 mono text-[10px] text-foreground"
        >
          <option value="">Selected source scope</option>
          {props.nodes.map((item) => (
            <option key={item.id} value={item.id}>
              {item.name} / {item.status}
            </option>
          ))}
        </select>
      </label>
      <label className="flex items-center justify-between border border-border px-2.5 py-2">
        <span className="section-label">Public Research</span>
        <input
          type="checkbox"
          checked={props.research === "auto"}
          onChange={(event) => props.setResearch(event.target.checked ? "auto" : "off")}
          className="h-3.5 w-3.5 accent-[hsl(var(--signal))]"
        />
      </label>
    </div>
  );
}

function MessageRow({ message }: { message: NonNullable<AIConversation["messages"]>[number] }) {
  const isUser = message.role === "user";
  return (
    <div className={`flex gap-3 ${isUser ? "justify-end" : ""}`}>
      {!isUser && (
        <Avatar>
          <Bot className="h-3.5 w-3.5 text-signal" />
        </Avatar>
      )}
      <div
        className={`max-w-[720px] whitespace-pre-wrap border p-3 text-[13px] leading-relaxed ${isUser ? "border-signal/40 bg-signal/5 text-foreground" : "bg-surface text-foreground"}`}
      >
        {message.content}
      </div>
      {isUser && (
        <Avatar>
          <User className="h-3.5 w-3.5 text-muted-foreground" />
        </Avatar>
      )}
    </div>
  );
}

function ApprovalCard({
  approval,
  run,
  value,
  onChange,
  onApprove,
  onReject,
  busy,
}: {
  approval: AIApproval;
  run: AIRun;
  value: string;
  onChange: (value: string) => void;
  onApprove: () => void;
  onReject: () => void;
  busy: boolean;
}) {
  const invocation = run.tool_calls.find((item) => item.id === approval.invocation_id);
  return (
    <div className="border border-severity-medium/50 bg-severity-medium/5 p-3">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-severity-medium" />
        <span className="mono text-[10px] uppercase text-severity-medium">
          Operator approval required
        </span>
      </div>
      <div className="mt-2 text-[13px] text-foreground">{approval.tool_name}</div>
      <div className="mt-1 break-all mono text-[10px] leading-relaxed text-muted-foreground">
        {invocation?.arguments_json || "{}"}
      </div>
      <div className="mt-1 break-all mono text-[9px] uppercase leading-relaxed text-muted-foreground">
        Scope {approval.scope_json || "{}"} / {approval.requester || "local-operator"}
      </div>
      {approval.confirmation_phrase && (
        <input
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder={approval.confirmation_phrase}
          className="mt-3 h-8 w-full border border-border bg-background px-2 mono text-[10px] text-foreground"
        />
      )}
      <div className="mt-3 flex gap-2">
        <button
          onClick={onApprove}
          disabled={busy}
          className="flex h-8 items-center gap-1.5 border border-signal/60 px-3 mono text-[10px] uppercase text-signal hover:bg-signal hover:text-primary-foreground disabled:opacity-40"
        >
          <Check className="h-3 w-3" />
          Approve
        </button>
        <button
          onClick={onReject}
          disabled={busy}
          className="flex h-8 items-center gap-1.5 border border-border px-3 mono text-[10px] uppercase text-muted-foreground hover:border-severity-critical hover:text-severity-critical disabled:opacity-40"
        >
          <X className="h-3 w-3" />
          Reject
        </button>
      </div>
    </div>
  );
}

function CitationRow({ citation }: { citation: AIRun["citations"][number] }) {
  const external = citation.kind === "external";
  return (
    <div className="px-3 py-2.5">
      <div
        className={`mono text-[9px] uppercase ${external ? "text-severity-medium" : "text-signal"}`}
      >
        {external ? "External research" : "WatchTower evidence"}
      </div>
      {citation.url ? (
        <a
          href={citation.url}
          target="_blank"
          rel="noreferrer"
          className="mt-1 block truncate text-[11px] text-foreground hover:text-signal"
        >
          {citation.source}
        </a>
      ) : (
        <div className="mt-1 truncate text-[11px] text-foreground">{citation.reference}</div>
      )}
      <div className="mt-1 line-clamp-3 text-[11px] leading-relaxed text-muted-foreground">
        {citation.summary}
      </div>
    </div>
  );
}

function Avatar({ children }: { children: React.ReactNode }) {
  return (
    <div className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center border border-border bg-surface">
      {children}
    </div>
  );
}
function formatTime(value: number) {
  return new Date(value * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
