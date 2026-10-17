import { createFileRoute, Link } from "@tanstack/react-router";
import {
  AlertTriangle,
  Bot,
  Check,
  Ban,
  ChevronRight,
  Circle,
  Loader2,
  Pencil,
  Plus,
  RotateCcw,
  RefreshCw,
  Send,
  ShieldCheck,
  Sparkles,
  User,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { attachAIRunStream, isTerminalAIRunStatus } from "@/lib/ai-run-stream";
import { canRetryInterruptedAIRun } from "@/lib/ai-run-retry";
import { providerProbeSummary } from "@/lib/provider-capability";
import { summarizeEffectiveScope } from "@/lib/ai-scope";
import {
  approveAIAction,
  branchAIConversation,
  cancelAIRun,
  createAIConversation,
  fetchAIConversation,
  fetchAIConversations,
  fetchAIRun,
  fetchAIStatus,
  fetchEntities,
  fetchInterfaces,
  fetchMeshNodes,
  fetchSessions,
  aiRunEventsUrl,
  retryAIRun,
  testAIProvider,
  rejectAIAction,
  startAIRun,
} from "@/lib/api.functions";
import {
  activeConversationIdFromSearch,
  buildPriorityInvestigationPrompt,
  latestRunIdForConversation,
  parseInvestigationResult,
  persistedRunIdsForConversation,
  selectHighestPriorityEndpoint,
} from "@/lib/analyst-workflows";
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
  validateSearch: (search: Record<string, unknown>) => ({
    conversation: activeConversationIdFromSearch(search.conversation),
  }),
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

const PRIORITY_SUGGESTION = "Investigate top-priority endpoint";
const SUGGESTIONS = [
  "Summarize the current alert picture with evidence.",
  PRIORITY_SUGGESTION,
  "Show the current pipeline health and visibility limits.",
  "Prepare a historical Sigma hunt for this scope.",
];
function AiPage() {
  const initial = Route.useLoaderData();
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
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
  const [editingMessageId, setEditingMessageId] = useState<string | null>(null);
  const [run, setRun] = useState<AIRun | null>(null);
  const [persistedRuns, setPersistedRuns] = useState<Record<string, AIRun>>({});
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [priorityTarget, setPriorityTarget] = useState<{
    ip: string;
    priority_score: number;
  } | null>(null);
  const investigationSummary = useMemo(
    () => parseInvestigationResult(run?.tool_calls || []),
    [run?.tool_calls],
  );
  const retryOriginMessage = run?.user_message_id
    ? conversation?.messages?.find((message) => message.id === run.user_message_id)
    : undefined;
  const canRetryCurrentRun = Boolean(
    run && canRetryInterruptedAIRun(run, Boolean(retryOriginMessage)),
  );
  const [typedConfirmations, setTypedConfirmations] = useState<Record<string, string>>({});
  const viewRequest = useRef(0);

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

  const hydratePersistedRun = useCallback(
    async (
      messages: AIConversation["messages"],
      clearWhenMissing = false,
      preferredRunId?: string,
    ) => {
      const runIds = persistedRunIdsForConversation(messages || []);
      if (!runIds.length) {
        if (clearWhenMissing) {
          setRun(null);
          setPersistedRuns({});
        }
        return;
      }
      const loadedRuns = await Promise.all(
        runIds.map((runId) => fetchAIRun({ data: { run_id: runId } })),
      );
      setPersistedRuns((current) => ({
        ...current,
        ...Object.fromEntries(loadedRuns.map((loadedRun) => [loadedRun.id, loadedRun])),
      }));
      const latestRunId = preferredRunId || latestRunIdForConversation(messages || []);
      const latestRun = loadedRuns.find((loadedRun) => loadedRun.id === latestRunId);
      if (latestRun) {
        setRun((current) => {
          if (preferredRunId && current && current.id !== preferredRunId) return current;
          return latestRun;
        });
      }
    },
    [],
  );

  const openConversation = useCallback(
    async (id: string) => {
      const requestId = ++viewRequest.current;
      setBusy(true);
      setNotice(null);
      setEditingMessageId(null);
      setInput("");
      try {
        const next = await fetchAIConversation({ data: { conversation_id: id } });
        if (requestId !== viewRequest.current) return;
        setConversation(next);
        setProvider(next.provider === "openai" ? "openai" : "ollama");
        setSource(next.scope.source || "live");
        setCaptureInterface(next.scope.interface || "");
        setSessionId(next.scope.session_id || "");
        setNodeId(next.scope.node_id || "");
        setRun(null);
        setPriorityTarget(null);
        if (search.conversation !== id) {
          await navigate({
            search: (previous) => ({ ...previous, conversation: id }),
            replace: true,
          });
        }
        await hydratePersistedRun(next.messages, true);
      } catch (error) {
        setNotice(error instanceof Error ? error.message : "Unable to open conversation");
        if (search.conversation === id) {
          void navigate({
            search: (previous) => ({ ...previous, conversation: undefined }),
            replace: true,
          });
        }
      } finally {
        setBusy(false);
      }
    },
    [hydratePersistedRun, navigate, search.conversation],
  );

  useEffect(() => {
    if (search.conversation && conversation?.id !== search.conversation) {
      void openConversation(search.conversation);
    }
  }, [conversation?.id, openConversation, search.conversation]);

  const newConversation = async () => {
    ++viewRequest.current;
    setBusy(true);
    setNotice(null);
    setEditingMessageId(null);
    setInput("");
    try {
      const next = await createAIConversation({ data: { provider, scope } });
      setConversation({ ...next, messages: [] });
      setRun(null);
      setPersistedRuns({});
      setPriorityTarget(null);
      await navigate({
        search: (previous) => ({ ...previous, conversation: next.id }),
        replace: true,
      });
      await refreshList();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Unable to create conversation");
    } finally {
      setBusy(false);
    }
  };

  const refreshConversation = useCallback(
    async (id: string, preferredRunId?: string) => {
      const next = await fetchAIConversation({ data: { conversation_id: id } });
      if (conversation?.id && conversation.id !== id) return;
      setConversation(next);
      if (search.conversation !== id) {
        await navigate({
          search: (previous) => ({ ...previous, conversation: id }),
          replace: true,
        });
      }
      await hydratePersistedRun(next.messages, false, preferredRunId);
      await refreshList();
    },
    [conversation?.id, hydratePersistedRun, navigate, refreshList, search.conversation],
  );

  const startPrompt = async (
    prompt: string,
    scopeOverride: AIContextScope = scope,
    modeOverride = mode,
    busyAlready = false,
  ) => {
    if (!busyAlready) setBusy(true);
    setNotice(null);
    try {
      const next = await startAIRun({
        data: {
          prompt,
          conversation_id: conversation?.id,
          provider,
          scope: scopeOverride,
          research_mode: research,
          mode: modeOverride,
          client_request_id: crypto.randomUUID(),
        },
      });
      setRun(next);
      setPersistedRuns((current) => ({ ...current, [next.id]: next }));
      setInput("");
      if (next.conversation_id) await refreshConversation(next.conversation_id, next.id);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Unable to start analyst run");
    } finally {
      setBusy(false);
    }
  };

  const send = async (
    value = input,
    scopeOverride: AIContextScope = scope,
    modeOverride = mode,
  ) => {
    const prompt = value.trim();
    if (!prompt || busy) return;
    if (editingMessageId && conversation) {
      setBusy(true);
      setNotice(null);
      try {
        const result = await branchAIConversation({
          data: {
            conversation_id: conversation.id,
            message_id: editingMessageId,
            prompt,
            client_request_id: crypto.randomUUID(),
          },
        });
        const nextConversation = await fetchAIConversation({
          data: { conversation_id: result.conversation.id },
        });
        setConversation(nextConversation);
        setProvider(nextConversation.provider === "openai" ? "openai" : "ollama");
        setSource(nextConversation.scope.source || "live");
        setCaptureInterface(nextConversation.scope.interface || "");
        setSessionId(nextConversation.scope.session_id || "");
        setNodeId(nextConversation.scope.node_id || "");
        setRun(result.run);
        await navigate({
          search: (previous) => ({ ...previous, conversation: nextConversation.id }),
          replace: true,
        });
        setPersistedRuns((current) => ({ ...current, [result.run.id]: result.run }));
        setInput("");
        setEditingMessageId(null);
        await hydratePersistedRun(nextConversation.messages, false, result.run.id);
        await refreshList();
      } catch (error) {
        setNotice(error instanceof Error ? error.message : "Unable to branch edited question");
      } finally {
        setBusy(false);
      }
      return;
    }
    await startPrompt(prompt, scopeOverride, modeOverride);
  };

  const editMessage = (messageId: string, content: string) => {
    if (busy) return;
    setEditingMessageId(messageId);
    setInput(content);
    requestAnimationFrame(() => {
      const composer = document.querySelector<HTMLTextAreaElement>("[data-ai-composer]");
      composer?.focus();
      composer?.setSelectionRange(content.length, content.length);
    });
  };

  const investigatePriority = async () => {
    if (busy) return;
    setBusy(true);
    setNotice(null);
    try {
      const result = await fetchEntities({
        data: {
          source: nodeId ? undefined : source.trim() || "live",
          interface: captureInterface || undefined,
          session: sessionId || undefined,
          node: nodeId || undefined,
          limit: 100,
        },
      });
      const selected = selectHighestPriorityEndpoint(result.items);
      if (!selected?.ip) {
        setNotice(
          "No prioritized endpoint is available in the current scope. Choose a capture session or run a capture first.",
        );
        return;
      }
      const target = { ip: selected.ip, priority_score: Number(selected.priority_score) };
      setPriorityTarget(target);
      await startPrompt(
        buildPriorityInvestigationPrompt(target),
        { ...scope, target_ips: [target.ip] },
        "investigate",
        true,
      );
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Unable to select a priority endpoint");
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (!activeRunId || isTerminalAIRunStatus(activeRunStatus || "")) return;
    let closed = false;
    const sync = async () => {
      try {
        const next = await fetchAIRun({ data: { run_id: activeRunId } });
        if (closed) return;
        setRun(next);
        setPersistedRuns((current) => ({ ...current, [next.id]: next }));
        if (isTerminalAIRunStatus(next.status)) {
          await refreshConversation(next.conversation_id, next.id);
        }
      } catch (error) {
        if (!closed)
          setNotice(error instanceof Error ? error.message : "Analyst status unavailable");
      }
    };
    const events = new EventSource(aiRunEventsUrl(activeRunId), { withCredentials: true });
    const detachEvents = attachAIRunStream(events, sync, window);
    void sync();
    return () => {
      closed = true;
      detachEvents();
    };
  }, [activeRunId, activeRunStatus, refreshConversation]);

  const cancelCurrentRun = async () => {
    if (!run || isTerminalAIRunStatus(run.status)) return;
    setBusy(true);
    try {
      const next = await cancelAIRun({ data: { run_id: run.id } });
      setRun(next);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Analyst run could not be cancelled");
    } finally {
      setBusy(false);
    }
  };

  const retryCurrentRun = async () => {
    if (!run || !canRetryCurrentRun || busy) return;
    setBusy(true);
    setNotice(null);
    try {
      const next = await retryAIRun({ data: { run_id: run.id } });
      setRun(next);
      setPersistedRuns((current) => ({ ...current, [next.id]: next }));
      await refreshConversation(next.conversation_id, next.id);
    } catch (error) {
      setNotice(
        error instanceof Error ? error.message : "The interrupted run could not be retried",
      );
    } finally {
      setBusy(false);
    }
  };

  const testCurrentProvider = async () => {
    setBusy(true);
    setNotice(null);
    try {
      const result = await testAIProvider({ data: { provider } });
      await refreshList();
      setNotice(providerProbeSummary(provider, result));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : `${provider} provider test failed`);
    } finally {
      setBusy(false);
    }
  };

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
              /{" "}
              {selectedProvider.agentic_ready === true
                ? "tools ready"
                : selectedProvider.capability_probe === "not_run"
                  ? "test needed"
                  : "chat only"}
            </span>
          )}
        </span>
        <button
          onClick={testCurrentProvider}
          disabled={busy}
          title={`Test ${provider} chat and tool support`}
          className="border border-border px-2 py-1 mono text-[9px] uppercase text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-40"
        >
          Test AI
        </button>
        <button
          onClick={() => refreshList()}
          title="Refresh analyst state"
          className="grid h-7 w-7 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal"
        >
          <RefreshCw className="h-3.5 w-3.5" />
        </button>
      </header>

      {selectedProvider && !selectedProvider.available && (
        <div
          role="status"
          className="flex flex-wrap items-center justify-between gap-2 border-b border-severity-medium/30 bg-severity-medium/5 px-4 py-2.5 text-[12px]"
        >
          <span className="text-foreground">
            {providerProbeSummary(provider, {
              available: selectedProvider.available,
              configured: selectedProvider.configured,
              credential_configured: selectedProvider.credential_configured,
              requires_credential: selectedProvider.requires_credential,
              detail: selectedProvider.detail,
            })}
          </span>
          <Link to="/settings" className="shrink-0 text-signal underline underline-offset-2">
            Provider settings
          </Link>
        </div>
      )}

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
              <div className="ml-auto flex items-center gap-2">
                <span className="mono text-[10px] uppercase text-muted-foreground">
                  {run.status}
                </span>
                {!isTerminalAIRunStatus(run.status) && (
                  <button
                    onClick={cancelCurrentRun}
                    disabled={busy}
                    className="flex items-center gap-1 border border-severity-medium/50 px-2 py-1 mono text-[9px] uppercase text-severity-medium hover:bg-severity-medium/10 disabled:opacity-40"
                    title="Stop this analyst run"
                  >
                    <Ban className="h-3 w-3" /> Stop
                  </button>
                )}
              </div>
            )}
          </div>
          {notice && (
            <div className="m-3 border border-severity-high/40 bg-severity-high/10 px-3 py-2 mono text-[10px] text-severity-high">
              {notice}
            </div>
          )}
          {priorityTarget && (
            <div className="mx-3 mt-3 border border-signal/30 bg-signal/[0.04] px-3 py-2 mono text-[10px] uppercase text-muted-foreground">
              Target selected <span className="text-signal">{priorityTarget.ip}</span>
              <span className="mx-2 text-border">·</span>
              priority{" "}
              <span className="text-foreground">
                {priorityTarget.priority_score.toFixed(1)}/100
              </span>
            </div>
          )}
          <div className="flex-1 space-y-4 overflow-auto px-4 py-5 md:px-6">
            {(conversation?.messages || []).map((message) => {
              const messageRun = message.run_id ? persistedRuns[message.run_id] : undefined;
              const messageSummary = parseInvestigationResult(messageRun?.tool_calls || []);
              return (
                <div key={message.id} className="space-y-3">
                  <MessageRow message={message} onEdit={editMessage} />
                  {messageSummary && message.role === "assistant" && (
                    <InvestigationSummaryCard summary={messageSummary} />
                  )}
                </div>
              );
            })}
            {investigationSummary &&
              !conversation?.messages?.some(
                (message) => message.role === "assistant" && message.run_id === run?.id,
              ) && <InvestigationSummaryCard summary={investigationSummary} />}
            {run && !isTerminalAIRunStatus(run.status) && (
              <div className="flex items-center gap-2 mono text-[10px] uppercase text-muted-foreground">
                <Loader2 className="h-3.5 w-3.5 animate-spin text-signal" /> Analyst processing
              </div>
            )}
            {run?.error && (
              <div
                className={`border p-3 mono text-[11px] ${run.status === "INTERRUPTED" ? "border-severity-medium/40 bg-severity-medium/5 text-foreground" : "border-severity-critical/40 bg-severity-critical/10 text-severity-critical"}`}
              >
                {run.error}
                {canRetryCurrentRun && (
                  <button
                    onClick={retryCurrentRun}
                    disabled={busy}
                    className="mt-3 flex items-center gap-2 border border-signal/50 px-3 py-2 text-signal hover:bg-signal/10 disabled:opacity-40"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                    Retry original question
                  </button>
                )}
                {run.status === "INTERRUPTED" && !canRetryCurrentRun && (
                  <p className="mt-2 text-muted-foreground">
                    WatchTower cannot safely retry this run automatically. Review its activity and
                    submit a new request if appropriate.
                  </p>
                )}
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
              {editingMessageId && (
                <div className="flex items-center justify-between gap-3 border border-signal/30 bg-signal/[0.04] px-3 py-2 text-[11px] text-muted-foreground">
                  <span>
                    Editing a prior question. Sending creates a separate conversation with the
                    original scope; the original stays unchanged.
                  </span>
                  <button
                    onClick={() => {
                      setEditingMessageId(null);
                      setInput("");
                    }}
                    className="shrink-0 text-signal underline underline-offset-2"
                  >
                    Cancel edit
                  </button>
                </div>
              )}
              <div className="flex flex-wrap gap-1.5">
                {SUGGESTIONS.map((suggestion) => (
                  <button
                    key={suggestion}
                    onClick={() =>
                      suggestion === PRIORITY_SUGGESTION ? investigatePriority() : send(suggestion)
                    }
                    disabled={busy}
                    className="border border-border px-2 py-1 mono text-[9px] uppercase text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-40"
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
              <div className="flex">
                <textarea
                  data-ai-composer
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
              <div className="bg-surface px-3 py-2 text-muted-foreground">
                Evidence{" "}
                <span
                  className={
                    run.answer?.completeness === "partial"
                      ? "text-severity-medium"
                      : "text-foreground"
                  }
                >
                  {run.answer?.completeness || "not reported"}
                </span>
              </div>
            </div>
          )}
          {run?.operation && (
            <div className="border-b border-border px-3 py-2.5">
              <div className="section-label">
                Run state <span className="ml-1 text-foreground">{run.operation.state}</span>
              </div>
              {run.operation.next_actions.map((action) => (
                <div
                  key={action}
                  className="mt-1 text-[11px] leading-relaxed text-muted-foreground"
                >
                  Next: {action}
                </div>
              ))}
            </div>
          )}
          {run && (
            <div className="border-b border-border px-3 py-2.5">
              <div className="section-label">
                {run.answer?.effective_scope ? "Effective scope" : "Requested scope"}
              </div>
              <div className="mt-1 break-words text-[11px] leading-relaxed text-muted-foreground">
                {summarizeEffectiveScope(run.answer?.effective_scope || run.scope)}
              </div>
              {run.answer?.requested_scope &&
                JSON.stringify(run.answer.requested_scope) !==
                  JSON.stringify(run.answer.effective_scope) && (
                  <div className="mt-2 break-words text-[10px] leading-relaxed text-muted-foreground">
                    Requested: {summarizeEffectiveScope(run.answer.requested_scope)}
                  </div>
                )}
              {(run.answer?.limitations || []).length > 0 && (
                <ul className="mt-2 space-y-1 text-[11px] leading-relaxed text-severity-medium">
                  {run.answer?.limitations?.slice(0, 3).map((limitation, index) => (
                    <li key={`${index}-${limitation}`}>Limitation: {limitation}</li>
                  ))}
                </ul>
              )}
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

function MessageRow({
  message,
  onEdit,
}: {
  message: NonNullable<AIConversation["messages"]>[number];
  onEdit: (messageId: string, content: string) => void;
}) {
  const isUser = message.role === "user";
  return (
    <div className={`flex gap-3 ${isUser ? "justify-end" : ""}`}>
      {!isUser && (
        <Avatar>
          <Bot className="h-3.5 w-3.5 text-signal" />
        </Avatar>
      )}
      <div className="max-w-[720px]">
        <div
          className={`whitespace-pre-wrap border p-3 text-[13px] leading-relaxed ${isUser ? "border-signal/40 bg-signal/5 text-foreground" : "bg-surface text-foreground"}`}
        >
          {message.content}
        </div>
        {isUser && (
          <button
            onClick={() => onEdit(message.id, message.content)}
            className="mt-1 inline-flex items-center gap-1 px-1 py-1 mono text-[9px] uppercase text-muted-foreground hover:text-signal focus-visible:outline focus-visible:outline-1 focus-visible:outline-signal"
            aria-label="Edit question in a new conversation"
            title="Edit question in a new conversation"
          >
            <Pencil className="h-3 w-3" /> Edit as new conversation
          </button>
        )}
      </div>
      {isUser && (
        <Avatar>
          <User className="h-3.5 w-3.5 text-muted-foreground" />
        </Avatar>
      )}
    </div>
  );
}

function InvestigationSummaryCard({
  summary,
}: {
  summary: NonNullable<ReturnType<typeof parseInvestigationResult>>;
}) {
  const roleConfidence =
    summary.role_confidence === null
      ? "unavailable"
      : `${Math.round(summary.role_confidence * 100)}%`;

  return (
    <section
      aria-label={`Investigation summary for ${summary.ip}`}
      className="border border-signal/30 bg-signal/[0.04] p-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="section-label text-signal">WatchTower investigation</div>
          <h2 className="mt-1 mono text-sm text-foreground">{summary.ip}</h2>
          <div className="mt-1 mono text-[10px] uppercase text-muted-foreground">
            {`${summary.role} · role confidence ${roleConfidence} · investigation confidence ${Math.round(summary.confidence * 100)}%`}
          </div>
        </div>
        <div className="text-right mono text-[10px] uppercase">
          <div className="text-muted-foreground">{summary.verdict}</div>
          <div className="numeral text-xl text-foreground">{summary.risk_score.toFixed(1)}/100</div>
          <div className="text-muted-foreground">investigation risk score</div>
        </div>
      </div>
      <p className="mt-4 text-[13px] leading-relaxed text-foreground">{summary.summary}</p>
      <div className="mt-4 grid grid-cols-2 gap-px border border-border bg-border sm:grid-cols-4">
        <InvestigationMetric label="Flows" value={summary.flow_count} />
        <InvestigationMetric label="Alerts" value={summary.alert_count} />
        <InvestigationMetric label="Files" value={summary.carved_file_count} />
        <InvestigationMetric label="Correlations" value={summary.correlation_count} />
      </div>
      {summary.findings.length > 0 && (
        <div className="mt-4">
          <div className="section-label">Evidence findings</div>
          <ul className="mt-2 space-y-1 text-[12px] text-foreground">
            {summary.findings.slice(0, 4).map((finding) => (
              <li key={finding} className="flex gap-2">
                <span className="text-signal">•</span>
                <span>{finding}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {summary.next_actions.length > 0 && (
        <div className="mt-4">
          <div className="section-label">Next actions</div>
          <ol className="mt-2 space-y-1 text-[12px] text-foreground">
            {summary.next_actions.slice(0, 4).map((action, index) => (
              <li key={action} className="flex gap-2">
                <span className="mono text-[10px] text-signal">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <span>{action}</span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </section>
  );
}

function InvestigationMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-surface px-2.5 py-2">
      <div className="section-label">{label}</div>
      <div className="mt-1 numeral text-sm text-foreground">{value}</div>
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
