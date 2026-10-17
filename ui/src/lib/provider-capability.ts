export function toolSupportLabel(supportsTools: boolean | null | undefined): string {
  if (supportsTools === true) return "Yes";
  if (supportsTools === false) return "No";
  return "Not tested";
}

export interface ProviderProbeSummary {
  model?: string;
  available?: boolean;
  model_catalog_available?: boolean;
  selected_model_available?: boolean;
  agentic_ready?: boolean;
  capability?: { chat_ready?: boolean; detail?: string };
  configured?: boolean;
  credential_configured?: boolean;
  requires_credential?: boolean;
  detail?: string;
}

export function providerProbeSummary(provider: string, result: ProviderProbeSummary): string {
  if (result.available === false) {
    const label = provider.toLowerCase() === "ollama" ? "Ollama" : provider;
    const detail = (result.detail || result.capability?.detail || "").trim().replace(/[.]+$/, "");
    if (provider.toLowerCase() === "ollama") {
      if (result.configured === false || detail.toLowerCase() === "disabled") {
        return "Ollama is disabled. Enable it in Settings, then test again.";
      }
      if (/configured model .*not installed|no installed models/i.test(detail)) {
        return `Ollama is unavailable: ${detail}. Choose or install a model in Settings, then test again.`;
      }
      return `Ollama is unavailable${detail ? `: ${detail}` : ""}. Start Ollama, then test again.`;
    }
    if (result.requires_credential && result.credential_configured === false) {
      return `${label} credentials are not configured. Add them in Settings, then test again.`;
    }
    return `${label} is unavailable${detail ? `: ${detail}` : ""}. Check provider settings, then test again.`;
  }

  const model = result.model || "no model selected";
  const catalog =
    (result.model_catalog_available ?? result.available)
      ? "model catalog available"
      : "model catalog unavailable";
  const chat = result.capability?.chat_ready ? "chat ready" : "chat not ready";
  const tools = result.agentic_ready ? "agentic tools ready" : "agentic tools not ready";
  const detail = result.capability?.detail;
  const modelAdvice =
    result.selected_model_available === false
      ? " The selected model is not installed; choose an installed model in Settings and test again."
      : "";
  return `${provider}: ${catalog}; ${model} — ${chat}; ${tools}.${modelAdvice}${detail ? ` ${detail}` : ""}`;
}
