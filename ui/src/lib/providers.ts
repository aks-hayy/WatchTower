import { apiV2Base } from "@/lib/api-url";
import type { AIProviderStatus } from "@/types/watchtower";

export interface ProviderModel {
  id: string;
  label: string;
  supports_tools: boolean;
  provider: string;
  local: boolean;
}

class ProviderRequestError extends Error {
  code: string;
  status: number;

  constructor(message: string, code: string, status: number) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

async function providerRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiV2Base()}/ai${path}`, {
    ...init,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new ProviderRequestError(
      payload?.error?.message || `Provider request failed (${response.status})`,
      payload?.error?.code || "provider_request_failed",
      response.status,
    );
  }
  return payload as T;
}

export function fetchProviders() {
  return providerRequest<{ providers: AIProviderStatus[] }>("/providers");
}

export function connectProvider(
  provider: string,
  values: { secret?: string; model?: string; base_url?: string },
) {
  return providerRequest<{
    provider: string;
    status: string;
    model: string;
    models: ProviderModel[];
  }>(`/providers/${encodeURIComponent(provider)}/connect`, {
    method: "POST",
    body: JSON.stringify(values),
  });
}

export function testProvider(provider: string) {
  return providerRequest<{ provider: string; available: boolean; models: ProviderModel[] }>(
    `/providers/${encodeURIComponent(provider)}/test`,
    { method: "POST", body: "{}" },
  );
}

export function disconnectProvider(provider: string) {
  return providerRequest<Record<string, unknown>>(`/providers/${encodeURIComponent(provider)}`, {
    method: "DELETE",
  });
}

export function fetchProviderModels(provider: string, refresh = false) {
  const suffix = refresh ? "?refresh=true" : "";
  return providerRequest<{ provider: string; models: ProviderModel[] }>(
    `/providers/${encodeURIComponent(provider)}/models${suffix}`,
  );
}

export function setProviderModel(provider: string, model: string) {
  return providerRequest<Record<string, unknown>>(
    `/providers/${encodeURIComponent(provider)}/model`,
    { method: "POST", body: JSON.stringify({ model }) },
  );
}

export { ProviderRequestError };
