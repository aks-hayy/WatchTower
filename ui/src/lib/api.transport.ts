import type { PcapResult } from "@/types/watchtower";

declare global {
  interface Window {
    __WATCHTOWER_API_URL__?: string;
  }
}

function apiBase() {
  const runtimeUrl = typeof window !== "undefined" ? window.__WATCHTOWER_API_URL__ : undefined;
  return (runtimeUrl || import.meta.env.VITE_WATCHTOWER_API_URL || "/api/v1").replace(/\/$/, "");
}

async function apiResponse<T>(response: Response): Promise<T> {
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const requestId = response.headers.get("X-Request-ID");
    const message = payload?.error?.message || `WatchTower API returned HTTP ${response.status}`;
    throw new Error(requestId ? `${message} (request ${requestId})` : message);
  }
  return payload as T;
}

export async function submitPcap(file: File, mode: string, backend: string) {
  const body = new FormData();
  body.append("file", file);
  body.append("mode", mode);
  body.append("backend", backend);
  return apiResponse<{ id: string; status: string }>(
    await fetch(`${apiBase()}/pcap/jobs`, {
      method: "POST",
      body,
      credentials: "same-origin",
    }),
  );
}

export async function getPcapJob(id: string): Promise<PcapResult> {
  return apiResponse<PcapResult>(
    await fetch(`${apiBase()}/pcap/jobs/${encodeURIComponent(id)}`, {
      credentials: "same-origin",
    }),
  );
}

export async function cancelPcapJob(id: string) {
  return apiResponse<{ id: string; status: string }>(
    await fetch(`${apiBase()}/pcap/jobs/${encodeURIComponent(id)}/cancel`, {
      method: "POST",
      credentials: "same-origin",
    }),
  );
}
