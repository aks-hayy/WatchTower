import { apiV2Base } from "@/lib/api-url";
import type { PcapResult } from "@/types/watchtower";

export type PcapProjection =
  | "flows"
  | "entities"
  | "findings"
  | "alerts"
  | "artifacts"
  | "streams"
  | "evidence";

export interface PcapPage<T = Record<string, unknown>> {
  items: T[];
  next_cursor: number | null;
  cursor: number;
  limit: number;
}

export interface PcapTopologyData {
  nodes: Array<{ data: Record<string, unknown> & { id: string; label: string } }>;
  edges: Array<{
    data: Record<string, unknown> & {
      id: string;
      source: string;
      target: string;
      protocol?: string;
      first_seen?: number;
      last_seen?: number;
    };
  }>;
  next_cursor: number | null;
  mode?: "analyst" | "conversations";
  analyst_total_conversations?: number;
  analyst_omitted_conversations?: number;
}

export interface PcapTimelineData extends PcapPage {
  start_time: number | null;
  end_time: number | null;
}

async function responseJson<T>(response: Response): Promise<T> {
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = payload?.error?.message || payload?.detail || `HTTP ${response.status}`;
    const requestId = response.headers.get("X-Request-ID");
    throw new Error(requestId ? `${detail} (request ${requestId})` : detail);
  }
  return payload as T;
}

export async function submitPcapAnalysis(
  file: File,
  mode: string,
  backend: string,
  keylog?: File | null,
) {
  const body = new FormData();
  body.append("file", file);
  body.append("mode", mode);
  body.append("backend", backend);
  if (keylog) body.append("keylog", keylog);
  return responseJson<PcapResult>(
    await fetch(`${apiV2Base()}/pcap/analyses`, {
      method: "POST",
      body,
      credentials: "same-origin",
    }),
  );
}

export async function listPcapAnalyses() {
  return responseJson<{ items: PcapResult[] }>(
    await fetch(`${apiV2Base()}/pcap/analyses?limit=100`, { credentials: "same-origin" }),
  );
}

export async function getPcapAnalysis(id: string) {
  return responseJson<PcapResult>(
    await fetch(`${apiV2Base()}/pcap/analyses/${encodeURIComponent(id)}`, {
      credentials: "same-origin",
    }),
  );
}

export async function listPcapCaseFlags(caseId: string) {
  return responseJson<{ items: Record<string, unknown>[] }>(
    await fetch(`${apiV2Base()}/pcap/cases/${encodeURIComponent(caseId)}/flags?limit=250`, {
      credentials: "same-origin",
    }),
  );
}

export async function createPcapCaseFlag(caseId: string, payload: Record<string, unknown>) {
  return responseJson<Record<string, unknown>>(
    await fetch(`${apiV2Base()}/pcap/cases/${encodeURIComponent(caseId)}/flags`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload),
    }),
  );
}

export async function cancelPcapAnalysis(id: string) {
  return responseJson<{ id: string; status: string }>(
    await fetch(`${apiV2Base()}/pcap/analyses/${encodeURIComponent(id)}/cancel`, {
      method: "POST",
      credentials: "same-origin",
    }),
  );
}

export async function getPcapProjection<T = Record<string, unknown>>(
  id: string,
  projection: PcapProjection,
  cursor = 0,
  limit = 100,
) {
  const query = new URLSearchParams({ cursor: String(cursor), limit: String(limit) });
  return responseJson<PcapPage<T>>(
    await fetch(`${apiV2Base()}/pcap/analyses/${encodeURIComponent(id)}/${projection}?${query}`, {
      credentials: "same-origin",
    }),
  );
}

export async function getPcapTopology(id: string) {
  return responseJson<PcapTopologyData>(
    await fetch(
      `${apiV2Base()}/pcap/analyses/${encodeURIComponent(id)}/topology?limit=250&mode=analyst`,
      {
        credentials: "same-origin",
      },
    ),
  );
}

export async function getPcapTimeline(id: string) {
  return responseJson<PcapTimelineData>(
    await fetch(`${apiV2Base()}/pcap/analyses/${encodeURIComponent(id)}/timeline?limit=5000`, {
      credentials: "same-origin",
    }),
  );
}

export function pcapEventsUrl(id: string) {
  return `${apiV2Base()}/pcap/analyses/${encodeURIComponent(id)}/events`;
}
