import { createContext, useContext } from "react";
import type { SensorNode } from "@/types/watchtower";

export type ScopeValue = "all" | "local" | string;

export interface SensorScopeState {
  scope: ScopeValue;
  setScope: (scope: ScopeValue) => void;
  nodes: SensorNode[];
  selectedNodeId?: string;
  selectedLabel: string;
  isRemote: boolean;
}

export const SensorScopeContext = createContext<SensorScopeState | null>(null);

export function useSensorScope() {
  const context = useContext(SensorScopeContext);
  if (!context) throw new Error("useSensorScope must be used within SensorScopeProvider");
  return context;
}
