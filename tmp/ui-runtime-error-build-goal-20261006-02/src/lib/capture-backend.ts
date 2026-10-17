export type BackendDevice = {
  source_type: string;
  backends: string[];
  capturing: boolean;
  engine?: { backend?: unknown } | null;
};

export function selectCaptureBackend(device: BackendDevice): string | null {
  const activeBackend = device.capturing ? String(device.engine?.backend || "").toLowerCase() : "";
  if (activeBackend) return activeBackend;

  const supported = device.backends.map((backend) => backend.toLowerCase());
  if (device.source_type.toLowerCase() === "bluetooth") {
    return supported.includes("python") ? "python" : null;
  }
  if (supported.includes("rust")) return "rust";
  if (supported.includes("python")) return "python";
  return supported[0] || null;
}

export function captureStartBackend(
  device: BackendDevice,
  selectedBackend?: string | null,
): string | null | undefined {
  if (!selectCaptureBackend(device)) return null;
  if (!selectedBackend) return undefined;
  const selected = selectedBackend.toLowerCase();
  return device.backends.some((backend) => backend.toLowerCase() === selected) ? selected : null;
}
