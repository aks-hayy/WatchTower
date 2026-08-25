interface SeverityBadgeProps {
  severity: string;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const cls =
    {
      CRITICAL: "chip-critical",
      HIGH: "chip-high",
      MEDIUM: "chip-medium",
      LOW: "chip-low",
    }[severity] || "chip-low";

  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 mono text-[10px] tracking-wider ${cls}`}
    >
      {severity}
    </span>
  );
}
