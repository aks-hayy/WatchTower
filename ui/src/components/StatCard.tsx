import type { ReactNode } from "react";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: ReactNode;
  accentClass?: string;
}

export function StatCard({ title, value, subtitle, icon }: StatCardProps) {
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between">
        <span className="section-label">{title}</span>
        {icon && <span className="text-muted-foreground">{icon}</span>}
      </div>
      <div className="mt-2 numeral text-3xl text-foreground">
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
      {subtitle && (
        <div className="mt-1 mono text-[10px] uppercase tracking-wider text-muted-foreground">
          {subtitle}
        </div>
      )}
    </div>
  );
}
