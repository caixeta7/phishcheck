import clsx from "clsx";
import type { HTMLAttributes, ReactNode } from "react";

interface Props extends HTMLAttributes<HTMLDivElement> {
  hoverable?: boolean;
}

export function Card({ hoverable, className, ...props }: Props) {
  return (
    <div
      className={clsx(
        "min-w-0 rounded-xl border bg-[var(--bg-card)] border-[var(--border-default)]",
        "shadow-[var(--shadow-card)]",
        hoverable && "transition-shadow hover:shadow-[var(--shadow-elevated)]",
        className,
      )}
      {...props}
    />
  );
}

export function CardTitle({ children, count }: { children: ReactNode; count?: number }) {
  return (
    <h3 className="mb-4 flex items-baseline gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-[var(--text-secondary)]">
      {children}
      {count !== undefined && <span className="font-mono font-normal text-[var(--text-muted)]">{count}</span>}
    </h3>
  );
}
