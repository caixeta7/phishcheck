import clsx from "clsx";
import type { HTMLAttributes } from "react";

interface Props extends HTMLAttributes<HTMLDivElement> {
  hoverable?: boolean;
}

export function Card({ hoverable, className, ...props }: Props) {
  return (
    <div
      className={clsx(
        "rounded-xl border bg-[var(--bg-card)] border-[var(--border-default)]",
        "shadow-[var(--shadow-card)]",
        hoverable && "transition-shadow hover:shadow-[var(--shadow-elevated)]",
        className,
      )}
      {...props}
    />
  );
}
