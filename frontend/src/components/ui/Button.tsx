import clsx from "clsx";
import type { ButtonHTMLAttributes } from "react";

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "ghost";
  size?: "sm" | "md";
}

export function Button({ variant = "primary", size = "md", className, ...props }: Props) {
  return (
    <button
      className={clsx(
        "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-all",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/50",
        "disabled:opacity-50 disabled:cursor-not-allowed",
        "active:scale-[0.98]",
        {
          sm: "px-3 py-1.5 text-sm",
          md: "px-4 py-2.5 text-sm",
        }[size],
        {
          primary: "bg-blue-600 text-white hover:bg-blue-700 shadow-sm",
          secondary:
            "bg-[var(--bg-elevated)] text-[var(--text-primary)] border border-[var(--border-default)] hover:bg-[var(--bg-card)]",
          ghost: "text-[var(--text-secondary)] hover:bg-[var(--bg-elevated)] hover:text-[var(--text-primary)]",
        }[variant],
        className,
      )}
      {...props}
    />
  );
}
