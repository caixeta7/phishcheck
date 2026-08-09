import clsx from "clsx";
import type { Severity } from "../../types";
import { SEVERITY_CONFIG } from "../../types";

interface Props {
  severity: Severity;
  className?: string;
}

export function Badge({ severity, className }: Props) {
  const cfg = SEVERITY_CONFIG[severity];
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium border",
        cfg.bg,
        cfg.color,
        cfg.border,
        className,
      )}
    >
      {cfg.label}
    </span>
  );
}
