import { useMemo, useState } from "react";
import { ChevronDown } from "lucide-react";
import clsx from "clsx";
import { Card } from "./ui/Card";
import { Badge } from "./ui/Badge";
import { SEVERITY_CONFIG, type Finding, type Severity } from "../types";

interface Props {
  findings: Finding[];
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function FindingsTimeline({ findings }: Props) {
  const grouped = useMemo(() => {
    const map = new Map<Severity, Finding[]>();
    for (const s of SEVERITY_ORDER) map.set(s, []);
    for (const f of findings) {
      map.get(f.severity)?.push(f);
    }
    return map;
  }, [findings]);

  return (
    <Card className="p-5">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--text-muted)]">
          Achados ({findings.length})
        </h3>
      </div>

      {findings.length === 0 ? (
        <div className="flex items-center justify-center py-8 text-sm text-[var(--text-muted)]">
          Nenhum sinal detectado.
        </div>
      ) : (
        <div className="space-y-6">
          {SEVERITY_ORDER.map((sev) => {
            const items = grouped.get(sev) || [];
            if (!items.length) return null;
            return (
              <div key={sev} className="space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-base">{SEVERITY_CONFIG[sev].icon}</span>
                  <span className="text-xs font-medium uppercase text-[var(--text-muted)]">
                    {SEVERITY_CONFIG[sev].label} ({items.length})
                  </span>
                </div>
                <div className="ml-6 space-y-1.5 border-l border-[var(--border-default)] pl-4">
                  {items.map((f, i) => (
                    <FindingItem key={`${sev}-${i}`} finding={f} />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}

function FindingItem({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      onClick={() => setExpanded(!expanded)}
      className="cursor-pointer rounded-lg p-2.5 transition-colors hover:bg-[var(--bg-elevated)]"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <Badge severity={finding.severity} />
          <span className="text-xs text-[var(--text-muted)] shrink-0">{finding.category}</span>
          <span className="text-sm text-[var(--text-primary)] truncate">
            {finding.description}
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {finding.weight > 0 && (
            <span className="text-xs font-mono text-[var(--text-muted)]">
              +{finding.weight}
            </span>
          )}
          <ChevronDown
            className={clsx(
              "h-3.5 w-3.5 text-[var(--text-muted)] transition-transform",
              expanded && "rotate-180",
            )}
          />
        </div>
      </div>
    </div>
  );
}
