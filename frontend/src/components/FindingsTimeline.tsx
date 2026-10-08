import { useMemo, useState } from "react";
import { ChevronDown } from "lucide-react";
import clsx from "clsx";
import { Card, CardTitle } from "./ui/Card";
import { SEVERITY_CONFIG, SEVERITY_ORDER, type Finding, type Severity } from "../types";

interface Props {
  findings: Finding[];
}

export function FindingsTimeline({ findings }: Props) {
  const grouped = useMemo(() => {
    const map = new Map<Severity, Finding[]>();
    for (const s of SEVERITY_ORDER) map.set(s, []);
    for (const f of findings) map.get(f.severity)?.push(f);
    return map;
  }, [findings]);

  return (
    <Card className="p-5 sm:p-6">
      <CardTitle count={findings.length}>Achados</CardTitle>

      {findings.length === 0 ? (
        <p className="py-8 text-center text-sm text-[var(--text-muted)]">Nenhum sinal de risco encontrado.</p>
      ) : (
        <div className="space-y-6">
          {SEVERITY_ORDER.map((sev) => {
            const items = grouped.get(sev) || [];
            if (!items.length) return null;
            const cfg = SEVERITY_CONFIG[sev];
            return (
              <section key={sev}>
                <h4 className={clsx("mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em]", cfg.color)}>
                  <span className={clsx("h-2 w-2 rounded-full", cfg.dot)} />
                  {cfg.label}
                  <span className="font-mono font-normal text-[var(--text-muted)]">{items.length}</span>
                </h4>
                <ul className="divide-y divide-[var(--border-default)] overflow-hidden rounded-lg border border-[var(--border-default)]">
                  {items.map((f, i) => (
                    <FindingItem key={`${sev}-${i}`} finding={f} />
                  ))}
                </ul>
              </section>
            );
          })}
        </div>
      )}
    </Card>
  );
}

function FindingItem({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);
  const cfg = SEVERITY_CONFIG[finding.severity];

  return (
    <li className="relative">
      <span className={clsx("absolute inset-y-0 left-0 w-[3px]", cfg.dot)} aria-hidden />
      <button
        type="button"
        aria-expanded={expanded}
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-start gap-3 py-3 pl-4 pr-3 text-left transition-colors hover:bg-[var(--bg-elevated)] focus-visible:bg-[var(--bg-elevated)] focus-visible:outline-none"
      >
        <div className="min-w-0 flex-1">
          <p className="text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">{finding.category}</p>
          <p className="mt-0.5 text-sm leading-snug text-[var(--text-primary)] wrap-anywhere">{finding.description}</p>
        </div>
        {finding.weight > 0 && (
          <span className="mt-0.5 shrink-0 rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 font-mono text-xs text-[var(--text-secondary)]">
            +{finding.weight}
          </span>
        )}
        <ChevronDown
          className={clsx("mt-1 h-4 w-4 shrink-0 text-[var(--text-muted)] transition-transform", expanded && "rotate-180")}
        />
      </button>
      {expanded && (
        <dl className="flex flex-wrap gap-x-5 gap-y-1 border-t border-dashed border-[var(--border-default)] bg-[var(--bg-elevated)] py-2.5 pl-4 pr-3 text-xs">
          <div className="flex gap-1.5">
            <dt className="text-[var(--text-muted)]">Severidade</dt>
            <dd className={cfg.color}>{cfg.label}</dd>
          </div>
          <div className="flex gap-1.5">
            <dt className="text-[var(--text-muted)]">Peso</dt>
            <dd className="font-mono">+{finding.weight} pts</dd>
          </div>
          <div className="flex gap-1.5">
            <dt className="text-[var(--text-muted)]">Categoria</dt>
            <dd>{finding.category}</dd>
          </div>
        </dl>
      )}
    </li>
  );
}
