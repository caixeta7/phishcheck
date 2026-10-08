import { motion } from "framer-motion";
import { VERDICT_CONFIG, type Verdict } from "../types";

interface Props {
  score: number;
  verdict: Verdict;
}

const ZONES = Object.entries(VERDICT_CONFIG) as [Verdict, (typeof VERDICT_CONFIG)[Verdict]][];

export function RiskGauge({ score, verdict }: Props) {
  const cfg = VERDICT_CONFIG[verdict];
  const pos = Math.min(Math.max(score, 0), 100);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-2">
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.14em] text-[var(--text-muted)]">Veredito</p>
          <motion.p
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className={`font-display text-4xl font-extrabold leading-none tracking-tight sm:text-5xl ${cfg.color}`}
          >
            {cfg.label}
          </motion.p>
        </div>
        <p className="font-mono text-[var(--text-secondary)]">
          <span className="text-3xl font-medium tabular-nums text-[var(--text-primary)]">{score}</span>
          <span className="text-sm"> / 100</span>
        </p>
      </div>

      <div
        role="meter"
        aria-label="Pontuação de risco"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={score}
        aria-valuetext={`${score} de 100, ${cfg.label}`}
      >
        <div className="relative pt-3">
          <motion.div
            className="absolute top-0 -ml-[6px] h-0 w-0 border-x-[6px] border-t-[8px] border-x-transparent"
            style={{ borderTopColor: cfg.ring }}
            initial={{ left: "0%" }}
            animate={{ left: `${pos}%` }}
            transition={{ duration: 0.9, ease: [0.22, 1, 0.36, 1] }}
          />
          <div className="flex h-2.5 gap-[3px]">
            {ZONES.map(([key, z]) => (
              <div
                key={key}
                className="h-full rounded-[2px] transition-opacity"
                style={{
                  width: `${z.to - z.from}%`,
                  background: z.ring,
                  opacity: key === verdict ? 1 : 0.22,
                }}
              />
            ))}
          </div>
        </div>
        <div className="relative mt-1.5 h-4 font-mono text-[10px] text-[var(--text-muted)]">
          {[0, 10, 30, 60, 100].map((t) => (
            <span
              key={t}
              className="absolute -translate-x-1/2 first:translate-x-0 last:-translate-x-full"
              style={{ left: `${t}%` }}
            >
              {t}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
