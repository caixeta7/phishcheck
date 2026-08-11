import { motion } from "framer-motion";
import { VERDICT_CONFIG, type Verdict } from "../types";

interface Props {
  score: number;
  verdict: Verdict;
}

export function RiskGauge({ score, verdict }: Props) {
  const cfg = VERDICT_CONFIG[verdict];
  const radius = 80;
  const cx = 100;
  const cy = 90;
  const startX = cx - radius;
  const endX = cx + radius;
  const circumference = Math.PI * radius;
  const arc = (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative h-40 w-72">
        <svg viewBox="0 0 200 100" className="h-full w-full">
          <path
            d={`M ${startX} ${cy} A ${radius} ${radius} 0 0 1 ${endX} ${cy}`}
            fill="none"
            stroke="var(--border-default)"
            strokeWidth="12"
            strokeLinecap="round"
          />
          {score > 0 && (
            <motion.path
              d={`M ${startX} ${cy} A ${radius} ${radius} 0 0 1 ${endX} ${cy}`}
              fill="none"
              stroke={cfg.ring}
              strokeWidth="12"
              strokeLinecap="round"
              strokeDasharray={`${arc} ${circumference}`}
              initial={{ strokeDasharray: `0 ${circumference}` }}
              animate={{ strokeDasharray: `${arc} ${circumference}` }}
              transition={{ duration: 0.8, ease: "easeOut" }}
            />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-end gap-1 pb-3">
          <motion.span
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.3 }}
            className="text-4xl font-bold tabular-nums"
            style={{ color: cfg.ring }}
          >
            {score}
          </motion.span>
          <span className="text-xs text-[var(--text-muted)]">/ 100</span>
        </div>
      </div>
      <div className="text-center">
        <span className="text-sm text-[var(--text-muted)]">Veredito</span>
        <p className={`text-lg font-semibold ${cfg.color}`}>{cfg.label}</p>
      </div>
    </div>
  );
}
