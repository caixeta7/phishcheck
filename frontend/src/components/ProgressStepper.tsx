import { motion, AnimatePresence } from "framer-motion";
import { CheckCircle, XCircle, Loader2, Circle } from "lucide-react";
import clsx from "clsx";
import { ANALYSIS_STEPS, type StepStatus } from "../types";

interface Props {
  steps: Map<string, { step: string; status: StepStatus; message: string | null }>;
}

const STEP_ICONS = {
  running: Loader2,
  done: CheckCircle,
  error: XCircle,
  pending: Circle,
} as const;

export function ProgressStepper({ steps }: Props) {
  const stepsArray = ANALYSIS_STEPS.map((s) => ({ ...s, state: steps.get(s.key)?.status ?? "pending", message: steps.get(s.key)?.message }));

  return (
    <div className="space-y-1">
      <AnimatePresence>
        {stepsArray.map((step, idx) => {
          const Icon = STEP_ICONS[step.state] || Circle;
          const isActive = step.state === "running";
          const isDone = step.state === "done";
          const isError = step.state === "error";

          if (step.state === "pending") return null;

          return (
            <motion.div
              key={step.key}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: idx * 0.05 }}
              className={clsx("flex items-start gap-3 rounded-lg p-2.5 text-sm", isActive && "bg-blue-500/5")}
            >
              <Icon
                className={clsx(
                  "mt-0.5 h-4 w-4 shrink-0",
                  isActive && "text-blue-500 animate-spin",
                  isDone && "text-emerald-500",
                  isError && "text-red-500",
                )}
              />
              <div className="space-y-0.5">
                <p
                  className={clsx(
                    "font-medium",
                    isDone ? "text-[var(--text-primary)]" : "text-[var(--text-secondary)]",
                    isError && "text-red-500",
                  )}
                >
                  {step.label}
                </p>
                {step.message && (
                  <p className={clsx("text-xs", isActive ? "text-[var(--text-muted)]" : "text-[var(--text-muted)]")}>
                    {step.message}
                  </p>
                )}
              </div>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
