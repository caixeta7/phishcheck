import { AnimatePresence, motion } from "framer-motion";
import { X, AlertCircle, CheckCircle, Info } from "lucide-react";
import clsx from "clsx";
import type { ToastItem } from "../../hooks/useToast";

interface Props {
  toasts: ToastItem[];
  onDismiss: (id: number) => void;
}

const TOAST_CONFIG = {
  error: { icon: AlertCircle, color: "text-red-500", border: "border-red-500/30" },
  success: { icon: CheckCircle, color: "text-emerald-500", border: "border-emerald-500/30" },
  info: { icon: Info, color: "text-blue-500", border: "border-blue-500/30" },
} as const;

export function ToastContainer({ toasts, onDismiss }: Props) {
  return (
    <div className="fixed bottom-4 right-4 z-[200] space-y-2">
      <AnimatePresence>
        {toasts.map((t) => {
          const cfg = TOAST_CONFIG[t.type];
          const Icon = cfg.icon;
          return (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, y: 20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 20, scale: 0.95 }}
              className={clsx(
                "flex items-center gap-3 rounded-lg border bg-[var(--bg-card)] px-4 py-3 shadow-lg",
                "min-w-[300px] max-w-md",
                cfg.border,
              )}
            >
              <Icon className={clsx("h-5 w-5 shrink-0", cfg.color)} />
              <p className="flex-1 text-sm text-[var(--text-primary)]">{t.message}</p>
              <button
                onClick={() => onDismiss(t.id)}
                className="text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                <X className="h-4 w-4" />
              </button>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
