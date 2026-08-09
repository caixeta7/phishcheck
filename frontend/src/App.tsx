import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ShieldX, AlertTriangle } from "lucide-react";

import { useDarkMode } from "./hooks/useDarkMode";
import { useAnalysis } from "./hooks/useAnalysis";
import { useToast } from "./hooks/useToast";
import { Header } from "./components/Header";
import { InputPanel } from "./components/InputPanel";
import { ProgressStepper } from "./components/ProgressStepper";
import { RiskGauge } from "./components/RiskGauge";
import { SenderCard } from "./components/SenderCard";
import { FindingsTimeline } from "./components/FindingsTimeline";
import { TrustedModal } from "./components/TrustedModal";
import { ResultSkeleton } from "./components/ResultSkeleton";
import { ToastContainer } from "./components/ui/Toast";
import { Card } from "./components/ui/Card";
import type { AnalysisType } from "./types";

export function App() {
  const { isDark, toggle } = useDarkMode();
  const { status, steps, report, error, run, reset } = useAnalysis();
  const { toasts, show, dismiss } = useToast();
  const [trustedOpen, setTrustedOpen] = useState(false);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", isDark);
  }, [isDark]);

  useEffect(() => {
    if (status === "error" && error) {
      show(error, "error");
    }
  }, [status, error, show]);

  const handleAnalyze = (type: AnalysisType, content: string, file: File | null, online: boolean) => {
    reset();
    run(type, content, file, online);
  };

  return (
    <div className="min-h-screen bg-[var(--bg-primary)]">
      <Header isDark={isDark} onToggleTheme={toggle} onOpenTrusted={() => setTrustedOpen(true)} />

      <div className="mx-auto max-w-7xl px-6 py-8">
        <div className="mb-6">
          <h1 className="text-2xl font-bold tracking-tight">Análise de E-mails e Links</h1>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            Valide remetentes, links e domínios contra phishing, spam e fraudes.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="lg:col-span-5 lg:sticky lg:top-24 lg:self-start">
            <Card className="p-5">
              <InputPanel onAnalyze={handleAnalyze} disabled={status === "analyzing"} />
            </Card>

            {status === "analyzing" && (
              <Card className="mt-4 p-4">
                <ProgressStepper steps={steps} />
              </Card>
            )}
          </div>

          <div className="lg:col-span-7 space-y-4">
            <AnimatePresence mode="wait">
              {status === "idle" && (
                <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                  <EmptyState />
                </motion.div>
              )}

              {status === "analyzing" && (
                <motion.div key="skeleton" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                  <ResultSkeleton />
                </motion.div>
              )}

              {status === "error" && (
                <motion.div key="error" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                  <Card className="flex flex-col items-center gap-3 p-12 text-center">
                    <ShieldX className="h-12 w-12 text-red-500" />
                    <h2 className="text-lg font-semibold">Erro na análise</h2>
                    <p className="max-w-sm text-sm text-[var(--text-muted)]">{error}</p>
                  </Card>
                </motion.div>
              )}

              {status === "done" && report && (
                <motion.div
                  key="results"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className="space-y-4"
                >
                  <Card className="flex items-center gap-8 p-6">
                    <RiskGauge score={report.score} verdict={report.verdict} />
                    <div className="flex-1 space-y-3">
                      <div>
                        <span className="text-xs text-[var(--text-muted)]">Sujeito</span>
                        <p className="text-sm font-medium">{report.subject}</p>
                      </div>
                      {report.domains_checked.length > 0 && (
                        <div>
                          <span className="text-xs text-[var(--text-muted)]">Domínios verificados</span>
                          <p className="text-sm font-mono">{report.domains_checked.join(", ")}</p>
                        </div>
                      )}
                      {report.urls_found.length > 0 && (
                        <div>
                          <span className="text-xs text-[var(--text-muted)]">URLs encontradas</span>
                          <p className="text-sm font-mono truncate">{report.urls_found.length} URL(s)</p>
                        </div>
                      )}
                    </div>
                  </Card>

                  <SenderCard report={report} />

                  <FindingsTimeline findings={report.findings} />
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      <TrustedModal open={trustedOpen} onClose={() => setTrustedOpen(false)} />
      <ToastContainer toasts={toasts} onDismiss={dismiss} />
    </div>
  );
}

function EmptyState() {
  return (
    <Card className="flex flex-col items-center gap-4 p-16 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-[var(--bg-elevated)]">
        <AlertTriangle className="h-8 w-8 text-[var(--text-muted)]" />
      </div>
      <div>
        <h2 className="text-lg font-semibold text-[var(--text-secondary)]">Aguardando análise</h2>
        <p className="mt-1 max-w-sm text-sm text-[var(--text-muted)]">
          Cole um e-mail, faça upload de um arquivo .eml/.msg, ou informe uma URL/domínio para iniciar.
        </p>
      </div>
    </Card>
  );
}
