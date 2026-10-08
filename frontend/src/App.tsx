import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ShieldX, ScanSearch } from "lucide-react";

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
import { Card, CardTitle } from "./components/ui/Card";
import { SEVERITY_CONFIG, SEVERITY_ORDER, type AnalysisType } from "./types";

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

      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:py-10">
        <div className="mb-8 max-w-2xl">
          <h1 className="font-display text-3xl font-bold tracking-tight sm:text-4xl">
            Esse e-mail é quem diz ser?
          </h1>
          <p className="mt-2 text-[15px] text-[var(--text-secondary)]">
            Confira remetente, autenticação, links e domínios antes de clicar em qualquer coisa.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="min-w-0 lg:col-span-5 lg:sticky lg:top-20 lg:self-start">
            <Card className="p-4 sm:p-5">
              <InputPanel onAnalyze={handleAnalyze} disabled={status === "analyzing"} />
            </Card>

            {status === "analyzing" && (
              <Card className="mt-4 p-4">
                <ProgressStepper steps={steps} />
              </Card>
            )}
          </div>

          <div className="min-w-0 space-y-4 lg:col-span-7">
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
                  <Card className="flex flex-col items-center gap-3 p-10 text-center sm:p-12">
                    <ShieldX className="h-10 w-10 text-red-500" />
                    <h2 className="font-display text-xl font-semibold">A análise não foi concluída</h2>
                    <p className="max-w-sm text-sm text-[var(--text-secondary)] wrap-anywhere">{error}</p>
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
                  <Card className="p-5 sm:p-6">
                    <RiskGauge score={report.score} verdict={report.verdict} />

                    <dl className="mt-6 grid gap-4 border-t border-[var(--border-default)] pt-5 text-sm sm:grid-cols-2">
                      <div className="min-w-0">
                        <dt className="text-xs text-[var(--text-muted)]">Item analisado</dt>
                        <dd className="mt-0.5 font-mono text-[13px] wrap-anywhere">{report.subject}</dd>
                      </div>
                      {report.subject_line && (
                        <div className="min-w-0">
                          <dt className="text-xs text-[var(--text-muted)]">Assunto</dt>
                          <dd className="mt-0.5 wrap-anywhere">{report.subject_line}</dd>
                        </div>
                      )}
                    </dl>

                    {report.findings.length > 0 && (
                      <div className="mt-5 flex flex-wrap gap-2">
                        {SEVERITY_ORDER.map((sev) => {
                          const n = report.findings.filter((f) => f.severity === sev).length;
                          if (!n) return null;
                          const cfg = SEVERITY_CONFIG[sev];
                          return (
                            <span
                              key={sev}
                              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${cfg.bg} ${cfg.border} ${cfg.color}`}
                            >
                              <span className="font-mono">{n}</span> {cfg.label}
                            </span>
                          );
                        })}
                      </div>
                    )}
                  </Card>

                  <SenderCard report={report} />

                  {report.urls_found.length > 0 && (
                    <Card className="p-5 sm:p-6">
                      <CardTitle count={report.urls_found.length}>Links encontrados</CardTitle>
                      <ol className="max-h-72 divide-y divide-[var(--border-default)] overflow-y-auto rounded-lg border border-[var(--border-default)]">
                        {report.urls_found.map((url, i) => (
                          <li key={i} className="flex gap-3 px-3 py-2 font-mono text-xs">
                            <span className="w-5 shrink-0 text-right text-[var(--text-muted)]">{i + 1}</span>
                            <UrlText url={url} />
                          </li>
                        ))}
                      </ol>
                    </Card>
                  )}

                  {report.domains_checked.length > 0 && (
                    <Card className="p-5 sm:p-6">
                      <CardTitle count={report.domains_checked.length}>Domínios verificados</CardTitle>
                      <div className="flex flex-wrap gap-2">
                        {report.domains_checked.map((d, i) => (
                          <span
                            key={i}
                            className="max-w-full rounded-md border border-[var(--border-default)] bg-[var(--bg-elevated)] px-2 py-1 font-mono text-xs wrap-anywhere"
                          >
                            {d}
                          </span>
                        ))}
                      </div>
                    </Card>
                  )}

                  <FindingsTimeline findings={report.findings} />
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </main>

      <TrustedModal open={trustedOpen} onClose={() => setTrustedOpen(false)} />
      <ToastContainer toasts={toasts} onDismiss={dismiss} />
    </div>
  );
}

function EmptyState() {
  return (
    <Card className="flex flex-col items-center gap-4 border-dashed bg-transparent p-10 text-center shadow-none sm:p-16">
      <ScanSearch className="h-10 w-10 text-[var(--text-muted)]" strokeWidth={1.5} />
      <div>
        <h2 className="font-display text-xl font-semibold">O resultado aparece aqui</h2>
        <p className="mt-1 max-w-sm text-sm text-[var(--text-secondary)]">
          Cole o e-mail com cabeçalhos, envie um arquivo .eml/.msg ou informe uma URL ou domínio.
        </p>
      </div>
    </Card>
  );
}

// Destaca o host: é onde mora o domínio falso (paypa1.com, login.banco.com.evil.io).
function UrlText({ url }: { url: string }) {
  const m = url.match(/^([a-z][\w+.-]*:\/\/)?([^/?#\s]+)(.*)$/i);
  if (!m) return <span className="min-w-0 wrap-anywhere">{url}</span>;
  return (
    <span className="min-w-0 wrap-anywhere text-[var(--text-muted)]">
      {m[1]}
      <span className="font-medium text-[var(--text-primary)]">{m[2]}</span>
      {m[3]}
    </span>
  );
}
