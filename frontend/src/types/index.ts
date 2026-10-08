export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Verdict = "LEGITIMO" | "BAIXO_RISCO" | "SUSPEITO" | "ALTO_RISCO";
export type AnalysisType = "email_text" | "email_file" | "url" | "domain";
export type StepStatus = "pending" | "running" | "done" | "error";

export interface Finding {
  category: string;
  description: string;
  weight: number;
  severity: Severity;
}

export interface AnalysisReport {
  subject: string;
  score: number;
  verdict: Verdict;
  sender_domain: string | null;
  sender_email: string | null;
  from_name: string | null;
  reply_to: string | null;
  return_path: string | null;
  subject_line: string | null;
  domains_checked: string[];
  urls_found: string[];
  findings: Finding[];
}

export interface ProgressStep {
  step: string;
  status: StepStatus;
  message: string | null;
  findings?: Finding[];
}

export interface TrustedDomainList {
  domains: string[];
}

export const SEVERITY_CONFIG: Record<Severity, { label: string; color: string; bg: string; border: string; dot: string }> = {
  critical: { label: "Crítico", color: "text-red-600 dark:text-red-400",       bg: "bg-red-500/10",    border: "border-red-500/30",    dot: "bg-red-500" },
  high:     { label: "Alto",    color: "text-orange-600 dark:text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", dot: "bg-orange-500" },
  medium:   { label: "Médio",   color: "text-amber-700 dark:text-amber-400",   bg: "bg-amber-500/10",  border: "border-amber-500/30",  dot: "bg-amber-500" },
  low:      { label: "Baixo",   color: "text-sky-700 dark:text-sky-400",       bg: "bg-sky-500/10",    border: "border-sky-500/30",    dot: "bg-sky-500" },
  info:     { label: "Info",    color: "text-slate-500 dark:text-slate-400",   bg: "bg-slate-500/10",  border: "border-slate-500/30",  dot: "bg-slate-400" },
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

// Faixas espelham report_builder.verdict (10 / 30 / 60).
export const VERDICT_CONFIG: Record<Verdict, { label: string; color: string; ring: string; from: number; to: number }> = {
  LEGITIMO:    { label: "Legítimo",    color: "text-emerald-600 dark:text-emerald-400", ring: "#10b981", from: 0,  to: 10 },
  BAIXO_RISCO: { label: "Baixo risco", color: "text-amber-700 dark:text-amber-400",     ring: "#eab308", from: 10, to: 30 },
  SUSPEITO:    { label: "Suspeito",    color: "text-orange-600 dark:text-orange-400",   ring: "#f97316", from: 30, to: 60 },
  ALTO_RISCO:  { label: "Alto risco",  color: "text-red-600 dark:text-red-400",         ring: "#ef4444", from: 60, to: 100 },
};

export const ANALYSIS_STEPS = [
  { key: "parsing",      label: "Parsing" },
  { key: "headers",      label: "Remetente" },
  { key: "body",         label: "Conteúdo" },
  { key: "heuristics",  label: "Heurísticas" },
  { key: "dns",          label: "DNS / Auth" },
  { key: "threat_intel", label: "Threat Intel" },
  { key: "content",      label: "Conteúdo URL" },
  { key: "verdict",      label: "Veredito" },
] as const;
