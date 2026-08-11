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

export const SEVERITY_CONFIG: Record<Severity, { label: string; color: string; bg: string; border: string; icon: string }> = {
  critical: { label: "Crítico", color: "text-red-500", bg: "bg-red-500/10", border: "border-red-500/30", icon: "🔴" },
  high:     { label: "Alto",     color: "text-orange-500", bg: "bg-orange-500/10", border: "border-orange-500/30", icon: "🟠" },
  medium:   { label: "Médio",    color: "text-yellow-500", bg: "bg-yellow-500/10", border: "border-yellow-500/30", icon: "🟡" },
  low:      { label: "Baixo",    color: "text-blue-500", bg: "bg-blue-500/10", border: "border-blue-500/30", icon: "🔵" },
  info:     { label: "Info",     color: "text-gray-400", bg: "bg-gray-500/10", border: "border-gray-500/30", icon: "⚪" },
};

export const VERDICT_CONFIG: Record<Verdict, { label: string; color: string; ring: string }> = {
  LEGITIMO:    { label: "Legítimo",    color: "text-emerald-500", ring: "#10b981" },
  BAIXO_RISCO:  { label: "Baixo Risco", color: "text-yellow-500",  ring: "#eab308" },
  SUSPEITO:     { label: "Suspeito",     color: "text-orange-500", ring: "#f97316" },
  ALTO_RISCO:   { label: "Alto Risco",   color: "text-red-500",    ring: "#ef4444" },
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
