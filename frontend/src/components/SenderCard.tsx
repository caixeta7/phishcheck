import { Mail, Reply, CornerUpLeft, Shield, Calendar, Globe } from "lucide-react";
import { Card } from "./ui/Card";
import type { AnalysisReport } from "../types";

interface Props {
  report: AnalysisReport;
}

export function SenderCard({ report: r }: Props) {
  const fromDomain = r.sender_domain;
  const fromEmail = r.sender_email;
  const fromName = r.from_name;
  const replyTo = r.reply_to;
  const returnPath = r.return_path;
  const subject = r.subject_line;

  const hasSender = fromEmail || fromDomain;

  if (!hasSender) {
    return (
      <Card className="p-5">
        <div className="flex items-center gap-2 text-sm text-[var(--text-muted)]">
          <Mail className="h-4 w-4" />
          Análise de URL/domínio — sem dados de remetente.
        </div>
      </Card>
    );
  }

  const authFindings = r.findings.filter(
    (f) => f.category === "E-mail Auth" || f.category === "WHOIS",
  );
  const spfFound = authFindings.some((f) => f.description.includes("SPF"));
  const dmarcFound = authFindings.some((f) => f.description.includes("DMARC"));
  const whoisAge = authFindings.find((f) => f.category === "WHOIS");

  return (
    <Card className="p-5">
      <div className="mb-4 flex items-center gap-2">
        <Mail className="h-5 w-5 text-blue-500" />
        <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--text-muted)]">
          Remetente
        </h3>
      </div>

      <dl className="grid grid-cols-12 gap-x-4 gap-y-3 text-sm">
        {fromName && (
          <Row icon={Mail} label="Nome" value={fromName} />
        )}
        {fromEmail && (
          <Row icon={Mail} label="E-mail" value={fromEmail} mono />
        )}
        {fromDomain && (
          <Row icon={Globe} label="Domínio" value={fromDomain} mono />
        )}
        {replyTo && (
          <Row icon={Reply} label="Reply-To" value={replyTo} highlight>
            <div className="text-xs text-orange-500 mt-0.5">Diferente do From</div>
          </Row>
        )}
        {returnPath && (
          <Row icon={CornerUpLeft} label="Return-Path" value={returnPath} mono highlight />
        )}
        {subject && (
          <Row icon={Mail} label="Assunto" value={subject} full />
        )}
      </dl>

      <div className="mt-4 flex flex-wrap gap-3 border-t border-[var(--border-default)] pt-4">
        <AuthChip label="SPF" active={spfFound} />
        <AuthChip label="DMARC" active={dmarcFound} />
        {whoisAge && (
          <div className="flex items-center gap-1.5 text-sm text-[var(--text-secondary)]">
            <Calendar className="h-3.5 w-3.5" />
            {whoisAge.description}
          </div>
        )}
      </div>
    </Card>
  );
}

function Row({
  icon: Icon,
  label,
  value,
  mono,
  highlight,
  full,
  children,
}: {
  icon: typeof Mail;
  label: string;
  value: string;
  mono?: boolean;
  highlight?: boolean;
  full?: boolean;
  children?: React.ReactNode;
}) {
  return (
    <div className={`${full ? "col-span-12" : "col-span-12 sm:col-span-6"}`}>
      <div className="flex items-start gap-2">
        <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--text-muted)]" />
        <div className="min-w-0">
          <dt className="text-xs text-[var(--text-muted)]">{label}</dt>
          <dd
            className={`break-words ${
              highlight ? "text-orange-500 font-medium" : "text-[var(--text-primary)]"
            } ${mono ? "font-mono text-sm" : "text-sm"}`}
          >
            {value}
          </dd>
          {children}
        </div>
      </div>
    </div>
  );
}

function AuthChip({ label, active }: { label: string; active: boolean }) {
  return (
    <div className="flex items-center gap-1.5 text-sm">
      <Shield
        className={`h-3.5 w-3.5 ${active ? "text-emerald-500" : "text-red-500"}`}
      />
      <span className="font-medium">{label}</span>
      <span className={active ? "text-emerald-500" : "text-red-500"}>{active ? "✓" : "✗"}</span>
    </div>
  );
}
