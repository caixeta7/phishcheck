import { useCallback, useRef, useState } from "react";
import { Upload, Mail, Link as LinkIcon, Globe, FileText, Send } from "lucide-react";
import clsx from "clsx";
import { Button } from "./ui/Button";
import type { AnalysisType } from "../types";

const TABS = [
  { key: "email_text", label: "Colar e-mail", icon: Mail },
  { key: "email_file", label: ".eml / .msg", icon: Upload },
  { key: "url", label: "URL", icon: LinkIcon },
  { key: "domain", label: "Domínio", icon: Globe },
] as const;

interface Props {
  onAnalyze: (type: AnalysisType, content: string, file: File | null, online: boolean) => void;
  disabled: boolean;
}

export function InputPanel({ onAnalyze, disabled }: Props) {
  const [activeTab, setActiveTab] = useState<AnalysisType>("email_text");
  const [content, setContent] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [online, setOnline] = useState(true);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f && /\.(eml|msg)$/i.test(f.name)) setFile(f);
  }, []);

  const handleSubmit = () => {
    if (activeTab === "email_file" && !file) return;
    if (activeTab !== "email_file" && !content.trim()) return;
    onAnalyze(activeTab, content, file, online);
  };

  return (
    <div className="flex flex-col gap-4">
      <div role="tablist" className="grid grid-cols-2 gap-1 rounded-lg border border-[var(--border-default)] bg-[var(--bg-elevated)] p-1 sm:grid-cols-4">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={activeTab === key}
            onClick={() => setActiveTab(key)}
            className={clsx(
              "flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md px-2 py-2 text-[13px] font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]/50",
              activeTab === key
                ? "bg-[var(--bg-card)] text-[var(--text-primary)] shadow-sm"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]",
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>

      {activeTab === "email_file" ? (
        <div
          onClick={() => fileRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          className={clsx(
            "flex cursor-pointer flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed p-10 transition-all",
            dragging ? "border-[var(--accent)] bg-[var(--accent-soft)]" : "border-[var(--border-default)] hover:border-[var(--text-muted)]",
          )}
        >
          {file ? (
            <>
              <FileText className="h-10 w-10 text-[var(--accent)]" />
              <div className="text-center">
                <p className="font-medium wrap-anywhere">{file.name}</p>
                <p className="text-sm text-[var(--text-muted)]">{(file.size / 1024).toFixed(1)} KB</p>
              </div>
            </>
          ) : (
            <>
              <Upload className="h-10 w-10 text-[var(--text-muted)]" />
              <div className="text-center">
                <p className="font-medium text-[var(--text-secondary)]">Arraste um arquivo .eml ou .msg</p>
                <p className="text-sm text-[var(--text-muted)]">ou clique para selecionar</p>
              </div>
            </>
          )}
          <input ref={fileRef} type="file" accept=".eml,.msg" hidden onChange={(e) => setFile(e.target.files?.[0] || null)} />
        </div>
      ) : (
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder={
            activeTab === "url"
              ? "https://exemplo-suspeito.com/login"
              : activeTab === "domain"
                ? "exemplo.com"
                : "Cole aqui o e-mail completo (cabeçalhos + corpo)..."
          }
          className={clsx(
            "w-full rounded-lg border border-[var(--border-default)] bg-[var(--bg-elevated)] p-3.5 font-mono text-[13px] leading-relaxed",
            "focus:border-[var(--accent)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]/30",
            "placeholder:text-[var(--text-muted)] resize-none",
            activeTab === "url" || activeTab === "domain" ? "h-20" : "h-72",
          )}
        />
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <label className="flex cursor-pointer items-center gap-2 text-sm text-[var(--text-secondary)]">
          <input
            type="checkbox"
            checked={online}
            onChange={(e) => setOnline(e.target.checked)}
            className="h-4 w-4 rounded accent-[var(--accent)]"
          />
          Consultas online (DNS, WHOIS, threat intel)
        </label>
        <Button onClick={handleSubmit} disabled={disabled}>
          <Send className="h-4 w-4" />
          Analisar
        </Button>
      </div>
    </div>
  );
}
