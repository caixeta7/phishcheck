import { useCallback, useRef, useState } from "react";
import { Upload, Mail, Link as LinkIcon, Globe, FileText, Send } from "lucide-react";
import clsx from "clsx";
import { Button } from "./ui/Button";
import type { AnalysisType } from "../types";

const TABS = [
  { key: "email_text", label: "Colar E-mail", icon: Mail },
  { key: "email_file", label: "Arquivo .eml/.msg", icon: Upload },
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
      <div className="flex gap-1 rounded-lg border border-[var(--border-default)] bg-[var(--bg-elevated)] p-1">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={clsx(
              "flex items-center gap-1.5 rounded-md px-3 py-2 text-sm font-medium transition-all",
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
            "flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed p-12 cursor-pointer transition-all",
            dragging ? "border-blue-500 bg-blue-500/5" : "border-[var(--border-default)] hover:border-[var(--text-muted)]",
          )}
        >
          {file ? (
            <>
              <FileText className="h-10 w-10 text-blue-500" />
              <div className="text-center">
                <p className="font-medium">{file.name}</p>
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
            "w-full rounded-xl border border-[var(--border-default)] bg-[var(--bg-card)] p-4 text-sm",
            "focus:outline-none focus:ring-2 focus:ring-blue-500/50",
            "placeholder:text-[var(--text-muted)] resize-none",
            activeTab === "url" || activeTab === "domain" ? "h-16" : "h-64",
          )}
        />
      )}

      <div className="flex items-center justify-between">
        <label className="flex cursor-pointer items-center gap-2 text-sm text-[var(--text-secondary)]">
          <input
            type="checkbox"
            checked={online}
            onChange={(e) => setOnline(e.target.checked)}
            className="h-4 w-4 rounded accent-blue-600"
          />
          Verificações online (DNS, WHOIS, Threat Intel)
        </label>
        <Button onClick={handleSubmit} disabled={disabled}>
          <Send className="h-4 w-4" />
          Analisar
        </Button>
      </div>
    </div>
  );
}
