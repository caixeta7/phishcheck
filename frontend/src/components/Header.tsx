import { Moon, Sun, ShieldCheck, Settings } from "lucide-react";
import { Button } from "./ui/Button";

interface Props {
  isDark: boolean;
  onToggleTheme: () => void;
  onOpenTrusted: () => void;
}

export function Header({ isDark, onToggleTheme, onOpenTrusted }: Props) {
  return (
    <header className="sticky top-0 z-50 border-b border-[var(--border-default)] bg-[var(--bg-card)]/80 backdrop-blur-lg">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-[var(--accent)]" strokeWidth={2.2} />
          <span className="font-display text-lg font-bold tracking-tight">PhishCheck</span>
          <span className="rounded border border-[var(--border-default)] px-1.5 font-mono text-[10px] text-[var(--text-muted)]">v2.0</span>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={onOpenTrusted} aria-label="Domínios confiáveis">
            <Settings className="h-4 w-4" />
            <span className="hidden sm:inline">Domínios confiáveis</span>
          </Button>
          <Button variant="ghost" size="sm" onClick={onToggleTheme} aria-label={isDark ? "Usar tema claro" : "Usar tema escuro"}>
            {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </Button>
        </div>
      </div>
    </header>
  );
}
