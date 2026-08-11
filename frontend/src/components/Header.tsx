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
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        <div className="flex items-center gap-2.5">
          <ShieldCheck className="h-6 w-6 text-blue-500" strokeWidth={2.2} />
          <span className="text-lg font-semibold tracking-tight">PhishCheck</span>
          <span className="text-xs text-[var(--text-muted)] ml-1">v2.0</span>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={onOpenTrusted}>
            <Settings className="h-4 w-4" />
            Domínios Confiáveis
          </Button>
          <Button variant="ghost" size="sm" onClick={onToggleTheme}>
            {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </Button>
        </div>
      </div>
    </header>
  );
}
