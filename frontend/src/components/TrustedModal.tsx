import { useCallback, useEffect, useState } from "react";
import { X, Plus, Trash2 } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "./ui/Button";
import { getTrustedDomains, addTrustedDomain, removeTrustedDomain } from "../api/client";

interface Props {
  open: boolean;
  onClose: () => void;
}

export function TrustedModal({ open, onClose }: Props) {
  const [domains, setDomains] = useState<string[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    const resp = await getTrustedDomains();
    setDomains(resp.domains);
  }, []);

  useEffect(() => {
    if (open) load();
  }, [open, load]);

  const handleAdd = async () => {
    if (!input.trim()) return;
    setLoading(true);
    try {
      const resp = await addTrustedDomain(input.trim());
      setDomains(resp.domains);
      setInput("");
    } finally {
      setLoading(false);
    }
  };

  const handleRemove = async (d: string) => {
    setLoading(true);
    try {
      const resp = await removeTrustedDomain(d);
      setDomains(resp.domains);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 backdrop-blur-sm"
        >
          <motion.div
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-md rounded-2xl border border-[var(--border-default)] bg-[var(--bg-card)] p-6 shadow-2xl"
          >
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-lg font-semibold">Domínios Confiáveis</h2>
              <button onClick={onClose} className="text-[var(--text-muted)] hover:text-[var(--text-primary)]">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="mb-4 flex gap-2">
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleAdd()}
                placeholder="dominio.com.br"
                className="flex-1 rounded-lg border border-[var(--border-default)] bg-[var(--bg-primary)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50"
              />
              <Button size="sm" onClick={handleAdd} disabled={loading || !input.trim()}>
                <Plus className="h-4 w-4" />
                Adicionar
              </Button>
            </div>

            <div className="max-h-64 space-y-1 overflow-y-auto">
              {domains.length === 0 ? (
                <p className="py-8 text-center text-sm text-[var(--text-muted)]">
                  Nenhum domínio confiável cadastrado.
                </p>
              ) : (
                domains.map((d) => (
                  <div
                    key={d}
                    className="flex items-center justify-between rounded-lg px-3 py-2 text-sm hover:bg-[var(--bg-elevated)]"
                  >
                    <span className="font-mono">{d}</span>
                    <button
                      onClick={() => handleRemove(d)}
                      disabled={loading}
                      className="text-[var(--text-muted)] hover:text-red-500"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
