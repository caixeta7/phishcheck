import { useCallback, useState } from "react";
import type { AnalysisReport, AnalysisType, ProgressStep } from "../types";

import { analyzeStream } from "../api/client";

interface AnalysisState {
  status: "idle" | "analyzing" | "done" | "error";
  steps: Map<string, ProgressStep>;
  report: AnalysisReport | null;
  error: string | null;
}

export function useAnalysis() {
  const [state, setState] = useState<AnalysisState>({
    status: "idle",
    steps: new Map(),
    report: null,
    error: null,
  });

  const run = useCallback(
    async (type: AnalysisType, content: string, file: File | null, online: boolean) => {
      setState({ status: "analyzing", steps: new Map(), report: null, error: null });

      await analyzeStream(
        type,
        content,
        file,
        online,
        (step) =>
          setState((prev) => {
            const next = new Map(prev.steps);
            next.set(step.step, step);
            return { ...prev, steps: next };
          }),
        (report) => setState((prev) => ({ ...prev, status: "done", report })),
        (error) => setState((prev) => ({ ...prev, status: "error", error })),
      );
    },
    [],
  );

  const reset = useCallback(() => {
    setState({ status: "idle", steps: new Map(), report: null, error: null });
  }, []);

  return { ...state, run, reset };
}
