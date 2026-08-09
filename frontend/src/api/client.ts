import type { AnalysisReport, AnalysisType, ProgressStep, TrustedDomainList } from "../types";

const TIMEOUT_MS = 30_000;

async function fetchWithTimeout(url: string, options: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const resp = await fetch(url, { ...options, signal: controller.signal });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({ detail: resp.statusText }));
      throw new Error(body.detail || `HTTP ${resp.status}`);
    }
    return resp;
  } finally {
    clearTimeout(timeout);
  }
}

export async function analyzeStream(
  analysisType: AnalysisType,
  content: string,
  file: File | null,
  online: boolean,
  onStep: (step: ProgressStep) => void,
  onResult: (report: AnalysisReport) => void,
  onError: (error: string) => void,
): Promise<void> {
  const formData = new FormData();
  formData.append("analysis_type", analysisType);
  formData.append("content", content);
  formData.append("online", String(online));
  if (file) formData.append("file", file);

  try {
    const resp = await fetch("/api/v1/analyze/stream", { method: "POST", body: formData });
    if (!resp.ok || !resp.body) throw new Error(`HTTP ${resp.status}`);

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n\n");
      buffer = lines.pop() || "";

      for (const chunk of lines) {
        const dataLine = chunk.match(/^data: (.+)$/ms);
        if (!dataLine) continue;
        const json = dataLine[1].trim();

        if (chunk.startsWith("event: result")) {
          onResult(JSON.parse(json));
        } else {
          const step: ProgressStep = JSON.parse(json);
          onStep(step);
        }
      }
    }
  } catch (err) {
    onError(err instanceof Error ? err.message : "Erro desconhecido");
  }
}

export async function getTrustedDomains(): Promise<TrustedDomainList> {
  return (await fetchWithTimeout("/api/v1/trusted-domains")).json();
}

export async function addTrustedDomain(domain: string): Promise<TrustedDomainList> {
  return (
    await fetchWithTimeout("/api/v1/trusted-domains", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    })
  ).json();
}

export async function removeTrustedDomain(domain: string): Promise<TrustedDomainList> {
  return (
    await fetchWithTimeout("/api/v1/trusted-domains", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    })
  ).json();
}
