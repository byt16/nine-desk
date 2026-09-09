const AV: Record<string, string> = {
  N: "Network",
  A: "Adjacent",
  L: "Local",
  P: "Physical",
};
const AC: Record<string, string> = { L: "Low", H: "High" };
const PR: Record<string, string> = { N: "None", L: "Low", H: "High" };
const UI: Record<string, string> = { N: "None", R: "Required" };
const S: Record<string, string> = { U: "Unchanged", C: "Changed" };
const CIA: Record<string, string> = { N: "None", L: "Low", H: "High" };

const MAP: Record<string, Record<string, string>> = {
  AV,
  AC,
  PR,
  UI,
  S,
  C: CIA,
  I: CIA,
  A: CIA,
};

const LABEL: Record<string, string> = {
  AV: "Attack vector",
  AC: "Attack complexity",
  PR: "Privileges",
  UI: "User interaction",
  S: "Scope",
  C: "Confidentiality",
  I: "Integrity",
  A: "Availability",
};

export type VectorPiece = { key: string; label: string; code: string; value: string };

export function decodeVector(vector: string): VectorPiece[] {
  const body = vector.replace(/^CVSS:[\d.]+\/?/, "");
  return body
    .split("/")
    .map((part) => {
      const [key, code] = part.split(":");
      if (!key || !code) return null;
      const value = MAP[key]?.[code] ?? code;
      return { key, label: LABEL[key] ?? key, code, value };
    })
    .filter((p): p is VectorPiece => Boolean(p));
}

export function scoreBand(score: number): "ceiling" | "critical" {
  return score >= 10 ? "ceiling" : "critical";
}

export function formatScore(score: number): string {
  return score.toFixed(1);
}
