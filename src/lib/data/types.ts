export type CveCategory =
  | "rce"
  | "auth-bypass"
  | "injection"
  | "memory"
  | "ssrf"
  | "upload"
  | "deserialization"
  | "path-traversal";

export type Cve = {
  id: string;
  name: string;
  cvss: number;
  vector: string;
  published: string;
  vendor: string;
  product: string;
  cwe: string;
  kev: boolean;
  ransomware: boolean;
  summary: string;
  impact: string;
  affected: string[];
  detect: string[];
  remediate: string[];
  category: CveCategory;
  references: { label: string; href: string }[];
};

export type Misconfig = {
  slug: string;
  title: string;
  equivalent: number;
  cis?: string;
  owasp: string;
  cwe: string;
  summary: string;
  looksLike: string[];
  why: string;
  detect: string[];
  harden: string[];
  relatedCves: string[];
};

export const CATEGORY_LABEL: Record<CveCategory, string> = {
  rce: "Remote code execution",
  "auth-bypass": "Authentication bypass",
  injection: "Injection",
  memory: "Memory corruption",
  ssrf: "Server-side request forgery",
  upload: "Unauthenticated upload",
  deserialization: "Insecure deserialization",
  "path-traversal": "Path traversal",
};
