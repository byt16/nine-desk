export type FindingSeverity = "critical" | "high" | "medium" | "ok";

export type HeaderFinding = {
  id: string;
  title: string;
  severity: FindingSeverity;
  detail: string;
  misconfig?: string;
};

export type HeaderReport = {
  parsed: { name: string; value: string }[];
  findings: HeaderFinding[];
  exposure: number;
  missing: number;
  present: number;
};

function canon(name: string): string {
  return name.trim().toLowerCase();
}

export function parseRawHeaders(raw: string): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [];
  const lines = raw.replace(/\r\n/g, "\n").split("\n");
  for (const line of lines) {
    if (!line.trim()) continue;
    if (/^HTTP\/\d/i.test(line) || /^(GET|POST|PUT|HEAD|OPTIONS)\s/i.test(line)) {
      continue;
    }
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!name) continue;
    out.push({ name, value });
  }
  return out;
}

function get(parsed: { name: string; value: string }[], name: string): string | undefined {
  const key = canon(name);
  const row = parsed.find((h) => canon(h.name) === key);
  return row?.value;
}

export function analyzeHeaders(raw: string): HeaderReport {
  const parsed = parseRawHeaders(raw);
  const findings: HeaderFinding[] = [];
  const has = (n: string) => Boolean(get(parsed, n));

  if (parsed.length === 0) {
    return { parsed, findings: [], exposure: 0, missing: 0, present: 0 };
  }

  if (!has("strict-transport-security")) {
    findings.push({
      id: "hsts",
      title: "No Strict-Transport-Security",
      severity: "high",
      detail:
        "Browsers will still accept a cleartext hop to this host. Set max-age of at least 15552000, then includeSubDomains once HTTPS is universal.",
      misconfig: "tls-downgrade",
    });
  } else {
    const v = get(parsed, "strict-transport-security") ?? "";
    const age = /max-age=(\d+)/i.exec(v);
    const seconds = age ? Number(age[1]) : 0;
    if (seconds < 15552000) {
      findings.push({
        id: "hsts-age",
        title: "HSTS max-age is short",
        severity: "medium",
        detail: `max-age is ${seconds || "missing"}. Six months (15552000) is the floor; a year is the working default.`,
        misconfig: "tls-downgrade",
      });
    } else {
      findings.push({
        id: "hsts-ok",
        title: "HSTS present",
        severity: "ok",
        detail: v,
      });
    }
  }

  const csp = get(parsed, "content-security-policy");
  if (!csp) {
    findings.push({
      id: "csp",
      title: "No Content-Security-Policy",
      severity: "high",
      detail:
        "Without a CSP, XSS becomes a reliable session-theft primitive. Start with default-src 'self' and a nonce or hash for scripts.",
      misconfig: "missing-headers",
    });
  } else if (/unsafe-inline/.test(csp) && /script-src|default-src/.test(csp)) {
    findings.push({
      id: "csp-inline",
      title: "CSP allows unsafe-inline scripts",
      severity: "medium",
      detail: "unsafe-inline disables the main XSS benefit of CSP. Move to nonces or hashes.",
      misconfig: "missing-headers",
    });
  } else {
    findings.push({
      id: "csp-ok",
      title: "Content-Security-Policy present",
      severity: "ok",
      detail: csp,
    });
  }

  const xfo = get(parsed, "x-frame-options");
  const ancestors = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !ancestors) {
    findings.push({
      id: "frame",
      title: "No frame policy",
      severity: "medium",
      detail:
        "Neither X-Frame-Options nor CSP frame-ancestors is set. This origin can be framed for clickjacking.",
      misconfig: "missing-headers",
    });
  } else {
    findings.push({
      id: "frame-ok",
      title: "Frame policy present",
      severity: "ok",
      detail: ancestors ? "CSP frame-ancestors" : (xfo ?? ""),
    });
  }

  if (!has("x-content-type-options")) {
    findings.push({
      id: "nosniff",
      title: "No X-Content-Type-Options",
      severity: "medium",
      detail: "Set nosniff so the browser does not MIME-sniff a response into an executable context.",
      misconfig: "missing-headers",
    });
  } else {
    findings.push({
      id: "nosniff-ok",
      title: "nosniff present",
      severity: "ok",
      detail: get(parsed, "x-content-type-options") ?? "",
    });
  }

  if (!has("referrer-policy")) {
    findings.push({
      id: "referrer",
      title: "No Referrer-Policy",
      severity: "medium",
      detail: "Use strict-origin-when-cross-origin or no-referrer so tokens in URLs do not leak.",
      misconfig: "missing-headers",
    });
  }

  if (!has("permissions-policy") && !has("feature-policy")) {
    findings.push({
      id: "permissions",
      title: "No Permissions-Policy",
      severity: "medium",
      detail: "Lock camera, microphone, and geolocation to none unless a page actually needs them.",
      misconfig: "missing-headers",
    });
  }

  if (!has("cross-origin-opener-policy")) {
    findings.push({
      id: "coop",
      title: "No Cross-Origin-Opener-Policy",
      severity: "medium",
      detail: "same-origin isolates the browsing context from cross-origin attackers holding a window handle.",
      misconfig: "missing-headers",
    });
  }

  const acao = get(parsed, "access-control-allow-origin");
  const acac = (get(parsed, "access-control-allow-credentials") ?? "").toLowerCase();
  if (acao === "*" && acac === "true") {
    findings.push({
      id: "cors-star-cred",
      title: "Wildcard CORS with credentials",
      severity: "critical",
      detail:
        "Allow-Origin * combined with Allow-Credentials: true. Any site can read authenticated responses in the victim browser. Browsers should refuse this; many stacks still emit it.",
      misconfig: "wildcard-cors",
    });
  } else if (acao === "*") {
    findings.push({
      id: "cors-star",
      title: "Wildcard CORS",
      severity: "medium",
      detail:
        "Access-Control-Allow-Origin is *. Acceptable only for a truly public, unauthenticated resource. Never pair with cookies.",
      misconfig: "wildcard-cors",
    });
  }

  const server = get(parsed, "server");
  if (server && /\/\d|\d+\.\d+/.test(server)) {
    findings.push({
      id: "server-ver",
      title: "Server banner leaks a version",
      severity: "medium",
      detail: `Server: ${server}. Strip the version so scanners cannot pin a 9+ CVE from the banner alone.`,
      misconfig: "verbose-banner",
    });
  } else if (server) {
    findings.push({
      id: "server",
      title: "Server banner present",
      severity: "medium",
      detail: `Server: ${server}. Prefer omitting the header.`,
      misconfig: "verbose-banner",
    });
  }

  const powered = get(parsed, "x-powered-by");
  if (powered) {
    findings.push({
      id: "powered",
      title: "X-Powered-By present",
      severity: "medium",
      detail: `X-Powered-By: ${powered}. Remove it in the application or at the edge.`,
      misconfig: "verbose-banner",
    });
  }

  const cookies = parsed.filter((h) => canon(h.name) === "set-cookie");
  if (cookies.length) {
    for (const cookie of cookies) {
      const v = cookie.value;
      const flags = {
        secure: /;\s*secure\b/i.test(v),
        httpOnly: /;\s*httponly\b/i.test(v),
        sameSite: /;\s*samesite=/i.test(v),
      };
      const name = v.split("=")[0] ?? "cookie";
      if (!flags.secure || !flags.httpOnly || !flags.sameSite) {
        findings.push({
          id: `cookie-${name}`,
          title: `Cookie ${name} is missing flags`,
          severity: "high",
          detail: [
            !flags.secure ? "Secure" : null,
            !flags.httpOnly ? "HttpOnly" : null,
            !flags.sameSite ? "SameSite" : null,
          ]
            .filter(Boolean)
            .join(", ")
            .concat(" missing. Stolen or script-readable sessions skip MFA."),
          misconfig: "insecure-cookies",
        });
      } else {
        findings.push({
          id: `cookie-ok-${name}`,
          title: `Cookie ${name} flagged correctly`,
          severity: "ok",
          detail: "Secure, HttpOnly, and SameSite are set.",
        });
      }
    }
  }

  const rank: Record<FindingSeverity, number> = {
    critical: 34,
    high: 18,
    medium: 9,
    ok: 0,
  };
  const exposure = Math.min(
    100,
    findings.reduce((sum, f) => sum + rank[f.severity], 0),
  );
  const missing = findings.filter((f) => f.severity !== "ok").length;
  const present = findings.filter((f) => f.severity === "ok").length;

  return { parsed, findings, exposure, missing, present };
}

export const SAMPLE_BAD = `HTTP/1.1 200 OK
Server: Apache/2.4.49 (Unix)
X-Powered-By: PHP/8.1.0
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Set-Cookie: session=abc; Path=/
Content-Type: text/html`;

export const SAMPLE_GOOD = `HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Set-Cookie: session=abc; Path=/; Secure; HttpOnly; SameSite=Strict
Content-Type: text/html; charset=utf-8`;
