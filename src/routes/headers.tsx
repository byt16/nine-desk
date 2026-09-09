import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  analyzeHeaders,
  SAMPLE_BAD,
  SAMPLE_GOOD,
  type FindingSeverity,
} from "@/lib/headers";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/headers")({ component: HeadersLab });

function HeadersLab() {
  const [raw, setRaw] = useState(SAMPLE_BAD);
  const report = useMemo(() => analyzeHeaders(raw), [raw]);

  return (
    <main>
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-muted">
        Local lab
      </p>
      <h1 className="mt-3 font-display text-4xl italic tracking-tight sm:text-5xl">
        Header hardening
      </h1>
      <p className="mt-3 max-w-xl text-sm leading-relaxed text-muted">
        Paste a response from a host you own. Nothing is fetched. Exposure is a
        0–100 score of missing or dangerous headers — not a CVSS, and not a
        scan of anyone else.
      </p>

      <div className="mt-8 grid gap-8 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
        <div>
          <div className="mb-3 flex flex-wrap gap-2">
            <Button
              type="button"
              size="sm"
              variant="secondary"
              onClick={() => setRaw(SAMPLE_BAD)}
            >
              Load exposed sample
            </Button>
            <Button
              type="button"
              size="sm"
              variant="secondary"
              onClick={() => setRaw(SAMPLE_GOOD)}
            >
              Load hardened sample
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => setRaw("")}
            >
              Clear
            </Button>
          </div>
          <Textarea
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            spellCheck={false}
            aria-label="HTTP response headers"
            placeholder="HTTP/1.1 200 OK&#10;Strict-Transport-Security: max-age=31536000"
          />
        </div>

        <aside className="rounded-2xl bg-surface p-5 shadow-[var(--shadow-border)] sm:p-6">
          {report.parsed.length === 0 ? (
            <p className="text-sm text-muted">
              Paste headers to score this origin.
            </p>
          ) : (
            <>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-muted">
                Exposure
              </p>
              <p
                className={cn(
                  "mt-2 font-mono text-5xl tabular-nums tracking-tight",
                  report.exposure >= 50 ? "text-critical" : "text-fg",
                )}
              >
                {report.exposure}
              </p>
              <p className="mt-2 text-sm text-muted">
                {report.missing} issue{report.missing === 1 ? "" : "s"} ·{" "}
                {report.present} control{report.present === 1 ? "" : "s"} in
                place · {report.parsed.length} header
                {report.parsed.length === 1 ? "" : "s"} parsed
              </p>
            </>
          )}
        </aside>
      </div>

      {report.findings.length ? (
        <section className="mt-10">
          <h2 className="font-display text-2xl italic tracking-tight">
            Findings
          </h2>
          <ul className="mt-4 flex flex-col gap-2">
            {report.findings.map((f) => (
              <li
                key={f.id}
                className="rounded-xl px-4 py-4 shadow-[var(--shadow-border)]"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <p className="text-sm text-fg">{f.title}</p>
                </div>
                <p className="mt-2 text-sm leading-relaxed text-muted">
                  {f.detail}
                </p>
                {f.misconfig ? (
                  <Link
                    to="/misconfigs/$slug"
                    params={{ slug: f.misconfig }}
                    className="mt-3 inline-flex h-11 items-center text-sm text-fg underline-offset-4 hover:underline"
                  >
                    Related misconfig
                  </Link>
                ) : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </main>
  );
}

function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  if (severity === "ok") return <Badge tone="ok">OK</Badge>;
  if (severity === "critical") return <Badge tone="critical">Critical</Badge>;
  if (severity === "high") return <Badge tone="critical">High</Badge>;
  return <Badge>Medium</Badge>;
}
