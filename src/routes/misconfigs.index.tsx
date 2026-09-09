import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { MisconfigRow } from "@/components/cve-row";
import { Input } from "@/components/ui/input";
import { MISCONFIGS, searchMisconfigs } from "@/lib/data";

export const Route = createFileRoute("/misconfigs/")({
  component: MisconfigsIndex,
});

function MisconfigsIndex() {
  const [q, setQ] = useState("");
  const rows = useMemo(
    () =>
      searchMisconfigs(q).sort((a, b) => b.equivalent - a.equivalent),
    [q],
  );

  return (
    <main>
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-muted">
        Server
      </p>
      <h1 className="mt-3 font-display text-4xl italic tracking-tight sm:text-5xl">
        Misconfiguration
      </h1>
      <p className="mt-3 max-w-xl text-sm leading-relaxed text-muted">
        {MISCONFIGS.length} faults that do not need a CVE number to score as
        critical. Equivalent severity is the CVSS these look like once they are
        internet-facing.
      </p>
      <div className="mt-8">
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search title, OWASP, CWE"
          aria-label="Search misconfigurations"
        />
      </div>
      <p className="mt-6 font-mono text-xs tabular-nums text-subtle">
        {rows.length} {rows.length === 1 ? "record" : "records"}
      </p>
      <div className="mt-3 flex flex-col gap-2">
        {rows.map((m) => (
          <MisconfigRow
            key={m.slug}
            slug={m.slug}
            title={m.title}
            equivalent={m.equivalent}
            owasp={m.owasp}
          />
        ))}
        {rows.length === 0 ? (
          <p className="rounded-xl px-4 py-10 text-center text-sm text-muted shadow-[var(--shadow-border)]">
            No records match that search.
          </p>
        ) : null}
      </div>
    </main>
  );
}
