import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { CveRow } from "@/components/cve-row";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { CVES, searchCves, isPass2Cve, type CveCategory, CATEGORY_LABEL } from "@/lib/data";
import { cn } from "@/lib/utils";

const YEARS = [...new Set(CVES.map((c) => c.published.slice(0, 4)))].sort(
  (a, b) => b.localeCompare(a),
);

const CATEGORIES = Object.keys(CATEGORY_LABEL) as CveCategory[];

export const Route = createFileRoute("/cves/")({ component: CvesIndex });

function CvesIndex() {
  const [q, setQ] = useState("");
  const [kev, setKev] = useState(false);
  const [ransom, setRansom] = useState(false);
  const [gap, setGap] = useState(false);
  const [year, setYear] = useState("");
  const [category, setCategory] = useState<CveCategory | "">("");

  const rows = useMemo(() => {
    return searchCves(q)
      .filter((c) => (kev ? c.kev : true))
      .filter((c) => (ransom ? c.ransomware : true))
      .filter((c) => (gap ? isPass2Cve(c.id) : true))
      .filter((c) => (year ? c.published.startsWith(year) : true))
      .filter((c) => (category ? c.category === category : true))
      .sort((a, b) => b.cvss - a.cvss || b.published.localeCompare(a.published));
  }, [q, kev, ransom, gap, year, category]);

  return (
    <main>
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-muted">
        Catalog
      </p>
      <h1 className="mt-3 font-display text-4xl italic tracking-tight sm:text-5xl">
        Critical CVEs
      </h1>
      <p className="mt-3 max-w-xl text-sm leading-relaxed text-muted">
        {CVES.length} records at or above 9.0. Filter by KEV, year, or class.
        Open a record for detection and remediation — not a proof of concept.
      </p>

      <div className="mt-8 flex flex-col gap-3">
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search CVE, vendor, product, CWE"
          aria-label="Search CVEs"
        />
        <div className="flex flex-wrap gap-2">
          <FilterChip on={kev} onClick={() => setKev((v) => !v)}>
            KEV
          </FilterChip>
          <FilterChip on={ransom} onClick={() => setRansom((v) => !v)}>
            Ransomware
          </FilterChip>
          <FilterChip on={gap} onClick={() => setGap((v) => !v)}>
            Added this pass
          </FilterChip>
          {YEARS.map((y) => (
            <FilterChip
              key={y}
              on={year === y}
              onClick={() => setYear((cur) => (cur === y ? "" : y))}
            >
              {y}
            </FilterChip>
          ))}
        </div>
        <div className="flex flex-wrap gap-2">
          {CATEGORIES.map((c) => (
            <FilterChip
              key={c}
              on={category === c}
              onClick={() => setCategory((cur) => (cur === c ? "" : c))}
            >
              {CATEGORY_LABEL[c]}
            </FilterChip>
          ))}
        </div>
      </div>

      <p className="mt-6 font-mono text-xs tabular-nums text-subtle">
        {rows.length} {rows.length === 1 ? "record" : "records"}
      </p>
      <div className="mt-3 flex flex-col gap-2">
        {rows.map((cve) => (
          <CveRow key={cve.id} cve={cve} />
        ))}
        {rows.length === 0 ? (
          <p className="rounded-xl px-4 py-10 text-center text-sm text-muted shadow-[var(--shadow-border)]">
            No records match those filters.
          </p>
        ) : null}
      </div>
    </main>
  );
}

function FilterChip({
  on,
  onClick,
  children,
}: {
  on: boolean;
  onClick: () => void;
  children: string;
}) {
  return (
    <Button
      type="button"
      variant={on ? "default" : "secondary"}
      size="sm"
      onClick={onClick}
      aria-pressed={on}
      className={cn("rounded-full", on && "bg-fg text-bg")}
    >
      {children}
    </Button>
  );
}
