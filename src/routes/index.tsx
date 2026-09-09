import type { ReactNode } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { CveRow, MisconfigRow } from "@/components/cve-row";
import { ScoreMark } from "@/components/score-mark";
import {
  cvesByBand,
  cvesByYear,
  deskStats,
  latestKev,
  pass2Cves,
  topMisconfigs,
} from "@/lib/data";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  const stats = deskStats();
  const kev = latestKev(6);
  const mis = topMisconfigs(6);
  const years = cvesByYear();
  const bands = cvesByBand();
  const added = pass2Cves();

  return (
    <main>
      <section className="nine-enter">
        <p className="font-mono text-xs uppercase tracking-[0.22em] text-muted">
          Critical intelligence desk
        </p>
        <h1 className="mt-3 max-w-2xl font-display text-5xl italic leading-[1.05] tracking-tight sm:text-6xl">
          Nothing below 9.0.
        </h1>
        <p className="mt-5 max-w-xl text-base leading-relaxed text-muted">
          Curated CVSS 9+ vulnerabilities currently on the public record, mapped
          against the server misconfigurations that turn a patchable CVE into a
          10.0 incident. Detection and hardening only.
        </p>
      </section>

      <dl className="nine-enter nine-enter-2 mt-10 grid grid-cols-2 gap-px overflow-hidden rounded-2xl bg-border sm:grid-cols-4">
        <Stat label="On the desk" value={String(stats.cves)} hint="CVEs ≥ 9.0" />
        <Stat label="CISA KEV" value={String(stats.kev)} hint="Known exploited" />
        <Stat
          label="Added this pass"
          value={String(stats.pass2Added)}
          hint="VPN / edge / RMM / mail"
        />
        <Stat
          label="2026 KEV 9+"
          value={`${stats.y2026}/${stats.kev2026Critical}`}
          hint="Internet-facing subset"
        />
      </dl>

      <div className="nine-enter nine-enter-3 mt-10 grid gap-6 lg:grid-cols-2">
        <ChartCard title="By year" caption="Publication year on this desk">
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={years} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
              <XAxis
                dataKey="year"
                tick={{ fill: "var(--color-muted)", fontSize: 11, fontFamily: "IBM Plex Mono" }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "var(--color-muted)", fontSize: 11, fontFamily: "IBM Plex Mono" }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                cursor={{ fill: "var(--color-surface-2)" }}
                contentStyle={{
                  background: "var(--color-surface)",
                  border: "1px solid var(--color-border)",
                  borderRadius: 8,
                  color: "var(--color-fg)",
                  fontFamily: "IBM Plex Sans",
                  fontSize: 12,
                }}
              />
              <Bar dataKey="count" fill="var(--color-fg)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
        <ChartCard title="By score" caption="Bands at or above the floor">
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={bands} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
              <XAxis
                dataKey="band"
                tick={{ fill: "var(--color-muted)", fontSize: 11, fontFamily: "IBM Plex Mono" }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "var(--color-muted)", fontSize: 11, fontFamily: "IBM Plex Mono" }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                cursor={{ fill: "var(--color-surface-2)" }}
                contentStyle={{
                  background: "var(--color-surface)",
                  border: "1px solid var(--color-border)",
                  borderRadius: 8,
                  color: "var(--color-fg)",
                  fontFamily: "IBM Plex Sans",
                  fontSize: 12,
                }}
              />
              <Bar dataKey="count" fill="var(--color-critical)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      <div className="nine-enter nine-enter-4 mt-12 grid gap-12 lg:grid-cols-2">
        <section>
          <div className="mb-4 flex items-end justify-between gap-4">
            <div>
              <h2 className="font-display text-2xl italic tracking-tight">
                On KEV
              </h2>
              <p className="mt-1 text-sm text-muted">
                Known exploited, CVSS still at or above 9.0.
              </p>
            </div>
            <Link
              to="/cves"
              className="inline-flex h-11 items-center text-sm text-muted hover:text-fg"
            >
              All CVEs
            </Link>
          </div>
          <div className="flex flex-col gap-2">
            {kev.map((cve) => (
              <CveRow key={cve.id} cve={cve} />
            ))}
          </div>
        </section>

        <section>
          <div className="mb-4 flex items-end justify-between gap-4">
            <div>
              <h2 className="font-display text-2xl italic tracking-tight">
                Misconfiguration
              </h2>
              <p className="mt-1 text-sm text-muted">
                Server faults scored as equivalent critical.
              </p>
            </div>
            <Link
              to="/misconfigs"
              className="inline-flex h-11 items-center text-sm text-muted hover:text-fg"
            >
              All
            </Link>
          </div>
          <div className="flex flex-col gap-2">
            {mis.map((m) => (
              <MisconfigRow
                key={m.slug}
                slug={m.slug}
                title={m.title}
                equivalent={m.equivalent}
                owasp={m.owasp}
              />
            ))}
          </div>
        </section>
      </div>

      <aside className="mt-14 rounded-2xl bg-surface px-5 py-6 shadow-[var(--shadow-border)] sm:px-8">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-muted">
          Coverage
        </p>
        <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted">
          First cut held {stats.firstCut}. A later pass added {stats.gapAdded}{" "}
          (React2Shell, Sangoma, UniFi). This pass adds {stats.pass2Added}{" "}
          internet-facing 2026 KEV 9+ — VPN, edge, RMM, mail, identity. CISA
          lists {stats.kev2026Critical} criticals in 2026; NINE holds {stats.y2026}.
          Still not WordPress/Joomla plugins, Langflow, or screensharing. No
          scanners. No payloads.
        </p>
        <div className="mt-5 flex items-center gap-3 text-sm text-muted">
          <ScoreMark score={9.0} size="sm" />
          <span>is the floor. Everything else is noise.</span>
        </div>
      </aside>

      <section className="mt-12">
        <div className="mb-4 flex items-end justify-between gap-4">
          <div>
            <h2 className="font-display text-2xl italic tracking-tight">
              Added this pass
            </h2>
            <p className="mt-1 text-sm text-muted">
              {added.length} 2026 KEV 9+ on VPN, edge, RMM, mail, identity.
            </p>
          </div>
          <Link
            to="/cves"
            className="inline-flex h-11 items-center text-sm text-muted hover:text-fg"
          >
            Full catalog
          </Link>
        </div>
        <div className="flex flex-col gap-2">
          {added.slice(0, 8).map((cve) => (
            <CveRow key={cve.id} cve={cve} />
          ))}
        </div>
      </section>
    </main>
  );
}

function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <div className="bg-bg px-4 py-5 sm:px-5">
      <dt className="font-mono text-xs uppercase tracking-[0.16em] text-muted">
        {label}
      </dt>
      <dd className="mt-2 font-mono text-3xl tabular-nums tracking-tight text-fg">
        {value}
      </dd>
      <p className="mt-1 text-xs text-subtle">{hint}</p>
    </div>
  );
}

function ChartCard({
  title,
  caption,
  children,
}: {
  title: string;
  caption: string;
  children: ReactNode;
}) {
  return (
    <div className="rounded-2xl bg-surface p-4 shadow-[var(--shadow-border)] sm:p-5">
      <div className="mb-3 flex items-baseline justify-between gap-3">
        <h2 className="font-display text-xl italic tracking-tight">{title}</h2>
        <p className="font-mono text-xs text-subtle">{caption}</p>
      </div>
      {children}
    </div>
  );
}
