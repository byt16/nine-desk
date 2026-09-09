import { createFileRoute, Link } from "@tanstack/react-router";
import { Badge } from "@/components/ui/badge";
import { ScoreMark } from "@/components/score-mark";
import { WatchCve } from "@/components/watch-toggle";
import { MisconfigRow } from "@/components/cve-row";
import { CATEGORY_LABEL, getCve, misconfigsForCve } from "@/lib/data";
import { decodeVector } from "@/lib/cvss";

export const Route = createFileRoute("/cves/$id")({
  component: CveDetail,
});

function CveDetail() {
  const { id } = Route.useParams();
  const cve = getCve(id);
  if (!cve) {
    return (
      <main className="py-10">
        <p className="font-mono text-xs text-muted">Unknown CVE</p>
        <h1 className="mt-3 font-display text-4xl italic">{id}</h1>
        <p className="mt-3 text-sm text-muted">
          This identifier is not on the desk.
        </p>
        <Link to="/cves" className="mt-6 inline-flex h-11 items-center text-sm text-fg">
          Back to catalog
        </Link>
      </main>
    );
  }

  const pieces = decodeVector(cve.vector);
  const related = misconfigsForCve(cve.id);

  return (
    <main>
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-muted">
        {cve.vendor} · {cve.product}
      </p>
      <div className="mt-4 flex flex-col gap-6 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="font-mono text-sm text-muted">{cve.id}</p>
          <h1 className="mt-2 font-display text-4xl italic tracking-tight sm:text-5xl">
            {cve.name}
          </h1>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            {cve.kev ? <Badge tone="critical">CISA KEV</Badge> : null}
            {cve.ransomware ? <Badge tone="outline">Ransomware use</Badge> : null}
            <Badge>{CATEGORY_LABEL[cve.category]}</Badge>
            <Badge>{cve.cwe}</Badge>
          </div>
        </div>
        <div className="flex shrink-0 flex-col items-start gap-3 sm:items-end">
          <ScoreMark score={cve.cvss} size="lg" />
          <WatchCve id={cve.id} />
        </div>
      </div>

      <p className="mt-8 max-w-2xl text-base leading-relaxed text-muted">
        {cve.summary}
      </p>

      <section className="mt-10">
        <h2 className="font-display text-2xl italic tracking-tight">Vector</h2>
        <p className="mt-1 font-mono text-xs text-subtle">{cve.vector}</p>
        <dl className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {pieces.map((p) => (
            <div
              key={p.key}
              className="rounded-xl bg-surface px-4 py-3 shadow-[var(--shadow-border)]"
            >
              <dt className="font-mono text-xs text-subtle">{p.label}</dt>
              <dd className="mt-1 text-sm text-fg">{p.value}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="mt-10 grid gap-8 lg:grid-cols-2">
        <Block title="Impact" body={cve.impact} />
        <div>
          <h2 className="font-display text-2xl italic tracking-tight">
            Affected
          </h2>
          <ul className="mt-3 space-y-2 text-sm leading-relaxed text-muted">
            {cve.affected.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ul>
        </div>
      </section>

      <section className="mt-10 grid gap-8 lg:grid-cols-2">
        <ListBlock title="Detect" items={cve.detect} />
        <ListBlock title="Remediate" items={cve.remediate} />
      </section>

      {related.length ? (
        <section className="mt-10">
          <h2 className="font-display text-2xl italic tracking-tight">
            Related misconfiguration
          </h2>
          <div className="mt-4 flex flex-col gap-2">
            {related.map((m) => (
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
      ) : null}

      <section className="mt-10">
        <h2 className="font-display text-2xl italic tracking-tight">
          References
        </h2>
        <ul className="mt-3 space-y-2">
          {cve.references.map((r) => (
            <li key={r.href}>
              <a
                href={r.href}
                target="_blank"
                rel="noreferrer"
                className="text-sm text-fg underline-offset-4 hover:underline"
              >
                {r.label}
              </a>
            </li>
          ))}
        </ul>
        <p className="mt-4 font-mono text-xs text-subtle">
          Published {cve.published}
        </p>
      </section>
    </main>
  );
}

function Block({ title, body }: { title: string; body: string }) {
  return (
    <div>
      <h2 className="font-display text-2xl italic tracking-tight">{title}</h2>
      <p className="mt-3 text-sm leading-relaxed text-muted">{body}</p>
    </div>
  );
}

function ListBlock({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <h2 className="font-display text-2xl italic tracking-tight">{title}</h2>
      <ol className="mt-3 list-decimal space-y-2 pl-4 text-sm leading-relaxed text-muted">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ol>
    </div>
  );
}
