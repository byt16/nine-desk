import { createFileRoute, Link } from "@tanstack/react-router";
import { Badge } from "@/components/ui/badge";
import { ScoreMark } from "@/components/score-mark";
import { WatchMisconfig } from "@/components/watch-toggle";
import { CveRow } from "@/components/cve-row";
import { getMisconfig, relatedCves } from "@/lib/data";

export const Route = createFileRoute("/misconfigs/$slug")({
  component: MisconfigDetail,
});

function MisconfigDetail() {
  const { slug } = Route.useParams();
  const m = getMisconfig(slug);
  if (!m) {
    return (
      <main className="py-10">
        <p className="font-mono text-xs text-muted">Unknown record</p>
        <h1 className="mt-3 font-display text-4xl italic">{slug}</h1>
        <Link
          to="/misconfigs"
          className="mt-6 inline-flex h-11 items-center text-sm text-fg"
        >
          Back to misconfigs
        </Link>
      </main>
    );
  }

  const related = relatedCves(m.relatedCves);

  return (
    <main>
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-muted">
        Equivalent critical
      </p>
      <div className="mt-4 flex flex-col gap-6 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h1 className="font-display text-4xl italic tracking-tight sm:text-5xl">
            {m.title}
          </h1>
          <div className="mt-4 flex flex-wrap gap-2">
            <Badge tone="critical">{m.cwe}</Badge>
            <Badge>{m.owasp}</Badge>
            {m.cis ? <Badge tone="outline">{m.cis}</Badge> : null}
          </div>
        </div>
        <div className="flex shrink-0 flex-col items-start gap-3 sm:items-end">
          <ScoreMark score={m.equivalent} size="lg" />
          <WatchMisconfig slug={m.slug} />
        </div>
      </div>

      <p className="mt-8 max-w-2xl text-base leading-relaxed text-muted">
        {m.summary}
      </p>

      <section className="mt-10">
        <h2 className="font-display text-2xl italic tracking-tight">
          Why it scores here
        </h2>
        <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted">
          {m.why}
        </p>
      </section>

      <section className="mt-10 grid gap-8 lg:grid-cols-3">
        <ListBlock title="What it looks like" items={m.looksLike} />
        <ListBlock title="Detect" items={m.detect} />
        <ListBlock title="Harden" items={m.harden} />
      </section>

      {related.length ? (
        <section className="mt-10">
          <h2 className="font-display text-2xl italic tracking-tight">
            Productized as CVE
          </h2>
          <p className="mt-1 text-sm text-muted">
            The same class, with a number attached.
          </p>
          <div className="mt-4 flex flex-col gap-2">
            {related.map((cve) => (
              <CveRow key={cve.id} cve={cve} />
            ))}
          </div>
        </section>
      ) : null}
    </main>
  );
}

function ListBlock({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <h2 className="font-display text-2xl italic tracking-tight">{title}</h2>
      <ul className="mt-3 space-y-2 text-sm leading-relaxed text-muted">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
