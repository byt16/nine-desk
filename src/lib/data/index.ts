import { CVES as CORE_CVES } from "./cves";
import { GAP_CVES, GAP_PASS } from "./cves-gap";
import { PASS2_CVES, PASS2 } from "./cves-pass2";
import { MISCONFIGS } from "./misconfigs";
import type { Cve, Misconfig } from "./types";

export type { Cve, CveCategory, Misconfig } from "./types";
export { CATEGORY_LABEL } from "./types";
export { MISCONFIGS } from "./misconfigs";
export { GAP_PASS, GAP_CVES } from "./cves-gap";
export { PASS2, PASS2_CVES } from "./cves-pass2";

export const CVES: Cve[] = [...CORE_CVES, ...GAP_CVES, ...PASS2_CVES];

const CVE_BY_ID = new Map(CVES.map((c) => [c.id, c]));
const MIS_BY_SLUG = new Map(MISCONFIGS.map((m) => [m.slug, m]));
const GAP_IDS = new Set(GAP_CVES.map((c) => c.id));
const PASS2_IDS = new Set(PASS2_CVES.map((c) => c.id));

export function isGapCve(id: string): boolean {
  return GAP_IDS.has(id);
}

export function isPass2Cve(id: string): boolean {
  return PASS2_IDS.has(id);
}

export function isAddedCve(id: string): boolean {
  return GAP_IDS.has(id) || PASS2_IDS.has(id);
}

export function getCve(id: string): Cve | undefined {
  return CVE_BY_ID.get(id.toUpperCase()) ?? CVE_BY_ID.get(id);
}

export function getMisconfig(slug: string): Misconfig | undefined {
  return MIS_BY_SLUG.get(slug);
}

export function relatedCves(ids: string[]): Cve[] {
  return ids.map(getCve).filter((c): c is Cve => Boolean(c));
}

export function cvesForMisconfig(slug: string): Misconfig[] {
  return MISCONFIGS.filter((m) => m.relatedCves.includes(slug));
}

export function misconfigsForCve(id: string): Misconfig[] {
  return MISCONFIGS.filter((m) => m.relatedCves.includes(id));
}

export function searchCves(query: string): Cve[] {
  const q = query.trim().toLowerCase();
  if (!q) return CVES;
  return CVES.filter((c) => {
    const hay = [
      c.id,
      c.name,
      c.vendor,
      c.product,
      c.cwe,
      c.summary,
      c.category,
    ]
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  });
}

export function searchMisconfigs(query: string): Misconfig[] {
  const q = query.trim().toLowerCase();
  if (!q) return MISCONFIGS;
  return MISCONFIGS.filter((m) => {
    const hay = [m.slug, m.title, m.owasp, m.cwe, m.summary, m.cis ?? ""]
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  });
}

export function deskStats() {
  const kev = CVES.filter((c) => c.kev).length;
  const ten = CVES.filter((c) => c.cvss >= 10).length;
  const ransomware = CVES.filter((c) => c.ransomware).length;
  const y2026 = CVES.filter((c) => c.published.startsWith("2026")).length;
  const max = Math.max(...CVES.map((c) => c.cvss));
  return {
    cves: CVES.length,
    kev,
    ten,
    ransomware,
    misconfigs: MISCONFIGS.length,
    max,
    floor: 9.0,
    y2026,
    gapAdded: GAP_PASS.added,
    firstCut: GAP_PASS.firstCut,
    kev2026Critical: GAP_PASS.kev2026Critical,
    pass2Added: PASS2.added,
  };
}

export function cvesByYear(): { year: string; count: number }[] {
  const map = new Map<string, number>();
  for (const c of CVES) {
    const year = c.published.slice(0, 4);
    map.set(year, (map.get(year) ?? 0) + 1);
  }
  return [...map.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([year, count]) => ({ year, count }));
}

export function cvesByBand(): { band: string; count: number }[] {
  const bands = [
    { band: "10.0", count: 0 },
    { band: "9.8–9.9", count: 0 },
    { band: "9.5–9.7", count: 0 },
    { band: "9.0–9.4", count: 0 },
  ];
  for (const c of CVES) {
    if (c.cvss >= 10) bands[0].count += 1;
    else if (c.cvss >= 9.8) bands[1].count += 1;
    else if (c.cvss >= 9.5) bands[2].count += 1;
    else bands[3].count += 1;
  }
  return bands;
}

export function latestKev(limit = 6): Cve[] {
  return [...CVES]
    .filter((c) => c.kev)
    .sort((a, b) => b.published.localeCompare(a.published) || b.cvss - a.cvss)
    .slice(0, limit);
}

export function topMisconfigs(limit = 6): Misconfig[] {
  return [...MISCONFIGS]
    .sort((a, b) => b.equivalent - a.equivalent)
    .slice(0, limit);
}

export function gapCves(): Cve[] {
  return [...GAP_CVES].sort(
    (a, b) => b.published.localeCompare(a.published) || b.cvss - a.cvss,
  );
}

export function pass2Cves(): Cve[] {
  return [...PASS2_CVES].sort(
    (a, b) => b.published.localeCompare(a.published) || b.cvss - a.cvss,
  );
}
