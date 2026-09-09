# NINE

Defensive intelligence desk for **CVSS 9.0+** vulnerabilities and equivalent server misconfigurations. Detection and hardening only — no scanners, no payloads.

## Open on Vercel

This repo is set up for a Git import:

1. Open [vercel.com/new](https://vercel.com/new)
2. Import **`byt16/nine-desk`**
3. Framework: leave auto. Build command is already `npm run build`.
4. Deploy.

No database and no auth. The catalog is static.

## Local

```bash
npm install
npm run dev
```

## Catalog

| | |
|---|---|
| On the desk | 52 CVEs ≥ 9.0 |
| CISA KEV | 52 known-exploited |
| 2026 KEV 9+ held | 21 of 71 (internet-facing initial access) |
