import type { Misconfig } from "./types";

export const MISCONFIGS: Misconfig[] = [
  {
    slug: "default-credentials",
    title: "Default or shared credentials",
    equivalent: 9.8,
    cis: "CIS 5.2",
    owasp: "A07 Identification and Authentication Failures",
    cwe: "CWE-798",
    summary:
      "Vendor-default, documented-demo, or shared admin passwords on consoles, databases, and appliances. Equivalent to an unauthenticated critical when the service is reachable.",
    looksLike: [
      "Admin/admin, root/changeme, postgres/postgres still accepted on a management port.",
      "A single password reused across jump hosts, hypervisors, and backup consoles.",
      "API tokens committed in the image or in a public README.",
    ],
    why: "Default credentials are how internet-wide scanners land SYSTEM on NAS, cameras, RMM, and cloud consoles. CVSS 9+ auth-bypass CVEs are often just this class, productized.",
    detect: [
      "Attempt a documented default only against assets you own, from an inventory — never against third parties.",
      "Flag any login success with vendor-default usernames.",
      "Secret scanning in images, IaC, and ticket exports.",
    ],
    harden: [
      "Force unique credentials at first boot; refuse to start with defaults.",
      "SSO + phishing-resistant MFA on every console.",
      "Break-glass accounts in a sealed vault, not a shared spreadsheet.",
    ],
    relatedCves: ["CVE-2026-82329", "CVE-2024-1709", "CVE-2023-22515", "CVE-2024-27198", "CVE-2025-31161"],
  },
  {
    slug: "exposed-git",
    title: "Exposed .git or source archives",
    equivalent: 9.1,
    owasp: "A01 Broken Access Control",
    cwe: "CWE-538",
    summary:
      "The Git directory, .svn, or a deployment zip is served by the web root. Attackers reconstruct source, secrets, and infrastructure from it.",
    looksLike: [
      "GET /.git/HEAD returns ref: refs/heads/main.",
      "GET /.git/config leaks remotes.",
      "A downloadable dist.zip or backup.tgz next to the application.",
    ],
    why: "Source plus .env history is usually enough to take the application and its cloud account. Severity tracks the secrets in the repo, not the misconfig in isolation.",
    detect: [
      "Request /.git/HEAD, /.svn/entries, /backup.zip only on properties you own.",
      "WAF or scanner signature for SCM metadata paths.",
      "Deny rules in nginx/Apache/CDN for dotfiles.",
    ],
    harden: [
      "Deploy a build artifact, never a working tree.",
      "Return 404 for /.git, /.svn, /.hg, /.env, /vendor/.",
      "Rotate every secret that ever lived in that repository.",
    ],
    relatedCves: ["CVE-2026-60004"],
  },
  {
    slug: "dotenv-and-backups",
    title: "Readable .env, backups, and dumps",
    equivalent: 9.8,
    owasp: "A02 Cryptographic Failures",
    cwe: "CWE-200",
    summary:
      "Application secrets, SQL dumps, and configuration backups sitting in a web-reachable path. Direct credential disclosure.",
    looksLike: [
      "GET /.env, /wp-config.php.bak, /config.yml, /.aws/credentials returns 200.",
      "A world-readable mysqldump-*.sql in /backup or an open object store.",
      "Source maps shipping production API URLs and internal hostnames.",
    ],
    why: "One 200 on .env is usually database, JWT, and cloud-key compromise in a single request. Treat it as a 9.8 even without a CVE.",
    detect: [
      "Inventory robots, sitemap, and leftover files after deploys.",
      "Block well-known secret filenames at the edge.",
      "Alert on 200s for *.sql, *.bak, *.env, *credentials*.",
    ],
    harden: [
      "Keep secrets in a manager, not on disk next to the app.",
      "Object-storage buckets private by default; no public ACLs.",
      "Rotate every value that was reachable.",
    ],
    relatedCves: ["CVE-2026-82329", "CVE-2025-31324"],
  },
  {
    slug: "open-admin",
    title: "Admin consoles on the public internet",
    equivalent: 9.8,
    cis: "CIS 3.3",
    owasp: "A01 Broken Access Control",
    cwe: "CWE-749",
    summary:
      "vCenter, Veeam, FortiGate, Jenkins, Kestra, N-central, phpMyAdmin, Kubernetes dashboard — reachable on 0.0.0.0 or a public VIP. The CVE is optional; the exposure is the incident.",
    looksLike: [
      "A management UI answers on :443 from an untrusted network.",
      "No allow-list, no SSO, no MFA.",
      "The same origin serves both customers and operators.",
    ],
    why: "Every 10.0 in this desk that is currently on KEV is, first, an internet-facing admin plane. Patching without shrinking the attack surface repeats the event.",
    detect: [
      "External attack-surface management: find admin titles, default ports, TLS names.",
      "Compare production DNS to an inventory of consoles that should be private.",
      "Fail a control if a management port answers from outside the VPN/ZTNA range.",
    ],
    harden: [
      "Management plane on a dedicated network or identity-aware proxy.",
      "No public VIP for backup, virtualization, RMM, CI, or identity.",
      "SSO + hardware-backed MFA; break-glass offline.",
    ],
    relatedCves: [
      "CVE-2026-49869",
      "CVE-2026-59310",
      "CVE-2024-40711",
      "CVE-2024-1709",
      "CVE-2026-86218",
      "CVE-2026-34910",
      "CVE-2026-48558",
      "CVE-2026-10520",
      "CVE-2024-27198",
      "CVE-2026-63077",
    ],
  },
  {
    slug: "directory-listing",
    title: "Directory listing enabled",
    equivalent: 7.5,
    owasp: "A01 Broken Access Control",
    cwe: "CWE-548",
    summary:
      "The server renders an index of files when a directory is requested. Combined with backups or writable upload dirs this becomes source and secret disclosure.",
    looksLike: [
      "GET /uploads/ or /static/ returns an HTML file list.",
      "Apache Options +Indexes, nginx autoindex on, or a framework static-file app in debug.",
    ],
    why: "Listing alone is medium. Listing plus a dump, key, or upload directory is critical. Score the combination, not the checkbox.",
    detect: [
      "Request directory URLs on properties you own and expect 403.",
      "Disable autoindex in the baseline image.",
    ],
    harden: [
      "autoindex off; Options -Indexes.",
      "No default document? Return 403, not a listing.",
      "Upload directories outside the web root, served through an authorized handler.",
    ],
    relatedCves: ["CVE-2025-31324"],
  },
  {
    slug: "wildcard-cors",
    title: "Wildcard CORS with credentials",
    equivalent: 9.1,
    owasp: "A05 Security Misconfiguration",
    cwe: "CWE-942",
    summary:
      "Access-Control-Allow-Origin: * (or reflecting any Origin) together with Allow-Credentials: true. Any website can read authenticated API responses in the victim's browser.",
    looksLike: [
      "ACA-Origin is * or echoes the request Origin without an allow-list.",
      "ACA-Credentials is true.",
      "Session is a cookie, not a header bearer the foreign page cannot set.",
    ],
    why: "This is account takeover for every user who visits a malicious page while logged in. Equivalent to a stored XSS on the API origin.",
    detect: [
      "Inspect preflight responses from your own API.",
      "Fail CI if ACA-Origin is * and credentials are allowed.",
    ],
    harden: [
      "Explicit origin allow-list. Never * with cookies.",
      "Prefer authorization headers over cookie sessions for APIs.",
      "SameSite=Strict on cookies that remain.",
    ],
    relatedCves: ["CVE-2025-29927"],
  },
  {
    slug: "missing-headers",
    title: "Missing security headers",
    equivalent: 6.5,
    owasp: "A05 Security Misconfiguration",
    cwe: "CWE-693",
    summary:
      "No HSTS, CSP, frame-ancestors, or nosniff. Individually medium; together they turn XSS and cookie theft into reliable account takeover.",
    looksLike: [
      "HTTPS site without Strict-Transport-Security.",
      "No Content-Security-Policy, or default-src *.",
      "X-Powered-By and Server leaking versions.",
    ],
    why: "Headers do not patch a 10.0. They do stop the cheap follow-on: clickjacking, MIME sniffing, downgrade, and token exfil. Floor, not ceiling.",
    detect: [
      "Paste a live response into the Headers lab on this desk.",
      "Fail the pipeline if HSTS, nosniff, and a frame policy are absent on the apex origin.",
    ],
    harden: [
      "HSTS with includeSubDomains and preload once HTTPS is universal.",
      "CSP with a nonce or hash; frame-ancestors 'none' or a named parent.",
      "Strip Server and X-Powered-By.",
    ],
    relatedCves: [],
  },
  {
    slug: "insecure-cookies",
    title: "Cookies without Secure, HttpOnly, SameSite",
    equivalent: 8.1,
    owasp: "A07 Identification and Authentication Failures",
    cwe: "CWE-614",
    summary:
      "Session cookies missing Secure, HttpOnly, or SameSite. XSS or a cleartext hop becomes session theft.",
    looksLike: [
      "Set-Cookie without Secure on an HTTPS origin.",
      "Session cookie readable from document.cookie.",
      "SameSite omitted (legacy default) on a cross-site surface.",
    ],
    why: "CitrixBleed showed that stolen sessions skip MFA. Cookie flags are the cheap half of that lesson; token binding is the rest.",
    detect: [
      "Parse Set-Cookie on the login response.",
      "Fail if session cookies lack Secure; HttpOnly; SameSite=Lax or Strict.",
    ],
    harden: [
      "Secure; HttpOnly; SameSite=Strict (or Lax only if you have a documented cross-site flow).",
      "__Host- prefix where the cookie is host-only.",
      "Short TTL + server-side revocation.",
    ],
    relatedCves: ["CVE-2023-4966"],
  },
  {
    slug: "debug-and-traces",
    title: "Debug mode and stack traces in production",
    equivalent: 7.5,
    owasp: "A05 Security Misconfiguration",
    cwe: "CWE-215",
    summary:
      "Django DEBUG, Spring devtools, PHP display_errors, ASP.NET customErrors Off, verbose 500 pages. Paths, queries, versions, and sometimes secrets in the response.",
    looksLike: [
      "A 500 page with a stack, SQL, or environment dump.",
      "/_debug, /actuator, /phpinfo.php, /console reachable.",
      "Source maps on the production CDN.",
    ],
    why: "Debug endpoints have been the difference between a scanner finding a host and a scanner getting RCE (actuators, profiling consoles, TRACE).",
    detect: [
      "Request a missing route and a deliberate 500 on properties you own.",
      "Block /actuator, /_debug, /phpinfo.php at the edge.",
    ],
    harden: [
      "DEBUG off. Generic error document. Logs stay on the host.",
      "Disable TRACE, method override, and profiling consoles.",
      "Do not ship source maps to the public CDN.",
    ],
    relatedCves: ["CVE-2026-49869"],
  },
  {
    slug: "open-data-stores",
    title: "Open Redis, Mongo, Elasticsearch, Kafka",
    equivalent: 9.8,
    cis: "CIS 3.2",
    owasp: "A01 Broken Access Control",
    cwe: "CWE-306",
    summary:
      "Data stores bound to 0.0.0.0 with no AUTH, or cloud security groups that include 0.0.0.0/0 on 6379, 27017, 9200, 9092, 2379.",
    looksLike: [
      "A banner on a well-known port from an untrusted network.",
      "No requirepass, no TLS, no VPC-only binding.",
      "etcd or Kubernetes API with anonymous auth.",
    ],
    why: "Unrelated to a CVE number. A public Redis is a 9.8: session store, cache-poison, and often cron-based code execution on the host.",
    detect: [
      "External port scan of your own ranges; fail on data-store ports.",
      "Cloud config rules: no 0.0.0.0/0 on 6379/27017/9200/5432/3306/2379.",
    ],
    harden: [
      "Private subnets only. AUTH + TLS. No anonymous Kubernetes.",
      "NetworkPolicy / security groups default deny.",
      "Rotate if the port was ever public.",
    ],
    relatedCves: ["CVE-2023-46604"],
  },
  {
    slug: "public-buckets",
    title: "Public object storage",
    equivalent: 9.1,
    owasp: "A01 Broken Access Control",
    cwe: "CWE-732",
    summary:
      "S3, GCS, Azure Blob, or MinIO buckets with public ACL, a public policy, or a website endpoint serving dumps, backups, or PII.",
    looksLike: [
      "AllUsers or allAuthenticatedUsers on the bucket policy.",
      "A website endpoint listing keys.",
      "Backup tarballs, database dumps, or ID images at predictable names.",
    ],
    why: "Bucket misconfig is a recurring 9+ in practice: payroll, medical images, source, and cloud keys. No CVE required.",
    detect: [
      "CSPM: flag public ACLs and policies.",
      "Known-key probes only on buckets you own.",
    ],
    harden: [
      "Block public access at the account level.",
      "Pre-signed URLs for the exceptions.",
      "Versioning + object lock on backups.",
    ],
    relatedCves: [],
  },
  {
    slug: "tls-downgrade",
    title: "Cleartext, expired, or obsolete TLS",
    equivalent: 7.4,
    cis: "CIS 3.1",
    owasp: "A02 Cryptographic Failures",
    cwe: "CWE-319",
    summary:
      "HTTP on the apex, TLS 1.0/1.1 still offered, expired certificates, or mixed content. Session cookies then travel in the clear on some paths.",
    looksLike: [
      "No redirect from http:// to https://.",
      "Handshake offers TLS 1.0.",
      "Certificate expired or name-mismatched, users click through.",
    ],
    why: "On its own this is high, not 9. Combined with missing HSTS and Secure cookies it is full session theft on any shared network.",
    detect: [
      "Probe your own apex and www over HTTP.",
      "Fail if TLS 1.0/1.1 is offered or the cert is inside 14 days of expiry.",
    ],
    harden: [
      "HTTPS only, HSTS preload once stable.",
      "TLS 1.2+ with a modern cipher suite.",
      "Automated issuance and renewal.",
    ],
    relatedCves: [],
  },
  {
    slug: "unrestricted-upload",
    title: "Unauthenticated or unsandboxed file upload",
    equivalent: 9.8,
    owasp: "A04 Insecure Design",
    cwe: "CWE-434",
    summary:
      "Upload endpoints that accept executable types, write inside the web root, or skip authentication. The SAP, CrushFTP, and Magento 10.0s in this desk are this class.",
    looksLike: [
      "A public /upload, /media, or /api/files with no authn.",
      "Content-Type trusted from the client; extension not rewritten.",
      "Files served from the same origin they were written to.",
    ],
    why: "Write a webshell, request it, own the host. This is why Visual Composer and similar uploaders score 10.0.",
    detect: [
      "Inventory upload handlers; require authn and an allow-list of types.",
      "Uploads must land outside the web root.",
      "Scan storage for unexpected interpreters (.aspx, .jsp, .php, .cgi).",
    ],
    harden: [
      "Authenticated, type-checked, size-capped uploads.",
      "Store in object storage; serve via a separate domain with Content-Disposition: attachment.",
      "Disable script execution in upload buckets.",
    ],
    relatedCves: [
      "CVE-2025-31324",
      "CVE-2025-53770",
      "CVE-2026-75650",
      "CVE-2025-31161",
      "CVE-2025-47812",
      "CVE-2026-48282",
    ],
  },
  {
    slug: "cloud-metadata",
    title: "Cloud metadata reachable via SSRF",
    equivalent: 9.9,
    owasp: "A10 Server-Side Request Forgery",
    cwe: "CWE-918",
    summary:
      "The instance can fetch 169.254.169.254 (or the cloud equivalent) and the metadata service still issues v1 credentials without a session hop. Any SSRF becomes cloud-admin.",
    looksLike: [
      "Application features that fetch URLs on behalf of a user (webhooks, previews, PDF renderers).",
      "IMDSv1 still enabled on EC2; equivalent on other clouds.",
      "No egress filter from the workload subnet to the metadata IP.",
    ],
    why: "SSRF plus metadata is how a 5.0 becomes a 10.0. SonicWall SMA 2026 and ProxyLogon are the productized form of the same idea.",
    detect: [
      "Require IMDSv2 (or the vendor hop-by-hop equivalent) on every instance.",
      "Deny egress to the metadata IP from containers that fetch user URLs.",
      "Review webhook and preview features as SSRF surfaces.",
    ],
    harden: [
      "IMDSv2 / metadata concealment. Hop limit 1.",
      "URL allow-lists for any server-side fetch.",
      "Least-privilege instance roles; no AdministratorAccess.",
    ],
    relatedCves: ["CVE-2026-83548", "CVE-2021-26855"],
  },
  {
    slug: "http-verbs",
    title: "Dangerous HTTP methods enabled",
    equivalent: 8.6,
    owasp: "A05 Security Misconfiguration",
    cwe: "CWE-650",
    summary:
      "PUT, DELETE, TRACE, or WebDAV on the public origin. PUT-to-webroot is how several Tomcat and IIS incidents became RCE without an application bug.",
    looksLike: [
      "OPTIONS lists PUT, DELETE, TRACE, CONNECT.",
      "WebDAV modules loaded on a public site.",
      "A PUT of a harmless file under the web root succeeds.",
    ],
    why: "A writable web root is an unauthenticated upload. Score it as 9 if it lands an interpreter; otherwise high.",
    detect: [
      "OPTIONS and a controlled PUT against properties you own.",
      "Disable WebDAV, TRACE, and method override in the baseline.",
    ],
    harden: [
      "Allow-list GET, HEAD, POST (and PUT/PATCH only on authenticated APIs).",
      "Web root mounted read-only in production.",
    ],
    relatedCves: ["CVE-2025-53770"],
  },
  {
    slug: "kubernetes-open",
    title: "Open Kubernetes API or dashboard",
    equivalent: 9.8,
    owasp: "A01 Broken Access Control",
    cwe: "CWE-306",
    summary:
      "kube-apiserver, the dashboard, etcd, or kubelet ports reachable without a client certificate. Anonymous auth still enabled.",
    looksLike: [
      ":6443, :8443, :10250, :2379 answer from an untrusted network.",
      "Anonymous requests return 200 instead of 401.",
      "Dashboard with skip-login.",
    ],
    why: "Cluster admin is datacenter admin. This has been a 10.0-class incident every year since 2018 without needing a new CVE.",
    detect: [
      "External scan of your own ranges for 6443/10250/2379.",
      "Anonymous auth must be false; RBAC default deny.",
    ],
    harden: [
      "Private API endpoint. Dashboard off, or behind SSO.",
      "etcd not on the network; kubelet authn required.",
      "Rotate if any control-plane port was public.",
    ],
    relatedCves: ["CVE-2026-49869"],
  },
  {
    slug: "verbose-banner",
    title: "Version banners and fingerprinting",
    equivalent: 5.3,
    owasp: "A05 Security Misconfiguration",
    cwe: "CWE-200",
    summary:
      "Server, X-Powered-By, X-AspNet-Version, generator meta, and default error pages advertising exact versions. Not critical alone; it is how the 9+ CVE is chosen.",
    looksLike: [
      "Server: Apache/2.4.49 (Unix).",
      "X-Powered-By: PHP/8.1.0, Express, ASP.NET.",
      "Default nginx or IIS landing page on a public IP.",
    ],
    why: "Banners do not grant RCE. They collapse the attacker's search space from 'which CVE' to 'this exact one'. Strip them anyway.",
    detect: [
      "The Headers lab on this desk flags Server and X-Powered-By.",
      "Default error pages should be replaced.",
    ],
    harden: [
      "server_tokens off; Header unset X-Powered-By.",
      "Custom error documents.",
      "Do not run default sites on public addresses.",
    ],
    relatedCves: ["CVE-2021-44228", "CVE-2025-55182"],
  },
  {
    slug: "missing-rate-limit",
    title: "No rate limit on auth and reset",
    equivalent: 8.1,
    owasp: "A07 Identification and Authentication Failures",
    cwe: "CWE-307",
    summary:
      "Login, password-reset, and OTP endpoints with no throttle, lockout, or step-up. Credential stuffing and reset-token brute force become practical.",
    looksLike: [
      "Unlimited POSTs to /login, /reset, /mfa/verify.",
      "User enumeration via distinct error messages or timing.",
      "Reset tokens short, numeric, or reusable.",
    ],
    why: "Paired with default or stuffed passwords this is account takeover at scale. Metabase 2026 is the productized reset-endpoint version.",
    detect: [
      "Load-test only systems you own; expect 429.",
      "Same error text for unknown users and bad passwords.",
    ],
    harden: [
      "Per-account and per-IP throttles; 429 with jitter.",
      "Phishing-resistant MFA on privileged roles.",
      "High-entropy, single-use reset tokens.",
    ],
    relatedCves: ["CVE-2026-72898", "CVE-2024-1709", "CVE-2024-27198"],
  },
];
