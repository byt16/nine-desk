import type { Cve } from "./types";

/**
 * Second 2026 KEV pass: internet-facing initial access only
 * (VPN / edge / RMM / mail / identity). WordPress, Joomla, Langflow,
 * Apple screensharing, TrueConf stay out.
 */
export const PASS2_CVES: Cve[] = [
  {
    id: "CVE-2026-15409",
    name: "SonicWall SMA1000 Workplace SSRF",
    cvss: 10.0,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    published: "2026-07-15",
    vendor: "SonicWall",
    product: "SMA1000",
    cwe: "CWE-918",
    kev: true,
    ransomware: true,
    summary:
      "Unauthenticated Work Place SSRF on SMA1000, chained in the wild with admin command injection to unauthenticated RCE. Distinct from the later SMA1000 SSRF (CVE-2026-83548) already on this desk.",
    impact:
      "SSL-VPN appliance as root. Session tokens, LDAP binds, and a foothold into the corporate network. Ransomware affiliates used the chain.",
    affected: ["SMA1000 appliances prior to the July 2026 SonicWall firmware"],
    detect: [
      "Confirm SMA1000 firmware is past the July 2026 security release.",
      "SMA1000 management and Work Place must not be on the public internet without an allowlist.",
      "Hunt unexpected outbound fetches from the appliance and new admin sessions.",
    ],
    remediate: [
      "Apply the SonicWall firmware.",
      "Rebuild the appliance if it was unpatched and public.",
      "Rotate directory, VPN, and appliance credentials.",
    ],
    category: "ssrf",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "NVD", href: "https://nvd.nist.gov/vuln/detail/CVE-2026-15409" },
    ],
  },
  {
    id: "CVE-2026-20182",
    name: "Cisco Catalyst SD-WAN vdaemon bypass",
    cvss: 10.0,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    published: "2026-05-06",
    vendor: "Cisco",
    product: "Catalyst SD-WAN / vManage",
    cwe: "CWE-287",
    kev: true,
    ransomware: false,
    summary:
      "Unauthenticated remote auth bypass via vdaemon DTLS vHub device-type confusion. An internet-reachable SD-WAN controller accepts a peer it should have rejected.",
    impact:
      "Control-plane of the SD-WAN fabric. Route tables, certificates, and reachability into every site.",
    affected: ["Cisco Catalyst SD-WAN / vManage trains named in the May 2026 Cisco advisory"],
    detect: [
      "vManage and vBond interfaces must not be on the public internet.",
      "Confirm the May 2026 Cisco fixed release is installed.",
      "Review DTLS peer tables for unexpected vHub device types.",
    ],
    remediate: [
      "Upgrade vManage / controllers to the fixed train.",
      "Rotate controller certificates and site credentials.",
      "Rebuild if the controller was unpatched and public.",
    ],
    category: "auth-bypass",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "Cisco", href: "https://sec.cloudapps.cisco.com/security/center/publicationListing.x" },
    ],
  },
  {
    id: "CVE-2026-20127",
    name: "Cisco Catalyst SD-WAN peering bypass",
    cvss: 10.0,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    published: "2026-02-11",
    vendor: "Cisco",
    product: "Catalyst SD-WAN",
    cwe: "CWE-287",
    kev: true,
    ransomware: false,
    summary:
      "Peering authentication bypass enabling fabric-wide NETCONF access. UAT-8616 exploited the class of defect in the wild for years before the 2026 CVE.",
    impact:
      "Any site on the fabric. NETCONF as the controller, then configuration and traffic of every spoke.",
    affected: ["Cisco Catalyst SD-WAN controllers prior to the February 2026 advisory"],
    detect: [
      "Controller overlay ports must not be on the public internet.",
      "Confirm the February 2026 Cisco fixed release.",
      "Audit NETCONF sessions originating off the expected controller identity.",
    ],
    remediate: [
      "Upgrade controllers and edges in lockstep.",
      "Rotate overlay certificates.",
      "Treat a public unpatched controller as compromised.",
    ],
    category: "auth-bypass",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "Cisco", href: "https://sec.cloudapps.cisco.com/security/center/publicationListing.x" },
    ],
  },
  {
    id: "CVE-2026-20131",
    name: "Cisco FMC Java deserialization",
    cvss: 10.0,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    published: "2026-03-11",
    vendor: "Cisco",
    product: "Secure Firewall Management Center",
    cwe: "CWE-502",
    kev: true,
    ransomware: false,
    summary:
      "Unauthenticated Java deserialization on Cisco Secure Firewall Management Center. A single request to a management listener yields RCE as the FMC process.",
    impact:
      "The brain of the firewall estate: policies, VPN configs, and a path onto every managed sensor.",
    affected: ["Cisco Secure FMC builds named in the March 2026 Cisco advisory"],
    detect: [
      "FMC management must not be on the public internet.",
      "Confirm the March 2026 fixed FMC train.",
      "Hunt unexpected child processes of the FMC Java service.",
    ],
    remediate: [
      "Upgrade FMC.",
      "Rotate admin, API, and directory credentials.",
      "Rebuild if the manager was unpatched and public.",
    ],
    category: "deserialization",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "Cisco", href: "https://sec.cloudapps.cisco.com/security/center/publicationListing.x" },
    ],
  },
  {
    id: "CVE-2026-0300",
    name: "PAN-OS authentication portal OOB write",
    cvss: 9.3,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
    published: "2026-05-13",
    vendor: "Palo Alto Networks",
    product: "PAN-OS",
    cwe: "CWE-787",
    kev: true,
    ransomware: true,
    summary:
      "Unauthenticated out-of-bounds write in the PAN-OS authentication portal. Internet-facing captive-portal / auth pages were the entry.",
    impact:
      "Firewall as root. Then the networks behind it. Same operator class that lives on GlobalProtect.",
    affected: ["PAN-OS 10.2 / 11.1 / 11.2 / 12.1 trains prior to the May 2026 hotfixes"],
    detect: [
      "Compare PAN-OS to the May 2026 PAN-SA fixed builds.",
      "Authentication portal on a public interface is the exposure.",
      "Review dp-logs and crash dumps around the portal process.",
    ],
    remediate: [
      "Upgrade PAN-OS to the fixed hotfix in your train.",
      "If the portal was public and unpatched, rebuild and rotate.",
      "Do not leave captive portal on an unfiltered WAN IP.",
    ],
    category: "memory",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "Palo Alto", href: "https://security.paloaltonetworks.com/" },
    ],
  },
  {
    id: "CVE-2026-0257",
    name: "PAN-OS GlobalProtect cookie bypass",
    cvss: 9.1,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    published: "2026-05-13",
    vendor: "Palo Alto Networks",
    product: "PAN-OS GlobalProtect",
    cwe: "CWE-565",
    kev: true,
    ransomware: true,
    summary:
      "GlobalProtect trusts any authentication-override cookie it can decrypt. If that certificate is reused on the public HTTPS service, an attacker forges a session for any user — including admin — and lands on the VPN. Qilin used it.",
    impact:
      "Unauthorized VPN tunnel. No password, no MFA. Then Impacket and NTLM relay on the inside.",
    affected: [
      "PAN-OS 10.2 / 11.1 / 11.2 / 12.1 with GlobalProtect and authentication-override cookies, prior to May 2026 hotfixes",
      "Prisma Access 10.2 / 11.2 in the same window",
    ],
    detect: [
      "GlobalProtect plus authentication-override cookies is the vulnerable config.",
      "Confirm PAN-OS is on 12.1.4-h6 / 12.1.7, 11.2.4-h17, 11.1.4-h33, 10.2.7-h34 or the later listed hotfixes.",
      "Hunt GlobalProtect logins for users who did not complete MFA.",
    ],
    remediate: [
      "Upgrade PAN-OS.",
      "Disable authentication-override cookies, or issue a certificate used only for that feature.",
      "Rotate VPN, directory, and firewall admin credentials.",
    ],
    category: "auth-bypass",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "Palo Alto", href: "https://security.paloaltonetworks.com/" },
    ],
  },
  {
    id: "CVE-2026-50751",
    name: "Check Point IKEv1 VPN auth bypass",
    cvss: 9.3,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
    published: "2026-06-17",
    vendor: "Check Point",
    product: "Security Gateway",
    cwe: "CWE-287",
    kev: true,
    ransomware: true,
    summary:
      "IKEv1 authentication bypass on Check Point Security Gateway. Unauthenticated VPN access. Qilin ransomware affiliates exploited it against internet-facing gateways.",
    impact:
      "A VPN session without credentials. Then the LAN behind the gateway.",
    affected: ["Check Point Security Gateway trains named in the June 2026 Check Point advisory"],
    detect: [
      "IKEv1 on a public interface is the exposure.",
      "Confirm the June 2026 jumbo / hotfix is installed.",
      "Review IKE logs for tunnels that never completed user auth.",
    ],
    remediate: [
      "Apply the Check Point hotfix.",
      "Prefer IKEv2; disable IKEv1 if the business allows it.",
      "Rotate VPN secrets and directory credentials.",
    ],
    category: "auth-bypass",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "Check Point", href: "https://supportcenter.checkpoint.com/" },
    ],
  },
  {
    id: "CVE-2026-24858",
    name: "FortiCloud SSO cross-tenant bypass",
    cvss: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    published: "2026-01-14",
    vendor: "Fortinet",
    product: "FortiCloud SSO",
    cwe: "CWE-287",
    kev: true,
    ransomware: false,
    summary:
      "Cross-tenant authentication bypass in FortiCloud SSO. An attacker logs into another customer's Fortinet devices through the cloud identity path.",
    impact:
      "Admin on someone else's firewall, switch, or EMS. Configuration, VPN, and a path into that tenant's network.",
    affected: ["Fortinet products using FortiCloud SSO prior to the January 2026 FortiGuard advisory"],
    detect: [
      "Inventory devices with FortiCloud SSO enabled.",
      "Confirm the January 2026 Fortinet fixed firmware / cloud-side fix.",
      "Review FortiCloud login history for foreign tenants and unexpected geos.",
    ],
    remediate: [
      "Apply the Fortinet advisory.",
      "Rotate FortiCloud and local admin credentials.",
      "Disable FortiCloud SSO on appliances that do not need it.",
    ],
    category: "auth-bypass",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "Fortinet", href: "https://www.fortiguard.com/psirt" },
    ],
  },
  {
    id: "CVE-2026-3055",
    name: "Citrix NetScaler SAML IDP overread",
    cvss: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    published: "2026-03-25",
    vendor: "Cloud Software Group",
    product: "NetScaler ADC / Gateway",
    cwe: "CWE-125",
    kev: true,
    ransomware: false,
    summary:
      "Pre-auth memory overread in NetScaler SAML identity-provider handling. Distinct from the August CTX696604 overflow (CVE-2026-8452) already on this desk.",
    impact:
      "Gateway memory: session tokens, SAML secrets, then the applications behind the VIP.",
    affected: ["NetScaler ADC and Gateway builds listed in the March 2026 Citrix advisory"],
    detect: [
      "SAML IDP on an internet VIP is the exposure.",
      "Compare firmware to the March 2026 fixed builds.",
      "Collect crash dumps around SAML IDP handling.",
    ],
    remediate: [
      "Upgrade firmware.",
      "Terminate sessions and rotate IdP / directory credentials.",
      "Rebuild if the box was unpatched and public.",
    ],
    category: "memory",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "Citrix", href: "https://support.citrix.com/" },
    ],
  },
  {
    id: "CVE-2026-8037",
    name: "Kemp LoadMaster escape_quotes RCE",
    cvss: 9.6,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    published: "2026-08-18",
    vendor: "Progress",
    product: "Kemp LoadMaster",
    cwe: "CWE-122",
    kev: true,
    ransomware: false,
    summary:
      "Pre-auth root RCE via uninitialized heap in escape_quotes() on Progress Kemp LoadMaster. The load balancer is the edge.",
    impact:
      "Root on the balancer: certificates, real-server credentials, and a view of every VIP.",
    affected: ["Kemp LoadMaster builds prior to the August 2026 Progress advisory"],
    detect: [
      "LoadMaster WUI must not be on the public internet.",
      "Confirm the August 2026 firmware.",
      "Hunt unexpected root processes and new admin users on the appliance.",
    ],
    remediate: [
      "Apply the Progress firmware.",
      "Rotate balancer, VIP, and backend credentials.",
      "Rebuild if the WUI was public and unpatched.",
    ],
    category: "rce",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "NVD", href: "https://nvd.nist.gov/vuln/detail/CVE-2026-8037" },
    ],
  },
  {
    id: "CVE-2026-1731",
    name: "BeyondTrust RS/PRA WebSocket RCE",
    cvss: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    published: "2026-02-06",
    vendor: "BeyondTrust",
    product: "Remote Support / Privileged Remote Access",
    cwe: "CWE-78",
    kev: true,
    ransomware: false,
    summary:
      "Pre-auth OS command injection in the thin SCC wrapper. Crafted WebSocket input (remoteVersion) is evaluated as bash arithmetic. VShell and SparkRAT followed in the wild. SaaS was patched 2026-02-02; self-hosted was not.",
    impact:
      "The support appliance as the site user, then admin accounts and every endpoint it can reach.",
    affected: [
      "Remote Support 25.3.1 and prior (fixed 25.3.2 / BT26-02-RS)",
      "Privileged Remote Access 24.3.4 and prior (fixed 25.1 / BT26-02-PRA)",
    ],
    detect: [
      "Self-hosted RS/PRA on the public internet is the exposure. SaaS was patched by the vendor.",
      "Confirm RS ≥ 25.3.2 or BT26-02-RS, PRA ≥ 25.1 or BT26-02-PRA.",
      "Hunt new admin users, web shells, SparkRAT / VShell, and DNS tunneling from the appliance.",
    ],
    remediate: [
      "Apply BT26-02 or upgrade.",
      "Rebuild self-hosted appliances that were public and unpatched.",
      "Rotate appliance, directory, and jumphost credentials.",
    ],
    category: "rce",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "BeyondTrust BT26-02", href: "https://www.beyondtrust.com/trust-center/security-advisories/bt26-02" },
    ],
  },
  {
    id: "CVE-2026-1340",
    name: "Ivanti EPMM Android file-transfer RCE",
    cvss: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    published: "2026-04-14",
    vendor: "Ivanti",
    product: "Endpoint Manager Mobile",
    cwe: "CWE-78",
    kev: true,
    ransomware: false,
    summary:
      "Pre-auth RCE in Ivanti EPMM via Android file-transfer URL injection. The MDM plane is the target, not the phone.",
    impact:
      "MDM as the service account: device inventory, enrollments, and a path onto the management network.",
    affected: ["Ivanti EPMM builds prior to the April 2026 Ivanti security update"],
    detect: [
      "EPMM admin and device-facing portals must not be on the public internet without an allowlist.",
      "Confirm the April 2026 Ivanti fixed release.",
      "Hunt unexpected child processes of the EPMM service.",
    ],
    remediate: [
      "Apply the Ivanti update.",
      "Rotate MDM, directory, and APNs / push credentials.",
      "Treat a public unpatched EPMM as compromised.",
    ],
    category: "rce",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "Ivanti", href: "https://www.ivanti.com/blog/security-advisories" },
    ],
  },
  {
    id: "CVE-2026-1281",
    name: "Ivanti EPMM App Store URL injection",
    cvss: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    published: "2026-01-21",
    vendor: "Ivanti",
    product: "Endpoint Manager Mobile",
    cwe: "CWE-78",
    kev: true,
    ransomware: false,
    summary:
      "Pre-auth RCE via App Store URL bash injection. Same product class as CVE-2026-1340, earlier in the year. EPMM keeps landing on KEV.",
    impact:
      "MDM host and every enrolled device the console can push to.",
    affected: ["Ivanti EPMM builds prior to the January 2026 Ivanti security update"],
    detect: [
      "EPMM on a public IP is the exposure.",
      "Confirm the January 2026 fixed release, then the April 2026 follow-up.",
      "Review App Store / catalog logs for unexpected URLs.",
    ],
    remediate: [
      "Apply both 2026 EPMM advisories.",
      "Bind the console to a management network.",
      "Rotate MDM and directory credentials.",
    ],
    category: "rce",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "Ivanti", href: "https://www.ivanti.com/blog/security-advisories" },
    ],
  },
  {
    id: "CVE-2026-21643",
    name: "FortiClient EMS Site-header SQLi",
    cvss: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    published: "2026-04-08",
    vendor: "Fortinet",
    product: "FortiClient EMS",
    cwe: "CWE-89",
    kev: true,
    ransomware: false,
    summary:
      "Pre-auth SQL injection via the Site HTTP header on FortiClient EMS. The endpoint-management plane is internet-facing in too many estates.",
    impact:
      "EMS database and then the host. Endpoint inventory, installer tokens, and a push channel onto every FortiClient.",
    affected: ["FortiClient EMS versions named in the April 2026 FortiGuard advisory"],
    detect: [
      "EMS web UI must not be on the public internet.",
      "Confirm the April 2026 Fortinet fixed build.",
      "Review SQL and HTTP logs for unexpected Site header values.",
    ],
    remediate: [
      "Apply the FortiGuard update.",
      "Rotate EMS, directory, and FortiClient enrollment credentials.",
      "Rebuild if the UI was public and unpatched.",
    ],
    category: "injection",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "Fortinet", href: "https://www.fortiguard.com/psirt" },
    ],
  },
  {
    id: "CVE-2026-35616",
    name: "FortiClient EMS pre-auth RCE",
    cvss: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    published: "2026-04-08",
    vendor: "Fortinet",
    product: "FortiClient EMS",
    cwe: "CWE-94",
    kev: true,
    ransomware: false,
    summary:
      "Pre-authentication remote code execution on FortiClient EMS, disclosed with the Site-header SQLi. Two doors on the same console.",
    impact:
      "EMS host as the service account, then every enrolled endpoint.",
    affected: ["FortiClient EMS versions named in the April 2026 FortiGuard advisory"],
    detect: [
      "Same exposure as CVE-2026-21643: a public EMS UI.",
      "Confirm the April 2026 fixed build covers both CVEs.",
      "Hunt unexpected child processes of the EMS service.",
    ],
    remediate: [
      "Apply the FortiGuard update.",
      "Bind EMS to a management network.",
      "Rotate enrollment and directory credentials.",
    ],
    category: "rce",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "Fortinet", href: "https://www.fortiguard.com/psirt" },
    ],
  },
  {
    id: "CVE-2026-24423",
    name: "SmarterMail ConnectToHub RCE",
    cvss: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    published: "2026-02-18",
    vendor: "SmarterTools",
    product: "SmarterMail",
    cwe: "CWE-78",
    kev: true,
    ransomware: false,
    summary:
      "Unauthenticated ConnectToHub API follows a malicious server redirect into OS command execution. Internet-facing mail appliances were hit.",
    impact:
      "Mail host as the service account: mailboxes, credentials, and a pivot onto the LAN.",
    affected: ["SmarterMail builds prior to the February 2026 SmarterTools advisory"],
    detect: [
      "SmarterMail admin and API must not be on the public internet without an allowlist.",
      "Confirm the February 2026 fixed build.",
      "Hunt ConnectToHub calls to unexpected hosts.",
    ],
    remediate: [
      "Upgrade SmarterMail.",
      "Disable ConnectToHub if unused.",
      "Rotate mail, directory, and host credentials.",
    ],
    category: "rce",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "NVD", href: "https://nvd.nist.gov/vuln/detail/CVE-2026-24423" },
    ],
  },
  {
    id: "CVE-2026-23760",
    name: "SmarterMail IsSysAdmin reset",
    cvss: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    published: "2026-01-28",
    vendor: "SmarterTools",
    product: "SmarterMail",
    cwe: "CWE-306",
    kev: true,
    ransomware: false,
    summary:
      "Unauthenticated admin password reset via IsSysAdmin bypass. Exploited within two days of the patch. Same product as CVE-2026-24423.",
    impact:
      "Admin on the mail server. Then every mailbox.",
    affected: ["SmarterMail builds prior to the January 2026 SmarterTools advisory"],
    detect: [
      "Password-reset and admin endpoints on a public IP are the exposure.",
      "Confirm the January 2026 fixed build, then the February follow-up.",
      "Review admin-reset events that did not originate from known operators.",
    ],
    remediate: [
      "Upgrade SmarterMail.",
      "Rotate every admin and mailbox credential issued from that host.",
      "Bind admin UI to a management network.",
    ],
    category: "auth-bypass",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "NVD", href: "https://nvd.nist.gov/vuln/detail/CVE-2026-23760" },
    ],
  },
  {
    id: "CVE-2026-41940",
    name: "cPanel WHM pre-auth CRLF",
    cvss: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    published: "2026-04-21",
    vendor: "WebPros",
    product: "cPanel & WHM",
    cwe: "CWE-93",
    kev: true,
    ransomware: true,
    summary:
      "Pre-auth CRLF injection grants unauthenticated root WHM. Hosting control planes on the public internet, exploited in the wild, ransomware-flagged.",
    impact:
      "Root on the hosting box: every site, every mailbox, every customer.",
    affected: ["cPanel & WHM and WP2 builds prior to the April 2026 WebPros advisory"],
    detect: [
      "WHM and cPanel must not be on the public internet without an allowlist and MFA.",
      "Confirm the April 2026 WebPros fixed build.",
      "Hunt new root WHM sessions and unexpected cron / reseller accounts.",
    ],
    remediate: [
      "Upgrade cPanel / WHM.",
      "Rotate WHM, root, and customer credentials.",
      "Treat a public unpatched WHM as a full-host compromise.",
    ],
    category: "injection",
    references: [
      { label: "CISA KEV", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { label: "NVD", href: "https://nvd.nist.gov/vuln/detail/CVE-2026-41940" },
    ],
  },
];

export const PASS2 = {
  date: "2026-09-09",
  added: PASS2_CVES.length,
  kev2026HeldAfter: 39,
  kev2026Critical: 71,
  scope: "VPN / edge / RMM / mail / identity",
} as const;
