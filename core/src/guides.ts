// Guided-manual provider instructions (Tier 3). For each known provider: a
// deep link to its DNS page + host-format quirks + short steps. Covers the
// top providers; unknown providers fall back to generic guidance.
//
// Host-format note is the #1 manual-setup gotcha: some providers want the full
// subdomain, some want it relative to the apex, some reject "@".

export interface ProviderGuide {
  provider: string;
  label: string;
  /** Link to the provider's DNS management area. %domain% is substituted. */
  dashboardUrl?: string;
  /** How this provider expects the record host/name to be entered. */
  hostFormat: string;
  /** Whether the apex is entered as "@", blank, or the domain itself. */
  apexToken: "@" | "(blank)" | "%domain%";
  steps: string[];
  notes?: string[];
}

const GUIDES: Record<string, ProviderGuide> = {
  cloudflare: {
    provider: "cloudflare",
    label: "Cloudflare",
    dashboardUrl: "https://dash.cloudflare.com/?to=/:account/%domain%/dns",
    hostFormat: "Enter the subdomain only (e.g. `www`); Cloudflare appends the domain.",
    apexToken: "@",
    steps: [
      "Open the Cloudflare dashboard and pick %domain%.",
      "Go to DNS → Records → Add record.",
      "Add each record below. For CNAME/A on a website, set Proxy status to DNS only if verification stalls.",
      "Save, then come back and click Verify.",
    ],
    notes: ["Proxied A/CNAME records won't show their real value on public DNS — that's expected."],
  },
  godaddy: {
    provider: "godaddy",
    label: "GoDaddy",
    dashboardUrl: "https://dcc.godaddy.com/control/%domain%/dns",
    hostFormat: "Enter the subdomain only in the Name field; use `@` for the apex.",
    apexToken: "@",
    steps: [
      "Open GoDaddy → My Products → DNS for %domain%.",
      "Under Records, click Add and choose the record type.",
      "Enter the Name (host) and Value exactly as shown below.",
      "Save each record, then click Verify here.",
    ],
  },
  namecheap: {
    provider: "namecheap",
    label: "Namecheap",
    dashboardUrl: "https://ap.www.namecheap.com/domains/domaincontrolpanel/%domain%/advancedns",
    hostFormat: "Enter the subdomain only in Host; use `@` for the apex.",
    apexToken: "@",
    steps: [
      "Namecheap → Domain List → Manage %domain% → Advanced DNS.",
      "Under Host Records, click Add New Record.",
      "Pick the type, set Host and Value as below (TTL: Automatic).",
      "Save all changes, then click Verify.",
    ],
    notes: ["Namecheap splits CNAME 'Value' without a trailing dot — enter the target as shown."],
  },
  squarespace: {
    provider: "squarespace",
    label: "Squarespace Domains",
    dashboardUrl: "https://account.squarespace.com/domains/managed/%domain%/dns/dns-settings",
    hostFormat: "Enter the subdomain in Host; use `@` for the apex.",
    apexToken: "@",
    steps: [
      "Squarespace → Domains → %domain% → DNS Settings.",
      "Under Custom Records, add each record below.",
      "Save, then return here and click Verify.",
    ],
    notes: ["Squarespace has no DNS API — manual entry is the only path here."],
  },
  route53: {
    provider: "route53",
    label: "AWS Route 53",
    dashboardUrl: "https://console.aws.amazon.com/route53/v2/hostedzones",
    hostFormat: "Enter the FULL record name including the domain (e.g. `www.%domain%`).",
    apexToken: "%domain%",
    steps: [
      "Route 53 → Hosted zones → %domain%.",
      "Create record → enter the full Record name and Value as below.",
      "Create records, then click Verify here.",
    ],
  },
  // —— Entri-manual-parity batch (2026-07), alphabetical. Dashboard URLs and
  // host-format quirks verified against each provider's own docs or live
  // route checks at authoring time; %domain% only where the URL genuinely
  // accepts the domain.
  bluehost: {
    provider: "bluehost",
    label: "Bluehost",
    dashboardUrl: "https://my.bluehost.com",
    hostFormat: "Enter the subdomain only in Host Record; use `@` for the main domain.",
    apexToken: "@",
    steps: [
      "Log in to the Bluehost portal and go to Domains → %domain% → DNS.",
      "Under Manage Advanced DNS Records, click + Add record.",
      "Pick the type, enter Host Record and Value as below.",
      "Save each record, then come back and click Verify.",
    ],
  },
  digitalocean: {
    provider: "digitalocean",
    label: "DigitalOcean",
    dashboardUrl: "https://cloud.digitalocean.com/networking/domains/%domain%",
    hostFormat: "Enter the subdomain prefix only in Hostname; use `@` for the apex.",
    apexToken: "@",
    steps: [
      "DigitalOcean → Networking → Domains → %domain%.",
      "In Create new record, pick the record type tab.",
      "Enter Hostname and Value as below, then Create Record.",
      "Come back here and click Verify.",
    ],
  },
  dnsimple: {
    provider: "dnsimple",
    label: "DNSimple",
    dashboardUrl: "https://dnsimple.com/dashboard",
    hostFormat: "Enter the subdomain only in Name; leave it blank for the root domain.",
    apexToken: "(blank)",
    steps: [
      "DNSimple → Domains → %domain% → DNS → Manage records.",
      "Click Add record and pick the type.",
      "Enter Name and Content as below, then Add Record.",
      "Come back here and click Verify.",
    ],
  },
  dreamhost: {
    provider: "dreamhost",
    label: "DreamHost",
    dashboardUrl: "https://panel.dreamhost.com/index.cgi?tree=domain.dashboard",
    hostFormat:
      "Enter the subdomain only in Name — leave it blank for the apex (`@` is added automatically).",
    apexToken: "(blank)",
    steps: [
      "DreamHost panel → Manage Websites → three-dot menu on %domain% → DNS Settings.",
      "Click Add Record in the section for the record type.",
      "Enter Name and Value as below (never include the domain itself), then confirm.",
      "Come back here and click Verify.",
    ],
  },
  gandi: {
    provider: "gandi",
    label: "Gandi",
    dashboardUrl: "https://admin.gandi.net",
    hostFormat: "Enter the relative name only (e.g. `www`); use `@` for the apex.",
    apexToken: "@",
    steps: [
      "Gandi admin → Domain → %domain% → DNS Records.",
      "Click Add, pick the type, set Name and Value as below.",
      "Create the record, then come back and click Verify.",
    ],
    notes: [
      "Records are editable at Gandi only while the domain uses Gandi's LiveDNS name servers.",
    ],
  },
  hostgator: {
    provider: "hostgator",
    label: "HostGator",
    dashboardUrl: "https://portal.hostgator.com",
    hostFormat: "Enter the subdomain only in Name; use `@` for the apex.",
    apexToken: "@",
    steps: [
      "HostGator Customer Portal → Domains → %domain% → Advanced Tools.",
      "Next to Advanced DNS Records, click Manage.",
      "Add each record below (type, Name, Value).",
      "Save, then come back and click Verify.",
    ],
    notes: ["Older cPanel Zone Editor screens want the FULL host name ending in a period instead."],
  },
  hostinger: {
    provider: "hostinger",
    label: "Hostinger",
    dashboardUrl: "https://hpanel.hostinger.com/domains",
    hostFormat: "Enter the subdomain only in Name; use `@` for the apex.",
    apexToken: "@",
    steps: [
      "hPanel → Domains → %domain% → DNS / Nameservers.",
      "Under Manage DNS records, pick the type and enter Name and Content as below.",
      "Click Add Record for each, then come back and click Verify.",
    ],
  },
  ionos: {
    provider: "ionos",
    label: "IONOS",
    dashboardUrl: "https://my.ionos.com/start-with-domain/dns",
    hostFormat: "Enter the subdomain only in Host name; leave it empty for the apex.",
    apexToken: "(blank)",
    steps: [
      "Log in to IONOS and pick %domain% (Domains & SSL → %domain% → DNS).",
      "Click Add record and choose the record type.",
      "Enter Host name and Value as below (empty Host name = the apex).",
      "Save each record, then come back and click Verify.",
    ],
  },
  namecom: {
    provider: "namecom",
    label: "Name.com",
    dashboardUrl: "https://www.name.com/account/domain/details/%domain%/dns",
    hostFormat: "Enter the subdomain only in Host; leave it blank for the apex.",
    apexToken: "(blank)",
    steps: [
      "Name.com → My Domains → %domain% → Manage DNS Records.",
      "Choose the record Type, enter Host and Answer as below.",
      "Click Add Record for each, then come back and click Verify.",
    ],
  },
  namesilo: {
    provider: "namesilo",
    label: "NameSilo",
    dashboardUrl: "https://www.namesilo.com/account_domains.php",
    hostFormat: "Enter the subdomain only in Hostname; use `@` (or leave it blank) for the apex.",
    apexToken: "@",
    steps: [
      "NameSilo → Domain Manager → click the blue globe (Manage DNS) next to %domain%.",
      "Select the record type you want to create.",
      "Enter Hostname and Value as below (default TTL is fine).",
      "Submit, then come back and click Verify.",
    ],
  },
  onecom: {
    provider: "onecom",
    label: "one.com",
    dashboardUrl: "https://www.one.com/admin/",
    hostFormat:
      "Enter the subdomain only in Hostname; leave it empty for the apex (a typed `@` is treated as empty).",
    apexToken: "(blank)",
    steps: [
      "one.com control panel → Advanced settings → DNS settings → DNS records.",
      "Click Create new record and pick the type.",
      "Enter Hostname and Value as below, then save.",
      "Come back here and click Verify.",
    ],
  },
  ovh: {
    provider: "ovh",
    label: "OVHcloud",
    dashboardUrl: "https://www.ovh.com/manager/",
    hostFormat: "Enter the subdomain only (OVH appends the domain); leave it empty for the apex.",
    apexToken: "(blank)",
    steps: [
      "OVHcloud Control Panel → Web Cloud → Domain names → %domain% → DNS zone.",
      "Click Add an entry and pick the record type.",
      "Enter the subdomain and target as below, then confirm.",
      "Come back here and click Verify.",
    ],
  },
  porkbun: {
    provider: "porkbun",
    label: "Porkbun",
    dashboardUrl: "https://porkbun.com/account/dns/%domain%",
    hostFormat: "Enter the subdomain only in Host; leave it blank for the root domain.",
    apexToken: "(blank)",
    steps: [
      "Porkbun → Domain Management → DNS under %domain%.",
      "Pick the record Type, set Host and Answer as below.",
      "Click Add, then come back and click Verify.",
    ],
  },
  strato: {
    provider: "strato",
    label: "STRATO",
    dashboardUrl: "https://www.strato.de/apps/CustomerService",
    hostFormat:
      "No host field: records apply to the (sub)domain you select — create the subdomain under Domains first if it doesn't exist yet.",
    apexToken: "%domain%",
    steps: [
      "STRATO customer login → Domains → Domain management.",
      "Open the settings (gear) next to %domain% — or the subdomain — and go to DNS.",
      "Set each record below on the matching (sub)domain entry.",
      "Save, then come back and click Verify.",
    ],
  },
  vercel: {
    provider: "vercel",
    label: "Vercel",
    dashboardUrl: "https://vercel.com/dashboard/domains",
    hostFormat:
      "Enter the record name as the prefix only (e.g. `www`); leave it empty for the apex.",
    apexToken: "(blank)",
    steps: [
      "Open your Vercel team's Domains page and click %domain%.",
      "Under DNS Records, fill in the form (Name = prefix only) for each record below.",
      "Click Add for each, then come back and click Verify.",
    ],
    notes: ["Records are editable on Vercel only while the domain uses Vercel's name servers."],
  },
  wix: {
    provider: "wix",
    label: "Wix",
    dashboardUrl: "https://manage.wix.com/account/domains",
    hostFormat: "Enter the subdomain only in Host Name; leave it blank for the apex.",
    apexToken: "(blank)",
    steps: [
      "Wix → Domains → Domain Actions next to %domain% → Manage DNS Records.",
      "Click + Add Record in the section for the record type.",
      "Enter Host Name and Value as below, then Save.",
      "Come back here and click Verify.",
    ],
    notes: ["Domains connected to Wix by pointing are managed at the registrar, not in Wix."],
  },
  wordpress: {
    provider: "wordpress",
    label: "WordPress.com",
    dashboardUrl: "https://wordpress.com/domains/manage/%domain%/dns/%domain%",
    hostFormat: "Enter the subdomain only in Name; leave it blank for the root domain.",
    apexToken: "(blank)",
    steps: [
      "WordPress.com → Upgrades → Domains → %domain% → DNS records → Manage.",
      "Click Add a record and pick the type.",
      "Enter Name and Value as below, then save.",
      "Come back here and click Verify.",
    ],
    notes: [
      "DNS is editable at WordPress.com only while the domain uses WordPress.com name servers.",
    ],
  },
};

const GENERIC: ProviderGuide = {
  provider: "unknown",
  label: "your DNS provider",
  hostFormat: "Most providers want the subdomain only; use `@` (or a blank host) for the apex.",
  apexToken: "@",
  steps: [
    "Open your DNS provider's control panel for this domain.",
    "Find the DNS / records / zone editor.",
    "Add each record below (type, host/name, value).",
    "Save, then come back and click Verify.",
  ],
};

export function guideFor(provider: string, domain?: string): ProviderGuide {
  const base = GUIDES[provider] ?? GENERIC;
  if (!domain) return base;
  const sub = (s?: string) => (s ? s.replace(/%domain%/g, domain) : s);
  return {
    ...base,
    dashboardUrl: sub(base.dashboardUrl),
    steps: base.steps.map((s) => s.replace(/%domain%/g, domain)),
  };
}
