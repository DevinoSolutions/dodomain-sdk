// Guided-manual provider instructions (Tier 3). For each known provider: a
// deep link to its DNS page + host-format quirks + short steps. Covers the
// top providers; unknown providers fall back to generic guidance.
//
// Host-format note is the #1 manual-setup gotcha: some providers want the full
// subdomain, some want it relative to the apex, some reject "@".
//
// THE ONE HOME for provider guidance (Stage 9 WS-G, 2026-09-05): the hosted
// connect page renders this map through `ProviderGuidePanel`, and the public
// per-provider setup pages under apps/docs/content/docs/guides/dns-providers/
// are GENERATED from it (apps/docs/scripts/generate-dns-provider-guides.mts,
// drift-gated by scripts/check-dns-provider-guides.sh) — so what a customer
// reads in the docs and what the flow shows them can never be two copies.
// Change the copy here, regenerate, commit both.

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
  /**
   * The provider's OWN help article the steps and vocabulary were checked
   * against, and when — rendered as a dated citation on the docs page. Absent
   * on the entries whose wording was verified at authoring time (2026-07)
   * against docs or live route checks but not re-read since.
   */
  helpArticle?: { url: string; checkedOn: string };
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
    helpArticle: {
      url: "https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/",
      checkedOn: "2026-09-05",
    },
  },
  godaddy: {
    provider: "godaddy",
    label: "GoDaddy",
    dashboardUrl: "https://dcc.godaddy.com/control/%domain%/dns",
    hostFormat:
      "Enter the subdomain only in Name (e.g. `www`), never the full domain; use `@` for the apex on A/TXT records — GoDaddy refuses `@` as a CNAME Name, so a CNAME always needs a subdomain.",
    apexToken: "@",
    steps: [
      "Sign in to GoDaddy → Domain Portfolio → select %domain% → DNS.",
      "Select Add New Record and pick the record type from the Type menu.",
      "Enter Name (host) and Value exactly as shown below; leave TTL at the default (1 hour).",
      "Select Save (Save All Records if you added several), then come back and click Verify.",
    ],
    notes: [
      "Domains with Domain Protection ask for a 2-step verification code before the record saves.",
      "GoDaddy says most changes take effect within an hour but can take up to 48 hours globally.",
    ],
    helpArticle: {
      url: "https://www.godaddy.com/help/add-a-cname-record-19236",
      checkedOn: "2026-09-05",
    },
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
      "Click Save All Changes, then come back and click Verify.",
    ],
    notes: [
      "Namecheap splits CNAME 'Value' without a trailing dot — enter the target as shown.",
      "Namecheap warns against a CNAME on the bare domain (`@`) because it overrides the domain's mail records — a CNAME belongs on a subdomain.",
      "Namecheap says new host records take up to 30 minutes to be accepted.",
    ],
    helpArticle: {
      url: "https://www.namecheap.com/support/knowledgebase/article.aspx/9646/2237/how-to-create-a-cname-record-for-your-domain/",
      checkedOn: "2026-09-05",
    },
  },
  squarespace: {
    provider: "squarespace",
    label: "Squarespace Domains",
    dashboardUrl: "https://account.squarespace.com/domains/managed/%domain%/dns/dns-settings",
    hostFormat:
      "Enter the subdomain only in Name (older panels label it Host); use `@` for the apex.",
    apexToken: "@",
    steps: [
      "Open the Squarespace domains dashboard → click %domain% → DNS in the side panel.",
      "Under Custom records, add each record below (Type, Name, Priority, TTL, Data).",
      "Confirm with your password or 2FA code when asked, then come back and click Verify.",
    ],
    notes: [
      "Squarespace has no DNS API — manual entry is the only path here.",
      "Google Domains customers: every Google Domains registration moved to Squarespace (migration complete 10 July 2024), so this is your DNS panel too — even while the nameservers still say googledomains.com.",
      "Custom records default to a 4-hour TTL; Squarespace says changes can take 24–48 hours to update.",
    ],
    helpArticle: {
      url: "https://support.squarespace.com/hc/en-us/articles/360002101888",
      checkedOn: "2026-09-05",
    },
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
      "Porkbun → Account → Domain Management → Details under %domain% → the edit icon next to DNS Records.",
      "Click Add Record, pick the record Type, and set Host and Answer as below (TTL can stay at the default).",
      "Click Add, then come back and click Verify.",
    ],
    notes: [
      '"A CNAME or ALIAS record with that host already exists" means Porkbun\'s default ALIAS/CNAME entries are in the way — delete the one at that host first.',
    ],
    helpArticle: {
      url: "https://kb.porkbun.com/article/68-how-to-edit-dns-records",
      checkedOn: "2026-09-05",
    },
  },
  // —— Stage 9 WS-G batch (2026-09-05): vocabulary read from the provider's
  // own help page on the date in `helpArticle`.
  hover: {
    provider: "hover",
    label: "Hover",
    dashboardUrl: "https://www.hover.com/control_panel",
    hostFormat:
      "Enter the subdomain only in Hostname; use `@` for the root domain (if a form asks for your full domain as the hostname, type `@` instead).",
    apexToken: "@",
    steps: [
      "Sign in to Hover → Domains → %domain% → the DNS tab.",
      "Click Add a record and pick the record type.",
      "Enter Hostname and the value field as below (Target Name for a CNAME, Content for TXT, IP address for A).",
      "Save the record, then come back and click Verify.",
    ],
    notes: [
      "Hover cannot host a CNAME on the root domain (`@`) — a CNAME must sit on a subdomain.",
    ],
    helpArticle: {
      url: "https://support.hover.com/support/solutions/articles/201000064728",
      checkedOn: "2026-09-05",
    },
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
      "Click + Add Record in the section for the record type (CNAME (Aliases), A (Host), TXT (Text)).",
      "Enter Host Name and Value as below, then Save, and Save Changes in the confirmation.",
      "Come back here and click Verify.",
    ],
    notes: [
      "Domains connected to Wix by pointing are managed at the registrar, not in Wix — these steps apply only to domains on Wix name servers.",
    ],
    helpArticle: {
      url: "https://support.wix.com/en/article/adding-or-updating-cname-records-in-your-wix-account",
      checkedOn: "2026-09-05",
    },
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

/**
 * Every provider with a dedicated guide, sorted by label — the docs generator's
 * input. The generic fallback is deliberately NOT in the list: it is what the
 * hosted flow shows for an unrecognised provider, not a page anyone searches for.
 */
export function listProviderGuides(): ProviderGuide[] {
  return Object.values(GUIDES).sort((a, b) => a.label.localeCompare(b.label, "en"));
}

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
