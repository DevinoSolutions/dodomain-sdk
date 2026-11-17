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
   * True when this guide's own copy (hostFormat / notes) says a CNAME does not
   * belong on the bare domain (GoDaddy refuses it, Namecheap and Hover advise
   * against it). The docs page then also links the ALIAS / CNAME-flattening
   * definition, the workaround a customer in that spot needs. Drives docs copy
   * only, never the connect flow.
   */
  discouragesApexCname?: true;
  /**
   * The sentence from this guide's own copy saying a CNAME does not belong on
   * the root domain. Set on every guide with `discouragesApexCname`; drives the
   * docs FAQ only (the connect flow renders `notes` and `hostFormat`, never
   * this field).
   */
  apexCnameNote?: string;
  /**
   * True when the provider's panel has no host field at all (records apply to
   * the (sub)domain you select). The docs page then does not headline a
   * "host field" the panel does not have.
   */
  hasNoHostField?: true;
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
    notes: [
      "Proxied A/CNAME records won't show their real value on public DNS, which is expected.",
    ],
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
      "Enter the subdomain only in Name (e.g. `www`), never the full domain; use `@` for the apex on A/TXT records. GoDaddy refuses `@` as a CNAME Name, so a CNAME always needs a subdomain.",
    apexToken: "@",
    discouragesApexCname: true,
    apexCnameNote: "GoDaddy refuses `@` as a CNAME Name, so a CNAME always needs a subdomain.",
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
    discouragesApexCname: true,
    apexCnameNote:
      "Namecheap warns against a CNAME on the bare domain (`@`) because it overrides the domain's mail records. A CNAME belongs on a subdomain.",
    steps: [
      "Namecheap → Domain List → Manage %domain% → Advanced DNS.",
      "Under Host Records, click Add New Record.",
      "Pick the type, set Host and Value as below (TTL: Automatic).",
      "Click Save All Changes, then come back and click Verify.",
    ],
    notes: [
      "Namecheap splits CNAME 'Value' without a trailing dot, so enter the target as shown.",
      "Namecheap warns against a CNAME on the bare domain (`@`) because it overrides the domain's mail records. A CNAME belongs on a subdomain.",
      "Namecheap says new host records take up to 30 minutes to be accepted.",
      "Namecheap does not offer one-click DNS setup for third-party apps: its API needs a personal key, a whitelisted server IP and an eligible account, and saving host records replaces the whole set, so DoDomain shows these steps instead.",
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
      "Squarespace has no DNS API, so manual entry is the only path here.",
      "Google Domains customers: every Google Domains registration moved to Squarespace (migration complete 10 July 2024), so this is your DNS panel too, even while the nameservers still say googledomains.com.",
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
      "Enter the subdomain only in Name, and leave it blank for the apex (`@` is added automatically).",
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
      '"A CNAME or ALIAS record with that host already exists" means Porkbun\'s default ALIAS/CNAME entries are in the way. Delete the one at that host first.',
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
    discouragesApexCname: true,
    apexCnameNote:
      "Hover cannot host a CNAME on the root domain (`@`). A CNAME must sit on a subdomain.",
    steps: [
      "Sign in to Hover → Domains → %domain% → the DNS tab.",
      "Click Add a record and pick the record type.",
      "Enter Hostname and the value field as below (Target Name for a CNAME, Content for TXT, IP address for A).",
      "Save the record, then come back and click Verify.",
    ],
    notes: ["Hover cannot host a CNAME on the root domain (`@`). A CNAME must sit on a subdomain."],
    helpArticle: {
      url: "https://support.hover.com/support/solutions/articles/201000064728",
      checkedOn: "2026-09-05",
    },
  },
  // —— T-6545 batch (2026-10-22). Domain Chief, Glauca and Simply.com are found
  // by Domain Connect discovery (their providerIds map here through
  // GUIDE_BY_DOMAIN_CONNECT_ID below); Google Cloud DNS by its nameservers.
  // Vocabulary read from the source in `helpArticle` on that date.
  domainchief: {
    provider: "domainchief",
    label: "Domain Chief",
    dashboardUrl: "https://domain.chief.app/permalink/domain/%domain%/dns",
    hostFormat:
      "Enter the subdomain only in Name (e.g. `www`), never the domain itself; leave it empty for the root domain.",
    apexToken: "(blank)",
    steps: [
      "Sign in to Domain Chief, pick %domain% and open its DNS records.",
      "Add a record, pick the Type, and enter Name and the value as below.",
      "Save each record, then come back and click Verify.",
    ],
    helpArticle: { url: "https://domain.chief.app/api/docs/v1", checkedOn: "2026-10-23" },
  },
  glauca: {
    provider: "glauca",
    label: "Glauca HexDNS",
    dashboardUrl: "https://dns.glauca.digital/",
    hostFormat:
      "Enter the subdomain only in Record name (the zone is appended); use `@` for the zone root.",
    apexToken: "@",
    steps: [
      "Sign in to the HexDNS control panel and open the zone for %domain%.",
      "In the section for the record type (Address records, CNAME records, TXT records), click New.",
      "Enter Record name and the value field as below (Address for A, Alias for CNAME, Data for TXT), then Save.",
      "Come back here and click Verify.",
    ],
    helpArticle: {
      url: "https://github.com/AS207960/hexdns/blob/master/hexdns_django/dns_grpc/templates/dns_grpc/fzone/zone.html",
      checkedOn: "2026-10-22",
    },
  },
  googleclouddns: {
    provider: "googleclouddns",
    label: "Google Cloud DNS",
    dashboardUrl: "https://console.cloud.google.com/net-services/dns/zones",
    hostFormat:
      "Enter the subdomain only in DNS name (e.g. `www`); the zone's domain is appended. Leave it blank for the apex. `@` does not create an apex record.",
    apexToken: "(blank)",
    steps: [
      "Google Cloud console → Cloud DNS zones → click the zone for %domain%.",
      "On the Zone details page, click Add standard.",
      "Enter DNS name, pick the Resource record type and fill in the value as below.",
      "Click Create, then come back and click Verify.",
    ],
    notes: [
      "Bought the domain through Google Domains and never set up Cloud DNS? Google Domains registrations moved to Squarespace, so the records live in Squarespace Domains' DNS panel instead.",
    ],
    helpArticle: { url: "https://cloud.google.com/dns/docs/records", checkedOn: "2026-10-22" },
  },
  simplycom: {
    provider: "simplycom",
    label: "Simply.com",
    dashboardUrl: "https://www.simply.com/en/controlpanel/",
    hostFormat: "Enter the subdomain only in Name; use `@` for the root domain.",
    apexToken: "@",
    steps: [
      "Sign in to the Simply.com control panel, select %domain% and click DNS.",
      "Create a new DNS record and pick the record type.",
      "Fill in Name and Value as below, leaving the other fields as they are.",
      "Save, then come back and click Verify.",
    ],
    notes: [
      "Simply.com says CNAME records only work on subdomains.",
      "Changes apply at Simply.com's name servers immediately; Simply.com says they can take a few hours to reach every resolver.",
    ],
    helpArticle: {
      url: "https://www.simply.com/en/support/faq/domain/339-about-dns-records/",
      checkedOn: "2026-10-23",
    },
  },
  strato: {
    provider: "strato",
    label: "STRATO",
    dashboardUrl: "https://www.strato.de/apps/CustomerService",
    hostFormat:
      "No host field: records apply to the (sub)domain you select, so create the subdomain under Domains first if it doesn't exist yet.",
    apexToken: "%domain%",
    hasNoHostField: true,
    steps: [
      "STRATO customer login → Domains → Domain management.",
      "Open the settings (gear) next to %domain% (or the subdomain) and go to DNS.",
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
      "Domains connected to Wix by pointing are managed at the registrar, not in Wix. These steps apply only to domains on Wix name servers.",
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
  // —— T-5809 batch 1 (2026-10-22): every label, field, TTL and limit below was
  // read from the provider's own help page named in `helpArticle` on that date;
  // anything those pages do not state is left out.
  // TODO(scope): none of these five has a detect.ts NS_MAP row, so the connect flow cannot select them yet (the docs pages are live). A row also moves the "23 DNS providers" detection count and the apex table in apps/docs/content/docs/apex-domains.mdx, and some of their name servers belong to resellers with other panels, so each row needs its own review — T-5809
  dynadot: {
    provider: "dynadot",
    label: "Dynadot",
    dashboardUrl: "https://www.dynadot.com/account/",
    hostFormat:
      "Enter the subdomain prefix only (e.g. `www`) in Subdomain Records; the root domain goes in the Domain Record section, where you never type the `@` symbol itself.",
    apexToken: "(blank)",
    steps: [
      "Sign in to Dynadot → My Domains → Manage Domains.",
      "Tick %domain%, click Action, and choose DNS Settings.",
      "Pick Dynadot DNS in the drop-down at the top of the page.",
      "Add each record below: in Domain Record for the root domain, in Subdomain Records for a prefix such as `www`.",
      "Click Save Settings, then come back and click Verify.",
    ],
    notes: [
      "These screens apply only while the domain uses Dynadot DNS; with third-party name servers the records go to that provider.",
      "Dynadot says name server changes can take some time to propagate.",
    ],
    helpArticle: {
      url: "https://www.dynadot.com/help/question/set-up-DNS",
      checkedOn: "2026-10-22",
    },
  },
  enom: {
    provider: "enom",
    label: "Enom",
    dashboardUrl: "https://access.enom.com",
    hostFormat: "Enter the subdomain prefix only in Host Name; use `@` for the root domain.",
    apexToken: "@",
    steps: [
      "Sign in to Enom → Domains → My domains and pick %domain%.",
      "Choose Host records from the Manage domain drop-down.",
      "Enter the Host Name, pick the Record Type, and enter the Address (target).",
      "Click Save, then come back and click Verify.",
    ],
    notes: [
      "Host records take effect only while the domain uses Enom's default name servers; on other name servers they belong at that provider.",
      "Enom gives you 15 host-record rows to start with; more need a verified support request.",
      "Enom's default TTL is 3600 seconds and resets to 3600 whenever host records change.",
      "Enom says changes may take up to 8 to 24 hours to propagate.",
    ],
    helpArticle: {
      url: "https://support.enom.com/support/solutions/articles/201000065361-managing-dns-host-records",
      checkedOn: "2026-10-22",
    },
  },
  infomaniak: {
    provider: "infomaniak",
    label: "Infomaniak",
    dashboardUrl: "https://manager.infomaniak.com",
    hostFormat:
      "Enter the subdomain only in Source; leave Source blank for the root domain. The value goes in Target.",
    apexToken: "(blank)",
    steps: [
      "Infomaniak Manager → Domain → click %domain% → DNS Zone in the left menu.",
      "In the Simple Mode table, click the blue Add entry button, choose the record type, and click Next.",
      "Fill in Source and Target as below and leave the TTL as it is.",
      "Come back here and click Verify.",
    ],
    notes: ["Infomaniak says any DNS addition or change may take up to 48 hours to propagate."],
    helpArticle: {
      url: "https://www.infomaniak.com/en/support/faq/2000/modify-a-dns-zone-simple-mode-for-a-domain-managed-by-infomaniak",
      checkedOn: "2026-10-22",
    },
  },
  networksolutions: {
    provider: "networksolutions",
    label: "Network Solutions",
    hostFormat:
      "Pick `@`, `www` or Other Host in Refers to; the target goes in Points to for A, Alias to for a CNAME and TXT Value for a TXT record.",
    apexToken: "@",
    // No `discouragesApexCname`: with this label the docs generator's description
    // ("...why the root can't take a CNAME...") overruns its 160-char ceiling. The
    // restriction is stated in the first note instead.
    steps: [
      "Log in to Network Solutions → Domains → select %domain% and click Manage.",
      "Open the DNS tab and click +Add Record.",
      "Pick the record type and complete the fields as below, leaving the TTL as it is.",
      "Click Add, then come back and click Verify.",
    ],
    notes: [
      "Network Solutions says CNAME records can only be created for third-level domains; a CNAME on the root domain can conflict with other records and disrupt email or website services, and it suggests Web Forwarding for that case.",
      "The default TTL is 7200 seconds (2 hours) for every record type.",
      "Network Solutions says Advanced DNS updates may take up to two hours to propagate.",
      "The classic Advanced DNS view has no option for CAA records.",
    ],
    helpArticle: {
      url: "https://www.networksolutions.com/help/article/manage-dns-adns-records",
      checkedOn: "2026-10-22",
    },
  },
  transip: {
    provider: "transip",
    label: "TransIP",
    dashboardUrl: "https://www.transip.eu/cp/",
    hostFormat:
      "Enter the subdomain only in Name (TransIP adds the domain); use `@` for the root domain. A CNAME target outside the domain goes in Value ending in a dot.",
    apexToken: "@",
    // No `discouragesApexCname`: the docs description it adds is 158 chars here, over
    // the 155 the docs metadata gate allows. The restriction is the first note instead.
    steps: [
      "TransIP control panel → Domain → click %domain% in the left column (leave its box unticked).",
      "Scroll to DNS settings → DNS. If the records are not shown, switch off the TransIP settings toggle.",
      "Add each record below with its Name, TTL, Type and Value.",
      "Come back here and click Verify.",
    ],
    notes: [
      "TransIP says a CNAME record can only be used for subdomains, so a CNAME never goes on the root domain (`@`).",
      "Switching the TransIP settings toggle off is what reveals your own DNS records.",
      "The trailing dot belongs only in the Value of CNAME, ALIAS, MX and SRV records, never in the Name.",
      "TransIP recommends a low TTL, for example 1 or 5 minutes, and says changes can take up to 24 hours to take effect globally.",
    ],
    helpArticle: {
      url: "https://www.transip.eu/knowledgebase/407-setting-a-cname-record/",
      checkedOn: "2026-10-22",
    },
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

/**
 * Domain Connect providerId → guide key. A zone detection matches by Domain
 * Connect discovery alone (no NS row) reports the provider's own providerId
 * (detect.ts), which is not a guide key — without this, Glauca and Simply.com
 * users got the generic steps. providerIds as their settings endpoints return
 * them (live discovery, 2026-10-19 and 2026-10-22).
 */
const GUIDE_BY_DOMAIN_CONNECT_ID: Record<string, string> = {
  "glauca.digital": "glauca",
  "simply.com": "simplycom",
  "squarespace.com": "squarespace",
  "namesilo.com": "namesilo",
  "godaddy.com": "godaddy",
  "ionos.com": "ionos",
  "vercel.com": "vercel",
  "wordpress.com": "wordpress",
  "cloudflare.com": "cloudflare",
};

export function guideFor(provider: string, domain?: string): ProviderGuide {
  const base = GUIDES[provider] ?? GUIDES[GUIDE_BY_DOMAIN_CONNECT_ID[provider] ?? ""] ?? GENERIC;
  if (!domain) return base;
  const sub = (s?: string) => (s ? s.replace(/%domain%/g, domain) : s);
  return {
    ...base,
    dashboardUrl: sub(base.dashboardUrl),
    steps: base.steps.map((s) => s.replace(/%domain%/g, domain)),
  };
}

/**
 * The fields of a guide that are part of the published `/api/v1` contract
 * (`zProviderGuide` in schemas.ts, the OpenAPI spec, the SDK's `ProviderGuide`).
 * An ALLOWLIST on purpose: the docs-only fields on `ProviderGuide`
 * (`discouragesApexCname`, `apexCnameNote`, `hasNoHostField`, `helpArticle`)
 * drive the generated docs pages and never reach a wire body, and a field added
 * to `ProviderGuide` later stays off the wire until it is listed here AND in
 * `zProviderGuide`. guides.test.ts pins both directions: public keys are a
 * subset of `zProviderGuide`'s keys, and every `zProviderGuide` key defined on
 * the full guide is present on the public one.
 */
export type PublicProviderGuide = Pick<
  ProviderGuide,
  "provider" | "label" | "dashboardUrl" | "hostFormat" | "apexToken" | "steps" | "notes"
>;

/**
 * `guideFor` narrowed to the published contract: THE producer for every public
 * `guide` body (POST /domains/check, session detect, the preflight engine).
 * Routes must call this, never `guideFor`, so the wire cannot drift from the
 * contract (`scripts/check-public-guide-bans.sh`). `guideFor` itself stays
 * the full record for the docs generator and tests.
 */
export function publicGuideFor(provider: string, domain?: string): PublicProviderGuide {
  const g = guideFor(provider, domain);
  return {
    provider: g.provider,
    label: g.label,
    ...(g.dashboardUrl !== undefined && { dashboardUrl: g.dashboardUrl }),
    hostFormat: g.hostFormat,
    apexToken: g.apexToken,
    steps: g.steps,
    ...(g.notes !== undefined && { notes: g.notes }),
  };
}
