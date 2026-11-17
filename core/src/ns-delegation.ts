// A zone's nameservers as its PARENT delegates them — the current truth about
// where a zone lives, read without any recursive resolver's cache (T-10301).
//
// Why: a recursive resolver keeps a zone's NS RRset for its TTL, and NS TTLs
// are commonly 86400. On 2026-10-29 dodomaindemo.xyz moved Vercel -> Porkbun at
// 11:22Z; Google, Cloudflare and Quad9 all answered Porkbun within minutes, but
// the web container's system resolver (127.0.0.11 -> host upstreams, one of
// them a home router) kept answering Vercel, so POST /sessions/:token/detect
// offered the WRONG provider's one-click for ~20 min, and record read-back
// (verify.ts), which pins the zone's NS through the same recursive path, asked
// the old provider's servers. The parent's servers (the TLD's, or the parent
// zone's for a delegated subzone) hold the delegation itself, so they see the
// move the moment the registry publishes it.
//
// How: find the nearest ancestor that owns NS (through the recursive resolver —
// a TLD's or parent zone's own NS set is not what just moved), resolve those
// servers' addresses, and send ONE non-recursive (RD=0) NS query for the zone.
// The parent answers with a REFERRAL: the child's NS in the AUTHORITY section.
// c-ares cannot read that (it reports ENODATA), so the query is built and the
// reply parsed here, by hand; the socket is dns-defaults.ts's udpExchange and
// every exchange is bounded by DEFAULT_DNS_TIMEOUT_MS, at most
// DEFAULT_DNS_TRIES of them, each on the next parent server.
//
// Outcomes: the delegated NS names (lowercased, deduped), or an Error whose
// `code` says why — ENOTFOUND (parent answered NXDOMAIN) and ENODATA (parent
// answered but holds no delegation for that name) are ANSWERS, every other code
// means the lookup did not complete. The caller (zone-walk.ts zoneNameServers)
// decides what to fall back to and reports it; this module never swallows.

import { NODATA, NOTFOUND } from "node:dns";
import { randomInt } from "node:crypto";
import {
  DEFAULT_DNS_TIMEOUT_MS,
  DEFAULT_DNS_TRIES,
  sharedBoundedResolver,
  udpExchange,
} from "./dns-defaults.ts";

const TYPE_NS = 2;
const TYPE_OPT = 41;
const CLASS_IN = 1;
const RCODE_NXDOMAIN = 3;
/** EDNS0 payload size we advertise (the DNS Flag Day 2020 value), so a referral with glue fits one datagram. */
const EDNS_UDP_PAYLOAD = 1232;
/** Parent servers whose addresses are resolved per lookup. Three is what verify.ts pins for a zone's own NS. */
const MAX_PARENT_SERVERS = 3;
/** Ancestors tried when looking for the parent zone (e.g. a.b.example.co.uk -> b.example.co.uk -> example.co.uk -> co.uk -> uk). */
const MAX_PARENT_HOPS = 8;

export interface DelegationDeps {
  /** Recursive NS lookup, used ONLY for the parent's own nameservers. Default: the bounded shared resolver. */
  resolveNs?: (host: string) => Promise<string[]>;
  /** Recursive A lookup for the parent's nameserver names. Default: the bounded shared resolver. */
  resolve4?: (host: string) => Promise<string[]>;
  /** One UDP exchange with one server. Default: dns-defaults.ts udpExchange. Injected in tests. */
  exchange?: (server: string, packet: Uint8Array) => Promise<Uint8Array>;
  /** Per-exchange timeout; default DEFAULT_DNS_TIMEOUT_MS. */
  dnsTimeoutMs?: number;
  /** Exchanges spent before giving up, each on the next parent server; default DEFAULT_DNS_TRIES. */
  dnsTries?: number;
  /** Query ID source (tests pin it). Default: a random 16-bit ID. */
  nextId?: () => number;
}

function dnsError(code: string, message: string): Error {
  return Object.assign(new Error(message), { code });
}

function normalize(name: string): string {
  return name.trim().replace(/\.$/, "").toLowerCase();
}

function parentOf(name: string): string | null {
  const dot = name.indexOf(".");
  return dot < 0 ? null : name.slice(dot + 1);
}

// ——— wire format (RFC 1035 §4, EDNS0 RFC 6891) ———

function encodeName(name: string): number[] {
  const out: number[] = [];
  for (const label of normalize(name).split(".")) {
    if (label.length === 0 || label.length > 63 || !/^[\x21-\x7e]+$/.test(label)) {
      throw dnsError("EBADNAME", `cannot encode DNS name ${JSON.stringify(name)}`);
    }
    out.push(label.length, ...Array.from(label, (c) => c.charCodeAt(0)));
  }
  out.push(0);
  if (out.length > 255) throw dnsError("EBADNAME", `DNS name too long: ${name}`);
  return out;
}

/** An NS query for `name`, recursion NOT desired, with an EDNS0 OPT record. Exported for tests. */
export function encodeNsQuery(name: string, id: number): Uint8Array {
  const header = [id >> 8, id & 0xff, 0x00, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
  const question = [...encodeName(name), 0, TYPE_NS, 0, CLASS_IN];
  // OPT: root name, TYPE 41, CLASS = UDP payload size, TTL 0, RDLEN 0.
  const opt = [0, 0, TYPE_OPT, EDNS_UDP_PAYLOAD >> 8, EDNS_UDP_PAYLOAD & 0xff, 0, 0, 0, 0, 0, 0];
  return Uint8Array.from([...header, ...question, ...opt]);
}

interface DnsRecord {
  name: string;
  type: number;
  /** For NS records only: the target host. */
  target?: string;
}

interface DnsMessage {
  id: number;
  isResponse: boolean;
  truncated: boolean;
  rcode: number;
  questionName: string | null;
  answers: DnsRecord[];
  authority: DnsRecord[];
}

function readName(buf: Uint8Array, start: number): { name: string; next: number } {
  const labels: string[] = [];
  let pos = start;
  let next = -1;
  for (let jumps = 0; ;) {
    if (pos >= buf.length) throw dnsError("EFORMERR", "DNS name runs past the message");
    const len = buf[pos]!;
    if (len === 0) {
      if (next < 0) next = pos + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) throw dnsError("EFORMERR", "truncated DNS name pointer");
      if (++jumps > 64) throw dnsError("EFORMERR", "DNS name pointer loop");
      if (next < 0) next = pos + 2;
      pos = ((len & 0x3f) << 8) | buf[pos + 1]!;
      continue;
    }
    if ((len & 0xc0) !== 0) throw dnsError("EFORMERR", "unsupported DNS label type");
    if (pos + 1 + len > buf.length) throw dnsError("EFORMERR", "DNS label runs past the message");
    labels.push(String.fromCharCode(...buf.subarray(pos + 1, pos + 1 + len)));
    pos += 1 + len;
  }
  return { name: labels.join(".").toLowerCase(), next };
}

function u16(buf: Uint8Array, pos: number): number {
  if (pos + 2 > buf.length) throw dnsError("EFORMERR", "DNS message truncated");
  return (buf[pos]! << 8) | buf[pos + 1]!;
}

/** Parse a DNS response's header, question and answer/authority sections. Exported for tests. */
export function parseDnsMessage(buf: Uint8Array): DnsMessage {
  if (buf.length < 12) throw dnsError("EFORMERR", "DNS message shorter than its header");
  const flags = u16(buf, 2);
  const counts = [u16(buf, 4), u16(buf, 6), u16(buf, 8)] as const;
  let pos = 12;
  let questionName: string | null = null;
  for (let i = 0; i < counts[0]; i++) {
    const q = readName(buf, pos);
    if (i === 0) questionName = q.name;
    pos = q.next + 4;
  }
  const sections: DnsRecord[][] = [[], []];
  for (let s = 0; s < 2; s++) {
    for (let i = 0; i < counts[s + 1]!; i++) {
      const owner = readName(buf, pos);
      pos = owner.next;
      const type = u16(buf, pos);
      const rdlength = u16(buf, pos + 8);
      const rdata = pos + 10;
      if (rdata + rdlength > buf.length)
        throw dnsError("EFORMERR", "DNS record runs past the message");
      const record: DnsRecord = { name: owner.name, type };
      if (type === TYPE_NS) record.target = readName(buf, rdata).name;
      sections[s]!.push(record);
      pos = rdata + rdlength;
    }
  }
  return {
    id: u16(buf, 0),
    isResponse: (flags & 0x8000) !== 0,
    truncated: (flags & 0x0200) !== 0,
    rcode: flags & 0x000f,
    questionName,
    answers: sections[0]!,
    authority: sections[1]!,
  };
}

// ——— the lookup ———

/** The parent zone of `zone` and that parent's nameserver names. */
async function parentZoneOf(
  zone: string,
  resolveNs: (host: string) => Promise<string[]>,
): Promise<{ parent: string; nameServers: string[] }> {
  let candidate = parentOf(zone);
  for (let hop = 0; candidate && hop < MAX_PARENT_HOPS; hop++) {
    try {
      const ns = await resolveNs(candidate);
      if (ns.length > 0) return { parent: candidate, nameServers: ns.map(normalize) };
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      // NXDOMAIN/NODATA: not a zone cut, keep climbing. Anything else is the
      // lookup failing, which says nothing about the parent: surface it.
      if (code !== NOTFOUND && code !== NODATA) throw error;
    }
    candidate = parentOf(candidate);
  }
  throw dnsError("ENOPARENT", `no parent zone with nameservers found above ${zone}`);
}

/**
 * The NS names `zone`'s parent delegates it to, asked of the parent's own
 * servers with recursion off. Throws (see the header) when the parent has no
 * delegation for it or no parent server could be asked.
 */
export async function parentDelegatedNs(
  zone: string,
  deps: DelegationDeps = {},
): Promise<string[]> {
  const name = normalize(zone);
  const resolveNs = deps.resolveNs ?? ((h: string) => sharedBoundedResolver().resolveNs(h));
  const resolve4 = deps.resolve4 ?? ((h: string) => sharedBoundedResolver().resolve4(h));
  const timeoutMs = deps.dnsTimeoutMs ?? DEFAULT_DNS_TIMEOUT_MS;
  const exchange =
    deps.exchange ??
    ((server: string, packet: Uint8Array) => udpExchange(server, packet, timeoutMs));
  const tries = Math.max(1, deps.dnsTries ?? DEFAULT_DNS_TRIES);
  const nextId = deps.nextId ?? (() => randomInt(0, 0x10000));

  const { parent, nameServers: parentNs } = await parentZoneOf(name, resolveNs);
  const addressed = await Promise.allSettled(
    parentNs.slice(0, MAX_PARENT_SERVERS).map((h) => resolve4(h)),
  );
  const servers = addressed.flatMap((r) =>
    r.status === "fulfilled" && r.value[0] ? [r.value[0]] : [],
  );
  if (servers.length === 0) {
    throw dnsError(
      "EPARENTUNRESOLVABLE",
      `none of ${parent}'s nameservers (${parentNs.join(", ")}) resolved to an address`,
    );
  }

  let lastError: Error | undefined;
  for (let attempt = 0; attempt < tries; attempt++) {
    const server = servers[attempt % servers.length]!;
    const id = nextId();
    let reply: DnsMessage;
    try {
      reply = parseDnsMessage(await exchange(server, encodeNsQuery(name, id)));
    } catch (error) {
      lastError = error as Error;
      continue;
    }
    if (!reply.isResponse || reply.id !== id || reply.questionName !== name) {
      lastError = dnsError(
        "EFORMERR",
        `${server} answered a different query (id ${reply.id}, name ${reply.questionName})`,
      );
      continue;
    }
    if (reply.rcode === RCODE_NXDOMAIN) {
      throw dnsError(NOTFOUND, `${parent} (${server}) answered NXDOMAIN for ${name}`);
    }
    if (reply.rcode !== 0) {
      lastError = dnsError(
        `ERCODE${reply.rcode}`,
        `${parent} (${server}) answered rcode ${reply.rcode} for ${name}`,
      );
      continue;
    }
    // A referral carries the delegation in AUTHORITY; a parent server that also
    // hosts the child answers it in ANSWER. Only NS records owned by the zone
    // itself count — a parent's own NS in authority is not a delegation.
    const delegated = [...reply.answers, ...reply.authority]
      .filter((r) => r.type === TYPE_NS && r.name === name && r.target)
      .map((r) => r.target!);
    if (delegated.length > 0) return [...new Set(delegated)];
    if (reply.truncated) {
      lastError = dnsError("ETRUNCATED", `${parent} (${server}) truncated its answer for ${name}`);
      continue;
    }
    throw dnsError(NODATA, `${parent} (${server}) holds no delegation for ${name}`);
  }
  throw lastError ?? dnsError("ETIMEOUT", `no parent server answered for ${name}`);
}
