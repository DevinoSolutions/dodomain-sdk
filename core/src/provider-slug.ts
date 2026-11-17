// The URL slug of a watched Domain Connect provider, ONE rule. Dependency-free
// (no zod, no imports) on purpose: scripts/seo/check-dc-provider-pages.mjs runs
// it under plain `node`, and apps/landing builds /domain-connect/<slug> from it.
//
// "GoDaddy" -> "godaddy", "1&1" -> "1-and-1", "Simply.com" -> "simply-com",
// "Squarespace Domains" -> "squarespace-domains".
export function providerSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
