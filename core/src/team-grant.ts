// The zod-FREE half of the multi-team OAuth grant contract (2026-09-27) — the
// message-types.ts pattern. The consent card is a client component that needs
// the body field's name and the selection's shape, and must not pull zod into
// the browser bundle for a string and a type. Zero imports, so it cannot.
//
// schemas.ts re-exports everything here unchanged and pins its validator
// (teamGrantSelectionSchema) to TeamGrantSelection, so the two cannot drift.

/**
 * The request header that names the team an API call acts on, when the
 * credential may act on more than one (an OAuth grant covering several teams).
 * HTTP header names are case-insensitive; this is the canonical spelling.
 */
export const DODOMAIN_TEAM_HEADER = "DoDomain-Team";

/** The consent POST body field that carries the team selection, sent beside the
 * OAuth plugin's own `accept` and `oauth_query`. Absent on a denial. */
export const TEAM_GRANT_SELECTION_FIELD = "dodomain_team_grant";

/**
 * The team selection one consent approval records: every team the user belongs
 * to (including teams joined later), or a named subset.
 */
export type TeamGrantSelection = { mode: "all" } | { mode: "teams"; teamIds: string[] };
