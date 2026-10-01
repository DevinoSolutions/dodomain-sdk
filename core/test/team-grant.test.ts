// The multi-team OAuth grant contract (2026-09-27): the consent card's team
// selection, as the server validates it, and the zod-free constants the card
// imports without pulling zod into the browser bundle.
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DODOMAIN_TEAM_HEADER,
  TEAM_GRANT_SELECTION_FIELD,
  teamGrantSelectionSchema,
  zListTeamsResponse,
} from "../src/schemas.ts";
import * as zodFree from "../src/team-grant.ts";

const selection = teamGrantSelectionSchema(3);

test("schemas.ts re-exports the zod-free constants unchanged, so the card and the server share one spelling", () => {
  assert.equal(DODOMAIN_TEAM_HEADER, zodFree.DODOMAIN_TEAM_HEADER);
  assert.equal(TEAM_GRANT_SELECTION_FIELD, zodFree.TEAM_GRANT_SELECTION_FIELD);
  assert.equal(DODOMAIN_TEAM_HEADER, "DoDomain-Team");
  assert.equal(TEAM_GRANT_SELECTION_FIELD, "dodomain_team_grant");
});

test("an all-teams selection is accepted as exactly { mode: 'all' }", () => {
  assert.deepEqual(selection.parse({ mode: "all" }), { mode: "all" });
});

test("a chosen-teams selection keeps the ids in the order the card sent them", () => {
  assert.deepEqual(selection.parse({ mode: "teams", teamIds: ["t_b", "t_a"] }), {
    mode: "teams",
    teamIds: ["t_b", "t_a"],
  });
});

test("an empty checklist is refused with a message a person can act on", () => {
  const result = selection.safeParse({ mode: "teams", teamIds: [] });
  assert.equal(result.success, false);
  assert.match(result.error?.issues[0]?.message ?? "", /at least one team/);
});

test("the same team listed twice is refused rather than silently collapsed", () => {
  const result = selection.safeParse({ mode: "teams", teamIds: ["t_a", "t_a"] });
  assert.equal(result.success, false);
  assert.match(result.error?.issues[0]?.message ?? "", /listed once/);
});

test("more teams than a user may belong to is refused, bounding the write", () => {
  assert.equal(
    selection.safeParse({ mode: "teams", teamIds: ["t_1", "t_2", "t_3", "t_4"] }).success,
    false,
  );
});

test("an unknown mode, a missing mode, and extra keys are all refused", () => {
  for (const body of [
    { mode: "some" },
    { teamIds: ["t_a"] },
    { mode: "all", teamIds: ["t_a"] },
    { mode: "teams", teamIds: ["t_a"], allTeams: true },
    "all",
    null,
  ]) {
    assert.equal(selection.safeParse(body).success, false, JSON.stringify(body));
  }
});

test("blank and oversized team ids are refused", () => {
  assert.equal(selection.safeParse({ mode: "teams", teamIds: [""] }).success, false);
  assert.equal(selection.safeParse({ mode: "teams", teamIds: ["x".repeat(65)] }).success, false);
});

test("GET /api/v1/teams answers only ids and names", () => {
  const parsed = zListTeamsResponse.parse({
    teams: [{ id: "t_a", name: "Acme", plan: "pro" }],
  });
  assert.deepEqual(parsed, { teams: [{ id: "t_a", name: "Acme" }] });
});
