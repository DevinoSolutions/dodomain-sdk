// Integrator branding: the WCAG contrast clamp (branding.ts) and the
// write-boundary validation (schemas.ts's zAppBrandingInput). These guard the
// two safety promises end-user surfaces rely on: brand-colored TEXT is always
// legible on white, and a logo URL is always https (untrusted integrator
// input, rendered client-side only).
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  BRAND_COLOR_PATTERN,
  WCAG_AA_TEXT_CONTRAST,
  brandMarkForeground,
  contrastRatio,
  readableBrandInk,
} from "../src/branding.ts";
import { zAppBrandingInput, zAppName } from "../src/schemas.ts";

void describe("contrastRatio", () => {
  void it("returns 21:1 for black on white (the WCAG maximum) and 1:1 for identical colors", () => {
    assert.equal(contrastRatio("#000000", "#FFFFFF"), 21);
    assert.equal(contrastRatio("#0E6B4E", "#0E6B4E"), 1);
  });

  void it("is symmetric — the ratio does not depend on argument order", () => {
    assert.equal(contrastRatio("#0E6B4E", "#FFFFFF"), contrastRatio("#FFFFFF", "#0E6B4E"));
  });

  void it("rates the Graphite & Pine accent (#0E6B4E) around the ~6.5:1 docs/DESIGN.md advertises on white — comfortably past AA", () => {
    const ratio = contrastRatio("#0E6B4E", "#FFFFFF");
    assert.ok(ratio !== null && ratio > 6.3 && ratio < 6.7, `got ${ratio}`);
  });

  void it("returns null (not a throw) for anything that is not a #RRGGBB hex", () => {
    assert.equal(contrastRatio("red", "#FFFFFF"), null);
    assert.equal(contrastRatio("#FFF", "#FFFFFF"), null);
    assert.equal(contrastRatio("", "#FFFFFF"), null);
  });
});

void describe("readableBrandInk (the clamp end-user surfaces MUST use for brand text on white)", () => {
  void it("passes an already-legible dark brand color through unchanged", () => {
    assert.equal(readableBrandInk("#0E6B4E"), "#0e6b4e");
  });

  void it("darkens a pastel brand color until it reads at >= 4.5:1 on white", () => {
    const clamped = readableBrandInk("#7FDBCA");
    assert.ok(clamped !== null);
    assert.notEqual(clamped.toLowerCase(), "#7fdbca");
    const ratio = contrastRatio(clamped, "#FFFFFF");
    assert.ok(ratio !== null && ratio >= WCAG_AA_TEXT_CONTRAST, `got ${ratio}`);
  });

  void it("clamps even pure yellow and pure white — the worst-contrast inputs an integrator can pick", () => {
    for (const hostile of ["#FFFF00", "#FFFFFF"]) {
      const clamped = readableBrandInk(hostile);
      assert.ok(clamped !== null, `${hostile} clamped to null`);
      const ratio = contrastRatio(clamped, "#FFFFFF");
      assert.ok(
        ratio !== null && ratio >= WCAG_AA_TEXT_CONTRAST,
        `${hostile} → ${clamped} is ${ratio}:1`,
      );
    }
  });

  void it("returns null for a malformed stored value instead of rendering an illegible accent", () => {
    assert.equal(readableBrandInk("green"), null);
    assert.equal(readableBrandInk("#12"), null);
    assert.equal(readableBrandInk("rgb(14,107,78)"), null);
  });
});

void describe("brandMarkForeground (text ON the raw brand color, e.g. the monogram chip)", () => {
  void it("picks white on a dark brand color and graphite ink on a light one", () => {
    assert.equal(brandMarkForeground("#0E6B4E"), "#FFFFFF");
    assert.equal(brandMarkForeground("#F5E9C9"), "#17201C");
  });

  void it("returns null for a malformed value so callers skip brand chrome entirely", () => {
    assert.equal(brandMarkForeground("not-a-color"), null);
  });
});

void describe("zAppBrandingInput (the ONE write boundary for App branding)", () => {
  const valid = {
    logoUrl: "https://uptimely.io/logo.png",
    brandColor: "#2B6CB0",
  };

  void it("accepts an https logo URL and a #RRGGBB brand color", () => {
    const parsed = zAppBrandingInput.safeParse(valid);
    assert.ok(parsed.success);
    assert.deepEqual(parsed.data, valid);
  });

  void it("accepts null logoUrl and null brandColor — branding is optional per field", () => {
    const parsed = zAppBrandingInput.safeParse({ logoUrl: null, brandColor: null });
    assert.ok(parsed.success);
  });

  void it("rejects every non-https logo scheme an attacker could smuggle (http, javascript, data, ftp)", () => {
    for (const url of [
      "http://uptimely.io/logo.png",
      "javascript:alert(1)",
      "data:image/svg+xml;base64,PHN2Zy8+",
      "ftp://uptimely.io/logo.png",
      "//uptimely.io/logo.png",
    ]) {
      const parsed = zAppBrandingInput.safeParse({ ...valid, logoUrl: url });
      assert.equal(parsed.success, false, `${url} should be rejected`);
    }
  });

  void it("rejects a logo URL carrying embedded credentials (they would leak into end-user DOM)", () => {
    const parsed = zAppBrandingInput.safeParse({
      ...valid,
      logoUrl: "https://user:secret@uptimely.io/logo.png",
    });
    assert.equal(parsed.success, false);
  });

  void it("rejects brand colors branding.ts's clamp could not parse (#FFF, names, rgb())", () => {
    for (const color of ["#FFF", "pine", "rgb(14,107,78)", "#12345G"]) {
      const parsed = zAppBrandingInput.safeParse({ ...valid, brandColor: color });
      assert.equal(parsed.success, false, `${color} should be rejected`);
    }
  });

  void it("does NOT write a name — App.name has its own editor now (#37: one column, one writer)", () => {
    const parsed = zAppBrandingInput.safeParse({ ...valid, name: "Renamed via branding" });
    assert.ok(parsed.success);
    assert.equal(
      "name" in parsed.data,
      false,
      "a name smuggled through the branding form must never reach prisma.app.update",
    );
  });

  void it("keeps the accepted brandColor shape in lockstep with BRAND_COLOR_PATTERN (one home)", () => {
    const parsed = zAppBrandingInput.safeParse(valid);
    assert.ok(parsed.success);
    assert.ok(parsed.data.brandColor !== null && BRAND_COLOR_PATTERN.test(parsed.data.brandColor));
  });
});

// zAppName is the ONE rule both createApp and renameApp parse (#37) — the
// point of extracting it was that a rename can never accept a name a create
// would reject, so these cases stand for BOTH writers.
void describe("zAppName (the ONE write rule for App.name)", () => {
  void it("trims surrounding whitespace rather than storing it", () => {
    const parsed = zAppName.safeParse("  Uptimely  ");
    assert.ok(parsed.success);
    assert.equal(parsed.data, "Uptimely");
  });

  void it("rejects an empty or whitespace-only name with the create form's own message", () => {
    for (const value of ["", "   ", "\t\n"]) {
      const parsed = zAppName.safeParse(value);
      assert.equal(parsed.success, false, `${JSON.stringify(value)} should be rejected`);
    }
    const parsed = zAppName.safeParse("");
    assert.equal(parsed.success, false);
    assert.equal(parsed.error.issues[0]?.message, "Name is required.");
  });

  void it("caps the name at 80 characters — the length the column's other surfaces already assumed", () => {
    assert.ok(zAppName.safeParse("a".repeat(80)).success);
    const tooLong = zAppName.safeParse("a".repeat(81));
    assert.equal(tooLong.success, false);
    assert.equal(tooLong.error.issues[0]?.message, "Name is too long (80 characters max).");
  });

  void it("measures length AFTER trimming, so padding cannot push a legal name over the cap", () => {
    assert.ok(zAppName.safeParse(`   ${"a".repeat(80)}   `).success);
  });
});
