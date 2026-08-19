// Integrator brand-color math for END-USER surfaces (hosted connect flow,
// dashboard live preview). The ONE home for the brand-color literal pattern
// and the WCAG contrast clamp — surfaces never use an integrator's raw
// brandColor as TEXT color; they use readableBrandInk() (darkened until it
// reads on white) and brandMarkForeground() (white vs warm ink on the raw
// color). ZERO imports and zod-free on purpose (the F-010 message-types
// discipline): this module must stay safe to pull into any client bundle.
// The zod boundary schema that VALIDATES branding writes lives in
// schemas.ts (zAppBrandingInput) and imports this pattern.

/** #RRGGBB only — the one accepted brandColor shape (schemas.ts validates writes with it). */
export const BRAND_COLOR_PATTERN = /^#[0-9a-fA-F]{6}$/;

/** WCAG 2.x minimum contrast for normal text — the clamp target. */
export const WCAG_AA_TEXT_CONTRAST = 4.5;

interface Rgb {
  r: number;
  g: number;
  b: number;
}

function parseBrandHex(hex: string): Rgb | null {
  if (!BRAND_COLOR_PATTERN.test(hex)) return null;
  return {
    r: Number.parseInt(hex.slice(1, 3), 16),
    g: Number.parseInt(hex.slice(3, 5), 16),
    b: Number.parseInt(hex.slice(5, 7), 16),
  };
}

function toHex({ r, g, b }: Rgb): string {
  const channel = (v: number) =>
    Math.max(0, Math.min(255, Math.round(v)))
      .toString(16)
      .padStart(2, "0");
  return `#${channel(r)}${channel(g)}${channel(b)}`;
}

// WCAG 2.x relative luminance (sRGB linearization).
function relativeLuminance({ r, g, b }: Rgb): number {
  const linear = (v: number) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b);
}

/**
 * WCAG 2.x contrast ratio between two #RRGGBB colors (1..21, symmetric).
 * Returns null when either input is not a valid brand hex — callers treat
 * that as "no usable brand color" rather than throwing (DB rows written
 * before validation existed must degrade gracefully, not 500 a connect page).
 */
export function contrastRatio(hexA: string, hexB: string): number | null {
  const a = parseBrandHex(hexA);
  const b = parseBrandHex(hexB);
  if (!a || !b) return null;
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  const [lighter, darker] = la >= lb ? [la, lb] : [lb, la];
  return (lighter + 0.05) / (darker + 0.05);
}

/**
 * The brand color, darkened just enough to be legible as TEXT on a white
 * surface (>= 4.5:1, WCAG AA). Already-legible colors pass through
 * unchanged; light brand colors (pastel logos, yellows) converge toward
 * black in small multiplicative steps, so hue is preserved as long as
 * possible. Returns null for anything that is not a #RRGGBB hex.
 */
export function readableBrandInk(brandColor: string): string | null {
  let rgb = parseBrandHex(brandColor);
  if (!rgb) return null;
  const white = { r: 255, g: 255, b: 255 };
  const contrastOnWhite = (candidate: Rgb) => {
    const ll = relativeLuminance(white);
    const lc = relativeLuminance(candidate);
    return (ll + 0.05) / (lc + 0.05);
  };
  // 0.92 per step ≈ 8% darker each time; 64 steps reaches black from any
  // start, and black is 21:1 on white — the loop always terminates passing.
  for (let step = 0; step < 64 && contrastOnWhite(rgb) < WCAG_AA_TEXT_CONTRAST; step++) {
    rgb = { r: rgb.r * 0.92, g: rgb.g * 0.92, b: rgb.b * 0.92 };
    if (rgb.r < 1 && rgb.g < 1 && rgb.b < 1) break;
  }
  return toHex(rgb);
}

/** Graphite & Pine near-black ink (docs/DESIGN.md) — the dark foreground candidate on a brand color. */
const INK = "#17201C";
const WHITE = "#FFFFFF";

/**
 * The foreground to set ON the raw brand color (e.g. the monogram chip):
 * white or the warm ink, whichever contrasts more. Returns null for a
 * non-#RRGGBB input (callers then skip brand-colored chrome entirely).
 */
export function brandMarkForeground(brandColor: string): string | null {
  const onWhite = contrastRatio(brandColor, WHITE);
  const onInk = contrastRatio(brandColor, INK);
  if (onWhite === null || onInk === null) return null;
  return onWhite >= onInk ? WHITE : INK;
}
