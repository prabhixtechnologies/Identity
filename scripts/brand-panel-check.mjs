// What the sign-in brand panel measures, per product and per mode.
//
// `node scripts/brand-panel-check.mjs` — run it before changing any of the --panel-* numbers in
// login.css. The panel is dark in both modes, so its text is near-white and the risk is the
// accent glow washing the base out until that text stops clearing AA. This composites the
// hottest point of each glow over the base, reports the worst contrast per brand, and sweeps
// for the boldest tint and glow that still leave the dimmed text above 4.8:1.
//
// The PLAN below has to match login.css by hand. That is the weak spot: nothing fails if they
// drift. It is not wired into CI because it reads percentages out of a stylesheet rather than
// being generated from the tokens, unlike web-kit's contrast gate.
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../src/main/resources/static/assets/prabhix-tokens.css", import.meta.url), "utf8");

const hex = (h) => {
  const s = h.replace("#", "");
  const f = s.length === 3 ? s.split("").map((c) => c + c).join("") : s;
  return [0, 2, 4].map((i) => parseInt(f.slice(i, i + 2), 16));
};
const lum = (rgb) => {
  const [r, g, b] = rgb.map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const contrast = (a, b) => {
  const [l1, l2] = [lum(hex(a)), lum(hex(b))].sort((x, y) => y - x);
  return (l1 + 0.05) / (l2 + 0.05);
};
const over = (fg, alpha, bg) => {
  const [f, b] = [hex(fg), hex(bg)];
  const out = f.map((v, i) => Math.round(v * alpha + b[i] * (1 - alpha)));
  return "#" + out.map((v) => v.toString(16).padStart(2, "0")).join("");
};

// Pull --px-accent / --px-accent-2 out of each selector block.
function accentsFor(selector) {
  // The selector is one of possibly several in the prelude, so it can be followed by a comma
  // rather than the brace. The dark blocks are written that way now that a brand can be
  // declared below the root as well as on it:
  //
  //   [data-brand="oneops"][data-theme="dark"],
  //   [data-theme="dark"] [data-brand="oneops"] { ... }
  //
  // Requiring `selector + " {"` stopped finding those and reported the block missing, which is
  // the honest failure for a parser pinned to exact text - but the block is there, and this
  // should read it. Requiring a comma or a brace after the match is also what keeps
  // `[data-brand="x"]` from matching the start of `[data-brand="x"][data-theme="dark"]` and
  // measuring the dark accents as if they were the light ones.
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const at = css.search(new RegExp(escaped + "\\s*[,{]"));
  if (at < 0) throw new Error("missing block: " + selector);
  const block = css.slice(at, css.indexOf("}", at));
  const grab = (name) => block.match(new RegExp(`${name}:\\s*(#[0-9a-f]{3,8})`, "i"))?.[1];
  return { accent: grab("--px-accent"), accent2: grab("--px-accent-2") };
}

const brands = ["technologies", "oneops", "admin", "mobistack", "mailroom"];
const FOOT_MIX = 0.46; // .stage-foot, 12px, so 4.5:1 applies to it too

/**
 * The panel's own numbers, read out of the stylesheet that uses them.
 *
 * These were a hand-copied table, and the file said so: "nothing fails if they drift". That is
 * a real failure mode for a checker — it reports PASS against numbers nobody is shipping, which
 * is worse than not running, because it is believed. Parsed now, so changing `--panel-tint` in
 * login.css changes what this measures, and a value this cannot find is an error rather than a
 * silent fallback to the last one somebody typed here.
 */
const login = readFileSync(new URL("../src/main/resources/static/assets/login.css", import.meta.url), "utf8");

function panelVars(selector) {
  const at = login.indexOf(selector);
  if (at < 0) throw new Error(`login.css has no ${selector} block`);
  const block = login.slice(at, login.indexOf("}", at));
  const grab = (name, pattern) => {
    const found = block.match(new RegExp(`--panel-${name}:\\s*(${pattern})`, "i"));
    if (!found) throw new Error(`login.css ${selector} does not set --panel-${name}`);
    return found[1];
  };
  return {
    base: grab("floor", "#[0-9a-f]{3,8}"),
    tint: Number(grab("tint", "[\\d.]+(?=%)")) / 100,
    glow1: Number(grab("glow", "[\\d.]+(?=%)")) / 100,
    glow2: Number(grab("glow-2", "[\\d.]+(?=%)")) / 100,
  };
}

// --panel-ink and --panel-ink-muted both live on the light block; the dark rules override only
// the strengths, which is why there is one ink here and two sets of everything else.
const base = panelVars(".stage-brand {");
const INK = login.match(/--panel-ink:\s*(#[0-9a-f]{3,8})/i)?.[1];
if (!INK) throw new Error("login.css does not set --panel-ink");
const MUTED_MIX = Number(login.match(/--panel-ink-muted:[^;]*?([\d.]+)%/)?.[1]) / 100;
if (!MUTED_MIX) throw new Error("login.css does not set --panel-ink-muted");

const PLAN = {
  light: base,
  dark: panelVars('[data-theme="dark"] .stage-brand {'),
};

let worst = { ratio: 99 };
for (const mode of ["light", "dark"]) {
  const p = PLAN[mode];
  console.log(`\n  ${mode}  base ${p.base}  tint ${p.tint}  glow ${p.glow1}/${p.glow2}`);
  for (const brand of brands) {
    const sel = mode === "light" ? `[data-brand="${brand}"]` : `[data-brand="${brand}"][data-theme="dark"]`;
    const { accent, accent2 } = accentsFor(sel);
    const base = over(accent, p.tint, p.base);
    const hot1 = over(accent, p.glow1, base);
    const hot2 = over(accent2, p.glow2, base);
    const rows = [
      ["base", base, contrast(INK, base)],
      ["glow-accent", hot1, contrast(INK, hot1)],
      ["glow-accent-2", hot2, contrast(INK, hot2)],
      ["dimmed@78%", hot1, contrast(over(INK, MUTED_MIX, hot1), hot1)],
    ];
    // Not part of the verdict: the alpha .stage-foot used to carry, kept so the regression
    // this replaced stays visible in the output rather than only in a commit message.
    const wasFoot = contrast(over(INK, FOOT_MIX, hot1), hot1);
    for (const [what, bg, ratio] of rows) {
      if (ratio < worst.ratio) worst = { ratio, brand, mode, what, bg };
      const flag = ratio < 4.5 ? "  << under 4.5" : "";
      console.log(`    ${brand.padEnd(13)} ${what.padEnd(14)} ${bg}  ${ratio.toFixed(2)}:1${flag}`);
    }
    console.log(`    ${"".padEnd(13)} ${"(was 46%)".padEnd(14)} ${hot1}  ${wasFoot.toFixed(2)}:1  - replaced`);
  }
}
console.log(`\n  worst: ${worst.ratio.toFixed(2)}:1  (${worst.brand} ${worst.mode} ${worst.what} on ${worst.bg})`);
const pass = worst.ratio >= 4.5;
console.log(pass ? "  PASS - every panel clears AA for body text" : "  FAIL - see the row marked under 4.5 above");

// How much colour can the panel carry? Sweep tint and glow, keep the boldest pair that still
// leaves the dimmed text at 4.5:1 with a little margin. Colourfulness is scored as the mean
// chroma of the resulting base and hot-spot across all five brands, so a setting that only
// helps one product does not win.
function chroma(h) {
  const [r, g, b] = hex(h);
  return Math.max(r, g, b) - Math.min(r, g, b);
}
console.log("\n  boldest setting that keeps dimmed text at 4.8:1 or better:");
for (const mode of ["light", "dark"]) {
  let best = null;
  // Dark mode starts lower: its accents are light tints, so the same percentages that make a
  // light-mode panel richly coloured make a dark-mode one washed out.
  const lo = mode === "dark" ? 0.04 : 0.1;
  for (let tint = lo; tint <= 0.45001; tint += 0.01) {
    for (let glow = lo; glow <= 0.9001; glow += 0.01) {
      let ok = true;
      let score = 0;
      for (const brand of brands) {
        const sel = mode === "light" ? `[data-brand="${brand}"]` : `[data-brand="${brand}"][data-theme="dark"]`;
        const { accent, accent2 } = accentsFor(sel);
        const base = over(accent, tint, PLAN[mode].base);
        const hot = over(accent, glow, base);
        const hot2 = over(accent2, PLAN[mode].glow2, base);
        for (const bg of [base, hot, hot2]) {
          if (contrast(INK, bg) < 4.8) ok = false;
          if (contrast(over(INK, MUTED_MIX, bg), bg) < 4.8) ok = false;
        }
        score += chroma(base) + chroma(hot);
      }
      if (ok && (!best || score > best.score)) best = { tint, glow, score: score / brands.length };
    }
  }
  console.log(`    ${mode}: tint ${(best.tint * 100).toFixed(0)}%  glow ${(best.glow * 100).toFixed(0)}%  (mean chroma ${best.score.toFixed(0)})`);
}

// The lowest alpha that still clears 4.5:1 everywhere, for the two dimmed texts.
console.log("\n  minimum alpha for 4.5:1 across all ten panels:");
for (const label of ["role", "foot"]) {
  let need = 0;
  for (let a = 0.3; a <= 1.001; a += 0.01) {
    let ok = true;
    for (const mode of ["light", "dark"]) {
      const p = PLAN[mode];
      for (const brand of brands) {
        const sel = mode === "light" ? `[data-brand="${brand}"]` : `[data-brand="${brand}"][data-theme="dark"]`;
        const { accent } = accentsFor(sel);
        const hot = over(accent, p.glow1, over(accent, p.tint, p.base));
        if (contrast(over(INK, a, hot), hot) < 4.5) ok = false;
      }
    }
    if (ok) { need = a; break; }
  }
  console.log(`    ${label}: ${need ? (need * 100).toFixed(0) + "%" : "not reachable even at 100%"}`);
}

// Exit code, so this can be a CI step rather than something to read.
if (!pass) process.exit(1);
