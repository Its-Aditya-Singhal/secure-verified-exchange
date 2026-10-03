// The SVX logo ("The Clasp X", brand/svg): the sender's chevron meets the
// recipient's mirrored one; the gap between them is never closed. Drawn
// inline so the app needs no image or font files. Colors come from CSS
// (--brand-ink, --brand-signal) so light and dark themes both work.

const NS = "http://www.w3.org/2000/svg";

const TOP = "M7 4 H19 L32 17 L45 4 H57 L32 29 Z";
const BOTTOM = "M7 60 H19 L32 47 L45 60 H57 L32 35 Z";
// "SVX" in Unbounded Bold, outlined (from brand/svg/logo-lockup.svg).
const WORD = "M100.26 54.15L100.26 54.15L121.36 54.15Q121.86 57.25 124.26 59.55Q126.66 61.85 130.71 63.10Q134.76 64.35 140.26 64.35L140.26 64.35Q147.86 64.35 152.26 62.40Q156.66 60.45 156.66 56.65L156.66 56.65Q156.66 53.75 154.16 52.15Q151.66 50.55 144.56 49.85L144.56 49.85L130.56 48.55Q115.06 47.15 108.06 41.50Q101.06 35.85 101.06 26.25L101.06 26.25Q101.06 18.45 105.61 13.05Q110.16 7.65 118.41 4.90Q126.66 2.15 137.66 2.15L137.66 2.15Q148.46 2.15 156.86 5.20Q165.26 8.25 170.21 13.85Q175.16 19.45 175.56 26.85L175.56 26.85L154.56 26.85Q154.16 24.15 152.01 22.20Q149.86 20.25 146.16 19.20Q142.46 18.15 137.26 18.15L137.26 18.15Q130.26 18.15 126.16 20Q122.06 21.85 122.06 25.45L122.06 25.45Q122.06 28.05 124.51 29.65Q126.96 31.25 133.36 31.85L133.36 31.85L148.26 33.35Q158.96 34.35 165.36 36.80Q171.76 39.25 174.66 43.55Q177.56 47.85 177.56 54.25L177.56 54.25Q177.56 62.15 172.86 68Q168.16 73.85 159.66 77.10Q151.16 80.35 139.86 80.35L139.86 80.35Q128.26 80.35 119.41 77.10Q110.56 73.85 105.56 67.90Q100.56 61.95 100.26 54.15ZM205.26 3.75L234.36 69.45L225.56 69.45L254.46 3.75L276.36 3.75L241.46 78.75L217.96 78.75L183.06 3.75L205.26 3.75ZM364.46 3.75L329.76 46.05L329.76 33.45L366.56 78.75L341.06 78.75L316.76 47.35L326.96 47.35L302.56 78.75L277.36 78.75L314.36 33.55L314.36 45.95L279.56 3.75L305.46 3.75L327.46 32.15L317.26 32.15L338.96 3.75L364.46 3.75Z";

function svg(viewBox: string, cls: string, label?: string): SVGSVGElement {
  const el = document.createElementNS(NS, "svg");
  el.setAttribute("viewBox", viewBox);
  el.setAttribute("class", cls);
  if (label) {
    el.setAttribute("role", "img");
    el.setAttribute("aria-label", label);
  } else {
    el.setAttribute("aria-hidden", "true");
  }
  return el;
}

function path(d: string, cls: string): SVGPathElement {
  const p = document.createElementNS(NS, "path");
  p.setAttribute("d", d);
  p.setAttribute("class", cls);
  return p;
}

/** The symbol alone (64 x 64 grid). */
export function brandSymbol(cls = "brand-symbol", label?: string): SVGSVGElement {
  const el = svg("0 0 64 64", cls, label);
  el.append(path(TOP, "brand-ink"), path(BOTTOM, "brand-signal"));
  return el;
}

/** Symbol + "SVX" wordmark. */
export function brandLockup(cls = "brand-lockup", label = "SVX"): SVGSVGElement {
  const el = svg("0 0 366.6 82.5", cls, label);
  const g = document.createElementNS(NS, "g");
  g.setAttribute("transform", "translate(-10.313 -5.893) scale(1.4732)");
  g.append(path(TOP, "brand-ink"), path(BOTTOM, "brand-signal"));
  el.append(g, path(WORD, "brand-ink"));
  return el;
}
