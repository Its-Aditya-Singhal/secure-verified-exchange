# SVX marketing site

Static HTML, CSS and ES modules. No framework, no build step, no backend, no analytics, no external requests at runtime.

## Deploy (Cloudflare Pages)

Create a Pages project, set the **build command to none** and the **output directory to `site/`** (or upload the folder directly). `_headers` sets a strict CSP and caching. Cloudflare serves `security.html` at `/security` automatically; `404.html` is used for unknown paths.

## Release switch

`assets/js/boot.js` has one setting, `RELEASE`:

- `'soon'` (now): every download button says "Coming soon", checksums are hidden and the download page explains what to expect.
- `'live'`: the real download buttons, checksums and the "verify your download" section appear.

Elements marked `when-live` / `when-soon` follow it. Without JavaScript the site shows the "soon" state.

## Before going live

- The SVX service must be online and the installers must be built with it (`SVX_OFFICIAL_*`), or downloaded apps can't connect.
- Put the installers in `downloads/` (`SVX-beta-macOS.dmg`, `SVX-beta-Windows.exe`, `SVX-beta-Linux.deb`; `scripts/prepare-download.sh` makes the first two) or change the `href`s in `download.html`.
- Replace each "Published with the build" (`#sum-mac`, `#sum-win`, `#sum-linux`) with the real SHA-256.
- Fill in the bracketed parts of `privacy.html` and `terms.html` (operator, contact, retention, governing law) and have them reviewed. Then remove the dashed draft notes.
- When the macOS capture test passes, change the macOS view-only status from "In testing" (`index.html`, `docs.html`).
- Set `RELEASE = 'live'` in `boot.js`.

## Copy rules

Every claim on the site must be true of the shipped app. In particular: view-only can't stop a photo of the screen; Windows capture blocking was tested on a real Windows laptop (2026-10-06); Linux refuses view-only files; revocation can't recall an opened file; approval and one-time are defaults, not guarantees; the service is trusted to enforce rules but can't decrypt alone. Example people and companies are fictional (Alice, Bob, Carol, Eve, Acme Security, Example Corp).

## Structure

```
index.html  security.html  download.html  docs.html  privacy.html  terms.html  404.html
assets/css/site.css        all styles, dark (default) + light themes via [data-theme]
assets/js/boot.js          theme before paint (no flash) and the RELEASE switch
assets/js/site.js          nav, reveals, counters, scroll-fill text, sticky steps, cursor, transitions, tabs
assets/js/hero3d.js        the 3D Clasp X (lazy-loaded)
assets/vendor/             three.module.min.js (r169), gsap.min.js + ScrollTrigger.min.js (3.12.5)
assets/fonts/              Unbounded 700, IBM Plex Sans 400/500/600, IBM Plex Mono 400 (woff2, self-hosted)
assets/brand/              lockups and symbol from the brand kit, unchanged
```

## How the 3D logo is built

`assets/js/hero3d.js` builds the Clasp X from the exact paths in `symbol.svg` on the 64-unit grid:

```
top (primary):  M7 4  H19 L32 17 L45 4  H57 L32 29 Z
bottom (accent): M7 60 H19 L32 47 L45 60 H57 L32 35 Z
```

1. Each path becomes a `THREE.Shape`. Points are re-centred on the grid (`x-32`, `32-y`), so the y-axis flips from SVG to 3D and the clasp gap (y 29 → 35, 6 units) sits on the origin.
2. `ExtrudeGeometry` gives each chevron 7 units of depth. The bevel uses `bevelOffset = -bevelSize`, so the bevel is cut *inside* the outline: the silhouette, and therefore the 6-unit gap, stays exactly as drawn. The gap is never closed or filled.
3. Two flat `MeshStandardMaterial`s use brand colours only: bone `#F3F1EC` + signal-bright `#FF6A3D` on dark, graphite `#1D1F24` + signal `#CF4A1F` on light. They switch live with the theme. No gradients or textures.
4. Motion: the chevrons slide in from opposite sides (ease-out-expo, staggered 150 ms) and stop at their grid positions. After that: a slow idle sway, pointer parallax, and scroll progress through the sticky hero that turns the logo and moves the camera in.

### Performance and accessibility

- `three.module.min.js` is only imported after `load`, in an idle callback, so it never blocks first paint. Until then a flat inline SVG of the symbol is shown in the same place.
- The render loop stops when the hero is off-screen (IntersectionObserver) or the tab is hidden. Pixel ratio is capped at 2 (1.5 on small screens).
- With `prefers-reduced-motion: reduce`, the 3D module is never loaded: the static SVG stays, pinned sections become normal flow, and all text is shown.
- If WebGL isn't available, the SVG fallback stays.
- The canvas is `aria-hidden`; the hero headline carries the meaning.

## Motion elsewhere

- GSAP ScrollTrigger drives the hero text scrub, the four sticky "how it works" steps and the counters. Without GSAP, IntersectionObserver fallbacks do the same job.
- Page transitions use native cross-document View Transitions where supported, with a short fade fallback elsewhere.
- The custom cursor only appears with a fine pointer that can hover (desktop) and without reduced motion.
