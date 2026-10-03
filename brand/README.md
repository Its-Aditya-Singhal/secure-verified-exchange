# SVX brand: "The Clasp X"

An X made of two chevrons. The sender's V meets the recipient's mirrored V:
two paths crossing (an exchange), and a clasp that closes only when both
sides meet. The gap between the two points is the clasp. **Never close it.**

The production files are in [`svg/`](svg). They are final, and their text is
outlined, so no fonts are needed. The design board with the other directions
that were explored isn't kept here.

## Colors

| Token | Hex | Use |
|---|---|---|
| graphite | `#1D1F24` | primary, text, light-background symbol |
| signal | `#CF4A1F` | accent on light backgrounds: the logo and large accents only, never body text |
| signal-bright | `#FF6A3D` | accent on dark backgrounds |
| bone | `#F3F1EC` | primary on dark backgrounds |
| dark surface | `#16171B` | dark background |
| mono | `#111418` | one-color versions |

Contrast: graphite on white is 16.6:1, signal on white 4.5:1, bone on
`#16171B` 16.4:1, signal-bright on `#16171B` 6.4:1. No gradients: the
symbol is always flat, in two colors or one.

## Symbol

On a 64 × 64 grid:

```
top (primary):    M7 4 H19 L32 17 L45 4 H57 L32 29 Z
bottom (accent):  M7 60 H19 L32 47 L45 60 H57 L32 35 Z
```

- The arms are at 45°, about 8.5 units thick (about 2 px at 16 px).
- The gap between the two points is 6 units (y 29 → 35).
- Leave clear space of at least 25% of the symbol's width on every side.
- The minimum size is 16 px.

## Wordmark and lockups

- `SVX` is set in Unbounded Bold (700), letter-spacing +0.02em.
- **Lockup:** the symbol is 1.1 × the cap height, and the gap between symbol and text is 0.28 × the symbol size.
- **Full lockup:** symbol, `SVX`, a 1 px divider (`#D4D1CA`), then "Secure Verified Exchange" in IBM Plex Sans 500.
- Text color is `#1D1F24` on light backgrounds and `#F3F1EC` on dark.

## Files

| File | Use |
|---|---|
| `symbol.svg`, `-dark`, `-mono` | the symbol for light or dark backgrounds, or in one color (recolor mono to white for knockouts) |
| `app-icon.svg` | 1024 × 1024 macOS-grid app icon: graphite tile, dark-variant symbol |
| `favicon.svg` | 64 × 64 full-bleed tile, used for small icons (16–48 px) |
| `file-icon.svg` | 80 × 100 `.svx` document icon |
| `wordmark*.svg`, `logo-lockup*.svg`, `logo-lockup-full*.svg` | text and lockups, in light, dark and mono versions |

## Where it's used

`build-icons.sh` regenerates everything below from `svg/`. Run it after
changing an SVG:

| Output | Made from |
|---|---|
| `apps/desktop/src-tauri/icons/icon.icns`, PNGs | `app-icon.svg` |
| `apps/desktop/src-tauri/icons/icon.ico` | `favicon.svg` (16–48 px), `app-icon.svg` (256 px) |
| `apps/desktop/src-tauri/icons/svx-file.icns` | `file-icon.svg`; the macOS `.svx` document icon (`src-tauri/Info.plist`) |
| `packaging/linux/icons/` | `file-icon.svg`; the freedesktop `application/vnd.svx` icon (deb and `install.sh`) |
| `packaging/windows/svx-file.ico` | `file-icon.svg`; the registry association's `DefaultIcon` |
| `brand/web/` | `favicon.svg` and `favicon-32.png`, and a 180 px `apple-touch-icon.png`, for the website |

Other places that use the brand:

- **The desktop app** draws the symbol and lockup inline (`apps/desktop/src/brand.ts`, generated from `logo-lockup.svg`). It sets the colors as CSS tokens in `apps/desktop/src/style.css`: graphite and bone carry the interface, and signal marks the current item, focus rings and progress.
- **The repository README** uses `logo-lockup-full.svg` and its dark version.

The file type keeps its existing identifiers (UTI `org.svx.artifact`, MIME
`application/vnd.svx`). The design handoff suggested `com.svx.sealed` and
`application/x-svx`, but changing them would break existing associations.
Its display name is now "SVX sealed file".
