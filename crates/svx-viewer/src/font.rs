//! A bundled bitmap font (Noto Sans Mono, SIL OFL) for the watermark and
//! for plain-text documents.

use noto_sans_mono_bitmap::{FontWeight, RasterHeight, get_raster, get_raster_width};

#[derive(Clone, Copy, Debug)]
pub(crate) enum Size {
    S16,
    S20,
    S24,
    S32,
}

impl Size {
    fn height(self) -> RasterHeight {
        match self {
            Size::S16 => RasterHeight::Size16,
            Size::S20 => RasterHeight::Size20,
            Size::S24 => RasterHeight::Size24,
            Size::S32 => RasterHeight::Size32,
        }
    }

    /// Height of a text line in pixels.
    pub(crate) fn line_height(self) -> usize {
        self.height().val() + 2
    }

    /// Width of one character (the font is monospaced).
    pub(crate) fn cell_width(self) -> usize {
        get_raster_width(FontWeight::Regular, self.height())
    }
}

/// Draw `text` into a coverage mask (`mask_w` wide) with its top-left at
/// (`x`, `y`). Characters the font lacks show as `?`; anything off the
/// mask is clipped.
pub(crate) fn draw(mask: &mut [u8], mask_w: usize, x: usize, y: usize, text: &str, size: Size) {
    let mask_h = mask.len() / mask_w.max(1);
    let cw = size.cell_width();
    for (i, c) in text.chars().enumerate() {
        let glyph = get_raster(c, FontWeight::Regular, size.height())
            .or_else(|| get_raster('?', FontWeight::Regular, size.height()));
        let Some(glyph) = glyph else { continue };
        for (row, line) in glyph.raster().iter().enumerate() {
            let py = y + row;
            if py >= mask_h {
                break;
            }
            for (col, &v) in line.iter().enumerate() {
                let px = x + i * cw + col;
                if px >= mask_w {
                    break;
                }
                let m = &mut mask[py * mask_w + px];
                *m = (*m).max(v);
            }
        }
    }
}
