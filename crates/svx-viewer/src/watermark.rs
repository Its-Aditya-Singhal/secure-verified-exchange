//! The watermark: the recipient's address, the time and the file ID, tiled
//! diagonally over the whole page and burned into the pixels. It is applied
//! here, in Rust, after rendering, so nothing in the web layer can remove it.

use crate::Rgba;
use crate::font::{self, Size};

/// Longest line kept; the rest is cut.
const MAX_LINE_CHARS: usize = 64;
/// How strongly the text shows (0 to 1).
const OPACITY: f32 = 0.20;
/// Text rises to the right at this angle (degrees).
const ANGLE_DEG: f32 = 30.0;

/// The lines to burn in, such as the recipient's email, the time and a
/// short file ID.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Watermark {
    lines: Vec<String>,
}

impl Watermark {
    pub fn new(lines: impl IntoIterator<Item = String>) -> Watermark {
        Watermark {
            lines: lines
                .into_iter()
                .map(|l| {
                    l.chars()
                        .filter(|c| !c.is_control())
                        .take(MAX_LINE_CHARS)
                        .collect::<String>()
                })
                .filter(|l| !l.is_empty())
                .take(4)
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

struct Tile {
    mask: Vec<u8>,
    w: usize,
    h: usize,
}

fn size_for(width: u32) -> Size {
    match width {
        1800.. => Size::S32,
        1000.. => Size::S24,
        600.. => Size::S20,
        _ => Size::S16,
    }
}

fn tile(mark: &Watermark, size: Size) -> Tile {
    let cols = mark
        .lines
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(1);
    let pad = size.line_height() * 2;
    let w = cols * size.cell_width() + pad * 2;
    let h = mark.lines.len() * size.line_height() + pad * 2;
    let mut mask = vec![0u8; w * h];
    for (i, line) in mark.lines.iter().enumerate() {
        font::draw(&mut mask, w, pad, pad + i * size.line_height(), line, size);
    }
    Tile { mask, w, h }
}

impl Tile {
    /// Coverage (0 to 1) at a point, wrapping around, bilinear.
    fn at(&self, u: f32, v: f32) -> f32 {
        let (w, h) = (self.w as f32, self.h as f32);
        let (u, v) = (u.rem_euclid(w), v.rem_euclid(h));
        let (x0, y0) = (u.floor() as usize % self.w, v.floor() as usize % self.h);
        let (x1, y1) = ((x0 + 1) % self.w, (y0 + 1) % self.h);
        let (fx, fy) = (u.fract(), v.fract());
        let m = |x: usize, y: usize| f32::from(self.mask[y * self.w + x]) / 255.0;
        let top = m(x0, y0) * (1.0 - fx) + m(x1, y0) * fx;
        let bottom = m(x0, y1) * (1.0 - fx) + m(x1, y1) * fx;
        top * (1.0 - fy) + bottom * fy
    }
}

/// Burn the watermark into `img`.
pub(crate) fn apply(img: &mut Rgba, mark: &Watermark) {
    if mark.is_empty() || img.width == 0 || img.height == 0 {
        return;
    }
    let t = tile(mark, size_for(img.width));
    let (sin, cos) = ANGLE_DEG.to_radians().sin_cos();
    let width = img.width as usize;
    for (i, px) in img.data.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let (x, y) = ((i % width) as f32, (i / width) as f32);
        // Sample the tile in a frame rotated so the text rises to the right.
        let u = x * cos - y * sin;
        let v = x * sin + y * cos;
        let a = t.at(u, v) * OPACITY;
        if a <= 0.0 {
            continue;
        }
        // Dark text on light pixels, light text on dark ones.
        let lum = (u32::from(px[0]) * 3 + u32::from(px[1]) * 6 + u32::from(px[2])) / 10;
        let target = if lum > 140 { 20.0 } else { 235.0 };
        for c in &mut px[..3] {
            let v = f32::from(*c);
            *c = (v + (target - v) * a).round().clamp(0.0, 255.0) as u8;
        }
    }
}
