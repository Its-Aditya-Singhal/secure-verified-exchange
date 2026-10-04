//! Plain UTF-8 text, wrapped onto letter-sized pages in a monospaced font.

use image::RgbaImage;
use image::imageops::{self, FilterType};

use crate::font::{self, Size};
use crate::{MAX_PAGES, Result, Rgba, ViewError};

/// A page, in pixels (letter at 96 dpi).
pub(crate) const PAGE_SIZE: (u32, u32) = (816, 1056);
const MARGIN: usize = 72;
const SIZE: Size = Size::S20;

pub(crate) struct TextDoc {
    lines: Vec<String>,
    rows: usize,
}

impl TextDoc {
    pub(crate) fn open(bytes: Vec<u8>) -> Result<TextDoc> {
        let text =
            String::from_utf8(bytes).map_err(|_| ViewError::Malformed("not UTF-8 text".into()))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        let cols = (PAGE_SIZE.0 as usize - 2 * MARGIN) / SIZE.cell_width();
        let rows = (PAGE_SIZE.1 as usize - 2 * MARGIN) / SIZE.line_height();
        let mut lines = Vec::new();
        for raw in text.lines() {
            let line: String = raw
                .chars()
                .flat_map(|c| match c {
                    '\t' => vec![' '; 4],
                    c if c.is_control() => vec![],
                    c => vec![c],
                })
                .collect();
            let chars: Vec<char> = line.chars().collect();
            if chars.is_empty() {
                lines.push(String::new());
            }
            for chunk in chars.chunks(cols) {
                lines.push(chunk.iter().collect());
                if lines.len() > MAX_PAGES * rows {
                    return Err(ViewError::TooLarge("pages"));
                }
            }
        }
        if lines.is_empty() {
            lines.push(String::new());
        }
        Ok(TextDoc { lines, rows })
    }

    pub(crate) fn page_count(&self) -> usize {
        self.lines.len().div_ceil(self.rows)
    }

    pub(crate) fn render(&self, page: usize, width: u32, height: u32) -> Result<Rgba> {
        let (pw, ph) = (PAGE_SIZE.0 as usize, PAGE_SIZE.1 as usize);
        let mut mask = vec![0u8; pw * ph];
        for (i, line) in self
            .lines
            .iter()
            .skip(page * self.rows)
            .take(self.rows)
            .enumerate()
        {
            font::draw(
                &mut mask,
                pw,
                MARGIN,
                MARGIN + i * SIZE.line_height(),
                line,
                SIZE,
            );
        }
        let mut img = RgbaImage::new(pw as u32, ph as u32);
        for (px, &m) in img.pixels_mut().zip(&mask) {
            let v = 255 - (u16::from(m) * (255 - 24) / 255) as u8;
            *px = image::Rgba([v, v, v, 255]);
        }
        if (width, height) != PAGE_SIZE {
            img = imageops::resize(&img, width, height, FilterType::CatmullRom);
        }
        Ok(Rgba {
            width,
            height,
            data: img.into_raw(),
        })
    }
}
