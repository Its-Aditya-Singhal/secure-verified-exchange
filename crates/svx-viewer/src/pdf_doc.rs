//! PDF pages, drawn by `hayro` (pure Rust).

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use hayro::hayro_interpret::InterpreterSettings;
use hayro::hayro_syntax::Pdf;
use hayro::{PixmapSettings, RenderCache, RenderSettings};
use zeroize::Zeroizing;

use crate::{MAX_PAGES, Result, Rgba, ViewError};

pub(crate) struct PdfDoc {
    pdf: Pdf,
    pages: usize,
}

fn malformed(why: &str) -> ViewError {
    ViewError::Malformed(why.into())
}

impl PdfDoc {
    pub(crate) fn open(bytes: Zeroizing<Vec<u8>>) -> Result<PdfDoc> {
        if !bytes.starts_with(b"%PDF-") && !bytes.windows(5).take(1024).any(|w| w == b"%PDF-") {
            return Err(malformed("not a PDF"));
        }
        // The parser is third-party code on hostile input: a panic becomes an error.
        let pdf = catch_unwind(AssertUnwindSafe(|| Pdf::new(Arc::new(bytes))))
            .map_err(|_| malformed("damaged PDF"))?
            .map_err(|_| malformed("damaged or password-protected PDF"))?;
        let pages = catch_unwind(AssertUnwindSafe(|| pdf.pages().len()))
            .map_err(|_| malformed("damaged PDF"))?;
        if pages == 0 {
            return Err(malformed("the PDF has no pages"));
        }
        if pages > MAX_PAGES {
            return Err(ViewError::TooLarge("pages"));
        }
        Ok(PdfDoc { pdf, pages })
    }

    pub(crate) fn page_count(&self) -> usize {
        self.pages
    }

    pub(crate) fn page_size(&self, page: usize) -> Result<(u32, u32)> {
        if page >= self.pages {
            return Err(ViewError::NoSuchPage);
        }
        let (w, h) = catch_unwind(AssertUnwindSafe(|| {
            self.pdf.pages()[page].render_dimensions()
        }))
        .map_err(|_| malformed("damaged page"))?;
        if !(w.is_finite() && h.is_finite()) || w < 1.0 || h < 1.0 || w > 20_000.0 || h > 20_000.0 {
            return Err(malformed("unusable page size"));
        }
        Ok((w.ceil() as u32, h.ceil() as u32))
    }

    /// Render `page` `width` pixels wide; `natural_w` is its width in points.
    pub(crate) fn render(&self, page: usize, width: u32, natural_w: u32) -> Result<Rgba> {
        let scale = width as f32 / natural_w.max(1) as f32;
        let pixmap = catch_unwind(AssertUnwindSafe(|| {
            let pages = self.pdf.pages();
            hayro::render(
                &pages[page],
                &RenderCache::new(),
                &InterpreterSettings::default(),
                &RenderSettings::default(),
                &PixmapSettings {
                    x_scale: scale,
                    y_scale: scale,
                    ..PixmapSettings::default()
                },
            )
        }))
        .map_err(|_| malformed("this page can't be drawn"))?;
        let (w, h) = (u32::from(pixmap.width()), u32::from(pixmap.height()));
        // Premultiplied RGBA over white.
        let mut data = Vec::with_capacity(w as usize * h as usize * 4);
        for px in pixmap.data_as_u8_slice().as_chunks::<4>().0 {
            let a = 255 - u16::from(px[3]);
            for &c in &px[..3] {
                data.push((u16::from(c) + a).min(255) as u8);
            }
            data.push(255);
        }
        Ok(Rgba {
            width: w,
            height: h,
            data,
        })
    }
}
