//! Draws view-only documents (PDF, images, plain text) in memory.
//!
//! The recipient's app never receives the document itself in the web layer:
//! it asks this crate for one page at a time as raw pixels, with the
//! watermark already burned in. Everything here is pure Rust, runs without
//! network or files, and treats its input as hostile (size limits, no
//! panics reaching the caller).
//!
//! ```text
//! Document::open(bytes, Kind) -> page_count / page_size -> render(page, width, &Watermark) -> Rgba
//! ```

mod font;
mod image_doc;
mod pdf_doc;
mod text_doc;
mod watermark;

pub use watermark::Watermark;
use zeroize::Zeroizing;

/// Pages a document may have.
pub const MAX_PAGES: usize = 2_000;
/// Pixels an image may have (width x height).
pub const MAX_IMAGE_PIXELS: u64 = 100_000_000;
/// Widest page the viewer renders.
pub const MAX_RENDER_WIDTH: u32 = 4_096;
/// Most pixels one rendered page may have (160 MB as RGBA).
pub const MAX_RENDER_PIXELS: u64 = 40_000_000;
/// Largest document accepted.
pub const MAX_INPUT_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ViewError {
    /// The bytes aren't a document of the claimed kind, or it's damaged.
    #[error("this file can't be shown: {0}")]
    Malformed(String),
    /// A limit was exceeded.
    #[error("this file is too large to show ({0})")]
    TooLarge(&'static str),
    #[error("no such page")]
    NoSuchPage,
}

pub type Result<T> = std::result::Result<T, ViewError>;

/// What a view-only file's display copy is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Pdf,
    Image,
    Text,
}

impl Kind {
    /// The kind for a file name (by extension), if the viewer can show it.
    pub fn from_file_name(name: &str) -> Option<Kind> {
        let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
        match ext.as_str() {
            "pdf" => Some(Kind::Pdf),
            "png" | "jpg" | "jpeg" | "gif" | "webp" => Some(Kind::Image),
            "txt" | "text" | "md" | "log" | "csv" => Some(Kind::Text),
            _ => None,
        }
    }
}

/// A rendered page: opaque RGBA8, row after row, top to bottom.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rgba {
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
}

enum Inner {
    Pdf(pdf_doc::PdfDoc),
    Image(image_doc::ImageDoc),
    Text(text_doc::TextDoc),
}

/// An opened document. Dropping it frees the content.
pub struct Document {
    inner: Inner,
}

impl Document {
    /// Open `bytes` as `kind`. Fails on damaged, encrypted or oversized files.
    /// Pass a `Zeroizing` buffer so the document's bytes are wiped when the
    /// document is dropped (a plain `Vec` is dropped unwiped).
    pub fn open(bytes: impl Into<Zeroizing<Vec<u8>>>, kind: Kind) -> Result<Document> {
        let bytes: Zeroizing<Vec<u8>> = bytes.into();
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(ViewError::TooLarge("bytes"));
        }
        let inner = match kind {
            Kind::Pdf => Inner::Pdf(pdf_doc::PdfDoc::open(bytes)?),
            Kind::Image => Inner::Image(image_doc::ImageDoc::open(&bytes)?),
            Kind::Text => Inner::Text(text_doc::TextDoc::open(&bytes)?),
        };
        Ok(Document { inner })
    }

    pub fn page_count(&self) -> usize {
        match &self.inner {
            Inner::Pdf(d) => d.page_count(),
            Inner::Image(_) => 1,
            Inner::Text(d) => d.page_count(),
        }
    }

    /// A page's natural size (width, height), to lay out before rendering.
    pub fn page_size(&self, page: usize) -> Result<(u32, u32)> {
        match &self.inner {
            Inner::Pdf(d) => d.page_size(page),
            Inner::Image(d) if page == 0 => Ok(d.size()),
            Inner::Image(_) => Err(ViewError::NoSuchPage),
            Inner::Text(d) if page < d.page_count() => Ok(text_doc::PAGE_SIZE),
            Inner::Text(_) => Err(ViewError::NoSuchPage),
        }
    }

    /// Draw `page` about `width` pixels wide (at most [`MAX_RENDER_WIDTH`]),
    /// with the watermark burned into the pixels.
    pub fn render(&self, page: usize, width: u32, mark: &Watermark) -> Result<Rgba> {
        let width = width.clamp(64, MAX_RENDER_WIDTH);
        let (nw, nh) = self.page_size(page)?;
        let height = (u64::from(nh) * u64::from(width) / u64::from(nw.max(1))).max(1);
        if u64::from(width) * height > MAX_RENDER_PIXELS {
            return Err(ViewError::TooLarge("page size"));
        }
        let mut out = match &self.inner {
            Inner::Pdf(d) => d.render(page, width, nw)?,
            Inner::Image(d) => d.render(width, height as u32)?,
            Inner::Text(d) => d.render(page, width, height as u32)?,
        };
        watermark::apply(&mut out, mark);
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
