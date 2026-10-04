//! Protected viewer windows (Phase 7).
//!
//! A view-only document lives here, opened by `svx-viewer`, and only
//! rendered pages leave: raw pixels with the watermark already burned in.
//! The web layer of the viewer window never receives the document, its text
//! or its bytes, so it has nothing to copy, save or print. The window itself
//! is created with OS capture protection (screenshots and recordings show it
//! black). What that doesn't stop is in `threat-model/THREAT_MODEL.md`, T29.
//!
//! Each command acts only for the window its session belongs to.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use svx_app::AppError;
use svx_viewer::{Document, Kind, Rgba, Watermark};

/// Label prefix of viewer windows.
pub const LABEL_PREFIX: &str = "view-";

/// One open view.
pub struct View {
    // hayro's parser isn't promised to be thread-safe: one render at a time.
    doc: Mutex<Document>,
    mark: Watermark,
    sizes: Vec<(u32, u32)>,
    pub artifact_id: String,
    pub path: PathBuf,
    pub file_name: String,
    pub sender: String,
}

impl View {
    pub fn new(
        doc: Document,
        mark: Watermark,
        artifact_id: String,
        path: PathBuf,
        file_name: String,
        sender: String,
    ) -> Result<View, AppError> {
        let sizes = (0..doc.page_count())
            .map(|p| doc.page_size(p).map_err(|e| AppError::other(e.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(View {
            doc: Mutex::new(doc),
            mark,
            sizes,
            artifact_id,
            path,
            file_name,
            sender,
        })
    }

    /// Page sizes (width, height) to lay out before drawing.
    pub fn sizes(&self) -> &[(u32, u32)] {
        &self.sizes
    }

    /// Draw a page: 8 bytes (width, height as little-endian u32), then
    /// RGBA8 rows.
    pub fn render(&self, page: usize, width: u32) -> Result<Vec<u8>, AppError> {
        let img = self
            .doc
            .lock()
            .map_err(|_| {
                AppError::other("the viewer stopped working; close it and open the file again")
            })?
            .render(page, width, &self.mark)
            .map_err(|e| AppError::other(e.to_string()))?;
        Ok(encode(img))
    }
}

fn encode(img: Rgba) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + img.data.len());
    out.extend_from_slice(&img.width.to_le_bytes());
    out.extend_from_slice(&img.height.to_le_bytes());
    out.extend_from_slice(&img.data);
    out
}

/// The viewer kind for a display copy (`display.<ext>`).
pub fn kind_of(display_name: &str) -> Result<Kind, AppError> {
    Kind::from_file_name(display_name)
        .ok_or_else(|| AppError::other("this kind of file can't be shown"))
}

/// Open views, by id.
#[derive(Default)]
pub struct Views {
    next: AtomicU64,
    open: Mutex<HashMap<u64, Arc<View>>>,
}

impl Views {
    /// Register a view; returns its id.
    pub fn add(&self, view: View) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        self.open.lock().unwrap().insert(id, Arc::new(view));
        id
    }

    /// Forget a view; its document is wiped when the last user lets go.
    pub fn remove(&self, id: u64) {
        self.open.lock().unwrap().remove(&id);
    }

    /// The view of `id`, but only for the window that belongs to it.
    pub fn get(&self, id: u64, window_label: &str) -> Result<Arc<View>, AppError> {
        if window_label != label(id) {
            return Err(AppError::other("not your view"));
        }
        self.open
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or_else(|| AppError::other("this view has been closed"))
    }

    pub fn clear(&self) {
        self.open.lock().unwrap().clear();
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.open.lock().unwrap().len()
    }
}

/// The window label of view `id`.
pub fn label(id: u64) -> String {
    format!("{LABEL_PREFIX}{id}")
}

/// The view id of a window label, if it is a viewer window.
pub fn id_of(label: &str) -> Option<u64> {
    label.strip_prefix(LABEL_PREFIX)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> Document {
        Document::open(b"hello\nworld".to_vec(), Kind::Text).unwrap()
    }

    fn view() -> View {
        View::new(
            doc(),
            Watermark::new(["bob@example.test".to_string()]),
            "0123456789abcdef0123456789abcdef".into(),
            "/tmp/x.svx".into(),
            "notes.txt".into(),
            "alice@example.test".into(),
        )
        .unwrap()
    }

    #[test]
    fn labels_round_trip() {
        assert_eq!(id_of(&label(7)), Some(7));
        assert_eq!(id_of("main"), None);
        assert_eq!(id_of("view-x"), None);
        assert_eq!(id_of("view-"), None);
    }

    #[test]
    fn a_view_answers_only_its_own_window() {
        let views = Views::default();
        let a = views.add(view());
        let b = views.add(view());
        assert_ne!(a, b);
        assert!(views.get(a, &label(a)).is_ok());
        // Another viewer, or the main window, can't read it.
        assert!(views.get(a, &label(b)).is_err());
        assert!(views.get(a, "main").is_err());
        views.remove(a);
        assert!(views.get(a, &label(a)).is_err());
        assert_eq!(views.len(), 1);
        views.clear();
        assert_eq!(views.len(), 0);
    }

    #[test]
    fn pages_come_out_as_pixels_with_the_size_up_front() {
        let v = view();
        assert_eq!(v.sizes().len(), 1);
        let bytes = v.render(0, 400).unwrap();
        let w = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let h = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(w, 400);
        assert_eq!(bytes.len(), 8 + w as usize * h as usize * 4);
        // Opaque pixels, and none of the text survives as text.
        assert!(bytes[8..].as_chunks::<4>().0.iter().all(|p| p[3] == 255));
        assert!(!bytes.windows(5).any(|w| w == b"hello"));
        assert!(v.render(9, 400).is_err());
    }

    #[test]
    fn only_drawable_kinds_open() {
        assert!(matches!(kind_of("display.pdf"), Ok(Kind::Pdf)));
        assert!(matches!(kind_of("display.png"), Ok(Kind::Image)));
        assert!(kind_of("display.exe").is_err());
    }
}
