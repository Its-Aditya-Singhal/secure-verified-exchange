//! The viewer's PDF path on hostile input: opening and drawing pages must
//! neither panic nor produce an inconsistent picture.
#![no_main]
use libfuzzer_sys::fuzz_target;
use svx_viewer::{Document, Kind, Watermark};

fuzz_target!(|data: &[u8]| {
    let Ok(doc) = Document::open(data.to_vec(), Kind::Pdf) else {
        return;
    };
    let mark = Watermark::new(["bob@example.test".to_string(), "fuzz".to_string()]);
    for page in 0..doc.page_count().min(2) {
        let _ = doc.page_size(page);
        if let Ok(img) = doc.render(page, 200, &mark) {
            assert_eq!(img.data.len(), img.width as usize * img.height as usize * 4);
        }
    }
});
