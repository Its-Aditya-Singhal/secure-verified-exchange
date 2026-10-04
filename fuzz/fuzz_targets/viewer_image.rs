//! The viewer's image and text paths on hostile input.
#![no_main]
use libfuzzer_sys::fuzz_target;
use svx_viewer::{Document, Kind, Watermark};

fuzz_target!(|data: &[u8]| {
    let mark = Watermark::new(["bob@example.test".to_string()]);
    for kind in [Kind::Image, Kind::Text] {
        let Ok(doc) = Document::open(data.to_vec(), kind) else {
            continue;
        };
        for page in 0..doc.page_count().min(2) {
            if let Ok(img) = doc.render(page, 300, &mark) {
                assert_eq!(img.data.len(), img.width as usize * img.height as usize * 4);
            }
        }
    }
});
