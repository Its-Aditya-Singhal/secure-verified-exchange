use std::io::Cursor;

use image::{ImageFormat, RgbaImage};

use super::*;

/// A one-page PDF with some text (hand-made, fictional content).
fn tiny_pdf(text: &str) -> Vec<u8> {
    let content = format!("BT /F1 36 Tf 72 700 Td ({text}) Tj ET");
    let objs = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
         /Resources << /Font << /F1 5 0 R >> >> >>"
            .to_string(),
        format!(
            "<< /Length {} >>\nstream\n{content}\nendstream",
            content.len()
        ),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend(format!("{} 0 obj\n{o}\nendobj\n", i + 1).bytes());
    }
    let xref = out.len();
    out.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).bytes());
    for o in offsets {
        out.extend(format!("{o:010} 00000 n \n").bytes());
    }
    out.extend(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objs.len() + 1
        )
        .bytes(),
    );
    out
}

fn png(w: u32, h: u32, rgba: [u8; 4]) -> Vec<u8> {
    let mut img = RgbaImage::new(w, h);
    for p in img.pixels_mut() {
        *p = image::Rgba(rgba);
    }
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, ImageFormat::Png).unwrap();
    out.into_inner()
}

fn mark() -> Watermark {
    Watermark::new([
        "bob@example.test".to_string(),
        "2026-10-04 20:00 UTC".to_string(),
        "file 3a167c54".to_string(),
    ])
}

fn dark_pixels(img: &Rgba) -> usize {
    img.data
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|p| p[0] < 100 && p[1] < 100 && p[2] < 100)
        .count()
}

fn differing(a: &Rgba, b: &Rgba) -> usize {
    a.data
        .as_chunks::<4>()
        .0
        .iter()
        .zip(b.data.as_chunks::<4>().0)
        .filter(|(x, y)| x != y)
        .count()
}

#[test]
fn a_document_can_move_between_threads() {
    fn is_send<T: Send>() {}
    is_send::<Document>();
}

#[test]
fn a_pdf_page_is_drawn() {
    let doc = Document::open(tiny_pdf("Hello Alice"), Kind::Pdf).unwrap();
    assert_eq!(doc.page_count(), 1);
    assert_eq!(doc.page_size(0).unwrap(), (612, 792));
    let page = doc.render(0, 612, &Watermark::default()).unwrap();
    assert_eq!(
        page.data.len(),
        page.width as usize * page.height as usize * 4
    );
    assert!((610..=612).contains(&page.width) && (790..=792).contains(&page.height));
    assert!(dark_pixels(&page) > 200, "the text should be drawn");
    // Another width scales the page.
    let small = doc.render(0, 306, &Watermark::default()).unwrap();
    assert!((304..=306).contains(&small.width));
    assert_eq!(doc.page_size(1), Err(ViewError::NoSuchPage));
    assert!(matches!(
        doc.render(1, 612, &mark()),
        Err(ViewError::NoSuchPage)
    ));
}

#[test]
fn an_image_is_drawn_and_scaled() {
    let doc = Document::open(png(200, 100, [10, 120, 200, 255]), Kind::Image).unwrap();
    assert_eq!(
        (doc.page_count(), doc.page_size(0).unwrap()),
        (1, (200, 100))
    );
    let page = doc.render(0, 400, &Watermark::default()).unwrap();
    assert_eq!((page.width, page.height), (400, 200));
    assert_eq!(&page.data[..4], &[10, 120, 200, 255]);
    // Transparent areas show white, never black.
    let clear = Document::open(png(8, 8, [0, 0, 0, 0]), Kind::Image).unwrap();
    let page = clear.render(0, 64, &Watermark::default()).unwrap();
    assert_eq!(&page.data[..4], &[255, 255, 255, 255]);
}

#[test]
fn text_wraps_onto_pages() {
    let long = "x".repeat(300);
    let doc = Document::open(
        format!("Dear Bob,\n\ttabbed\n{long}\n").into_bytes(),
        Kind::Text,
    )
    .unwrap();
    assert_eq!(doc.page_count(), 1);
    let page = doc.render(0, 816, &Watermark::default()).unwrap();
    assert!(dark_pixels(&page) > 100);
    // Many lines make many pages.
    let many = "line\n".repeat(200);
    let doc = Document::open(many.into_bytes(), Kind::Text).unwrap();
    assert!(doc.page_count() >= 4, "{} pages", doc.page_count());
    // Characters the font lacks and control characters don't break anything.
    Document::open(
        "café — 日本語 \u{7} \r\n end".as_bytes().to_vec(),
        Kind::Text,
    )
    .unwrap()
    .render(0, 500, &mark())
    .unwrap();
    assert!(Document::open(vec![0xff, 0xfe, 0x00, 0xd8], Kind::Text).is_err());
    assert!(Document::open(Vec::new(), Kind::Text).unwrap().page_count() == 1);
}

#[test]
fn the_watermark_is_burned_into_the_pixels() {
    let doc = Document::open(png(900, 700, [255, 255, 255, 255]), Kind::Image).unwrap();
    let plain = doc.render(0, 900, &Watermark::default()).unwrap();
    assert!(plain.data.iter().all(|&b| b == 255), "no mark, no change");
    let marked = doc.render(0, 900, &mark()).unwrap();
    let changed = differing(&plain, &marked);
    assert!(
        changed > 5_000,
        "the mark should cover the page, changed {changed}"
    );
    // Different text gives a different mark; the same text, the same pixels.
    let other = doc
        .render(0, 900, &Watermark::new(["eve@example.test".to_string()]))
        .unwrap();
    assert!(differing(&marked, &other) > 1_000);
    assert_eq!(marked, doc.render(0, 900, &mark()).unwrap());
    // It shows on dark pages too, and on a PDF.
    let dark = Document::open(png(900, 700, [10, 10, 10, 255]), Kind::Image).unwrap();
    assert!(
        differing(
            &dark.render(0, 900, &Watermark::default()).unwrap(),
            &dark.render(0, 900, &mark()).unwrap()
        ) > 5_000
    );
    let pdf = Document::open(tiny_pdf("x"), Kind::Pdf).unwrap();
    assert!(
        differing(
            &pdf.render(0, 612, &Watermark::default()).unwrap(),
            &pdf.render(0, 612, &mark()).unwrap()
        ) > 3_000
    );
    // Control characters and long lines are cleaned up.
    let wm = Watermark::new(["a\u{0}b\nc".to_string(), "z".repeat(500), String::new()]);
    assert!(!wm.is_empty());
    doc.render(0, 900, &wm).unwrap();
}

#[test]
fn damaged_and_wrong_files_are_refused_without_panicking() {
    for kind in [Kind::Pdf, Kind::Image, Kind::Text] {
        for junk in [
            &b""[..],
            b"hello",
            b"%PDF-1.7 garbage",
            &[0u8; 64],
            &[0x89, b'P', b'N', b'G'],
        ] {
            if kind == Kind::Text && junk != [0u8; 64] && junk != [0x89, b'P', b'N', b'G'] {
                continue; // plain text accepts most bytes
            }
            let r = Document::open(junk.to_vec(), kind);
            if kind != Kind::Text {
                assert!(r.is_err(), "{kind:?} {junk:?}");
            }
        }
    }
    // A truncated PDF and a truncated PNG.
    let pdf = tiny_pdf("cut");
    let _ = Document::open(pdf[..pdf.len() / 2].to_vec(), Kind::Pdf);
    let img = png(50, 50, [1, 2, 3, 255]);
    assert!(Document::open(img[..img.len() / 2].to_vec(), Kind::Image).is_err());
    // An image of another type is refused (BMP).
    let mut bmp = Cursor::new(Vec::new());
    RgbaImage::new(4, 4)
        .write_to(&mut bmp, ImageFormat::Bmp)
        .unwrap_or_default();
    assert!(Document::open(bmp.into_inner(), Kind::Image).is_err());
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[test]
fn oversized_images_are_refused_before_decoding() {
    // A real PNG header that claims 60000 x 60000 pixels (3.6 billion).
    let mut ihdr = Vec::new();
    ihdr.extend(b"IHDR");
    ihdr.extend(60_000u32.to_be_bytes());
    ihdr.extend(60_000u32.to_be_bytes());
    ihdr.extend([8, 6, 0, 0, 0]);
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    png.extend(13u32.to_be_bytes());
    png.extend(&ihdr);
    png.extend(crc32(&ihdr).to_be_bytes());
    // The start of the image data (the decoder reads the header up to it).
    let idat = [b'I', b'D', b'A', b'T', 0x78, 0x9c];
    png.extend(2u32.to_be_bytes());
    png.extend(idat);
    png.extend(crc32(&idat).to_be_bytes());
    assert_eq!(
        Document::open(png, Kind::Image).err(),
        Some(ViewError::TooLarge("image size"))
    );
    assert_eq!(
        Document::open(vec![0; MAX_INPUT_BYTES + 1], Kind::Pdf).err(),
        Some(ViewError::TooLarge("bytes"))
    );
}

#[test]
fn render_sizes_are_bounded() {
    let doc = Document::open(png(100, 100, [9, 9, 9, 255]), Kind::Image).unwrap();
    let wide = doc.render(0, u32::MAX, &Watermark::default()).unwrap();
    assert_eq!(wide.width, MAX_RENDER_WIDTH);
    let tiny = doc.render(0, 1, &Watermark::default()).unwrap();
    assert_eq!(tiny.width, 64);
    // A very tall image can't be blown up past the pixel budget.
    let tall = Document::open(png(40, 4000, [9, 9, 9, 255]), Kind::Image).unwrap();
    assert_eq!(
        tall.render(0, 4096, &Watermark::default()).err(),
        Some(ViewError::TooLarge("page size"))
    );
}

#[test]
fn kinds_follow_file_names() {
    assert_eq!(Kind::from_file_name("Plan.PDF"), Some(Kind::Pdf));
    assert_eq!(Kind::from_file_name("a.b.jpeg"), Some(Kind::Image));
    assert_eq!(Kind::from_file_name("notes.txt"), Some(Kind::Text));
    assert_eq!(Kind::from_file_name("sheet.xlsx"), None);
    assert_eq!(Kind::from_file_name("noextension"), None);
}
