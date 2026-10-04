//! A single image: PNG, JPEG, GIF (first frame) or WebP.

use std::io::Cursor;

use image::imageops::{self, FilterType};
use image::{ImageFormat, ImageReader, Limits, RgbaImage};

use crate::{MAX_IMAGE_PIXELS, Result, Rgba, ViewError};

pub(crate) struct ImageDoc {
    img: RgbaImage,
}

fn reader(bytes: &[u8]) -> Result<ImageReader<Cursor<&[u8]>>> {
    let r = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| ViewError::Malformed("not an image".into()))?;
    match r.format() {
        Some(ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::Gif | ImageFormat::WebP) => Ok(r),
        _ => Err(ViewError::Malformed(
            "only PNG, JPEG, GIF and WebP images can be shown".into(),
        )),
    }
}

impl ImageDoc {
    pub(crate) fn open(bytes: &[u8]) -> Result<ImageDoc> {
        // Size first, from the header, before anything is allocated.
        let (w, h) = reader(bytes)?
            .into_dimensions()
            .map_err(|_| ViewError::Malformed("damaged image".into()))?;
        if u64::from(w) * u64::from(h) > MAX_IMAGE_PIXELS {
            return Err(ViewError::TooLarge("image size"));
        }
        let mut r = reader(bytes)?;
        let mut limits = Limits::default();
        limits.max_image_width = Some(20_000);
        limits.max_image_height = Some(20_000);
        limits.max_alloc = Some(512 * 1024 * 1024);
        r.limits(limits);
        let img = r
            .decode()
            .map_err(|_| ViewError::Malformed("damaged image".into()))?
            .to_rgba8();
        Ok(ImageDoc { img })
    }

    pub(crate) fn size(&self) -> (u32, u32) {
        self.img.dimensions()
    }

    pub(crate) fn render(&self, width: u32, height: u32) -> Result<Rgba> {
        let resized;
        let src = if self.img.dimensions() == (width, height) {
            &self.img
        } else {
            resized = imageops::resize(&self.img, width, height, FilterType::CatmullRom);
            &resized
        };
        // Straight alpha over white.
        let mut data = Vec::with_capacity(src.as_raw().len());
        for px in src.as_raw().as_chunks::<4>().0 {
            let a = u16::from(px[3]);
            for &c in &px[..3] {
                data.push(((u16::from(c) * a + 255 * (255 - a)) / 255) as u8);
            }
            data.push(255);
        }
        Ok(Rgba {
            width,
            height,
            data,
        })
    }
}
