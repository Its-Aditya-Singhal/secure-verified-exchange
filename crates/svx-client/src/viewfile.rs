//! The payload of a view-only file.
//!
//! A view-only file's payload is a small zip, marked in the signed manifest
//! with [`VIEW_CONTENT_TYPE`]:
//!
//! * `display.<ext>`: what the viewer draws (PDF, an image or plain text);
//! * `original/<name>`: the sender's original, only when it differs from the
//!   display copy (an Office file shown as PDF). It is what "save a copy"
//!   writes once the sender has allowed sharing.
//!
//! Office files are converted on the sender's computer (see
//! [`crate::convert`]); the recipient never parses an Office format.
//!
//! Like folders, the archive is treated as untrusted when read: exactly the
//! two entry shapes above, safe names, and limits on the bytes actually read.

use std::io::{Cursor, Read, Write};
use std::path::Path;

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::convert;
use crate::error::{ClientError, Result};
use crate::folder::{check_entry_name, zip_err};

/// Manifest content type marking a payload as a view-only container.
pub const VIEW_CONTENT_TYPE: &str = "application/vnd.svx.view+zip";
/// Largest display copy (what the viewer draws).
pub const MAX_DISPLAY_BYTES: u64 = 100 << 20;
/// Largest original kept beside the display copy.
pub const MAX_ORIGINAL_BYTES: u64 = 256 << 20;

/// Extensions the viewer can draw.
pub const DISPLAY_EXTENSIONS: [&str; 7] = ["pdf", "png", "jpg", "jpeg", "gif", "webp", "txt"];
/// Extensions converted to PDF (Microsoft Office or LibreOffice).
pub const OFFICE_EXTENSIONS: [&str; 10] = [
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf",
];

/// What a view-only file holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewParts {
    /// `display.<ext>`
    pub display_name: String,
    pub display: Vec<u8>,
    /// The sender's original file name and bytes, if not the display copy.
    pub original: Option<(String, Vec<u8>)>,
}

/// How a file would be made view-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// The file itself is drawn.
    Direct,
    /// Converted to PDF first (needs LibreOffice).
    Office,
}

fn extension(name: &str) -> Option<String> {
    Some(name.rsplit_once('.')?.1.to_ascii_lowercase())
}

/// Whether a file can be view-only, from its name; the reason if not.
/// Office files also need a converter (see [`convert::find_converter`]).
pub fn plan_for(name: &str) -> std::result::Result<Plan, String> {
    match extension(name).as_deref() {
        Some(e) if DISPLAY_EXTENSIONS.contains(&e) => Ok(Plan::Direct),
        Some(e) if OFFICE_EXTENSIONS.contains(&e) => Ok(Plan::Office),
        _ => Err(
            "view-only works for PDF, images (PNG, JPEG, GIF, WebP), plain text and Office \
                  files. Convert this one to PDF first, or send it normally."
                .into(),
        ),
    }
}

/// Read the sender's file and prepare what the container holds.
pub fn prepare(input: &Path) -> Result<ViewParts> {
    let name = input
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ClientError::Invalid("this file name can't be used".into()))?
        .to_owned();
    let meta = std::fs::metadata(input)?;
    if !meta.is_file() {
        return Err(ClientError::Invalid(
            "only a single file can be view-only, not a folder".into(),
        ));
    }
    let plan = plan_for(&name).map_err(ClientError::Invalid)?;
    let limit = match plan {
        Plan::Direct => MAX_DISPLAY_BYTES,
        Plan::Office => MAX_ORIGINAL_BYTES,
    };
    if meta.len() > limit {
        return Err(ClientError::Invalid(format!(
            "this file is larger than {} MB, the limit for view-only files",
            limit >> 20
        )));
    }
    match plan {
        Plan::Direct => {
            let ext = extension(&name).unwrap_or_default();
            Ok(ViewParts {
                display_name: format!("display.{ext}"),
                display: std::fs::read(input)?,
                original: None,
            })
        }
        Plan::Office => {
            let ext = extension(&name).unwrap_or_default();
            let converter = convert::find_converter(&ext)
                .ok_or_else(|| ClientError::Invalid(convert::LIBREOFFICE_MISSING.into()))?;
            Ok(ViewParts {
                display_name: "display.pdf".into(),
                display: convert::convert(&converter, input)?,
                original: Some((name, std::fs::read(input)?)),
            })
        }
    }
}

fn valid_display_name(name: &str) -> bool {
    name.strip_prefix("display.")
        .is_some_and(|e| DISPLAY_EXTENSIONS.contains(&e))
}

fn valid_original_name(name: &str) -> bool {
    !name.contains('/') && check_entry_name(name).is_ok()
}

/// Make the container. The same parts always give the same bytes.
pub fn build(parts: &ViewParts) -> Result<Vec<u8>> {
    if !valid_display_name(&parts.display_name) {
        return Err(ClientError::Invalid("unsupported display file".into()));
    }
    let opts = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o600)
        .large_file(true);
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file(&parts.display_name, opts).map_err(zip_err)?;
    zip.write_all(&parts.display)?;
    if let Some((name, bytes)) = &parts.original {
        if !valid_original_name(name) {
            return Err(ClientError::Invalid("this file name can't be used".into()));
        }
        zip.start_file(format!("original/{name}"), opts)
            .map_err(zip_err)?;
        zip.write_all(bytes)?;
    }
    Ok(zip.finish().map_err(zip_err)?.into_inner())
}

fn rejected(why: &str) -> ClientError {
    ClientError::Rejected(format!("the view-only file is malformed: {why}"))
}

fn read_entry(entry: &mut zip::read::ZipFile<'_, Cursor<&[u8]>>, limit: u64) -> Result<Vec<u8>> {
    // Reserved from the declared size, so an honest entry is read without
    // reallocating (each reallocation would leave an unwiped copy behind).
    let mut out = Vec::with_capacity(entry.size().min(limit) as usize);
    // The bytes actually produced count, not the size the archive declares.
    (&mut *entry).take(limit + 1).read_to_end(&mut out)?;
    if out.len() as u64 > limit {
        return Err(rejected("an entry is larger than its limit"));
    }
    Ok(out)
}

/// Read a container in memory; nothing touches the disk.
pub fn parse(bytes: &[u8]) -> Result<ViewParts> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|e| rejected(&e.to_string()))?;
    if archive.is_empty() || archive.len() > 2 {
        return Err(rejected("unexpected contents"));
    }
    let (mut display, mut original) = (None, None);
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| rejected(&e.to_string()))?;
        let name = std::str::from_utf8(entry.name_raw())
            .map_err(|_| rejected("entry name is not UTF-8"))?
            .to_owned();
        if entry.is_dir() || entry.is_symlink() {
            return Err(rejected("only regular files are allowed"));
        }
        if valid_display_name(&name) {
            if display.is_some() {
                return Err(rejected("more than one display file"));
            }
            display = Some((name, read_entry(&mut entry, MAX_DISPLAY_BYTES)?));
        } else if let Some(orig) = name
            .strip_prefix("original/")
            .filter(|n| valid_original_name(n))
        {
            if original.is_some() {
                return Err(rejected("more than one original"));
            }
            original = Some((orig.to_owned(), read_entry(&mut entry, MAX_ORIGINAL_BYTES)?));
        } else {
            return Err(rejected("unexpected entry"));
        }
    }
    let (display_name, display) = display.ok_or_else(|| rejected("no display file"))?;
    Ok(ViewParts {
        display_name,
        display,
        original,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts() -> ViewParts {
        ViewParts {
            display_name: "display.pdf".into(),
            display: b"%PDF-1.4 fictional".to_vec(),
            original: Some(("Quarterly plan.docx".into(), b"fictional docx".to_vec())),
        }
    }

    /// A zip with these entries, for hostile-input tests.
    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut z = ZipWriter::new(Cursor::new(Vec::new()));
        for (n, b) in entries {
            z.start_file(*n, SimpleFileOptions::default()).unwrap();
            z.write_all(b).unwrap();
        }
        z.finish().unwrap().into_inner()
    }

    #[test]
    fn round_trip_and_determinism() {
        let bytes = build(&parts()).unwrap();
        assert_eq!(bytes, build(&parts()).unwrap());
        assert_eq!(parse(&bytes).unwrap(), parts());
        let direct = ViewParts {
            original: None,
            ..parts()
        };
        assert_eq!(parse(&build(&direct).unwrap()).unwrap(), direct);
    }

    #[test]
    fn hostile_containers_are_refused() {
        for entries in [
            vec![("display.pdf", &b"a"[..]), ("display.png", b"b")],
            vec![("display.exe", b"a")],
            vec![("../display.pdf", b"a")],
            vec![("display.pdf", b"a"), ("original/../x", b"b")],
            vec![("display.pdf", b"a"), ("original/a/b", b"b")],
            vec![("display.pdf", b"a"), ("original/CON", b"b")],
            vec![("display.pdf", b"a"), ("original/", b"")],
            vec![("original/a.docx", b"b")],
            vec![("display.pdf", b"a"), ("original/a", b"b"), ("extra", b"c")],
        ] {
            assert!(parse(&zip_of(&entries)).is_err(), "{entries:?}");
        }
        assert!(parse(b"not a zip").is_err());
        assert!(parse(&[]).is_err());
        assert!(parse(&zip_of(&[])).is_err());
    }

    #[test]
    fn bytes_are_limited_by_what_is_read() {
        // 101 MB of zeros compresses to almost nothing: only the real
        // output counts against the limit.
        let big = vec![0u8; (MAX_DISPLAY_BYTES + 1) as usize];
        let bytes = zip_of(&[("display.txt", &big)]);
        assert!(bytes.len() < 1 << 20);
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn invalid_parts_are_not_built() {
        let mut p = parts();
        p.display_name = "display.exe".into();
        assert!(build(&p).is_err());
        let mut p = parts();
        p.original = Some(("a/b.docx".into(), vec![]));
        assert!(build(&p).is_err());
    }

    #[test]
    fn planning_follows_file_names() {
        assert_eq!(plan_for("a.PDF"), Ok(Plan::Direct));
        assert_eq!(plan_for("photo.JPEG"), Ok(Plan::Direct));
        assert_eq!(plan_for("plan.docx"), Ok(Plan::Office));
        assert!(plan_for("tool.exe").unwrap_err().contains("PDF"));
        assert!(plan_for("noextension").is_err());
    }

    #[test]
    fn prepare_reads_direct_files_and_refuses_the_rest() {
        let d = tempfile::tempdir().unwrap();
        let pdf = d.path().join("Plan.PDF");
        std::fs::write(&pdf, b"%PDF-1.4 x").unwrap();
        let p = prepare(&pdf).unwrap();
        assert_eq!(p.display_name, "display.pdf");
        assert!(p.original.is_none());
        assert!(matches!(prepare(d.path()), Err(ClientError::Invalid(_))));
        let exe = d.path().join("run.exe");
        std::fs::write(&exe, b"x").unwrap();
        assert!(matches!(prepare(&exe), Err(ClientError::Invalid(_))));
        assert!(prepare(&d.path().join("missing.pdf")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn office_files_are_converted_and_kept() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        // The override is read by `find_office`; run `to_pdf` directly with a fake.
        let fake = d.path().join("soffice");
        std::fs::write(
            &fake,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in --outdir) o=\"$2\"; shift;; esac; shift; done\nprintf '%%PDF-1.4 converted' > \"$o/input.pdf\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let doc = d.path().join("plan.docx");
        std::fs::write(&doc, b"fictional").unwrap();
        let pdf = convert::to_pdf(&fake, &doc).unwrap();
        let parts = ViewParts {
            display_name: "display.pdf".into(),
            display: pdf,
            original: Some(("plan.docx".into(), b"fictional".to_vec())),
        };
        assert_eq!(parse(&build(&parts).unwrap()).unwrap(), parts);
    }
}
