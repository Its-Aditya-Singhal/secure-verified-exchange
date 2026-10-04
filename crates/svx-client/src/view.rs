//! View-only files on the recipient's side (Phase 7).
//!
//! A view-only file is decrypted only into memory. Viewing keeps just the
//! display copy, in a [`ViewSession`] that wipes it when dropped; nothing is
//! written to disk. Saving (once the sender has allowed it) writes the
//! sender's original, or the display copy if there is no other, and never
//! the container itself.
//!
//! What this can't do is stated in the threat model (T29): a modified app,
//! malware reading memory or a photo of the screen are out of reach.

use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;

use svx_core::Manifest;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{ClientError, Result};
use crate::open::{OpenOutcome, Output, output_path, place, private_temp};
use crate::personal::Released;
use crate::viewfile::{self, MAX_DISPLAY_BYTES, MAX_ORIGINAL_BYTES, VIEW_CONTENT_TYPE, ViewParts};

/// Largest view-only payload decrypted: both parts plus room for the zip.
pub const MAX_VIEW_PAYLOAD: u64 = MAX_DISPLAY_BYTES + MAX_ORIGINAL_BYTES + (1 << 20);

/// Writes into a buffer whose capacity was reserved up front and refuses to
/// grow it, so the plaintext is never copied by a reallocation (a copy that
/// would be freed without being wiped).
struct Bounded<'a>(&'a mut Vec<u8>);

impl Write for Bounded<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.0.capacity() - self.0.len() {
            return Err(std::io::Error::other("larger than the file says"));
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Decrypt a released view-only file into memory and read its container.
pub(crate) fn decrypt(path: &Path, r: &Released) -> Result<(Manifest, ViewParts)> {
    let v = &r.verified;
    // Every chunk holds at most `chunk_size` bytes of plaintext.
    let bound = v.chunk_count.saturating_mul(u64::from(v.header.chunk_size));
    if bound > MAX_VIEW_PAYLOAD + u64::from(v.header.chunk_size) {
        return Err(ClientError::Rejected(
            "this view-only file is larger than the limit".into(),
        ));
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(bound as usize));
    let manifest = v
        .decrypt(
            BufReader::new(File::open(path)?),
            &r.svc_share,
            &r.recipient_share,
            Bounded(&mut plain),
        )
        .map_err(|e| ClientError::Rejected(e.to_string()))?;
    if manifest.files[0].content_type.as_deref() != Some(VIEW_CONTENT_TYPE) {
        return Err(ClientError::Rejected(
            "this file is marked view-only but holds no view-only content".into(),
        ));
    }
    let parts = viewfile::parse(&plain)?;
    Ok((manifest, parts))
}

/// Wipe both parts.
fn wipe(parts: &mut ViewParts) {
    parts.display.zeroize();
    if let Some((_, b)) = &mut parts.original {
        b.zeroize();
    }
}

/// Save a view-only file the sender allowed to be kept: the original if
/// there is one, otherwise the display copy, under a plain file name.
pub(crate) fn save(
    path: &Path,
    r: &Released,
    output: Output,
    sender_org: String,
    artifact_id: String,
) -> Result<OpenOutcome> {
    let (manifest, mut parts) = decrypt(path, r)?;
    let result = save_parts(&manifest, &parts, output, sender_org, artifact_id);
    wipe(&mut parts);
    result
}

fn save_parts(
    manifest: &Manifest,
    parts: &ViewParts,
    output: Output,
    sender_org: String,
    artifact_id: String,
) -> Result<OpenOutcome> {
    let (name, bytes) = match &parts.original {
        Some((name, bytes)) => (name.as_str(), bytes),
        None => (manifest.files[0].name.as_str(), &parts.display),
    };
    // What was saved, not the container.
    let saved = Manifest {
        files: vec![svx_core::FileEntry {
            name: name.to_owned(),
            size: bytes.len() as u64,
            content_type: None,
        }],
        ..manifest.clone()
    };
    match output {
        Output::Writer(mut w) => {
            w.write_all(bytes)?;
            w.flush()?;
            Ok(OpenOutcome {
                manifest: saved,
                path: None,
                sender_org,
                artifact_id,
            })
        }
        Output::Dir { dir, overwrite } => {
            let dest = output_path(&dir, name)?;
            let tmp = private_temp(&dir)?;
            tmp.as_file().write_all(bytes)?;
            tmp.as_file().sync_all()?;
            place(tmp, &dest, overwrite)?;
            Ok(OpenOutcome {
                manifest: saved,
                path: Some(dest),
                sender_org,
                artifact_id,
            })
        }
    }
}

/// An open view: the display copy in memory, and who is looking. Dropping
/// it wipes the content. Show it only in a window protected from capture.
pub struct ViewSession {
    /// The file name the sender gave.
    pub file_name: String,
    pub artifact_id: String,
    /// Who sent it, as shown elsewhere in the app.
    pub sender: String,
    /// The viewer's email, for the watermark.
    pub viewer: String,
    /// When the service released it (Unix seconds).
    pub opened_at: i64,
    display_name: String,
    display: Zeroizing<Vec<u8>>,
}

impl ViewSession {
    pub(crate) fn new(
        r: &Released,
        manifest: &Manifest,
        mut parts: ViewParts,
        viewer: String,
        opened_at: i64,
    ) -> ViewSession {
        let display = Zeroizing::new(std::mem::take(&mut parts.display));
        wipe(&mut parts);
        ViewSession {
            file_name: manifest.files[0].name.clone(),
            artifact_id: hex::encode(r.verified.header.artifact_id),
            sender: r.sender.clone(),
            viewer,
            opened_at,
            display_name: parts.display_name,
            display,
        }
    }

    /// `display.<ext>`: what kind of document [`display`](Self::display) is.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The bytes to draw (PDF, image or text).
    pub fn display(&self) -> &[u8] {
        &self.display
    }

    /// The lines to burn into every page: the viewer's email, the time it
    /// was opened (UTC) and a short file ID.
    pub fn watermark_lines(&self) -> Vec<String> {
        vec![
            self.viewer.clone(),
            format_utc(self.opened_at),
            format!(
                "file {}",
                &self.artifact_id[..8.min(self.artifact_id.len())]
            ),
        ]
    }
}

impl std::fmt::Debug for ViewSession {
    // Never the content.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewSession")
            .field("file_name", &self.file_name)
            .field("artifact_id", &self.artifact_id)
            .field("sender", &self.sender)
            .field("display_name", &self.display_name)
            .field("display_len", &self.display.len())
            .finish_non_exhaustive()
    }
}

/// `YYYY-MM-DD HH:MM UTC`.
pub fn format_utc(t: i64) -> String {
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_times() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(format_utc(1_791_123_456), "2026-10-04 14:17 UTC");
        assert_eq!(format_utc(-60), "1969-12-31 23:59 UTC");
    }

    #[test]
    fn saving_writes_the_original_not_the_container() {
        let d = tempfile::tempdir().unwrap();
        let mut manifest = Manifest::single_file("Quarterly plan.docx", 99);
        manifest.files[0].content_type = Some(VIEW_CONTENT_TYPE.into());
        let parts = ViewParts {
            display_name: "display.pdf".into(),
            display: b"%PDF-1.4 fictional".to_vec(),
            original: Some(("Quarterly plan.docx".into(), b"fictional docx".to_vec())),
        };
        let out = |name: &str| Output::Dir {
            dir: d.path().join(name),
            overwrite: false,
        };
        let o = save_parts(&manifest, &parts, out("a"), "u.x".into(), "00".into()).unwrap();
        let p = o.path.unwrap();
        assert_eq!(p, d.path().join("a/Quarterly plan.docx"));
        assert_eq!(std::fs::read(&p).unwrap(), b"fictional docx");
        assert_eq!(o.manifest.files[0].size, 14);
        assert_eq!(o.manifest.files[0].content_type, None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Never over an existing file.
        assert!(matches!(
            save_parts(&manifest, &parts, out("a"), "u.x".into(), "00".into()),
            Err(ClientError::OutputExists(_))
        ));
        assert_eq!(std::fs::read_dir(d.path().join("a")).unwrap().count(), 1);
        // Without an original, the display copy under the sender's name.
        let direct = ViewParts {
            original: None,
            ..parts
        };
        let mut m = manifest.clone();
        m.files[0].name = "scan.pdf".into();
        let o = save_parts(&m, &direct, out("b"), "u.x".into(), "00".into()).unwrap();
        assert_eq!(
            std::fs::read(o.path.unwrap()).unwrap(),
            b"%PDF-1.4 fictional"
        );
        // A hostile name is refused.
        m.files[0].name = "../escape.pdf".into();
        assert!(save_parts(&m, &direct, out("c"), "u.x".into(), "00".into()).is_err());
        assert!(!d.path().join("escape.pdf").exists());
    }

    #[test]
    fn the_buffer_never_grows() {
        let mut v = Vec::with_capacity(4);
        let mut w = Bounded(&mut v);
        w.write_all(b"abcd").unwrap();
        assert!(w.write_all(b"e").is_err());
        assert_eq!(v.capacity(), 4);
    }
}
