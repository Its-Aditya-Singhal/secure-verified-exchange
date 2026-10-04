//! Office files to PDF, for sending them view-only.
//!
//! The recipient's viewer only draws PDFs, images and text, so a document
//! from Word, Excel or PowerPoint is converted **on the sender's computer**
//! with LibreOffice (free), from the sender's own file. The recipient never
//! parses an Office format.
//!
//! Only convert files you made or trust: opening a hostile document in
//! LibreOffice is a risk of its own (headless conversion runs no macros).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{ClientError, Result};
use crate::viewfile::MAX_DISPLAY_BYTES;

/// How long a conversion may take.
pub const CONVERT_TIMEOUT: Duration = Duration::from_secs(180);

/// The message shown when LibreOffice isn't installed.
pub const LIBREOFFICE_MISSING: &str = "To send Office files as view-only, install LibreOffice \
     (free, libreoffice.org), or save the file as a PDF first.";

/// LibreOffice's command line, if it is installed. `SVX_SOFFICE` overrides
/// the search (unusual installs, tests).
pub fn find_office() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SVX_SOFFICE") {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    let exe = if cfg!(windows) {
        "soffice.exe"
    } else {
        "soffice"
    };
    let on_path = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|d| d.join(exe))
        .find(|p| p.is_file());
    on_path.or_else(|| {
        [
            "/Applications/LibreOffice.app/Contents/MacOS/soffice",
            r"C:\Program Files\LibreOffice\program\soffice.exe",
            r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
    })
}

/// A `file://` URL for LibreOffice's `-env:UserInstallation`.
fn file_url(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/").replace(' ', "%20");
    if s.starts_with('/') {
        format!("file://{s}")
    } else {
        format!("file:///{s}")
    }
}

/// Convert `input` to PDF bytes with `office` (see [`find_office`]).
pub fn to_pdf(office: &Path, input: &Path) -> Result<Vec<u8>> {
    let ext = input
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let work = tempfile::Builder::new().prefix(".svx-convert-").tempdir()?;
    // A fixed, plain name avoids odd characters on the command line, and a
    // throwaway profile keeps LibreOffice away from the user's own settings.
    let src = work.path().join(format!("input.{ext}"));
    std::fs::copy(input, &src)?;
    let out = work.path().join("out");
    std::fs::create_dir(&out)?;
    let mut child = Command::new(office)
        .arg("--headless")
        .arg("--norestore")
        .arg("--nolockcheck")
        .arg(format!(
            "-env:UserInstallation={}",
            file_url(&work.path().join("profile"))
        ))
        .arg("--convert-to")
        .arg("pdf")
        .arg("--outdir")
        .arg(&out)
        .arg(&src)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| ClientError::Invalid(format!("LibreOffice could not be started: {e}")))?;
    let started = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if started.elapsed() > CONVERT_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ClientError::Invalid(
                "LibreOffice took too long to convert the file".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let pdf = out.join("input.pdf");
    if !status.success() || !pdf.is_file() {
        return Err(ClientError::Invalid(
            "LibreOffice could not convert this file to PDF".into(),
        ));
    }
    let len = std::fs::metadata(&pdf)?.len();
    if len > MAX_DISPLAY_BYTES {
        return Err(ClientError::Invalid(
            "the converted PDF is larger than 100 MB, the limit for view-only files".into(),
        ));
    }
    Ok(std::fs::read(pdf)?)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A stand-in for `soffice` that writes a tiny "PDF" like LibreOffice would.
    fn fake(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("soffice");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    const COPY_SCRIPT: &str = r#"while [ $# -gt 0 ]; do
  case "$1" in --outdir) out="$2"; shift;; -*) ;; pdf) ;; *) in="$1";; esac; shift
done
printf '%%PDF-1.4 fake' > "$out/$(basename "${in%.*}").pdf""#;

    #[test]
    fn converts_through_the_office_program() {
        let d = tempfile::tempdir().unwrap();
        let office = fake(d.path(), COPY_SCRIPT);
        let doc = d.path().join("My Report (final).docx");
        std::fs::write(&doc, b"fictional document").unwrap();
        assert_eq!(to_pdf(&office, &doc).unwrap(), b"%PDF-1.4 fake");
    }

    #[test]
    fn failures_and_timeouts_are_clear() {
        let d = tempfile::tempdir().unwrap();
        let doc = d.path().join("a.docx");
        std::fs::write(&doc, b"x").unwrap();
        // Exits with an error.
        let office = fake(d.path(), "exit 3");
        assert!(
            matches!(to_pdf(&office, &doc), Err(ClientError::Invalid(m)) if m.contains("could not convert"))
        );
        // Succeeds but writes nothing.
        let office = fake(d.path(), "exit 0");
        assert!(to_pdf(&office, &doc).is_err());
        // Not an executable at all.
        assert!(to_pdf(&d.path().join("missing"), &doc).is_err());
    }

    #[test]
    fn file_urls_are_well_formed() {
        assert_eq!(
            file_url(Path::new("/tmp/a b/profile")),
            "file:///tmp/a%20b/profile"
        );
        assert_eq!(file_url(Path::new(r"C:\Temp\p")), "file:///C:/Temp/p");
    }
}
