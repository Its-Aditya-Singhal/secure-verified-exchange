//! Office files to PDF, for sending them view-only.
//!
//! The recipient's viewer only draws PDFs, images and text, so a document
//! from Word, Excel or PowerPoint is converted **on the sender's computer**,
//! from the sender's own file. The recipient never parses an Office format.
//!
//! On Windows, Microsoft Office does it when the matching app (Word, Excel or
//! PowerPoint) is installed: a fixed PowerShell script asks it, over COM, to
//! export a PDF, with macros forced off and the file opened read-only. The
//! paths go in environment variables, never into the script. Otherwise
//! LibreOffice (free) does it, headless.
//!
//! Only convert files you made or trust: opening a hostile document in an
//! office suite is a risk of its own (neither way runs macros).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{ClientError, Result};
use crate::viewfile::MAX_DISPLAY_BYTES;

/// How long a conversion may take.
pub const CONVERT_TIMEOUT: Duration = Duration::from_secs(180);

/// The message shown when nothing can convert Office files.
pub const LIBREOFFICE_MISSING: &str = if cfg!(windows) {
    "To send Office files as view-only, install Microsoft Office or LibreOffice \
     (free, libreoffice.org), or save the file as a PDF first."
} else {
    "To send Office files as view-only, install LibreOffice \
     (free, libreoffice.org), or save the file as a PDF first."
};

/// What converts a document to PDF on this computer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Converter {
    /// Microsoft Office over COM (Windows).
    Microsoft(MsApp),
    /// LibreOffice's `soffice`.
    LibreOffice(PathBuf),
}

/// The Microsoft Office app that opens a file type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsApp {
    Word,
    Excel,
    PowerPoint,
}

impl MsApp {
    /// The app for a file extension (lower case), if Office opens it.
    pub fn for_extension(ext: &str) -> Option<MsApp> {
        match ext {
            "doc" | "docx" | "odt" | "rtf" => Some(MsApp::Word),
            "xls" | "xlsx" | "ods" => Some(MsApp::Excel),
            "ppt" | "pptx" | "odp" => Some(MsApp::PowerPoint),
            _ => None,
        }
    }

    fn prog_id(self) -> &'static str {
        match self {
            MsApp::Word => "Word.Application",
            MsApp::Excel => "Excel.Application",
            MsApp::PowerPoint => "PowerPoint.Application",
        }
    }

    fn script_name(self) -> &'static str {
        match self {
            MsApp::Word => "word",
            MsApp::Excel => "excel",
            MsApp::PowerPoint => "powerpoint",
        }
    }

    /// Whether this app is installed (its COM class is registered).
    fn installed(self) -> bool {
        if !cfg!(windows) {
            return false;
        }
        let mut cmd = Command::new("reg");
        cmd.arg("query")
            .arg(format!(r"HKCR\{}\CLSID", self.prog_id()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        no_window(&mut cmd);
        cmd.status().is_ok_and(|s| s.success())
    }
}

/// Exports a PDF with Microsoft Office. Fixed text: the input and output
/// paths and the app come from environment variables. AutomationSecurity 3
/// (msoAutomationSecurityForceDisable) turns macros off for files opened
/// this way; COM automation would otherwise allow them.
const MS_OFFICE_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$in = $env:SVX_CONVERT_IN
$out = $env:SVX_CONVERT_OUT
$app = $null
try {
  switch ($env:SVX_CONVERT_APP) {
    'word' {
      $app = New-Object -ComObject Word.Application
      $app.Visible = $false
      $app.DisplayAlerts = 0
      $app.AutomationSecurity = 3
      $doc = $app.Documents.Open($in, $false, $true, $false)
      $doc.ExportAsFixedFormat($out, 17)
      $doc.Close(0)
    }
    'excel' {
      $app = New-Object -ComObject Excel.Application
      $app.Visible = $false
      $app.DisplayAlerts = $false
      $app.AutomationSecurity = 3
      $book = $app.Workbooks.Open($in, 0, $true)
      $book.ExportAsFixedFormat(0, $out)
      $book.Close($false)
    }
    'powerpoint' {
      $app = New-Object -ComObject PowerPoint.Application
      $app.AutomationSecurity = 3
      $pres = $app.Presentations.Open($in, -1, 0, 0)
      $pres.SaveAs($out, 32)
      $pres.Close()
    }
    default { exit 2 }
  }
} finally {
  if ($app) { $app.Quit() }
}
"#;

/// Don't flash a console window when a Windows GUI app starts a program.
fn no_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = cmd;
}

/// What can convert a file with this extension (lower case) here: Microsoft
/// Office first when its app is installed (Windows), then LibreOffice.
pub fn find_converter(ext: &str) -> Option<Converter> {
    if let Some(app) = MsApp::for_extension(ext)
        && std::env::var_os("SVX_SOFFICE").is_none()
        && app.installed()
    {
        return Some(Converter::Microsoft(app));
    }
    find_office().map(Converter::LibreOffice)
}

/// Convert `input` to PDF bytes with `converter` (see [`find_converter`]).
pub fn convert(converter: &Converter, input: &Path) -> Result<Vec<u8>> {
    match converter {
        Converter::LibreOffice(office) => to_pdf(office, input),
        Converter::Microsoft(app) => ms_to_pdf(*app, input),
    }
}

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
    let child = Command::new(office)
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
    let status = wait(child, "LibreOffice")?;
    let pdf = out.join("input.pdf");
    if !status.success() || !pdf.is_file() {
        return Err(ClientError::Invalid(
            "LibreOffice could not convert this file to PDF".into(),
        ));
    }
    read_pdf(&pdf)
}

/// Convert `input` to PDF bytes with Microsoft Office (Windows).
fn ms_to_pdf(app: MsApp, input: &Path) -> Result<Vec<u8>> {
    let ext = input
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let work = tempfile::Builder::new().prefix(".svx-convert-").tempdir()?;
    let src = work.path().join(format!("input.{ext}"));
    std::fs::copy(input, &src)?;
    let pdf = work.path().join("output.pdf");
    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        MS_OFFICE_SCRIPT,
    ])
    .env("SVX_CONVERT_APP", app.script_name())
    .env("SVX_CONVERT_IN", &src)
    .env("SVX_CONVERT_OUT", &pdf)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    no_window(&mut cmd);
    let child = cmd
        .spawn()
        .map_err(|e| ClientError::Invalid(format!("Microsoft Office could not be started: {e}")))?;
    let status = wait(child, "Microsoft Office")?;
    if !status.success() || !pdf.is_file() {
        return Err(ClientError::Invalid(
            "Microsoft Office could not convert this file to PDF".into(),
        ));
    }
    read_pdf(&pdf)
}

/// Wait for a converter, killing it after [`CONVERT_TIMEOUT`].
fn wait(mut child: std::process::Child, what: &str) -> Result<std::process::ExitStatus> {
    let started = Instant::now();
    loop {
        if let Some(s) = child.try_wait()? {
            return Ok(s);
        }
        if started.elapsed() > CONVERT_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ClientError::Invalid(format!(
                "{what} took too long to convert the file"
            )));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn read_pdf(pdf: &Path) -> Result<Vec<u8>> {
    let len = std::fs::metadata(pdf)?.len();
    if len > MAX_DISPLAY_BYTES {
        return Err(ClientError::Invalid(
            "the converted PDF is larger than 100 MB, the limit for view-only files".into(),
        ));
    }
    Ok(std::fs::read(pdf)?)
}

#[cfg(test)]
mod office_tests {
    use super::*;

    #[test]
    fn each_office_type_has_its_app_and_the_script_disables_macros() {
        for ext in crate::viewfile::OFFICE_EXTENSIONS {
            assert!(MsApp::for_extension(ext).is_some(), "{ext}");
        }
        assert_eq!(MsApp::for_extension("pdf"), None);
        assert_eq!(MsApp::for_extension("pptx"), Some(MsApp::PowerPoint));
        // Every app branch forces macros off before opening the file, and
        // opens it read-only; the script holds no paths.
        for app in ["word", "excel", "powerpoint"] {
            let branch = MS_OFFICE_SCRIPT
                .split(&format!("'{app}' {{"))
                .nth(1)
                .unwrap();
            let open = branch.find(".Open(").unwrap();
            assert!(branch[..open].contains("AutomationSecurity = 3"), "{app}");
        }
        for var in [
            "$env:SVX_CONVERT_IN",
            "$env:SVX_CONVERT_OUT",
            "$env:SVX_CONVERT_APP",
        ] {
            assert!(MS_OFFICE_SCRIPT.contains(var));
        }
        if !cfg!(windows) {
            assert!(!MsApp::Word.installed());
        }
    }
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
