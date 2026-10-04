//! Sending folders.
//!
//! The container holds a single file, so a folder is zipped before packing
//! and its manifest entry is marked with [`FOLDER_CONTENT_TYPE`]. The manifest
//! is inside the signed, encrypted payload, so only the sender can set the
//! marker. On open, a marked payload is extracted into a folder.
//!
//! Extraction treats the archive as untrusted even though it is
//! authenticated (a sender's tool may be buggy or compromised):
//!
//! * every entry name must be a relative path of plain components: no `..`,
//!   `.`, absolute paths, drive letters, backslashes, colons, control
//!   characters or Windows device names;
//! * only regular files and directories; symlinks and other types are refused;
//! * limits on entry count, total size and compression ratio, enforced on the
//!   bytes actually written, not the sizes the archive declares;
//! * everything is extracted into a private staging directory and moved into
//!   place only when complete; existing folders are never replaced;
//! * files are created owner-only (0600, directories 0700) on Unix, and
//!   permission bits stored in the archive are ignored.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::error::{ClientError, Result};

/// Manifest content type marking a payload as a zipped folder.
pub const FOLDER_CONTENT_TYPE: &str = "application/vnd.svx.folder+zip";

/// Extraction limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_entries: usize,
    pub max_total_bytes: u64,
    /// Total extracted bytes may not exceed this multiple of the archive
    /// size (plus [`Limits::ratio_allowance`]).
    pub max_ratio: u64,
    pub ratio_allowance: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_entries: 100_000,
            max_total_bytes: 64 << 30,
            max_ratio: 200,
            ratio_allowance: 16 << 20,
        }
    }
}

/// Zip `dir` into a private temporary file. Entries are sorted, so the same
/// tree gives the same archive. Symlinks and special files are refused, so
/// nothing outside `dir` is ever included.
pub fn zip_dir(dir: &Path) -> Result<tempfile::NamedTempFile> {
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(ClientError::Config(format!(
            "{} is not a folder",
            dir.display()
        )));
    }
    let tmp = tempfile::Builder::new().prefix(".svx-folder-").tempfile()?;
    let mut zip = ZipWriter::new(BufWriter::new(tmp.as_file()));
    let dirs = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o700);
    let files = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o600)
        .large_file(true);
    add_tree(&mut zip, dir, "", dirs, files)?;
    zip.finish()
        .map_err(zip_err)?
        .into_inner()
        .map_err(|e| ClientError::Io(e.into_error()))?
        .sync_all()?;
    Ok(tmp)
}

fn add_tree<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    dir: &Path,
    prefix: &str,
    dirs: SimpleFileOptions,
    files: SimpleFileOptions,
) -> Result<()> {
    let mut entries = fs::read_dir(dir)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        let name = e.file_name();
        let name = name.to_str().ok_or_else(|| {
            ClientError::Config(format!("{} has a name that is not UTF-8", path.display()))
        })?;
        let rel = format!("{prefix}{name}");
        check_entry_name(&rel)
            .map_err(|why| ClientError::Config(format!("cannot send {}: {why}", path.display())))?;
        let ty = fs::symlink_metadata(&path)?.file_type();
        if ty.is_dir() {
            zip.add_directory(format!("{rel}/"), dirs)
                .map_err(zip_err)?;
            add_tree(zip, &path, &format!("{rel}/"), dirs, files)?;
        } else if ty.is_file() {
            zip.start_file(rel, files).map_err(zip_err)?;
            io::copy(&mut BufReader::new(File::open(&path)?), zip)?;
        } else {
            return Err(ClientError::Config(format!(
                "cannot send {}: only regular files and folders can be sent (no links)",
                path.display()
            )));
        }
    }
    Ok(())
}

/// The folder name for a payload file name: `reports.zip` → `reports`.
pub fn folder_name(payload_name: &str) -> &str {
    payload_name.strip_suffix(".zip").unwrap_or(payload_name)
}

/// Extract `zip` as a new folder `dest`. Fails with
/// [`ClientError::OutputExists`] if `dest` exists; on any error nothing is
/// left at `dest`.
pub fn extract<R: Read + Seek>(zip: R, zip_len: u64, dest: &Path, limits: Limits) -> Result<()> {
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // Claim the name first, so an existing folder is never touched.
    match fs::create_dir(dest) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(ClientError::OutputExists(dest.to_path_buf()));
        }
        Err(e) => return Err(e.into()),
    }
    let staging = match tempfile::Builder::new()
        .prefix(".svx-partial-")
        .tempdir_in(parent)
    {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_dir(dest);
            return Err(e.into());
        }
    };
    let result = private_dir(staging.path())
        .and_then(|()| extract_into(zip, zip_len, staging.path(), limits))
        .and_then(|()| {
            // `dest` is the empty directory we created. On Unix, rename
            // atomically replaces an empty directory and fails if anything
            // was put in it meanwhile; Windows needs it removed first.
            #[cfg(windows)]
            fs::remove_dir(dest)?;
            fs::rename(staging.path(), dest).map_err(ClientError::from)
        });
    if result.is_err() {
        // `staging` is deleted on drop; remove our placeholder if still empty.
        let _ = fs::remove_dir(dest);
    }
    result
}

fn extract_into<R: Read + Seek>(zip: R, zip_len: u64, root: &Path, limits: Limits) -> Result<()> {
    let mut archive = ZipArchive::new(zip).map_err(bad)?;
    if archive.len() > limits.max_entries {
        return Err(bad_msg(format!(
            "folder has {} entries (limit {})",
            archive.len(),
            limits.max_entries
        )));
    }
    let budget = limits.max_total_bytes.min(
        zip_len
            .saturating_mul(limits.max_ratio)
            .saturating_add(limits.ratio_allowance),
    );
    let mut written: u64 = 0;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(bad)?;
        let name = std::str::from_utf8(entry.name_raw())
            .map_err(|_| bad_msg("entry name is not UTF-8".into()))?
            .to_owned();
        let (path, is_dir) = entry_path(root, &name)?;
        let kind = entry.unix_mode().map(|m| m & 0o170000);
        if entry.is_symlink() || !matches!(kind, None | Some(0) | Some(0o100000) | Some(0o040000)) {
            return Err(bad_msg(format!("{name:?} is not a regular file or folder")));
        }
        if is_dir || entry.is_dir() || kind == Some(0o040000) {
            create_dirs(root, &path)?;
            continue;
        }
        if let Some(p) = path.parent() {
            create_dirs(root, p)?;
        }
        let mut out = new_private_file(&path)?;
        // Count real output: declared sizes are not trusted.
        let remaining = budget - written;
        let n = io::copy(&mut (&mut entry).take(remaining + 1), &mut out)?;
        if n > remaining {
            return Err(bad_msg(format!(
                "folder expands beyond the size limit ({budget} bytes)"
            )));
        }
        written += n;
        out.flush()?;
    }
    Ok(())
}

/// Validate an entry name and join it onto `root`. Returns whether the name
/// denotes a directory (trailing `/`).
fn entry_path(root: &Path, name: &str) -> Result<(PathBuf, bool)> {
    let (rel, is_dir) = match name.strip_suffix('/') {
        Some(r) => (r, true),
        None => (name, false),
    };
    check_entry_name(rel).map_err(|why| bad_msg(format!("unsafe entry {name:?}: {why}")))?;
    let mut p = root.to_path_buf();
    p.extend(rel.split('/'));
    Ok((p, is_dir))
}

/// The portable subset of names that are safe on every platform.
pub(crate) fn check_entry_name(rel: &str) -> std::result::Result<(), &'static str> {
    if rel.is_empty() {
        return Err("empty name");
    }
    if rel.len() > 4096 {
        return Err("name too long");
    }
    for c in rel.split('/') {
        match c {
            "" => return Err("empty or absolute path component"),
            "." | ".." => return Err("relative path component"),
            _ => {}
        }
        if c.chars().any(|ch| {
            ch.is_control() || matches!(ch, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        }) {
            return Err("character not allowed in file names");
        }
        if c.ends_with('.') || c.ends_with(' ') {
            return Err("name ends with a dot or space");
        }
        let stem = c.split('.').next().unwrap_or(c).to_ascii_uppercase();
        let device = matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
        if device {
            return Err("reserved device name");
        }
    }
    Ok(())
}

/// Create `dir` and its missing parents below `root`, owner-only. `dir` is
/// always a path built by [`entry_path`], so it is inside `root`.
fn create_dirs(root: &Path, dir: &Path) -> Result<()> {
    debug_assert!(dir.starts_with(root));
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)?;
    Ok(())
}

fn private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Create a new file (never follows or replaces an existing path).
fn new_private_file(path: &Path) -> Result<BufWriter<File>> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    match o.open(path) {
        Ok(f) => Ok(BufWriter::new(f)),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(bad_msg(format!(
            "duplicate entry {}",
            path.file_name().unwrap_or_default().to_string_lossy()
        ))),
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn zip_err(e: zip::result::ZipError) -> ClientError {
    match e {
        zip::result::ZipError::Io(e) => ClientError::Io(e),
        e => ClientError::Other(format!("zip: {e}")),
    }
}

fn bad(e: zip::result::ZipError) -> ClientError {
    match e {
        zip::result::ZipError::Io(e) => ClientError::Io(e),
        e => bad_msg(e.to_string()),
    }
}

fn bad_msg(why: String) -> ClientError {
    ClientError::Rejected(format!("folder cannot be extracted safely: {why}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn tree(root: &Path) {
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::create_dir_all(root.join("empty")).unwrap();
        fs::write(root.join("top.txt"), b"top").unwrap();
        fs::write(root.join("a/b/deep.bin"), vec![7u8; 100_000]).unwrap();
        fs::write(root.join("a/rapport-été.txt"), "données").unwrap();
    }

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut z = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            if name.ends_with('/') {
                z.add_directory(*name, SimpleFileOptions::default())
                    .unwrap();
            } else {
                z.start_file(*name, SimpleFileOptions::default()).unwrap();
                z.write_all(data).unwrap();
            }
        }
        z.finish().unwrap().into_inner()
    }

    fn try_extract(bytes: &[u8], limits: Limits) -> (tempfile::TempDir, Result<()>) {
        let out = tempfile::tempdir().unwrap();
        let r = extract(
            Cursor::new(bytes),
            bytes.len() as u64,
            &out.path().join("dest"),
            limits,
        );
        (out, r)
    }

    #[test]
    fn round_trip() {
        let src = tempfile::tempdir().unwrap();
        tree(src.path());
        let z = zip_dir(src.path()).unwrap();
        let len = z.as_file().metadata().unwrap().len();
        let out = tempfile::tempdir().unwrap();
        let dest = out.path().join("reports");
        extract(File::open(z.path()).unwrap(), len, &dest, Limits::default()).unwrap();
        assert_eq!(fs::read(dest.join("top.txt")).unwrap(), b"top");
        assert_eq!(fs::read(dest.join("a/b/deep.bin")).unwrap().len(), 100_000);
        assert_eq!(
            fs::read_to_string(dest.join("a/rapport-été.txt")).unwrap(),
            "données"
        );
        assert!(dest.join("empty").is_dir());
        // No staging directories left behind.
        let names: Vec<_> = fs::read_dir(out.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("reports")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dest), 0o700);
            assert_eq!(mode(&dest.join("a/b")), 0o700);
            assert_eq!(mode(&dest.join("top.txt")), 0o600);
        }
    }

    #[test]
    fn zipping_is_deterministic() {
        let src = tempfile::tempdir().unwrap();
        tree(src.path());
        let a = fs::read(zip_dir(src.path()).unwrap().path()).unwrap();
        let b = fs::read(zip_dir(src.path()).unwrap().path()).unwrap();
        assert_eq!(a, b);
    }

    #[cfg(unix)]
    #[test]
    fn zipping_refuses_symlinks() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("ok.txt"), b"x").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.path().join("link")).unwrap();
        assert!(matches!(zip_dir(src.path()), Err(ClientError::Config(_))));
    }

    #[test]
    fn unsafe_names_are_refused() {
        for bad in [
            "../x",
            "a/../../x",
            "/abs",
            "./x",
            "a//b",
            "C:\\x",
            "C:x",
            "\\\\server\\share\\x",
            "a\\..\\x",
            "nul",
            "dir/COM1.txt",
            "trailing.",
            "bell\u{7}",
        ] {
            let (out, r) = try_extract(&zip_of(&[(bad, b"x")]), Limits::default());
            assert!(matches!(r, Err(ClientError::Rejected(_))), "{bad:?}: {r:?}");
            assert!(!out.path().join("dest").exists(), "{bad:?}");
            assert_eq!(fs::read_dir(out.path()).unwrap().count(), 0, "{bad:?}");
        }
    }

    #[test]
    fn symlink_entries_are_refused() {
        let mut z = ZipWriter::new(Cursor::new(Vec::new()));
        z.add_symlink("link", "/etc/passwd", SimpleFileOptions::default())
            .unwrap();
        let bytes = z.finish().unwrap().into_inner();
        let (_out, r) = try_extract(&bytes, Limits::default());
        assert!(matches!(r, Err(ClientError::Rejected(_))), "{r:?}");
    }

    #[test]
    fn zip_bombs_are_refused() {
        let zeros = vec![0u8; 10 << 20];
        let bytes = zip_of(&[("zeros.bin", &zeros)]);
        // Highly compressible: 10 MiB of zeros in a few KiB.
        let tight = Limits {
            ratio_allowance: 0,
            ..Limits::default()
        };
        let (out, r) = try_extract(&bytes, tight);
        assert!(matches!(r, Err(ClientError::Rejected(_))), "{r:?}");
        assert!(!out.path().join("dest").exists());
        // Absolute cap.
        let capped = Limits {
            max_total_bytes: 1 << 20,
            ..Limits::default()
        };
        assert!(try_extract(&bytes, capped).1.is_err());
        // Within limits it extracts.
        assert!(try_extract(&bytes, Limits::default()).1.is_ok());
    }

    #[test]
    fn too_many_entries_are_refused() {
        let names: Vec<String> = (0..20).map(|i| format!("f{i}")).collect();
        let entries: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
        let limits = Limits {
            max_entries: 10,
            ..Limits::default()
        };
        assert!(try_extract(&zip_of(&entries), limits).1.is_err());
    }

    #[test]
    fn clashing_entries_are_refused() {
        // A file and a folder with the same name (exact duplicates are
        // already refused by the zip reader).
        let (out, r) = try_extract(&zip_of(&[("a", b"1"), ("a/b", b"2")]), Limits::default());
        assert!(r.is_err());
        assert!(!out.path().join("dest").exists());
    }

    #[test]
    fn existing_destination_is_never_replaced() {
        let out = tempfile::tempdir().unwrap();
        let dest = out.path().join("dest");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("mine.txt"), b"keep").unwrap();
        let bytes = zip_of(&[("x", b"x")]);
        let r = extract(
            Cursor::new(&bytes),
            bytes.len() as u64,
            &dest,
            Limits::default(),
        );
        assert!(matches!(r, Err(ClientError::OutputExists(_))));
        assert_eq!(fs::read(dest.join("mine.txt")).unwrap(), b"keep");
    }

    #[test]
    fn folder_names() {
        assert_eq!(folder_name("reports.zip"), "reports");
        assert_eq!(folder_name("reports"), "reports");
    }
}
