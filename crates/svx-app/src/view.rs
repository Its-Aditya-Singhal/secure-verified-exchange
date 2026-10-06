//! View-only files in the app (Phase 7): what the Send screen asks before
//! offering "View only", starting a view, and asking to keep a copy.
//!
//! The document itself never passes through here as anything but the
//! [`ViewSession`] `svx-client` returns; drawing it is the desktop shell's
//! job (`svx-viewer`), and only pixels leave that.

use std::path::Path;

use serde::Serialize;
use svx_client::viewfile::{self, MAX_DISPLAY_BYTES, MAX_ORIGINAL_BYTES, Plan};
use svx_client::{ViewSession, convert};
use svx_protocol::personal::ShareStatus;

use crate::{App, AppError, Progress, Result};

/// Whether a file can be sent view-only, and if not, why (for the Send
/// screen to show before the person has to guess).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ViewCheck {
    pub ok: bool,
    /// An Office file: converted to PDF on this computer for viewing, and the
    /// original is what "keep a copy" saves.
    pub office: bool,
    pub reason: Option<String>,
}

impl ViewCheck {
    fn no(office: bool, reason: impl Into<String>) -> ViewCheck {
        ViewCheck {
            ok: false,
            office,
            reason: Some(reason.into()),
        }
    }
}

/// Check `path` without reading it.
pub fn view_check(path: &Path) -> ViewCheck {
    let Ok(meta) = std::fs::metadata(path) else {
        return ViewCheck::no(false, "this file can't be read");
    };
    if !meta.is_file() {
        return ViewCheck::no(false, "only a single file can be view-only, not a folder");
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (office, limit) = match viewfile::plan_for(&name) {
        Ok(Plan::Direct) => (false, MAX_DISPLAY_BYTES),
        Ok(Plan::Office) => (true, MAX_ORIGINAL_BYTES),
        Err(why) => return ViewCheck::no(false, why),
    };
    if meta.len() > limit {
        return ViewCheck::no(
            office,
            format!(
                "this file is larger than {} MB, the limit for view-only files",
                limit >> 20
            ),
        );
    }
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    if office && convert::find_converter(&ext).is_none() {
        return ViewCheck::no(true, convert::LIBREOFFICE_MISSING);
    }
    ViewCheck {
        ok: true,
        office,
        reason: None,
    }
}

impl App {
    /// Whether this computer can show view-only files (it must be able to
    /// keep the viewer out of screenshots; Linux can't).
    pub fn view_supported() -> bool {
        cfg!(not(target_os = "linux"))
    }

    /// Ask the service and decrypt a view-only file into memory. Personal
    /// accounts only. Progress uses the same steps as opening.
    pub async fn view_start(
        &self,
        path: &Path,
        progress: &mut (dyn FnMut(Progress) + Send),
    ) -> Result<ViewSession> {
        let c = self.client()?;
        if !c.cfg.is_personal() {
            return Err(AppError::other("view-only files are for personal accounts"));
        }
        let cancel = self.new_cancel();
        let mut on_step = |s: svx_client::Step| progress(Progress::from(&s));
        let session = c.view_personal(path, &mut on_step, &cancel).await?;
        self.remember_received(&session.artifact_id, &session.file_name);
        Ok(session)
    }

    /// Whether I may keep a copy of a view-only file I received.
    pub async fn share_status(&self, artifact_id: &str) -> Result<ShareStatus> {
        Ok(self.client()?.share_status(artifact_id).await?)
    }

    /// Ask the sender to let me keep a copy.
    pub async fn request_share(&self, artifact_id: &str) -> Result<ShareStatus> {
        Ok(self.client()?.request_share(artifact_id).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_single_viewable_files_pass_the_check() {
        let d = tempfile::tempdir().unwrap();
        let pdf = d.path().join("plan.pdf");
        std::fs::write(&pdf, b"%PDF-1.4").unwrap();
        assert_eq!(
            view_check(&pdf),
            ViewCheck {
                ok: true,
                office: false,
                reason: None
            }
        );
        let folder = view_check(d.path());
        assert!(!folder.ok && folder.reason.unwrap().contains("folder"));
        let exe = d.path().join("run.exe");
        std::fs::write(&exe, b"x").unwrap();
        assert!(view_check(&exe).reason.unwrap().contains("PDF"));
        assert!(!view_check(&d.path().join("missing.pdf")).ok);
        let docx = d.path().join("plan.docx");
        std::fs::write(&docx, b"x").unwrap();
        let c = view_check(&docx);
        assert!(c.office);
        // With LibreOffice it passes, without it the reason says to install it.
        assert_eq!(c.ok, convert::find_converter("docx").is_some());
        if !c.ok {
            assert!(c.reason.unwrap().contains("LibreOffice"));
        }
    }
}
