//! Secure Verified Exchange: the desktop shell.
//!
//! Each command forwards to [`svx_app::App`], which forwards to
//! `svx_client`. Nothing here verifies, authorizes or decrypts. The web UI
//! gets no plugin permissions of its own: file pickers, revealing and opening
//! files all go through the commands below, and only paths the app itself
//! produced can be revealed or opened.

// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Deserialize;
use svx_app::{
    App, AppError, AppState, OpenResult, Progress, Recipient, SendRequest, SetupForm, StatusView,
};
use svx_client::PackResult;
use svx_client::account::WhoAmI;
use svx_client::login::system_browser;
use svx_client::setup::SetupPreview;
use svx_protocol::Policy;
use svx_protocol::admin::AuditPage;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;

type Result<T> = std::result::Result<T, AppError>;

/// `.svx` files handed to the app (double-click, "Open with", command line,
/// a second launch) that the UI has not picked up yet.
#[derive(Default)]
struct Pending(Mutex<Vec<PathBuf>>);

/// Queue `.svx` paths and tell the UI to pick them up.
fn hand_over(app: &AppHandle, paths: impl IntoIterator<Item = PathBuf>) {
    let paths: Vec<PathBuf> = paths
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("svx")))
        .collect();
    if paths.is_empty() {
        return;
    }
    app.state::<Pending>().0.lock().unwrap().extend(paths);
    let _ = app.emit("open-file", ());
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// File arguments from a command line (Windows and Linux file association).
fn file_args(argv: &[String], cwd: &Path) -> Vec<PathBuf> {
    argv.iter()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .map(|a| cwd.join(a))
        .collect()
}

// ----- State and setup -----

#[tauri::command]
fn state(app: State<'_, App>) -> AppState {
    app.state()
}

#[tauri::command]
fn take_pending(pending: State<'_, Pending>) -> Vec<PathBuf> {
    std::mem::take(&mut *pending.0.lock().unwrap())
}

#[tauri::command]
async fn setup_verify(app: State<'_, App>, form: SetupForm) -> Result<SetupPreview> {
    app.setup_verify(form).await
}

#[tauri::command]
async fn setup_save(app: State<'_, App>, form: SetupForm, replace: bool) -> Result<SetupPreview> {
    app.setup_save(form, replace).await
}

#[tauri::command]
fn read_config_file(app: State<'_, App>, path: PathBuf) -> Result<SetupForm> {
    app.read_config_file(&path)
}

// ----- Open -----

#[tauri::command]
async fn status(app: State<'_, App>, path: PathBuf) -> Result<StatusView> {
    app.status(&path).await
}

#[tauri::command]
async fn open(
    handle: AppHandle,
    app: State<'_, App>,
    path: PathBuf,
    output_dir: Option<PathBuf>,
    dev_user: Option<String>,
) -> Result<OpenResult> {
    let login = App::login_method(dev_user, system_browser());
    let mut progress = |p: Progress| {
        let _ = handle.emit("open-progress", p);
    };
    app.open(&path, output_dir, login, &mut progress).await
}

// ----- Send -----

#[tauri::command]
async fn recipient(app: State<'_, App>, org: String) -> Result<Recipient> {
    app.recipient(&org).await
}

#[tauri::command]
async fn send(app: State<'_, App>, req: SendRequest) -> Result<PackResult> {
    app.send(req).await
}

// ----- Account and administration -----

#[tauri::command]
async fn login(app: State<'_, App>, dev_user: Option<String>) -> Result<WhoAmI> {
    app.login(App::login_method(dev_user, system_browser()))
        .await
}

#[tauri::command]
fn logout(app: State<'_, App>) -> Result<bool> {
    app.logout()
}

#[tauri::command]
async fn whoami(app: State<'_, App>) -> Result<Option<WhoAmI>> {
    app.whoami().await
}

#[tauri::command]
async fn revoke(app: State<'_, App>, target: String) -> Result<String> {
    app.revoke(&target).await
}

#[tauri::command]
async fn audit(app: State<'_, App>, limit: u32) -> Result<AuditPage> {
    app.audit(limit).await
}

#[tauri::command]
async fn policies(app: State<'_, App>) -> Result<std::collections::BTreeMap<String, Policy>> {
    app.policies().await
}

// ----- Files -----

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Pick {
    SendFile,
    SendFolder,
    Artifact,
    SigningKey,
    Config,
    OutputDir,
}

/// Native file pickers. Runs off the main thread (the dialogs block).
#[tauri::command]
async fn pick(handle: AppHandle, kind: Pick) -> Result<Option<PathBuf>> {
    tauri::async_runtime::spawn_blocking(move || {
        let d = handle.dialog().file();
        let picked = match kind {
            Pick::SendFile => d.set_title("Choose a file to protect").blocking_pick_file(),
            Pick::SendFolder => d
                .set_title("Choose a folder to protect")
                .blocking_pick_folder(),
            Pick::Artifact => d
                .set_title("Open an SVX file")
                .add_filter("SVX files", &["svx"])
                .blocking_pick_file(),
            Pick::SigningKey => d
                .set_title("Choose your organization's signing key")
                .add_filter("SVX signing keys", &["key"])
                .blocking_pick_file(),
            Pick::Config => d
                .set_title("Import an SVX configuration")
                .add_filter("SVX configuration", &["toml"])
                .blocking_pick_file(),
            Pick::OutputDir => d
                .set_title("Choose where opened files are saved")
                .blocking_pick_folder(),
        };
        picked.and_then(|p| p.into_path().ok())
    })
    .await
    .map_err(|e| AppError::other(e.to_string()))
}

/// Show a file or folder this app produced in Finder / Explorer.
#[tauri::command]
fn reveal(handle: AppHandle, app: State<'_, App>, path: PathBuf) -> Result<()> {
    let p = app.produced(&path)?;
    handle
        .opener()
        .reveal_item_in_dir(p)
        .map_err(|e| AppError::other(e.to_string()))
}

/// Open a document this app produced with the system's default app.
#[tauri::command]
fn open_document(handle: AppHandle, app: State<'_, App>, path: PathBuf) -> Result<()> {
    let p = app.openable(&path)?;
    handle
        .opener()
        .open_path(p.to_string_lossy(), None::<&str>)
        .map_err(|e| AppError::other(e.to_string()))
}

fn main() {
    let app = match App::new(None) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Secure Verified Exchange: {e}");
            std::process::exit(2);
        }
    };
    let builder = tauri::Builder::default()
        // Must be first: a second launch forwards its files and exits.
        .plugin(tauri_plugin_single_instance::init(|handle, argv, cwd| {
            hand_over(handle, file_args(&argv, Path::new(&cwd)));
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(app)
        .manage(Pending::default())
        .setup(|a| {
            let argv: Vec<String> = std::env::args().collect();
            let cwd = std::env::current_dir().unwrap_or_default();
            hand_over(a.handle(), file_args(&argv, &cwd));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            state,
            take_pending,
            setup_verify,
            setup_save,
            read_config_file,
            status,
            open,
            recipient,
            send,
            login,
            logout,
            whoami,
            revoke,
            audit,
            policies,
            pick,
            reveal,
            open_document,
        ]);
    let built = match builder.build(tauri::generate_context!()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Secure Verified Exchange failed to start: {e}");
            std::process::exit(1);
        }
    };
    built.run(|_handle, _event| {
        // macOS delivers double-clicked files as an event, cold or warm.
        #[cfg(target_os = "macos")]
        if let tauri::RunEvent::Opened { urls } = _event {
            let paths = urls.into_iter().filter_map(|u| u.to_file_path().ok());
            hand_over(_handle, paths);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_args_skip_program_and_flags() {
        let argv = vec![
            "svx-desktop".to_string(),
            "--flag".to_string(),
            "report.svx".to_string(),
        ];
        assert_eq!(
            file_args(&argv, Path::new("/home/alice")),
            vec![PathBuf::from("/home/alice/report.svx")]
        );
        // Absolute paths stay absolute.
        let abs = std::env::temp_dir().join("x.svx");
        let argv = vec!["svx-desktop".to_string(), abs.display().to_string()];
        assert_eq!(file_args(&argv, Path::new("/elsewhere")), vec![abs]);
    }
}
