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
    AdminOverview, App, AppError, AppState, HistoryView, OpenResult, PersonalSendRequest, Progress,
    Providers, Recipient, RequestView, SendRequest, SentView, SetupForm, StatusView,
};
use svx_client::PackResult;
use svx_client::account::WhoAmI;
use svx_client::keyadmin::{ExportedKemKey, NewSigningKey};
use svx_client::login::system_browser;
use svx_client::onboard::{OnboardRequest, PendingOrg};
use svx_client::personal::{AccountInfo, Contact, SendResult};
use svx_client::setup::SetupPreview;
use svx_protocol::admin::AuditPage;
use svx_protocol::personal::{ApprovalRequest, UpdateFileRequest};
use svx_protocol::{KeyEntry, KeyStatus, Policy};
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

// ----- Personal accounts (Phase 5d) -----

#[tauri::command]
async fn providers(app: State<'_, App>) -> Result<Providers> {
    app.providers().await
}

#[tauri::command]
async fn sign_up(
    app: State<'_, App>,
    issuer: Option<String>,
    reset: bool,
    dev_user: Option<String>,
    replace: bool,
) -> Result<AccountInfo> {
    app.sign_up(
        issuer,
        reset,
        App::login_method(dev_user, system_browser()),
        replace,
    )
    .await
}

/// Ask for the backup file, then sign in with it on this device.
#[tauri::command]
async fn restore(
    handle: AppHandle,
    app: State<'_, App>,
    issuer: Option<String>,
    password: String,
    dev_user: Option<String>,
    replace: bool,
) -> Result<Option<AccountInfo>> {
    let Some(path) = dialog(handle, |d| {
        d.set_title("Choose your SVX backup")
            .add_filter("SVX backups", &["svxbackup"])
            .blocking_pick_file()
    })
    .await?
    else {
        return Ok(None);
    };
    app.restore(
        &path,
        &password,
        issuer,
        App::login_method(dev_user, system_browser()),
        replace,
    )
    .await
    .map(Some)
}

/// Ask where to save, then write the encrypted backup.
#[tauri::command]
async fn save_backup(
    handle: AppHandle,
    app: State<'_, App>,
    password: String,
) -> Result<Option<PathBuf>> {
    let email = app.state().email.unwrap_or_else(|| "account".into());
    let name = format!("svx-{}.svxbackup", email.replace(['@', '.'], "-"));
    let Some(path) = dialog(handle, move |d| {
        d.set_title("Save your SVX backup")
            .set_file_name(name)
            .add_filter("SVX backups", &["svxbackup"])
            .blocking_save_file()
    })
    .await?
    else {
        return Ok(None);
    };
    app.save_backup(&path, &password)?;
    Ok(Some(path))
}

#[tauri::command]
async fn account(app: State<'_, App>) -> Result<AccountInfo> {
    app.account().await
}

#[tauri::command]
async fn lookup(app: State<'_, App>, email: String) -> Result<Contact> {
    app.lookup(&email).await
}

#[tauri::command]
async fn send_personal(app: State<'_, App>, req: PersonalSendRequest) -> Result<SendResult> {
    app.send_personal(req).await
}

#[tauri::command]
async fn requests(app: State<'_, App>) -> Result<Vec<RequestView>> {
    app.requests().await
}

#[tauri::command]
async fn approve(app: State<'_, App>, request_id: String) -> Result<ApprovalRequest> {
    app.approve(&request_id).await
}

#[tauri::command]
async fn decline(app: State<'_, App>, request_id: String) -> Result<ApprovalRequest> {
    app.decline(&request_id).await
}

#[tauri::command]
async fn history(app: State<'_, App>) -> Result<HistoryView> {
    app.history().await
}

#[tauri::command]
async fn file(app: State<'_, App>, artifact_id: String) -> Result<SentView> {
    app.file(&artifact_id).await
}

#[tauri::command]
async fn update_file(
    app: State<'_, App>,
    artifact_id: String,
    update: UpdateFileRequest,
) -> Result<SentView> {
    app.update_file(&artifact_id, update).await
}

#[tauri::command]
fn cancel_open(app: State<'_, App>) {
    app.cancel_open()
}

/// Ask for a folder, then save opened files there.
#[tauri::command]
async fn set_output_dir(handle: AppHandle, app: State<'_, App>) -> Result<Option<PathBuf>> {
    let Some(dir) = dialog(handle, |d| {
        d.set_title("Choose where opened files are saved")
            .blocking_pick_folder()
    })
    .await?
    else {
        return Ok(None);
    };
    app.set_output_dir(&dir)?;
    Ok(Some(dir))
}

#[tauri::command]
fn sign_out(app: State<'_, App>) -> Result<()> {
    app.sign_out()
}

// ----- Onboarding (Phase 5b) -----

#[tauri::command]
async fn onboard_register(app: State<'_, App>, req: OnboardRequest) -> Result<PendingOrg> {
    app.onboard_register(req).await
}

#[tauri::command]
async fn onboard_complete(
    app: State<'_, App>,
    dev_user: Option<String>,
    replace: bool,
) -> Result<SetupPreview> {
    let (preview, _) = app
        .onboard_complete(App::login_method(dev_user, system_browser()), replace)
        .await?;
    Ok(preview)
}

#[tauri::command]
fn onboard_cancel(app: State<'_, App>) {
    app.onboard_cancel()
}

// ----- Organization administration (Phase 5b) -----

#[tauri::command]
async fn admin_overview(app: State<'_, App>) -> Result<AdminOverview> {
    app.admin_overview().await
}

#[tauri::command]
async fn update_org(app: State<'_, App>, form: svx_app::OrgSettingsForm) -> Result<()> {
    app.update_org(form).await
}

#[tauri::command]
async fn add_admin(app: State<'_, App>, subject: String) -> Result<()> {
    app.add_admin(&subject).await
}

#[tauri::command]
async fn remove_admin(app: State<'_, App>, subject: String) -> Result<()> {
    app.remove_admin(&subject).await
}

#[tauri::command]
async fn set_policy(app: State<'_, App>, name: String, policy: Policy) -> Result<Policy> {
    app.set_policy(&name, policy).await
}

#[tauri::command]
async fn delete_policy(app: State<'_, App>, name: String) -> Result<()> {
    app.delete_policy(&name).await
}

#[tauri::command]
async fn audit_page(
    app: State<'_, App>,
    limit: u32,
    before_seq: Option<i64>,
    event: Option<String>,
) -> Result<AuditPage> {
    app.audit_page(limit, before_seq, event).await
}

/// Ask where to save, then write the audit trail as CSV. The UI never
/// supplies a path to write to.
#[tauri::command]
async fn export_audit(
    handle: AppHandle,
    app: State<'_, App>,
    event: Option<String>,
) -> Result<Option<(PathBuf, usize)>> {
    let dir = app.default_export_dir();
    let Some(path) = dialog(handle, move |d| {
        d.set_title("Save the audit trail")
            .set_directory(dir)
            .set_file_name("svx-audit.csv")
            .add_filter("CSV", &["csv"])
            .blocking_save_file()
    })
    .await?
    else {
        return Ok(None);
    };
    let n = app.export_audit_csv(&path, event).await?;
    Ok(Some((path, n)))
}

#[tauri::command]
async fn create_signing_key(app: State<'_, App>) -> Result<NewSigningKey> {
    app.create_signing_key().await
}

/// Ask for a signing key file, then move it into the keychain.
#[tauri::command]
async fn import_signing_key(
    handle: AppHandle,
    app: State<'_, App>,
) -> Result<Option<NewSigningKey>> {
    let Some(path) = dialog(handle, |d| {
        d.set_title("Choose a signing key file to move into the keychain")
            .add_filter("SVX signing keys", &["key"])
            .blocking_pick_file()
    })
    .await?
    else {
        return Ok(None);
    };
    app.import_signing_key(&path).map(Some)
}

/// Ask for another sender's public signing key file, then register it.
#[tauri::command]
async fn register_signing_public(
    handle: AppHandle,
    app: State<'_, App>,
) -> Result<Option<KeyEntry>> {
    let Some(path) = dialog(handle, |d| {
        d.set_title("Choose a sender's public signing key")
            .add_filter("SVX public signing keys", &["pub"])
            .blocking_pick_file()
    })
    .await?
    else {
        return Ok(None);
    };
    app.register_signing_public(&path).await.map(Some)
}

/// Ask for a folder, then write a new encryption key for the key agent.
#[tauri::command]
async fn export_encryption_key(
    handle: AppHandle,
    app: State<'_, App>,
) -> Result<Option<ExportedKemKey>> {
    let Some(dir) = dialog(handle, |d| {
        d.set_title("Choose a private folder for the key agent's new key")
            .blocking_pick_folder()
    })
    .await?
    else {
        return Ok(None);
    };
    app.export_encryption_key(&dir).map(Some)
}

#[tauri::command]
async fn activate_encryption_key(app: State<'_, App>) -> Result<KeyEntry> {
    app.activate_encryption_key().await
}

#[tauri::command]
fn discard_pending_encryption_key(app: State<'_, App>) {
    app.discard_pending_encryption_key()
}

#[tauri::command]
async fn set_key_status(
    app: State<'_, App>,
    key_id: String,
    status: KeyStatus,
) -> Result<KeyEntry> {
    app.set_key_status(&key_id, status).await
}

/// Run a blocking native dialog off the main thread.
async fn dialog(
    handle: AppHandle,
    f: impl FnOnce(
        tauri_plugin_dialog::FileDialogBuilder<tauri::Wry>,
    ) -> Option<tauri_plugin_dialog::FilePath>
    + Send
    + 'static,
) -> Result<Option<PathBuf>> {
    tauri::async_runtime::spawn_blocking(move || {
        f(handle.dialog().file()).and_then(|p| p.into_path().ok())
    })
    .await
    .map_err(|e| AppError::other(e.to_string()))
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
            providers,
            sign_up,
            restore,
            save_backup,
            account,
            lookup,
            send_personal,
            requests,
            approve,
            decline,
            history,
            file,
            update_file,
            cancel_open,
            set_output_dir,
            sign_out,
            onboard_register,
            onboard_complete,
            onboard_cancel,
            admin_overview,
            update_org,
            add_admin,
            remove_admin,
            set_policy,
            delete_policy,
            audit_page,
            export_audit,
            create_signing_key,
            import_signing_key,
            register_signing_public,
            export_encryption_key,
            activate_encryption_key,
            discard_pending_encryption_key,
            set_key_status,
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
