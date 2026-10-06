fn main() {
    // `generate_context!` embeds the built UI and fails if it is missing.
    // Workspace-wide `cargo build/test/clippy` should not need Node, so
    // provide a placeholder page when the UI has not been built
    // (`npm run build` replaces it; `dist/` is git-ignored).
    let dist = std::path::Path::new("../dist");
    if !dist.join("index.html").exists() {
        std::fs::create_dir_all(dist).expect("create ../dist");
        std::fs::write(
            dist.join("index.html"),
            "<!doctype html><meta charset=\"utf-8\"><title>Secure Verified Exchange</title>\
             <p>The user interface has not been built. Run <code>npm run build</code> in apps/desktop.</p>",
        )
        .expect("write placeholder UI");
    }
    // Every app command gets an `allow-…` permission, and a window can call
    // only what its capability grants (capabilities/): the main window all
    // of them, a viewer window only its own `view_*` commands. A command
    // missing here would be callable from every window, so a test in
    // main.rs checks this list against `generate_handler!`.
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri-build");
}

/// Every `#[tauri::command]` registered in main.rs.
const COMMANDS: &[&str] = &[
    "state",
    "take_pending",
    "setup_verify",
    "setup_save",
    "read_config_file",
    "status",
    "open",
    "view_check",
    "view_open",
    "view_info",
    "view_page",
    "view_share",
    "view_save",
    "view_close",
    "recipient",
    "send",
    "login",
    "logout",
    "whoami",
    "revoke",
    "audit",
    "policies",
    "providers",
    "sign_up",
    "restore",
    "set_presence",
    "lock_now",
    "check_update",
    "set_check_updates",
    "install_update",
    "request_email_code",
    "email_sign_up",
    "email_restore",
    "reset_password",
    "change_password",
    "password_strength",
    "save_backup",
    "account",
    "account_name",
    "set_account_name",
    "lookup",
    "send_personal",
    "requests",
    "approve",
    "decline",
    "history",
    "file",
    "update_file",
    "cancel_open",
    "set_output_dir",
    "sign_out",
    "onboard_register",
    "onboard_complete",
    "onboard_cancel",
    "admin_overview",
    "update_org",
    "add_admin",
    "remove_admin",
    "set_policy",
    "delete_policy",
    "audit_page",
    "export_audit",
    "create_signing_key",
    "import_signing_key",
    "register_signing_public",
    "export_encryption_key",
    "activate_encryption_key",
    "discard_pending_encryption_key",
    "set_key_status",
    "pick",
    "reveal",
    "open_document",
];
