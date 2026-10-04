//! Every request body the service accepts, and every response the client
//! parses, as untrusted JSON.
#![no_main]
use libfuzzer_sys::fuzz_target;
use svx_protocol::email_account::{
    ChangePasswordRequest, EmailAccountRequest, EmailCodeRequest, EmailCodeResponse,
    PasswordResetRequest,
};
use svx_protocol::personal::{
    ApprovalRequest, FileStatus, History, OpenedReceipt, PersonalReleaseRequest,
    PersonalReleaseResponse, RegisterFileRequest, SignUpRequest, UpdateFileRequest,
};
use svx_protocol::update::SignedReleaseManifest;

fn try_all(data: &[u8]) {
    macro_rules! parse {
        ($($t:ty),* $(,)?) => {
            $( let _ = serde_json::from_slice::<$t>(data); )*
        };
    }
    parse!(
        SignUpRequest,
        RegisterFileRequest,
        UpdateFileRequest,
        PersonalReleaseRequest,
        PersonalReleaseResponse,
        OpenedReceipt,
        ApprovalRequest,
        FileStatus,
        History,
        EmailCodeRequest,
        EmailCodeResponse,
        EmailAccountRequest,
        PasswordResetRequest,
        ChangePasswordRequest,
        SignedReleaseManifest,
        svx_protocol::ReleaseRequest,
        svx_protocol::ReleaseResponse,
        svx_protocol::AgentReleaseRequest,
        svx_protocol::AgentKeys,
        svx_protocol::ServiceInfo,
        svx_protocol::Policy,
        svx_protocol::ErrorBody,
    );
}

fuzz_target!(|data: &[u8]| {
    try_all(data);
});
