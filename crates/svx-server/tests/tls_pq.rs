//! Post-quantum TLS on the server side: the TLS stack svx-server uses
//! (axum-server with rustls' default provider) prefers the hybrid
//! X25519MLKEM768 key exchange over classical groups.

use rustls::{NamedGroup, ServerConfig};

#[test]
fn server_prefers_post_quantum_key_exchange() {
    let builder = ServerConfig::builder();
    let groups: Vec<NamedGroup> = builder
        .crypto_provider()
        .kx_groups
        .iter()
        .map(|g| g.name())
        .collect();
    assert_eq!(
        groups.first(),
        Some(&NamedGroup::X25519MLKEM768),
        "{groups:?}"
    );
}
