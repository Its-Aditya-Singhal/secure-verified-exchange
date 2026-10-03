//! Post-quantum TLS: the release client offers the hybrid X25519MLKEM768
//! key exchange first, with a key share, so a TLS server that supports it
//! (svx-server and svx-keyagent do) negotiates it without a retry. A
//! recorded release connection can then not be decrypted later by a
//! quantum computer, independently of SVX's own X-Wing release sealing.

use rustls::NamedGroup;
use rustls::server::Acceptor;
use svx_protocol::ManagedClient;
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;

#[tokio::test]
async fn release_client_offers_post_quantum_key_exchange_first() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let start = LazyConfigAcceptor::new(Acceptor::default(), tcp)
            .await
            .unwrap();
        start.client_hello().named_groups().map(<[_]>::to_vec)
    });
    // The handshake can't finish (this server has no certificate); only the
    // client's offer matters here.
    let client = ManagedClient::new(false).unwrap();
    let _ = client
        .http()
        .get(format!("https://127.0.0.1:{port}/v1/service"))
        .send()
        .await;
    let groups = server.await.unwrap().expect("client offers named groups");
    assert_eq!(groups.first(), Some(&NamedGroup::X25519MLKEM768));
    assert!(groups.contains(&NamedGroup::X25519));
}
