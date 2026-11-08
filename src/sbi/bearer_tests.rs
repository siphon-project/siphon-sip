//! The static bearer token on the wire, in the header the configuration names.
use super::{SbiBearerHeader, SbiConfig, SbiManager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One request's head, as a loopback server received it, lower-cased.
async fn request_head(header: SbiBearerHeader, name: &str) -> String {
    let path = std::env::temp_dir().join(format!("sbi-bearer-{}-{name}", std::process::id()));
    std::fs::write(&path, "t0ken-value\n").expect("token file");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("one connection");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.expect("request bytes");
            head.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await
            .expect("response");
        String::from_utf8_lossy(&head).to_ascii_lowercase()
    });
    let manager = SbiManager::new(SbiConfig {
        bearer_token_file: Some(path.to_string_lossy().into_owned()),
        bearer_token_header: header,
        npcf_url: Some(format!("http://{address}")),
        ..SbiConfig::default()
    })
    .expect("manager");
    manager
        .client()
        .get(format!(
            "http://{address}/npcf-policyauthorization/v1/app-sessions"
        ))
        .send()
        .await
        .expect("request sent");
    let head = server.await.expect("server");
    let _ = std::fs::remove_file(&path);
    head
}

#[tokio::test]
async fn the_token_is_sent_in_authorization_by_default() {
    let head = request_head(SbiBearerHeader::Authorization, "authorization").await;
    assert!(
        head.contains("\r\nauthorization: bearer t0ken-value\r\n"),
        "{head}"
    );
    assert!(!head.contains("proxy-authorization"), "{head}");
}

#[tokio::test]
async fn a_token_for_the_scp_is_sent_in_proxy_authorization() {
    let head = request_head(SbiBearerHeader::ProxyAuthorization, "proxy").await;
    assert!(
        head.contains("\r\nproxy-authorization: bearer t0ken-value\r\n"),
        "{head}"
    );
    assert!(!head.contains("\r\nauthorization:"), "{head}");
}
