//! TLS to a Redis target: real rustls handshakes against an in-process
//! server that speaks enough of the Redis protocol to answer a SET.
use super::*;
use crate::transport::outbound_tls::tests::{dns, ip, leaf, test_ca, Leaf, TestCa};
use redis::AsyncCommands;

/// A TLS listener on 127.0.0.1 serving `leaf`; returns its port.
async fn serve(leaf: &Leaf) -> u16 {
    let acceptor = leaf.acceptor();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(stream) = acceptor.accept(tcp).await {
                    super::tests::serve(stream, "+OK\r\n").await;
                }
            });
        }
    });
    port
}

fn ca_file(ca: &TestCa) -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ca.pem");
    std::fs::write(&path, ca.pem()).unwrap();
    let path = path.to_str().unwrap().to_string();
    (directory, path)
}

async fn set(url: String) -> RedisResult<()> {
    let mut connection = RedisConnection::connect(RedisTarget::Url(url)).await?;
    connection.set::<_, _, ()>("key", "value").await
}

fn refusal(result: RedisResult<()>) -> String {
    format!("{:?}", result.expect_err("the connection must be refused"))
}

#[tokio::test]
async fn a_certificate_from_the_given_ca_is_accepted_by_ip_and_by_name() {
    let ca = test_ca("Redis Test CA");
    let (_directory, path) = ca_file(&ca);
    let port = serve(&leaf(&ca, vec![ip("127.0.0.1"), dns("localhost")])).await;
    set(format!("rediss://127.0.0.1:{port}?ca_file={path}"))
        .await
        .expect("an IP subjectAltName the CA signed");
    set(format!("rediss://localhost:{port}/0?ca_file={path}"))
        .await
        .expect("a DNS subjectAltName the CA signed");
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_refused() {
    let (_directory, path) = ca_file(&test_ca("Redis Test CA"));
    let other = test_ca("Another Test CA");
    let port = serve(&leaf(&other, vec![ip("127.0.0.1")])).await;
    let error = refusal(set(format!("rediss://127.0.0.1:{port}?ca_file={path}")).await);
    // The test CAs share a subject name, so the chain is found and its
    // signature fails; a CA of another name is an unknown issuer.
    assert!(
        error.contains("BadSignature") || error.contains("UnknownIssuer"),
        "{error}"
    );
}

#[tokio::test]
async fn a_certificate_for_another_host_is_refused() {
    let ca = test_ca("Redis Test CA");
    let (_directory, path) = ca_file(&ca);
    let names = vec![dns("valkey.example.invalid"), ip("192.0.2.10")];
    let port = serve(&leaf(&ca, names)).await;
    for host in ["127.0.0.1", "localhost"] {
        let error = refusal(set(format!("rediss://{host}:{port}?ca_file={path}")).await);
        assert!(error.contains("not valid for name"), "{host}: {error}");
    }
}

#[tokio::test]
async fn without_a_ca_file_a_private_ca_is_refused() {
    let ca = test_ca("Redis Test CA");
    let port = serve(&leaf(&ca, vec![ip("127.0.0.1")])).await;
    let error = refusal(set(format!("rediss://127.0.0.1:{port}")).await);
    assert!(error.contains("UnknownIssuer"), "{error}");
}

#[tokio::test]
async fn verification_cannot_be_switched_off() {
    let ca = test_ca("Redis Test CA");
    let (_directory, path) = ca_file(&ca);
    let other = test_ca("Another Test CA");
    let port = serve(&leaf(&other, vec![ip("127.0.0.1")])).await;
    for url in [
        format!("rediss://127.0.0.1:{port}#insecure"),
        format!("rediss://127.0.0.1:{port}?ca_file={path}#insecure"),
    ] {
        assert!(set(url.clone()).await.is_err(), "{url}");
    }
}

#[tokio::test]
async fn a_ca_file_that_cannot_be_used_fails_the_connect() {
    let ca = test_ca("Redis Test CA");
    let port = serve(&leaf(&ca, vec![ip("127.0.0.1")])).await;
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.pem");
    let missing = missing.to_str().unwrap();
    let error = refusal(set(format!("rediss://127.0.0.1:{port}?ca_file={missing}")).await);
    assert!(error.contains(missing), "{error}");
    let (_directory, path) = ca_file(&ca);
    let error = refusal(set(format!("redis://127.0.0.1:{port}?ca_file={path}")).await);
    assert!(error.contains("rediss://"), "{error}");
}
