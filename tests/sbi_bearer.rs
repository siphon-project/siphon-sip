//! Static SBI bearer authentication, including wire-level NF client coverage.
#![allow(clippy::disallowed_methods)]
use siphon::{
    config::SbiYamlConfig,
    sbi::{
        nbsf::{BindingQuery, BsfClient},
        npcf::NpcfClient,
        SbiManager,
    },
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn parse(yaml: &str) -> SbiYamlConfig {
    serde_saphyr::from_str(yaml).unwrap()
}

fn token_file(value: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, value).unwrap();
    (dir, path.to_str().unwrap().to_owned())
}

#[test]
fn config_absent_present_and_expansion() {
    assert!(parse("{}").to_sbi_config().bearer_token_file.is_none());
    let expanded = siphon::config::expand_env_vars(
        "bearer_token_file: '${SBI_BEARER_TEST_UNSET:-/tmp/bearer}'",
    );
    assert_eq!(
        parse(&expanded)
            .to_sbi_config()
            .bearer_token_file
            .as_deref(),
        Some("/tmp/bearer")
    );
    let (_dir, path) = token_file(" \tvalid-._~+/09AZaz==\r\n");
    SbiManager::new(parse(&format!("bearer_token_file: '{path}'")).to_sbi_config()).unwrap();
}

#[test]
fn invalid_files_name_path_without_disclosing_token() {
    for value in [
        "",
        " \n",
        "secret bad",
        "secret\nbad",
        "secret:bad",
        "secreté",
        "=secret",
        "secret=bad",
        "===",
    ] {
        let (_dir, path) = token_file(value);
        let error = SbiManager::new(parse(&format!("bearer_token_file: '{path}'")).to_sbi_config())
            .unwrap_err();
        assert!(error.contains(&path), "{error}");
        assert!(!error.contains("secret"), "{error}");
    }
    let (_dir, path) = token_file("secret");
    std::fs::remove_file(&path).unwrap();
    let error = SbiManager::new(parse(&format!("bearer_token_file: '{path}'")).to_sbi_config())
        .unwrap_err();
    assert!(error.contains(&path), "{error}");
}

#[test]
fn transport_validation_for_every_peer() {
    let (_dir, path) = token_file("secret");
    for key in ["npcf_url", "bsf_url", "nchf_url", "nrf_url"] {
        for url in [
            "http://producer.example",
            "http://192.0.2.1",
            "http://[2001:db8::1]",
        ] {
            let config = parse(&format!("bearer_token_file: '{path}'\n{key}: '{url}'"));
            let error = SbiManager::new(config.to_sbi_config()).unwrap_err();
            assert!(error.contains(key) && error.contains("HTTPS"), "{error}");
            SbiManager::new(parse(&format!("{key}: '{url}'")).to_sbi_config()).unwrap();
        }
        for url in [
            "https://producer.example",
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://127.0.0.2",
            "http://[::1]",
        ] {
            SbiManager::new(
                parse(&format!("bearer_token_file: '{path}'\n{key}: '{url}'")).to_sbi_config(),
            )
            .unwrap();
        }
    }
}

#[test]
fn cached_token_and_debug_redaction() {
    let secret = "unique-secret-123";
    let (_dir, path) = token_file(secret);
    let yaml = parse(&format!("bearer_token_file: '{path}'"));
    let config = yaml.to_sbi_config();
    let manager = SbiManager::new(config.clone()).unwrap();
    std::fs::remove_file(&path).unwrap();
    let client = manager.client_with_timeout(Duration::from_secs(1)).unwrap();
    for debug in [
        format!("{yaml:?}"),
        format!("{config:?}"),
        format!("{manager:?}"),
        format!("{client:?}"),
    ] {
        assert!(!debug.contains(secret), "{debug}");
    }
}

#[tokio::test]
async fn wire_npcf_nbsf_defaults_explicit_override_and_cached_token() {
    for enabled in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (_dir, path) = token_file(" \tsecret-token==\n");
        let yaml = if enabled {
            format!("bearer_token_file: '{path}'\nnpcf_url: '{url}'\nbsf_url: '{url}'")
        } else {
            "{}".into()
        };
        let manager = SbiManager::new(parse(&yaml).to_sbi_config()).unwrap();
        std::fs::remove_file(path).unwrap();
        let bsf_http = manager.client_with_timeout(Duration::from_secs(2)).unwrap();
        let server = tokio::spawn(async move {
            for index in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut buffer = [0; 1024];
                    let read = socket.read(&mut buffer).await.unwrap();
                    assert_ne!(read, 0);
                    bytes.extend_from_slice(&buffer[..read]);
                    if bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
                let auth: Vec<_> = request
                    .lines()
                    .filter(|line| line.starts_with("authorization:"))
                    .collect();
                if index == 2 {
                    assert_eq!(auth, ["authorization: bearer explicit"]);
                } else if enabled {
                    assert_eq!(auth, ["authorization: bearer secret-token=="]);
                } else {
                    assert!(auth.is_empty());
                }
                if index == 0 {
                    assert!(request.starts_with(
                        "post /npcf-policyauthorization/v1/app-sessions/session/delete "
                    ));
                } else if index == 1 {
                    assert!(request.starts_with("get /nbsf-management/v1/pcfbindings?"));
                }
                socket
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        NpcfClient::new(&url, manager.client().clone())
            .delete_app_session("session")
            .await
            .unwrap();
        BsfClient::new(&url, bsf_http)
            .discover_binding(&BindingQuery::Ipv4("192.0.2.2".into()))
            .await
            .unwrap();
        manager
            .client()
            .get(&url)
            .bearer_auth("explicit")
            .send()
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
}
