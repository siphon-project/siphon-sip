//! The Redis layer of a named cache across a dropped link.
//!
//! A [`LinkCutter`] sits between the cache and the server named by
//! `SIPHON_TEST_REDIS_URL`: cutting it resets every open connection and
//! refuses new ones, which is what a server restart looks like from the
//! client. Skipped when the variable is unset.

use std::time::{Duration, Instant};

use super::*;
use crate::registrar::backend::link_cutter::LinkCutter;

fn unique(test: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("cache_test:{test}:{}:{nanos}", std::process::id())
}

/// A relay in front of the test server, and the URL that goes through it.
async fn relay() -> Option<(LinkCutter, String)> {
    let url = match std::env::var("SIPHON_TEST_REDIS_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("skipped: SIPHON_TEST_REDIS_URL is not set");
            return None;
        }
    };
    let (scheme, rest) = url.split_once("://").expect("a URL with a scheme");
    let (authority, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None => (rest, ""),
    };
    let (userinfo, upstream) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (format!("{userinfo}@"), host_port),
        None => (String::new(), authority),
    };
    let cutter = LinkCutter::start(upstream.to_string()).await;
    let relayed = format!("{scheme}://{userinfo}{}{path}", cutter.address());
    Some((cutter, relayed))
}

fn redis_only(name: &str, url: String) -> NamedCacheConfig {
    NamedCacheConfig {
        name: name.to_string(),
        target: url.into(),
        local_ttl_secs: None,
        local_max_entries: None,
        required_for_readiness: true,
    }
}

/// Poll `condition` for up to ten seconds.
async fn eventually(what: &str, condition: impl Fn() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never happened: {what}");
}

/// The spec case: the server goes away and comes back under a running node.
/// Fetches fail while it is gone, at once and counted; the gauge and the
/// readiness probe follow it down and, with no command issued, back up; and
/// the cache answers again without being rebuilt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cache_follows_its_server_down_and_back_up_without_a_restart() {
    let Some((cutter, url)) = relay().await else {
        return;
    };
    let name = "redis_tests_outage";
    let manager = std::sync::Arc::new(CacheManager::new(&[redis_only(name, url)]));
    let participants = crate::lifecycle::Participants::default();
    manager.watch_backends(&participants);
    let key = unique("outage");

    eventually("ready once the first probe answered", || {
        participants.not_ready_reason().is_none()
    })
    .await;
    assert!(crate::metrics::cache::backend_up(name));
    assert!(manager.store(name, &key, "aor", Some(60)).await);
    assert_eq!(manager.fetch(name, &key).await.as_deref(), Some("aor"));
    assert_eq!(crate::metrics::cache::errors(name, "get"), 0);

    cutter.cut();
    assert_eq!(manager.fetch(name, &key).await, None);
    assert!(crate::metrics::cache::errors(name, "get") >= 1);
    eventually("not ready while the server is gone", || {
        participants.not_ready_reason().is_some()
    })
    .await;
    assert_eq!(
        participants.not_ready_reason().as_deref(),
        Some("cache 'redis_tests_outage': Redis backend unreachable")
    );
    assert!(!crate::metrics::cache::backend_up(name));

    // A burst against a server that is known to be gone is answered at once:
    // no command waits on a redial of its own.
    let before = crate::metrics::cache::errors(name, "get");
    let started = Instant::now();
    let burst = futures_util::future::join_all((0..200).map(|_| manager.fetch(name, &key))).await;
    assert!(burst.iter().all(Option::is_none));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "200 fetches against a down backend took {:?}",
        started.elapsed()
    );
    assert_eq!(crate::metrics::cache::errors(name, "get"), before + 200);
    assert!(!manager.store(name, &key, "other", Some(60)).await);
    assert!(crate::metrics::cache::errors(name, "set") >= 1);

    cutter.restore();
    // No command is issued here: the monitor alone finds the server again.
    eventually("ready again once the server answers", || {
        participants.not_ready_reason().is_none()
    })
    .await;
    assert!(crate::metrics::cache::backend_up(name));
    assert_eq!(manager.fetch(name, &key).await.as_deref(), Some("aor"));
    assert!(manager.delete(name, &key).await);
}

/// A command issued on a connection that died while idle is retried once on a
/// new one, so it succeeds when the server is already back. Idempotent
/// commands only: `GET`, `SET`/`SETEX`, `DEL`, `EXISTS`, `EXPIRE`, `LLEN`,
/// `SCAN`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_command_on_a_dead_connection_is_retried_once_after_the_redial() {
    let Some((cutter, url)) = relay().await else {
        return;
    };
    // No monitor: nothing but the command itself can notice the dead link.
    let name = "redis_tests_retry";
    let manager = CacheManager::new(&[redis_only(name, url)]);
    let key = unique("retry");
    assert!(manager.store(name, &key, "one", Some(60)).await);

    for (round, value) in ["two", "three", "four", "five"].into_iter().enumerate() {
        cutter.cut();
        cutter.restore();
        match round {
            0 => assert!(manager.fetch(name, &key).await.is_some(), "GET"),
            1 => assert!(manager.store(name, &key, value, Some(60)).await, "SETEX"),
            2 => assert!(manager.exists(name, &key).await, "EXISTS"),
            _ => assert!(manager.expire(name, &key, 60).await, "EXPIRE"),
        }
    }
    cutter.cut();
    cutter.restore();
    assert!(manager.delete(name, &key).await, "DEL");
    assert_eq!(manager.fetch(name, &key).await, None);
    assert_eq!(crate::metrics::cache::errors(name, "get"), 0);
    assert_eq!(crate::metrics::cache::errors(name, "set"), 0);
}

/// `RPUSH` and the read-and-delete of `list_pop_all` are not idempotent, so
/// they are never replayed: on a dead connection they fail once, reported to
/// the caller, and the next one runs on the connection redialled meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_writes_on_a_dead_connection_fail_once_and_are_not_replayed() {
    let Some((cutter, url)) = relay().await else {
        return;
    };
    let name = "redis_tests_lists";
    let manager = CacheManager::new(&[redis_only(name, url)]);
    let key = unique("lists");
    assert_eq!(manager.list_push(name, &key, "first").await, Some(1));

    cutter.cut();
    cutter.restore();
    assert_eq!(manager.list_push(name, &key, "lost").await, None);
    assert_eq!(crate::metrics::cache::errors(name, "rpush"), 1);
    assert_eq!(manager.list_push(name, &key, "second").await, Some(2));

    cutter.cut();
    cutter.restore();
    assert!(manager.list_pop_all(name, &key).await.is_empty());
    assert_eq!(crate::metrics::cache::errors(name, "pop_all"), 1);
    assert_eq!(manager.list_len(name, &key).await, Some(2), "nothing lost");
    assert_eq!(
        manager.list_pop_all(name, &key).await,
        vec!["first".to_string(), "second".to_string()]
    );
}

/// A server that is not there when the node starts: not ready, and ready as
/// soon as it is, with the cache never used in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cache_whose_server_is_down_at_start_becomes_ready_when_it_appears() {
    let Some((cutter, url)) = relay().await else {
        return;
    };
    cutter.cut();
    let name = "redis_tests_late";
    let manager = std::sync::Arc::new(CacheManager::new(&[redis_only(name, url)]));
    let participants = crate::lifecycle::Participants::default();
    manager.watch_backends(&participants);
    assert!(participants.not_ready_reason().is_some(), "not checked yet");
    eventually("the first probe fails", || {
        participants.not_ready_reason().as_deref()
            == Some("cache 'redis_tests_late': Redis backend unreachable")
    })
    .await;
    assert!(!crate::metrics::cache::backend_up(name));

    cutter.restore();
    eventually("ready once the server is there", || {
        participants.not_ready_reason().is_none()
    })
    .await;
    assert!(crate::metrics::cache::backend_up(name));
}
