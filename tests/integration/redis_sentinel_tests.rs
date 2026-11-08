//! Real Redis/Sentinel processes; no external service is required.
use redis::AsyncCommands;
use siphon::redis_target::{RedisConnection, RedisTarget};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Processes {
    children: Vec<Child>,
    directory: tempfile::TempDir,
}
impl Drop for Processes {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Processes {
    fn start(&mut self, port: u16, extra: &str, sentinel: bool) {
        let path = self.directory.path().join(format!("{port}.conf"));
        std::fs::write(&path, format!("port {port}\nbind 127.0.0.1\nprotected-mode no\nsave \"\"\nappendonly no\ndir {}\n{extra}\n", self.directory.path().display())).unwrap();
        let mut command = Command::new("/usr/bin/redis-server");
        command.arg(path);
        if sentinel {
            command.arg("--sentinel");
        }
        self.children.push(
            command
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
}
async fn direct(port: u16) -> redis::aio::MultiplexedConnection {
    let client = redis::Client::open(format!("redis://127.0.0.1:{port}")).unwrap();
    loop {
        if let Ok(connection) = client.get_multiplexed_async_connection().await {
            return connection;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// Control-plane probes may reconnect during failover; the two clients under
// test below must retain their pre-failover connections until their writes.
async fn probe_connection(port: u16) -> redis::RedisResult<redis::aio::MultiplexedConnection> {
    redis::Client::open(format!("redis://127.0.0.1:{port}"))?
        .get_multiplexed_async_connection_with_config(
            &redis::AsyncConnectionConfig::new()
                .set_connection_timeout(Some(Duration::from_millis(500)))
                .set_response_timeout(Some(Duration::from_millis(500))),
        )
        .await
}

async fn wait_for_new_primary(ports: &[u16]) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let mut converged = true;
            for port in &ports[2..] {
                let observed: redis::RedisResult<Option<(String, u16)>> = async {
                    let mut probe = probe_connection(*port).await?;
                    redis::cmd("SENTINEL").arg("GET-MASTER-ADDR-BY-NAME")
                        .arg("primary").query_async(&mut probe).await
                }.await;
                converged &= matches!(observed, Ok(Some((host, port))) if host == "127.0.0.1" && port == ports[1]);
            }
            // Sentinel can announce the new primary before the old node has
            // become read-only. Fresh probes avoid failing on a control socket
            // that Redis closed during reconfiguration.
            for (port, role) in [(ports[0], "role:slave"), (ports[1], "role:master")] {
                let observed: redis::RedisResult<String> = async {
                    let mut probe = probe_connection(port).await?;
                    redis::cmd("INFO").arg("replication").query_async(&mut probe).await
                }.await;
                converged &= observed.is_ok_and(|info| info.lines().any(|line| line == role));
            }
            if converged { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await.expect("Sentinels and data-node roles did not converge within 20 seconds");
}

#[tokio::test]
async fn next_write_recovers_after_sentinel_failover() {
    if !Path::new("/usr/bin/redis-server").exists() {
        eprintln!("SKIP next_write_recovers_after_sentinel_failover: /usr/bin/redis-server absent");
        return;
    }
    tokio::time::timeout(Duration::from_secs(45), async {
        // Hold reservations together so every chosen port is distinct.
        let reservations: Vec<_> = (0..5).map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap()).collect();
        let ports: Vec<_> = reservations.iter().map(|listener| listener.local_addr().unwrap().port()).collect();
        drop(reservations);
        let mut processes = Processes { children: Vec::new(), directory: tempfile::tempdir().unwrap() };
        processes.start(ports[0], "", false);
        processes.start(ports[1], &format!("replicaof 127.0.0.1 {}", ports[0]), false);
        let mut primary = direct(ports[0]).await;
        let mut replica = direct(ports[1]).await;
        for port in &ports[2..] {
            processes.start(*port, &format!("sentinel monitor primary 127.0.0.1 {} 2\nsentinel down-after-milliseconds primary 1000\nsentinel failover-timeout primary 5000", ports[0]), true);
        }
        let mut sentinel = direct(ports[2]).await;
        loop {
            let info: String = redis::cmd("INFO").arg("replication").query_async(&mut replica).await.unwrap();
            let replicas: Vec<redis::Value> = redis::cmd("SENTINEL").arg("REPLICAS").arg("primary").query_async(&mut sentinel).await.unwrap();
            let peers: Vec<redis::Value> = redis::cmd("SENTINEL").arg("SENTINELS").arg("primary").query_async(&mut sentinel).await.unwrap();
            if info.contains("master_link_status:up") && replicas.len() == 1 && peers.len() == 2 { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let yaml = format!("sentinel:\n  master: primary\n  addresses: [127.0.0.1:{}, 127.0.0.1:{}, 127.0.0.1:{}]", ports[2], ports[3], ports[4]);
        let target: RedisTarget = serde_saphyr::from_str(&yaml).unwrap();
        let mut connection = RedisConnection::connect(target).await.unwrap();
        let mut pipeline_connection = RedisConnection::connect(serde_saphyr::from_str(&yaml).unwrap()).await.unwrap();
        let _: () = connection.set("before", "first").await.unwrap();
        let _: i64 = redis::cmd("WAIT").arg(1).arg(3000).query_async(&mut primary).await.unwrap();
        // Sentinel refuses a failover with NOGOODSLAVE until it has refreshed
        // the replica's state on its own INFO period, which can lag the
        // replica's link coming up. Any other refusal is a failure.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let refused: redis::RedisResult<()> =
                redis::cmd("SENTINEL").arg("FAILOVER").arg("primary").query_async(&mut sentinel).await;
            match refused {
                Ok(()) => break,
                Err(error) if error.to_string().contains("NOGOODSLAVE") && std::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
                Err(error) => panic!("SENTINEL FAILOVER refused: {error}"),
            }
        }
        wait_for_new_primary(&ports).await;
        // Exactly one caller operation, using the connection opened before failover.
        let _: () = connection.set("after", "second").await.unwrap();
        let _: () = redis::pipe().atomic().set("pipeline-after", "third").ignore()
            .query_async(&mut pipeline_connection).await.unwrap();
        let mut replica = probe_connection(ports[1]).await.expect("connect to promoted primary for verification");
        assert_eq!(replica.get::<_, String>("pipeline-after").await.unwrap(), "third");
        assert_eq!(replica.get::<_, String>("after").await.unwrap(), "second");
        assert_eq!(replica.get::<_, String>("before").await.unwrap(), "first");
    }).await.expect("Sentinel failover test exceeded 45 seconds");
}
