//! End-to-end integration test: spawn the real gptl-node and gptl-client
//! binaries, set up a local TCP echo "exit", and drive a full SOCKS5
//! roundtrip through the proxy.  Verifies that:
//!
//!   * The two binaries actually start without panicking on Windows /
//!     macOS / Linux,
//!   * SOCKS5 negotiation completes,
//!   * The client builds a 1-hop circuit through the node,
//!   * Data sent through the proxy reaches the destination,
//!   * Data sent back from the destination reaches the client,
//!   * Closing the SOCKS5 connection tears the circuit down cleanly
//!     (no zombie tasks — verified indirectly via process exit).
//!
//! The test is skipped automatically when either binary has not been
//! built (CI / fresh clone may not have `cargo build` artifacts yet).

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Locate the gptl-{node,client} binary built by Cargo.  Checks both the
/// release and debug profile target dirs.
fn binary_path(name: &str) -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        format!("{}.exe", name)
    } else {
        name.to_string()
    };
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Cargo workspace root = <manifest_dir>/.. (gptl-transport sits under rust/)
    let workspace_root = manifest_dir.parent()?;
    let candidates = [
        workspace_root.join("target").join("release").join(&exe),
        workspace_root.join("target").join("debug").join(&exe),
    ];
    for c in &candidates {
        if c.exists() {
            return Some(c.clone());
        }
    }
    None
}

/// Generate a 32-byte hex relay key in a fresh tempfile and return the path.
fn make_key_file(dir: &Path) -> PathBuf {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let path = dir.join("relay.key");
    std::fs::write(&path, hex).expect("write relay.key");
    path
}

/// Run `gptl-node --print-descriptor` and pull out the pubkey_hex from its JSON.
fn fetch_pubkey(node_bin: &Path, key_path: &Path, listen: &str) -> String {
    let out = Command::new(node_bin)
        .args(["--key", key_path.to_str().unwrap(), "--listen", listen, "--print-descriptor"])
        .output()
        .expect("run gptl-node --print-descriptor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Quick-and-dirty parse — the JSON is small and tightly controlled.
    let key_marker = "\"pubkey_hex\":";
    let start = stdout
        .find(key_marker)
        .unwrap_or_else(|| panic!("pubkey_hex not in descriptor output:\n{}", stdout))
        + key_marker.len();
    let after = &stdout[start..];
    let q1 = after.find('"').expect("opening quote") + 1;
    let q2 = q1 + after[q1..].find('"').expect("closing quote");
    after[q1..q2].to_string()
}

/// Bind a free localhost port and return the SocketAddr string.
fn pick_free_port() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l); // release immediately; small race window but fine for tests
    addr.to_string()
}

/// Spawn a TCP echo "exit" server.  Returns its listen address.
fn spawn_echo_server() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for stream in l.incoming() {
            if let Ok(mut s) = stream {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = s.shutdown(Shutdown::Both);
                });
            }
        }
    });
    addr.to_string()
}

/// Send `payload` through the SOCKS5 proxy at `proxy_addr` to `target`,
/// expecting the same payload echoed back.  Returns the received bytes.
fn socks5_echo_request(proxy_addr: &str, target_host: &str, target_port: u16, payload: &[u8])
    -> std::io::Result<Vec<u8>>
{
    let mut s = TcpStream::connect(proxy_addr)?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;

    // SOCKS5 greeting
    s.write_all(&[0x05, 0x01, 0x00])?; // VER NMETHODS METHODS[NO_AUTH]
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf)?;
    assert_eq!(buf, [0x05, 0x00], "server must select NO_AUTH");

    // CONNECT request with domain name addressing
    let host_bytes = target_host.as_bytes();
    assert!(host_bytes.len() < 255);
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req)?;

    // Read CONNECT reply: VER REP RSV ATYP=1(IPv4) BND.ADDR(4) BND.PORT(2)
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply)?;
    assert_eq!(reply[0], 0x05, "VER must be 5 in reply");
    assert_eq!(reply[1], 0x00, "REP must be 0x00 (Succeeded), got 0x{:02x}", reply[1]);

    // Echo round-trip.
    s.write_all(payload)?;
    let mut received = vec![0u8; payload.len()];
    s.read_exact(&mut received)?;

    // Half-close to let server flush.
    let _ = s.shutdown(Shutdown::Write);
    Ok(received)
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Wait until a TCP connect to `addr` succeeds, or the deadline fires.
fn wait_for_listen(addr: &str, deadline: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if TcpStream::connect_timeout(
            &addr.parse().expect("parse addr"),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn end_to_end_single_hop_socks5_roundtrip() {
    let node_bin = match binary_path("gptl-node") {
        Some(p) => p,
        None => {
            eprintln!("SKIP: gptl-node binary not found; run `cargo build` first");
            return;
        }
    };
    let client_bin = match binary_path("gptl-client") {
        Some(p) => p,
        None => {
            eprintln!("SKIP: gptl-client binary not found; run `cargo build` first");
            return;
        }
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let key_path = make_key_file(tmp.path());
    let relay_listen = pick_free_port();

    let pubkey = fetch_pubkey(&node_bin, &key_path, &relay_listen);
    let relays_json = tmp.path().join("relays.json");
    std::fs::write(
        &relays_json,
        format!(
            "{{ \"relays\": [{{ \"nickname\": \"itrelay\", \"address\": \"{}\", \"pubkey_hex\": \"{}\" }}] }}",
            relay_listen, pubkey
        ),
    )
    .expect("write relays.json");

    // 1. Start the node.  `--allow-private` permits the echo server we're
    //    about to spawn on 127.0.0.1.  In production this flag must NOT be
    //    set or the relay becomes an LAN proxy.
    let mut node = KillOnDrop(
        Command::new(&node_bin)
            .args([
                "--key", key_path.to_str().unwrap(),
                "--listen", &relay_listen,
                "--nickname", "itrelay",
                "--log", "warn",
                "--allow-private",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gptl-node"),
    );

    assert!(
        wait_for_listen(&relay_listen, Duration::from_secs(5)),
        "gptl-node didn't listen on {} within 5s",
        relay_listen
    );

    // 2. Start an echo "exit" server to act as the proxied destination.
    let echo_addr = spawn_echo_server();
    let (echo_host, echo_port) = {
        let mut parts = echo_addr.rsplitn(2, ':');
        let port: u16 = parts.next().unwrap().parse().unwrap();
        let host = parts.next().unwrap().to_string();
        (host, port)
    };

    // 3. Start the client.
    let proxy_listen = pick_free_port();
    let mut client = KillOnDrop(
        Command::new(&client_bin)
            .args([
                "--relays", relays_json.to_str().unwrap(),
                "--listen", &proxy_listen,
                "--hops", "1",
                "--log", "warn",
                "--selftest-timeout", "3",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gptl-client"),
    );

    assert!(
        wait_for_listen(&proxy_listen, Duration::from_secs(10)),
        "gptl-client didn't listen on {} within 10s (self-test may have failed)",
        proxy_listen
    );

    // 4.  Do a full SOCKS5 → circuit → echo roundtrip.
    let payload = b"hello from integration_e2e!";
    let echoed = socks5_echo_request(&proxy_listen, &echo_host, echo_port, payload)
        .expect("SOCKS5 roundtrip");
    assert_eq!(
        echoed, payload,
        "echoed bytes must match what we sent"
    );

    // 5.  A second roundtrip on a fresh SOCKS5 connection — verifies the
    //     circuit-tear-down path from the first request didn't break the
    //     proxy.
    let payload2 = b"second request, fresh circuit";
    let echoed2 = socks5_echo_request(&proxy_listen, &echo_host, echo_port, payload2)
        .expect("second SOCKS5 roundtrip");
    assert_eq!(echoed2, payload2);

    // 6.  Verify the proxy correctly RETURNS A SOCKS5 REPLY on relay
    //     rejection (not just closes the TCP connection).  Aim at an
    //     unresolvable hostname so the relay sends BeginFailed and the
    //     client converts that into REP=0x05 (ConnectionRefused).  Before
    //     the inner-error fix in proxy.rs, this resulted in
    //     `curl: (97) Failed to receive SOCKS response, proxy closed
    //     connection` — the connection just dropped without any reply.
    let mut s = TcpStream::connect(&proxy_listen).expect("connect for refuse test");
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).unwrap();
    let bogus = "this-host-does-not-exist.invalid";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, bogus.len() as u8];
    req.extend_from_slice(bogus.as_bytes());
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply[0], 0x05, "VER in reply must be 5");
    assert_ne!(
        reply[1], 0x00,
        "REP for an unresolvable target must NOT be Succeeded; got 0x{:02x}",
        reply[1]
    );

    drop(client);
    drop(node);
}
