//! Benchmark harness for `amneziawg-proxy`.
//!
//! Two modes, zero dependencies beyond the crate itself:
//!
//! ```text
//! # End-to-end loopback throughput through a real Proxy instance:
//! cargo run --release --example bench -- throughput \
//!     [--secs N] [--clients N] [--payload BYTES] [--window N] [--awg]
//!
//! # Userspace hot-path micro-benchmarks (classification, detection, padding):
//! cargo run --release --example bench -- hot-path
//! ```
//!
//! `throughput` spins up a UDP echo backend and a proxy on loopback, then
//! drives N concurrent clients with a fixed window of in-flight datagrams
//! each, reporting round trips/s, forwarded packets/s (each round trip
//! crosses the proxy twice), payload throughput, and loss. With `--awg` the
//! payloads are AmneziaWG-transport-shaped and the proxy runs with AWG
//! params, so the relay exercises classification + padding transform; without
//! it the proxy forwards verbatim (still paying probe detection per packet,
//! as in production).
//!
//! Numbers are loopback numbers: they overstate what a NIC will do but are
//! ideal for before/after comparisons of proxy changes (e.g. the Tier 1
//! batched-I/O work in doc/PERFORMANCE.md) on the same machine.

use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use amneziawg_proxy::config::{AwgParams, HRange, ProxyConfig};
use amneziawg_proxy::proxy::Proxy;
use amneziawg_proxy::responder::{classify_awg_packet, detect_protocol, Protocol};
use amneziawg_proxy::transform::apply_padding;
use tokio::net::UdpSocket;

/// AWG parameters used by both modes: S4 padding on transport data so the
/// data path exercises classification and the relay's padding transform.
fn bench_awg_params() -> AwgParams {
    AwgParams {
        jc: 4,
        jmin: 64,
        jmax: 256,
        s1: 64,
        s2: 44,
        s3: 24,
        s4: 32,
        h1: HRange {
            min: 0x1000_0000,
            max: 0x1000_ffff,
        },
        h2: HRange {
            min: 0x2000_0000,
            max: 0x2000_ffff,
        },
        h3: HRange {
            min: 0x3000_0000,
            max: 0x3000_ffff,
        },
        h4: HRange {
            min: 0x4000_0000,
            max: 0x4000_ffff,
        },
    }
}

/// Payload that `classify_awg_packet` recognises as TransportData under
/// [`bench_awg_params`]: S4 padding prefix, H4 header (LE), then body.
fn awg_transport_payload(params: &AwgParams, total_len: usize) -> Vec<u8> {
    let s4 = params.s4 as usize;
    let min_len = s4 + 32;
    let total_len = total_len.max(min_len);
    let mut pkt = vec![0u8; total_len];
    pkt[s4..s4 + 4].copy_from_slice(&params.h4.min.to_le_bytes());
    for (i, byte) in pkt[s4 + 4..].iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    pkt
}

/// Plain payload that no probe heuristic matches (zeros fail the QUIC, STUN,
/// strict-DNS, and SIP checks), mirroring opaque tunnel traffic.
fn plain_payload(total_len: usize) -> Vec<u8> {
    vec![0u8; total_len.max(12)]
}

struct ThroughputOpts {
    secs: u64,
    clients: usize,
    payload: usize,
    window: usize,
    awg: bool,
}

impl Default for ThroughputOpts {
    fn default() -> Self {
        Self {
            secs: 5,
            clients: 4,
            payload: 1200,
            window: 64,
            awg: false,
        }
    }
}

async fn spawn_echo_backend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind backend");
    let addr = sock.local_addr().expect("backend addr");
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    (addr, handle)
}

async fn run_throughput(opts: ThroughputOpts) {
    let (backend_addr, backend_handle) = spawn_echo_backend().await;

    let config = ProxyConfig {
        listen: "127.0.0.1:0".into(),
        backend: backend_addr.to_string(),
        // Quiet config: no QUIC responder ticking, status writes parked in
        // the temp dir (never the production status file) and effectively
        // disabled via a huge interval.
        quic_handshake_enabled: false,
        status_file: std::env::temp_dir()
            .join("amneziawg-proxy-bench-sessions.json")
            .display()
            .to_string(),
        status_interval_secs: 3600,
        // Decouple the harness from the relay-buffer default so oversized
        // --payload runs measure relaying, not truncation.
        relay_buffer_size: 65535,
        imitate_protocol: if opts.awg {
            "quic".into()
        } else {
            "auto".into()
        },
        ..ProxyConfig::default()
    };
    let awg_params = opts.awg.then(bench_awg_params);
    let payload = if let Some(ref params) = awg_params {
        awg_transport_payload(params, opts.payload)
    } else {
        plain_payload(opts.payload)
    };

    let proxy = Proxy::bind(config, awg_params).await.expect("bind proxy");
    let proxy_addr = proxy.local_addr().expect("proxy addr");
    let shutdown = proxy.shutdown_handle();
    let proxy_handle = tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    let stop_at = Instant::now() + Duration::from_secs(opts.secs);
    let total_rt = Arc::new(AtomicU64::new(0));
    let total_lost = Arc::new(AtomicU64::new(0));

    let mut clients = Vec::new();
    for _ in 0..opts.clients {
        let payload = payload.clone();
        let total_rt = Arc::clone(&total_rt);
        let total_lost = Arc::clone(&total_lost);
        let window = opts.window;
        clients.push(tokio::spawn(async move {
            let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
            sock.connect(proxy_addr).await.expect("connect client");
            let mut buf = vec![0u8; 65535];
            // Windowed echo loop: keep `window` datagrams in flight, refill
            // as echoes return. A short drain deadline per burst bounds the
            // cost of lost packets without stalling the pipeline.
            while Instant::now() < stop_at {
                for _ in 0..window {
                    let _ = sock.send(&payload).await;
                }
                let mut received = 0usize;
                let burst_deadline = Instant::now() + Duration::from_millis(200);
                while received < window {
                    let now = Instant::now();
                    if now >= burst_deadline {
                        break;
                    }
                    match tokio::time::timeout(burst_deadline - now, sock.recv(&mut buf)).await {
                        Ok(Ok(_)) => received += 1,
                        _ => break,
                    }
                }
                total_rt.fetch_add(received as u64, Ordering::Relaxed);
                total_lost.fetch_add((window - received) as u64, Ordering::Relaxed);
            }
        }));
    }

    let started = Instant::now();
    for client in clients {
        let _ = client.await;
    }
    let elapsed = started.elapsed().as_secs_f64();

    shutdown.shutdown();
    let _ = proxy_handle.await;
    backend_handle.abort();

    let rt = total_rt.load(Ordering::Relaxed);
    let lost = total_lost.load(Ordering::Relaxed);
    let rt_per_sec = rt as f64 / elapsed;
    // Each round trip crosses the proxy twice (client→backend, backend→client).
    let forwarded_pps = rt_per_sec * 2.0;
    let mbps = rt_per_sec * 2.0 * payload.len() as f64 * 8.0 / 1e6;
    let sent = rt + lost;
    let loss_pct = if sent > 0 {
        lost as f64 * 100.0 / sent as f64
    } else {
        0.0
    };

    println!("mode:            throughput (loopback echo)");
    println!(
        "config:          {} clients × window {}, payload {} B, awg transform: {}",
        opts.clients,
        opts.window,
        payload.len(),
        if opts.awg { "on" } else { "off" }
    );
    println!("duration:        {elapsed:.2} s");
    println!("round trips:     {rt}  ({rt_per_sec:.0}/s)");
    println!(
        "forwarded pkts:  {:.0}/s (2 proxy crossings per round trip)",
        forwarded_pps
    );
    println!("payload rate:    {mbps:.1} Mbit/s");
    println!("burst loss:      {lost} ({loss_pct:.2}%)");
}

/// Tight-loop micro-benchmark: warm up, then take the best of three timed
/// runs (best-of defends against scheduler noise; loopback comparisons only
/// need stable relative numbers).
fn bench_loop<F: FnMut()>(name: &str, iters: u64, mut f: F) {
    for _ in 0..iters / 10 {
        f();
    }
    let mut best = f64::INFINITY;
    for _ in 0..3 {
        let start = Instant::now();
        for _ in 0..iters {
            f();
        }
        let ns = start.elapsed().as_nanos() as f64 / iters as f64;
        if ns < best {
            best = ns;
        }
    }
    println!("{name:<44} {best:>9.1} ns/op");
}

fn run_hot_path() {
    let params = bench_awg_params();
    let transport = awg_transport_payload(&params, 1200);
    let junk = {
        // Random-ish junk that classifies as nothing (no H-range match, no
        // probe protocol).
        let mut pkt = vec![0u8; 160];
        for (i, byte) in pkt.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(167).wrapping_add(13) | 0x80;
        }
        pkt
    };
    let dns_query: Vec<u8> = {
        let mut pkt = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        pkt.extend_from_slice(b"\x03www\x07example\x03com\x00");
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        pkt
    };
    let quic_initial: Vec<u8> = {
        let mut pkt = vec![0xC3, 0x00, 0x00, 0x00, 0x01, 0x08];
        pkt.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        pkt.push(0);
        pkt
    };

    println!("userspace hot-path costs (per packet):");
    bench_loop("classify_awg_packet / transport hit", 2_000_000, || {
        black_box(classify_awg_packet(black_box(&transport), &params));
    });
    bench_loop("classify_awg_packet / junk miss", 2_000_000, || {
        black_box(classify_awg_packet(black_box(&junk), &params));
    });
    bench_loop(
        "detect_protocol / junk (probe path miss)",
        2_000_000,
        || {
            black_box(detect_protocol(black_box(&junk)));
        },
    );
    bench_loop("detect_protocol / strict DNS query", 2_000_000, || {
        black_box(detect_protocol(black_box(&dns_query)));
    });
    bench_loop("detect_protocol / QUIC initial", 2_000_000, || {
        black_box(detect_protocol(black_box(&quic_initial)));
    });

    let mut padded = vec![0u8; 1200];
    for proto in [Protocol::Quic, Protocol::Dns, Protocol::Stun, Protocol::Sip] {
        bench_loop(
            &format!("apply_padding / {proto} (pad 64, 1200 B)"),
            1_000_000,
            || {
                apply_padding(black_box(&mut padded), 64, proto);
            },
        );
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: bench <throughput|hot-path> [--secs N] [--clients N] [--payload BYTES] [--window N] [--awg]"
    );
    std::process::exit(2);
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "throughput".into());
    let mut opts = ThroughputOpts::default();
    while let Some(arg) = args.next() {
        let numeric = |args: &mut dyn Iterator<Item = String>| -> u64 {
            args.next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| usage())
        };
        match arg.as_str() {
            "--secs" => opts.secs = numeric(&mut args),
            "--clients" => opts.clients = numeric(&mut args) as usize,
            "--payload" => opts.payload = numeric(&mut args) as usize,
            "--window" => opts.window = numeric(&mut args) as usize,
            "--awg" => opts.awg = true,
            _ => usage(),
        }
    }

    match mode.as_str() {
        "hot-path" => run_hot_path(),
        "throughput" => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            runtime.block_on(run_throughput(opts));
        }
        _ => usage(),
    }
}
