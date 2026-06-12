# Performance Review — `amneziawg-proxy` hot path

_Scope: packet forwarding and protocol-imitation paths. Goal: identify remaining
avoidable runtime cost (CPU, allocation, locking, syscalls, tasks, timers) and
propose concrete, behavior-preserving optimizations with expected impact and
risk._

## Status

Implemented (see the summary table at the bottom for the rest):

- **Tier 2D** — per-session relay buffers are sized by the new
  `relay_buffer_size` option (default 8 KiB, was 64 KiB from `buffer_size`):
  ~640 MB → ~80 MB of relay memory at `max_sessions = 10k`.
- **Auto-mode outbound lookup** — the relay caches the client's protocol lock
  once observed (the lock is insert-once per client), removing the per-packet
  `client_protocols` DashMap read from the outbound path in `auto` mode.

Tier 1 (batched I/O, multi-core scaling) is deliberately **gated on profiling**
— run the plan below on the production host first.

## Headline

After the recent optimization rounds the **userspace per-packet path is already
lean**. In fixed non-DNS mode, steady-state forwarding does **zero heap
allocations, zero per-packet task spawns, and zero locks held across `.await`**,
with two inbound DashMap reads and zero outbound ones.

In **`auto` mode** (the common deployment) inbound adds a third read — the
`dns_active` protocol check consults `client_protocols` per packet — and
outbound added one until the relay-side cache landed (it now does at most one
read per session before the lock is observed, then zero).

The proxy is "expensive under load" because it is **syscall-bound and
single-core-bound on the inbound path**, not because of avoidable userspace
work. The remaining meaningful gains are structural I/O changes, not
micro-optimizations.

## What the per-packet path costs today

**Inbound** (`handle_client_packet`), per data packet:

1. `metrics.get_or_create` — 1 DashMap read + `Arc` clone
2. `record_in` — relaxed atomic
3. `classify_awg_packet` — 4-candidate scan (cheap, no alloc)
4. `dns_active` — static compare in fixed mode (no lookup); **in `auto` mode
   this is a third DashMap read per packet** (`client_protocols`) — removable
   only by the Tier 2C consolidation, since `handle_client_packet` keeps no
   per-client state between calls
5. `sessions.get_or_create` — 1 DashMap read + atomic touch + `Arc` clone
6. `forward_to_backend` — **1 `send()` syscall**

**Outbound** (relay loop), per data packet:

1. `backend_sock.recv()` — **1 syscall**
2. protocol resolution — fixed mode: static; `auto` mode: cached in the relay
   once the insert-once protocol lock is first observed (at most one DashMap
   read per session before that, zero after)
3. `apply_awg_transform` — `classify_awg_packet` + PRNG padding fill (in-place, no alloc)
4. `record_out` — cached `Arc`, atomics only (deliberately no session
   keep-alive on this path: only client packets refresh the TTL)
5. `send_to_client` — **1 `send_to()` syscall**

**Per forwarded round trip: 4 syscalls, 2 DashMap reads (both inbound), 0
allocations.** At ~1–3 µs/syscall and ~90k pps/direction (1 Gbps @ 1400 B),
the 4 syscalls cost roughly **0.4–1.1 s of CPU per wall-clock second** — most of
one core spent crossing the kernel boundary. Everything in userspace is small
next to that.

---

## Tier 1 — structural, high impact

These are the only changes that move throughput meaningfully.

### A. Batch the syscalls: `recvmmsg`/`sendmmsg` + GSO/GRO

The single biggest lever. Reading/writing N datagrams per syscall instead of one
cuts the dominant cost by the batch factor; on Linux, UDP **GRO** (`UDP_GRO`)
coalesces RX and **GSO** (`UDP_SEGMENT`) fans out TX further.

- **Where:** the frontend listener first — the single busiest socket (all
  clients' inbound). Replace `recv_from` in the run loop with a batched read,
  process the batch, batch the corresponding backend sends.
- **How:** `quinn-udp` (same ecosystem as the existing `quinn-proto` dependency)
  provides portable GSO/GRO + `sendmmsg`/`recvmmsg` with runtime feature
  detection and graceful fallback — avoids hand-rolling `libc`.
- **Expected impact:** 2–4× throughput per core for syscall-bound UDP
  forwarding (well-documented for quinn/quiche). **High.**
- **Risk:** Medium–high. Changes the I/O layer (not the wire bytes). Must
  preserve per-source ordering within a batch (process sequentially per
  `client_addr`; already forwarded immediately, so this holds). Needs careful
  testing; behavior-preserving if done right.

### B. `SO_REUSEPORT` × N inbound receive loops

The entire inbound direction is one task on one core. On a multi-core host that
is a hard ceiling regardless of batching.

- **How:** bind N frontend sockets with `SO_REUSEPORT`, run N copies of the
  receive loop (one per core). The kernel load-balances by flow hash, so each
  client's packets stay on one socket/core. Session/metrics tables are already
  concurrent (`DashMap`), so they're shared as-is.
- **Expected impact:** near-linear inbound scaling with cores. **High** on
  multi-core hosts. Also relieves outbound contention if each relay sends via
  its local reuseport socket.
- **Risk:** Medium. Main subtlety is per-client affinity for ordering/locality,
  which the kernel flow-hash provides for free.

**A and B compose:** batching cuts per-core cost; REUSEPORT adds cores.

---

## Tier 2 — behavior-preserving refactors, medium impact

### C. Collapse the inbound two-lookup into one

Inbound does two DashMap lookups keyed by the same `SocketAddr` (`metrics` then
`sessions`).

- **Lighter:** embed `Arc<ClientMetrics>` inside `Session`. The inbound hot path
  then does **one** `sessions.get_or_create` that yields backend socket *and*
  metrics — dropping the separate metrics lookup on the data path. Metrics map
  stays for probe-only clients.
- **Fuller:** consolidate the five per-client maps (`sessions`, `metrics`,
  `client_protocols`, `dns_query_echo`, `sip_dialogs`) into one
  `DashMap<SocketAddr, Arc<ClientState>>`. One lookup per inbound packet, and
  the 5-way cleanup choreography collapses to one removal.
- **Expected impact:** removes ~half the inbound map work; **~1–3% CPU** until
  Tier 1 lands (relatively more afterward). **Medium effort, medium risk** (the
  lighter variant is much safer).

### D. Relay buffer memory: 64 KB per session — implemented

Each relay allocated `vec![0u8; min(buffer_size, 65535)]` = **64 KB/session**
at the default (`default_buffer_size` = 65535). At `max_sessions` = 10k that
was **~640 MB resident** in relay buffers alone (the vec is zeroed, so
touched).

- **Implemented as:** a separate `relay_buffer_size` option (default **8192**,
  validated ≥ 1280 — the IPv6 minimum MTU — and capped at 65535 in use).
  8 KiB covers any internet-path tunnel MTU (≤ ~1500) plus AmneziaWG
  S-padding with margin; jumbo-MTU deployments raise it explicitly.
- **Impact:** **memory, not CPU** — ~640 MB → ~80 MB at 10k sessions; better
  cache/TLB locality is a secondary CPU benefit.
- **Residual risk:** datagrams larger than the buffer are truncated (as they
  always were beyond `buffer_size`); the config comment and USAGE.md document
  when to raise it.

---

## Tier 3 — micro-optimizations, low risk / low reward

- **Faster DashMap hasher.** All maps use the default `RandomState` (SipHash).
  Switching to `ahash` (keeps DoS-resistance via random seed, unlike
  `rustc-hash`/FxHash which is deterministic) speeds the per-lookup hash of
  `SocketAddr`. Real but small (~1–2%); trivial; worth bundling with Tier 2C.
- **DNS echo inline buffer.** `DnsEcho.qname` is a `Vec`; on query *change*
  (rare, gated to DNS) it allocates. A `[u8; 256] + len` inline buffer makes the
  DNS data path fully alloc-free. Marginal now that compare-before-write made
  writes rare.

## Explicitly do NOT do this (tempting but unsafe)

- **Reordering `classify_awg_packet` candidates** to check `TransportData` (S4)
  first for the common case **is not safe**: a handshake packet (exact size at
  S1/S2/S3) can also satisfy TransportData's permissive `len ≥ s4+32` check, and
  if the bytes at the S4 offset happen to fall in the H4 range it would
  misclassify → wrong S-padding → malformed output. The current handshake-first
  order is a correctness constraint, not an oversight.

---

## Measuring — the in-repo benchmark harness

`examples/bench.rs` ships two modes (no extra dependencies). Cargo's default
target selection for `cargo test` includes building examples — see "Target
Selection" in `cargo help test` — so the existing CI's plain `cargo test`
already compile-checks the harness and it cannot rot (easily verified: delete
`target/debug/examples/bench*` and run `cargo test`; it comes back).
`cargo test --all-targets` makes the same guarantee explicit.

```bash
# End-to-end loopback throughput through a real Proxy instance.
# --awg makes payloads AWG-transport-shaped and enables the padding
# transform, exercising the full data path.
cargo run --release --example bench -- throughput \
    [--secs N] [--clients N] [--payload BYTES] [--window N] [--awg]

# Userspace hot-path micro-benchmarks (classification, detection, padding).
cargo run --release --example bench -- hot-path
```

The throughput numbers are loopback numbers — they overstate what a NIC will
do, but they are the right tool for **before/after comparisons of proxy
changes on the same machine** (e.g. validating the Tier 1 batched-I/O work).
The hot-path mode confirms where userspace time goes; representative output
(one dev machine, release build):

```text
classify_awg_packet / transport hit                ~8 ns/op
detect_protocol / junk (probe path miss)           ~7 ns/op
detect_protocol / strict DNS query                 ~8 ns/op
apply_padding / quic|stun|sip (pad 64, 1200 B)   ~140–160 ns/op
apply_padding / dns (pad 64, 1200 B)              ~22 ns/op
```

Even the most expensive padding fill is an order of magnitude below a single
syscall — consistent with the syscall-bound headline: at 100k pps the full
transform costs ~1.5% of one core. The hot-path numbers are stable anywhere;
the end-to-end throughput numbers are **scheduler-sensitive** — on a busy
desktop, run-to-run variance can exceed the effect being measured — so
compare medians of repeated runs on an otherwise idle machine (the production
host is the right place for baselines).

## Profiling plan — confirm before investing in Tier 1

1. **`perf stat -p <pid>`** under an `iperf3` load through the tunnel — check the
   **kernel/user CPU split**. High `sys%` confirms syscall-bound → Tier 1.
2. **`strace -f -c -p <pid>`** (20 s window) — confirm `recvfrom`/`sendto`/
   `sendmsg` dominate the syscall count and the real pps.
3. **`perf record -g` + flamegraph** — verify userspace is small (expect
   `recv_from`/`send_to` + copy dominating; if `dashmap`/siphash show up
   materially, do Tier 2C + ahash; if `apply_*_padding`/PRNG shows up, that's
   protocol cost).
4. **`ss -ump` + `nstat -az | grep -i drop`** before/after — confirm the
   socket-buffer work eliminated in-proxy drops (RcvbufErrors flat) and whether
   CPU-bound vs. drop-bound.
5. **`pidstat -u 1`** across cores — one core pegged while others idle confirms
   the single-loop ceiling → Tier 1B (REUSEPORT).

---

## Bottom line / recommendation

Yes, it can be optimized further — but the userspace tuning is essentially done,
and the remaining wins are I/O-architectural.

1. **Profile first** (commands above) to confirm syscall-bound and
   single-core-bound.
2. If confirmed, **Tier 1A (GRO/GSO + batched recv/send on the frontend via
   `quinn-udp`)** is the highest-impact, contained change — start there.
3. **Tier 1B (SO_REUSEPORT)** for multi-core hosts; composes with 1A.
4. **Tier 2C (embed metrics in `Session`) + Tier 3 ahash** as a low-risk
   userspace cleanup. 2C is also what removes the remaining `auto`-mode
   per-packet inbound lookup (`dns_active`). (**2D — relay buffer sizing —
   and the `auto`-mode outbound lookup are already done.**)

Expected order of magnitude: Tier 1 can plausibly **2–4× per-core throughput and
add near-linear core scaling**; Tier 2/3 together are **single-digit % CPU** and
a large **memory** reduction.

| Item | Type | Impact | Risk | Status |
|------|------|--------|------|--------|
| 1A — recvmmsg/sendmmsg + GSO/GRO (quinn-udp) | I/O | 2–4× per core | Med–High | profile first |
| 1B — SO_REUSEPORT × N loops | I/O / scaling | near-linear cores | Med | profile first |
| 2C — one inbound lookup (embed metrics / consolidate maps) | CPU | ~1–3% | Med | open |
| 2D — relay buffer sizing (`relay_buffer_size`, default 8 KiB) | Memory | ~640 MB → ~80 MB @ 10k | Low | ✅ done |
| auto-mode relay protocol-lock cache | CPU (outbound, `auto`) | 1 → 0 lookups/packet | Low | ✅ done |
| 3 — ahash hasher | CPU | ~1–2% | Low | open (bundle with 2C) |
| 3 — DNS echo inline buffer | Alloc | marginal | Low | open |
| ✗ classify candidate reorder | — | — | Unsafe (do not do) | — |
