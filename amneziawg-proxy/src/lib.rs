//! # amneziawg-proxy
//!
//! An async UDP proxy that sits in front of an AmneziaWG server and disguises
//! the traffic as a legitimate application protocol (QUIC, DNS, STUN, or SIP)
//! to defeat Deep Packet Inspection (DPI).
//!
//! ## Protocol Compatibility: AmneziaWG 2.0 only
//!
//! `amneziawg-proxy` is compatible **only with AmneziaWG 2.0**; it is **incompatible
//! with AmneziaWG 3.0+**.
//!
//! In AmneziaWG 2.0, the S1–S4 padding prefix consists of random bytes preceding
//! plaintext headers matching H1–H4, allowing the proxy to classify packets and safely
//! overwrite the padding prefix with cover-protocol headers. Starting with AmneziaWG 3.0,
//! S1–S4 padding values are used as key material for header encryption (`HeaderProtectionKey`).
//! Overwriting padding bytes in flight breaks header decryption on the peer, and the
//! resulting encrypted headers prevent packet classification.

pub mod backend;
pub mod config;
pub mod errors;
pub mod metrics;
pub mod proxy;
pub mod quic_handshake;
pub mod responder;
pub mod session;
pub mod transform;
