//! Traffic history aggregation.
//!
//! Given an ordered sequence of peer snapshots (oldest first), compute
//! per-step RX/TX deltas and overall totals.
//!
//! ## Counter-reset handling
//!
//! WireGuard byte counters are monotonic within a kernel session.  They reset
//! to zero when the interface is restarted or when the kernel module is
//! reloaded.  A reset is detected when a counter value *decreases* relative to
//! the previous snapshot.
//!
//! When a reset is detected, `saturating_sub` produces 0 for that step (not a
//! negative number).  The summary totals sum only the non-negative deltas, so a
//! reset does not subtract from the reported cumulative traffic.

use serde::Serialize;

/// One data point in a traffic history response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryPoint {
    /// ISO-8601 timestamp of the snapshot that produced this point.
    pub timestamp: String,
    /// Absolute RX byte counter at this snapshot.
    pub rx_bytes_total: u64,
    /// Absolute TX byte counter at this snapshot.
    pub tx_bytes_total: u64,
    /// Non-negative change in RX bytes since the previous snapshot.
    /// Zero on the first point or after a counter reset.
    pub rx_delta: u64,
    /// Non-negative change in TX bytes since the previous snapshot.
    /// Zero on the first point or after a counter reset.
    pub tx_delta: u64,
}

/// Aggregated totals for the requested time window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistorySummary {
    /// Sum of all non-negative RX deltas in the window.
    pub rx_total_delta: u64,
    /// Sum of all non-negative TX deltas in the window.
    pub tx_total_delta: u64,
}

/// Input snapshot used by `compute_history`.
///
/// The caller is responsible for supplying snapshots in **ascending** timestamp
/// order (oldest first).
#[derive(Debug, Clone)]
pub struct SnapshotInput {
    /// ISO-8601 / RFC-3339 string – stored verbatim in `HistoryPoint.timestamp`.
    pub captured_at: String,
    /// Raw RX counter from `awg show`.
    pub rx_bytes: u64,
    /// Raw TX counter from `awg show`.
    pub tx_bytes: u64,
}

/// Compute only the aggregated totals without building per-step points.
///
/// This is a lightweight alternative to [`compute_history`] for callers that
/// only need `rx_total_delta` / `tx_total_delta` (e.g. the usage-summary
/// endpoints).  It avoids allocating the `Vec<HistoryPoint>` and cloning
/// each snapshot timestamp.
pub fn compute_usage_summary(snapshots: &[SnapshotInput]) -> HistorySummary {
    let mut rx_total: u64 = 0;
    let mut tx_total: u64 = 0;

    for (i, snap) in snapshots.iter().enumerate() {
        if i > 0 {
            let prev = &snapshots[i - 1];
            rx_total = rx_total.saturating_add(snap.rx_bytes.saturating_sub(prev.rx_bytes));
            tx_total = tx_total.saturating_add(snap.tx_bytes.saturating_sub(prev.tx_bytes));
        }
    }

    HistorySummary {
        rx_total_delta: rx_total,
        tx_total_delta: tx_total,
    }
}

/// Compute history points and a summary from a slice of ordered snapshots.
///
/// - `snapshots` must be sorted **oldest first**.
/// - Returns an empty `points` vec and zero totals if `snapshots` is empty.
/// - The first point always has `rx_delta = 0` and `tx_delta = 0`.
/// - Counter resets (current < previous) produce a delta of 0 for that step,
///   using `saturating_sub`.
pub fn compute_history(snapshots: &[SnapshotInput]) -> (Vec<HistoryPoint>, HistorySummary) {
    if snapshots.is_empty() {
        return (
            Vec::new(),
            HistorySummary {
                rx_total_delta: 0,
                tx_total_delta: 0,
            },
        );
    }

    let mut points: Vec<HistoryPoint> = Vec::with_capacity(snapshots.len());
    let mut rx_total: u64 = 0;
    let mut tx_total: u64 = 0;

    for (i, snap) in snapshots.iter().enumerate() {
        // saturating_sub returns 0 on underflow, which handles counter resets:
        // if the new counter is lower than the previous (interface restart),
        // the delta for this step is 0 rather than a negative number.
        let (rx_delta, tx_delta) = if i == 0 {
            (0u64, 0u64)
        } else {
            let prev = &snapshots[i - 1];
            (
                snap.rx_bytes.saturating_sub(prev.rx_bytes),
                snap.tx_bytes.saturating_sub(prev.tx_bytes),
            )
        };

        rx_total = rx_total.saturating_add(rx_delta);
        tx_total = tx_total.saturating_add(tx_delta);

        points.push(HistoryPoint {
            timestamp: snap.captured_at.clone(),
            rx_bytes_total: snap.rx_bytes,
            tx_bytes_total: snap.tx_bytes,
            rx_delta,
            tx_delta,
        });
    }

    (
        points,
        HistorySummary {
            rx_total_delta: rx_total,
            tx_total_delta: tx_total,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(ts: &str, rx: u64, tx: u64) -> SnapshotInput {
        SnapshotInput {
            captured_at: ts.to_string(),
            rx_bytes: rx,
            tx_bytes: tx,
        }
    }

    #[test]
    fn empty_snapshots() {
        let (points, summary) = compute_history(&[]);
        assert!(points.is_empty());
        assert_eq!(summary.rx_total_delta, 0);
        assert_eq!(summary.tx_total_delta, 0);
    }

    #[test]
    fn single_snapshot_produces_one_zero_delta_point() {
        let (points, summary) = compute_history(&[snap("2026-01-01T00:00:00Z", 1000, 2000)]);
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].rx_delta, 0);
        assert_eq!(points[0].tx_delta, 0);
        assert_eq!(points[0].rx_bytes_total, 1000);
        assert_eq!(points[0].tx_bytes_total, 2000);
        assert_eq!(summary.rx_total_delta, 0);
        assert_eq!(summary.tx_total_delta, 0);
    }

    #[test]
    fn monotonic_counters() {
        let snaps = vec![
            snap("2026-01-01T00:00:00Z", 0, 0),
            snap("2026-01-01T00:01:00Z", 100, 200),
            snap("2026-01-01T00:02:00Z", 150, 350),
        ];
        let (points, summary) = compute_history(&snaps);
        assert_eq!(points.len(), 3);

        assert_eq!(points[0].rx_delta, 0);
        assert_eq!(points[0].tx_delta, 0);

        assert_eq!(points[1].rx_delta, 100);
        assert_eq!(points[1].tx_delta, 200);

        assert_eq!(points[2].rx_delta, 50);
        assert_eq!(points[2].tx_delta, 150);

        assert_eq!(summary.rx_total_delta, 150);
        assert_eq!(summary.tx_total_delta, 350);
    }

    #[test]
    fn equal_consecutive_counters_produce_zero_delta() {
        let snaps = vec![
            snap("2026-01-01T00:00:00Z", 500, 1000),
            snap("2026-01-01T00:01:00Z", 500, 1000),
        ];
        let (points, summary) = compute_history(&snaps);
        assert_eq!(points[1].rx_delta, 0);
        assert_eq!(points[1].tx_delta, 0);
        assert_eq!(summary.rx_total_delta, 0);
        assert_eq!(summary.tx_total_delta, 0);
    }

    #[test]
    fn counter_reset_produces_zero_delta_for_that_step() {
        // Counters were 1000/2000, then reset to 50/100 (restart).
        let snaps = vec![
            snap("2026-01-01T00:00:00Z", 800, 1800),
            snap("2026-01-01T00:01:00Z", 1000, 2000),
            snap("2026-01-01T00:02:00Z", 50, 100), // reset
            snap("2026-01-01T00:03:00Z", 300, 500),
        ];
        let (points, summary) = compute_history(&snaps);

        assert_eq!(points[1].rx_delta, 200); // 1000 - 800
        assert_eq!(points[1].tx_delta, 200); // 2000 - 1800

        // Reset: saturating_sub clamps to 0
        assert_eq!(points[2].rx_delta, 0);
        assert_eq!(points[2].tx_delta, 0);

        assert_eq!(points[3].rx_delta, 250); // 300 - 50
        assert_eq!(points[3].tx_delta, 400); // 500 - 100

        // Total excludes the reset step
        assert_eq!(summary.rx_total_delta, 450); // 200 + 0 + 250
        assert_eq!(summary.tx_total_delta, 600); // 200 + 0 + 400
    }

    #[test]
    fn timestamps_preserved_in_order() {
        let snaps = vec![
            snap("2026-01-01T00:00:00Z", 0, 0),
            snap("2026-01-02T00:00:00Z", 100, 200),
            snap("2026-01-03T00:00:00Z", 300, 600),
        ];
        let (points, _) = compute_history(&snaps);
        assert_eq!(points[0].timestamp, "2026-01-01T00:00:00Z");
        assert_eq!(points[1].timestamp, "2026-01-02T00:00:00Z");
        assert_eq!(points[2].timestamp, "2026-01-03T00:00:00Z");
    }

    // ── compute_usage_summary tests ─────────────────────────────────────

    #[test]
    fn summary_empty_snapshots() {
        let s = compute_usage_summary(&[]);
        assert_eq!(s.rx_total_delta, 0);
        assert_eq!(s.tx_total_delta, 0);
    }

    #[test]
    fn summary_single_snapshot() {
        let s = compute_usage_summary(&[snap("2026-01-01T00:00:00Z", 1000, 2000)]);
        assert_eq!(s.rx_total_delta, 0);
        assert_eq!(s.tx_total_delta, 0);
    }

    #[test]
    fn summary_matches_compute_history() {
        let snaps = vec![
            snap("2026-01-01T00:00:00Z", 800, 1800),
            snap("2026-01-01T00:01:00Z", 1000, 2000),
            snap("2026-01-01T00:02:00Z", 50, 100), // reset
            snap("2026-01-01T00:03:00Z", 300, 500),
        ];
        let (_, full) = compute_history(&snaps);
        let light = compute_usage_summary(&snaps);
        assert_eq!(full.rx_total_delta, light.rx_total_delta);
        assert_eq!(full.tx_total_delta, light.tx_total_delta);
    }
}
