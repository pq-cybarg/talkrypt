//! Airtime estimation + duty-cycle pacing for LoRa mesh transmissions.
//!
//! A talkrypt frame fragments into many ~200-byte mesh packets; blasting them at
//! the node overruns its TX queue and violates regional **duty-cycle** limits
//! (e.g. EU868 is 1% — ~36 s of airtime per hour per sub-band). This module:
//!
//! - estimates a packet's **time-on-air** with the standard Semtech LoRa formula
//!   ([`airtime_ms`]) + the Meshtastic modem presets ([`MeshtasticPreset`]);
//! - budgets airtime over a rolling window with a minimum inter-packet gap
//!   ([`AirtimeBudget`], pure + fully testable on synthetic timestamps);
//! - wraps any [`MeshNode`] in a [`PacedMeshNode`] decorator that awaits the
//!   budget before each `send`, so the rest of talkrypt is unchanged.
//!
//! The airtime formula is deterministic and unit-tested against a hand-computed
//! value; preset SF/BW come from Meshtastic's modem definitions.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::{MeshInbox, MeshNode};
use crate::Result;

/// LoRa PHY parameters for the time-on-air computation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LoraParams {
    pub spreading_factor: u32, // SF 7..12
    pub bandwidth_hz: u32,     // e.g. 125_000, 250_000, 500_000
    pub coding_rate: u32,      // 1..4  (4/5 .. 4/8)
    pub preamble_symbols: u32, // Meshtastic uses 16
    pub crc: bool,             // CRC enabled
    pub implicit_header: bool, // Meshtastic uses an explicit header (false)
}

impl LoraParams {
    /// Low-data-rate optimization is on when a symbol is longer than 16 ms
    /// (SF11/SF12 at BW125), matching Semtech/Meshtastic behaviour.
    fn low_data_rate_opt(&self) -> bool {
        // Tsym (ms) = 1000 * 2^SF / BW.
        let tsym_ms = 1000.0 * (1u64 << self.spreading_factor) as f64 / self.bandwidth_hz as f64;
        tsym_ms > 16.0
    }
}

/// Meshtastic modem presets → LoRa PHY parameters (CR 4/5, 16-symbol preamble,
/// CRC on, explicit header — the on-air Meshtastic config). `LongFast` is default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshtasticPreset {
    ShortTurbo,
    ShortFast,
    ShortSlow,
    MediumFast,
    MediumSlow,
    LongFast,
    LongModerate,
    LongSlow,
}

impl MeshtasticPreset {
    pub fn params(self) -> LoraParams {
        let (sf, bw) = match self {
            MeshtasticPreset::ShortTurbo => (7, 500_000),
            MeshtasticPreset::ShortFast => (7, 250_000),
            MeshtasticPreset::ShortSlow => (8, 250_000),
            MeshtasticPreset::MediumFast => (9, 250_000),
            MeshtasticPreset::MediumSlow => (10, 250_000),
            MeshtasticPreset::LongFast => (11, 250_000),
            MeshtasticPreset::LongModerate => (11, 125_000),
            MeshtasticPreset::LongSlow => (12, 125_000),
        };
        LoraParams {
            spreading_factor: sf,
            bandwidth_hz: bw,
            coding_rate: 1, // 4/5
            preamble_symbols: 16,
            crc: true,
            implicit_header: false,
        }
    }
}

/// Time-on-air of a `payload_len`-byte LoRa packet, in milliseconds, per the
/// Semtech reference formula (SX127x datasheet §4.1.1.7):
///
/// ```text
/// Tsym          = 2^SF / BW
/// Tpreamble     = (n_preamble + 4.25) * Tsym
/// payloadSymbNb = 8 + max(ceil((8*PL - 4*SF + 28 + 16*CRC - 20*IH)
///                              / (4*(SF - 2*DE))) * (CR + 4), 0)
/// Tpayload      = payloadSymbNb * Tsym
/// airtime       = Tpreamble + Tpayload
/// ```
pub fn airtime_ms(payload_len: usize, p: LoraParams) -> f64 {
    let sf = p.spreading_factor as f64;
    let tsym_ms = 1000.0 * (1u64 << p.spreading_factor) as f64 / p.bandwidth_hz as f64;
    let t_preamble = (p.preamble_symbols as f64 + 4.25) * tsym_ms;
    let de = if p.low_data_rate_opt() { 1.0 } else { 0.0 };
    let crc = if p.crc { 1.0 } else { 0.0 };
    let ih = if p.implicit_header { 1.0 } else { 0.0 };
    let pl = payload_len as f64;
    let numerator = 8.0 * pl - 4.0 * sf + 28.0 + 16.0 * crc - 20.0 * ih;
    let denominator = 4.0 * (sf - 2.0 * de);
    let cr = p.coding_rate as f64;
    let payload_symb = 8.0 + (numerator / denominator).ceil().max(0.0) * (cr + 4.0);
    t_preamble + payload_symb * tsym_ms
}

/// A rolling-window airtime budget with a minimum inter-packet gap. Pure: the
/// caller supplies monotonic `now_ms`, so it is fully deterministic in tests.
///
/// `duty_cycle` is the allowed fraction of airtime over `window_ms` (e.g. 0.01 for
/// the EU868 1% limit). `min_gap_ms` spaces consecutive transmissions regardless of
/// the duty budget (protects the node's TX queue).
pub struct AirtimeBudget {
    window_ms: u64,
    budget_ms: f64,
    min_gap_ms: u64,
    log: VecDeque<(u64, f64)>, // (sent_at_ms, airtime_ms)
    total_ms: f64,
    last_sent_ms: Option<u64>,
}

impl AirtimeBudget {
    pub fn new(window_ms: u64, duty_cycle: f64, min_gap_ms: u64) -> Self {
        let duty = duty_cycle.clamp(0.0, 1.0);
        Self {
            window_ms: window_ms.max(1),
            budget_ms: window_ms as f64 * duty,
            min_gap_ms,
            log: VecDeque::new(),
            total_ms: 0.0,
            last_sent_ms: None,
        }
    }

    /// Common EU868 sub-band budget: 1% duty cycle over one hour, 250 ms gap.
    pub fn eu868() -> Self {
        Self::new(3_600_000, 0.01, 250)
    }

    fn prune(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        while let Some(&(t, air)) = self.log.front() {
            if t < cutoff {
                self.total_ms -= air;
                self.log.pop_front();
            } else {
                break;
            }
        }
        if self.total_ms < 0.0 {
            self.total_ms = 0.0;
        }
    }

    /// Milliseconds to wait before a packet of `airtime` may be sent at `now_ms`
    /// (0 = send now). Accounts for both the min-gap and the duty-cycle window.
    pub fn delay_ms(&mut self, now_ms: u64, airtime: f64) -> u64 {
        self.prune(now_ms);
        // Minimum inter-packet gap.
        let gap_wait = match self.last_sent_ms {
            Some(last) => (last + self.min_gap_ms).saturating_sub(now_ms),
            None => 0,
        };
        // Duty-cycle window: if adding this packet exceeds the budget, wait until
        // enough of the oldest airtime ages out of the window.
        let mut duty_wait = 0u64;
        if self.total_ms + airtime > self.budget_ms {
            let mut freed = 0.0;
            let need = self.total_ms + airtime - self.budget_ms;
            for &(t, air) in self.log.iter() {
                freed += air;
                if freed >= need {
                    // This entry ages out at t + window_ms.
                    duty_wait = (t + self.window_ms).saturating_sub(now_ms);
                    break;
                }
            }
            if freed < need {
                // Even emptying the whole window is not enough (packet bigger than
                // the budget): wait for the window to fully clear.
                if let Some(&(t, _)) = self.log.back() {
                    duty_wait = (t + self.window_ms).saturating_sub(now_ms);
                }
            }
        }
        gap_wait.max(duty_wait)
    }

    /// Record that a packet of `airtime` was sent at `now_ms`.
    pub fn record(&mut self, now_ms: u64, airtime: f64) {
        self.prune(now_ms);
        self.log.push_back((now_ms, airtime));
        self.total_ms += airtime;
        self.last_sent_ms = Some(now_ms);
    }

    /// Airtime (ms) currently charged against the window at `now_ms`.
    pub fn used_ms(&mut self, now_ms: u64) -> f64 {
        self.prune(now_ms);
        self.total_ms
    }
}

/// Wraps a [`MeshNode`], pacing each `send` to respect a LoRa [`AirtimeBudget`]
/// for the configured [`MeshtasticPreset`]. `mtu`/`subscribe` pass through. Drop-in:
/// build your radio `MeshNode`, wrap it, then hand the wrapper to
/// `Core::start_mesh_messaging` / a `MeshBeacon`.
pub struct PacedMeshNode {
    inner: Arc<dyn MeshNode>,
    preset: MeshtasticPreset,
    budget: Mutex<AirtimeBudget>,
}

impl PacedMeshNode {
    pub fn new(inner: Arc<dyn MeshNode>, preset: MeshtasticPreset, budget: AirtimeBudget) -> Self {
        Self {
            inner,
            preset,
            budget: Mutex::new(budget),
        }
    }
}

/// Monotonic milliseconds for pacing. `tokio::time::Instant` is monotonic and, under
/// `tokio::time::pause`, virtual — so tests can drive it deterministically.
fn now_ms() -> u64 {
    use std::sync::OnceLock;
    use tokio::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    let start = *START.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

#[async_trait]
impl MeshNode for PacedMeshNode {
    fn mtu(&self) -> usize {
        self.inner.mtu()
    }

    async fn send(&self, channel: u8, payload: &[u8]) -> Result<()> {
        let airtime = airtime_ms(payload.len(), self.preset.params());
        let delay = {
            let mut b = self.budget.lock().unwrap();
            b.delay_ms(now_ms(), airtime)
        };
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        {
            let mut b = self.budget.lock().unwrap();
            b.record(now_ms(), airtime);
        }
        self.inner.send(channel, payload).await
    }

    async fn subscribe(&self) -> Result<MeshInbox> {
        self.inner.subscribe().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn airtime_matches_hand_computed_semtech_value() {
        // SF7, BW125k, CR 4/5, 8-symbol preamble, CRC on, explicit header, no LDRO.
        // Tsym = 128/125000 = 1.024 ms; Tpreamble = 12.25*1.024 = 12.544 ms.
        // payloadSymbNb = 8 + ceil((160-28+28+16)/28)*5 = 8 + ceil(176/28=6.29→7)*5 = 43.
        // Tpayload = 43*1.024 = 44.032; total = 56.576 ms.
        let p = LoraParams {
            spreading_factor: 7,
            bandwidth_hz: 125_000,
            coding_rate: 1,
            preamble_symbols: 8,
            crc: true,
            implicit_header: false,
        };
        let ms = airtime_ms(20, p);
        assert!((ms - 56.576).abs() < 0.01, "airtime {ms} != 56.576");
    }

    #[test]
    fn slower_presets_take_longer() {
        let pl = 200;
        let fast = airtime_ms(pl, MeshtasticPreset::ShortFast.params());
        let long = airtime_ms(pl, MeshtasticPreset::LongFast.params());
        let slow = airtime_ms(pl, MeshtasticPreset::LongSlow.params());
        assert!(fast < long && long < slow, "{fast} < {long} < {slow}");
        // LongFast (SF11/BW250) enables low-data-rate optimization; sanity: > 100 ms.
        assert!(long > 100.0, "LongFast 200B airtime {long} ms unexpectedly small");
    }

    #[test]
    fn budget_allows_until_full_then_delays() {
        // 1000 ms window, 10% duty → 100 ms of airtime per window, no min gap.
        let mut b = AirtimeBudget::new(1000, 0.10, 0);
        // Three 40 ms packets: first two fit (80 ms), third (120 > 100) must wait.
        assert_eq!(b.delay_ms(0, 40.0), 0);
        b.record(0, 40.0);
        assert_eq!(b.delay_ms(10, 40.0), 0);
        b.record(10, 40.0);
        // Now 80 ms used; a third 40 ms would be 120 > 100 → wait for the first
        // packet (sent at t=0) to age out at t=1000, i.e. 1000 - 20 = 980 ms.
        assert_eq!(b.delay_ms(20, 40.0), 980);
    }

    #[test]
    fn budget_enforces_min_gap() {
        let mut b = AirtimeBudget::new(3_600_000, 1.0, 250); // effectively no duty cap
        assert_eq!(b.delay_ms(0, 5.0), 0);
        b.record(0, 5.0);
        // 100 ms later, still inside the 250 ms gap → wait 150 ms.
        assert_eq!(b.delay_ms(100, 5.0), 150);
        // 250 ms later → free.
        assert_eq!(b.delay_ms(250, 5.0), 0);
    }

    #[test]
    fn window_prunes_aged_out_airtime() {
        let mut b = AirtimeBudget::new(1000, 0.10, 0);
        b.record(0, 100.0); // fills the whole 100 ms budget
        assert!((b.used_ms(500) - 100.0).abs() < 0.001);
        // After the window, it ages out.
        assert!(b.used_ms(1001) < 0.001);
    }

    #[tokio::test]
    async fn paced_node_delegates_mtu_send_subscribe() {
        use crate::mesh::MockMeshFabric;
        let fabric = MockMeshFabric::new(200);
        let paced = PacedMeshNode::new(
            Arc::new(fabric.node(1)),
            MeshtasticPreset::LongFast,
            // Generous budget so the test does not actually sleep.
            AirtimeBudget::new(3_600_000, 1.0, 0),
        );
        assert_eq!(paced.mtu(), 200);
        // A peer subscribes; the paced node's send reaches it.
        let mut inbox = fabric.node(2).subscribe().await.unwrap();
        paced.send(0, b"hi").await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(1), inbox.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.payload, b"hi");
    }
}
