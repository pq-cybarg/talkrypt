//! Persistent-onion keep-alive strategies.
//!
//! A persistent onion stays reachable only while *something* keeps publishing
//! its descriptor. The three strategies differ in what that "something" is and
//! when this node should be publishing. Each reduces to a pure decision —
//! [`KeepAlive::should_publish`] — that a thin driver loop calls on a timer or
//! on state changes, which keeps the policy fully unit-testable without a live
//! Tor network.

/// Inputs to the keep-alive decision, sampled by the driver.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeepAliveContext {
    /// Designated anchor clients currently online.
    pub anchors_online: usize,
    /// Healthy replicated backends (including self) currently serving.
    pub healthy_backends: usize,
    /// Whether this node is itself a healthy backend right now.
    pub self_healthy: bool,
    /// Whether the published descriptor has expired / needs republishing.
    pub descriptor_expired: bool,
}

/// A keep-alive policy.
pub trait KeepAlive: Send + Sync {
    /// Should this node (re)publish the onion descriptor now?
    fn should_publish(&self, ctx: &KeepAliveContext) -> bool;
    /// Human-readable name.
    fn name(&self) -> &'static str;
}

/// Long-lived daemon: always keep the descriptor published, republishing on
/// expiry. Stable address, full uptime; the operator owns host opsec.
pub struct AlwaysOn;

impl KeepAlive for AlwaysOn {
    fn should_publish(&self, _ctx: &KeepAliveContext) -> bool {
        // Always be published; the driver also republishes on expiry, but the
        // steady-state answer is simply "yes".
        true
    }
    fn name(&self) -> &'static str {
        "always-on"
    }
}

/// No dedicated host: publish only while at least one anchor client is online.
/// Stable address, but reachable only when an anchor is up — maximally
/// non-identifying.
pub struct ClientAnchored;

impl KeepAlive for ClientAnchored {
    fn should_publish(&self, ctx: &KeepAliveContext) -> bool {
        ctx.anchors_online >= 1
    }
    fn name(&self) -> &'static str {
        "client-anchored"
    }
}

/// Replicated failover (OnionBalance-style): this node publishes whenever it is
/// a healthy backend, so the service survives any single backend dying and no
/// one host is essential.
pub struct ReplicatedFailover;

impl KeepAlive for ReplicatedFailover {
    fn should_publish(&self, ctx: &KeepAliveContext) -> bool {
        ctx.self_healthy && ctx.healthy_backends >= 1
    }
    fn name(&self) -> &'static str {
        "replicated-failover"
    }
}

/// Which keep-alive strategy a persistent server uses, chosen at server init.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    AlwaysOn,
    ClientAnchored,
    ReplicatedFailover,
}

impl Strategy {
    pub fn build(self) -> Box<dyn KeepAlive> {
        match self {
            Strategy::AlwaysOn => Box::new(AlwaysOn),
            Strategy::ClientAnchored => Box::new(ClientAnchored),
            Strategy::ReplicatedFailover => Box::new(ReplicatedFailover),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_on_publishes_unconditionally() {
        let k = AlwaysOn;
        assert!(k.should_publish(&KeepAliveContext::default()));
        assert!(k.should_publish(&KeepAliveContext {
            descriptor_expired: true,
            ..Default::default()
        }));
    }

    #[test]
    fn client_anchored_needs_an_anchor() {
        let k = ClientAnchored;
        assert!(!k.should_publish(&KeepAliveContext {
            anchors_online: 0,
            ..Default::default()
        }));
        assert!(k.should_publish(&KeepAliveContext {
            anchors_online: 1,
            ..Default::default()
        }));
    }

    #[test]
    fn replicated_failover_requires_self_healthy() {
        let k = ReplicatedFailover;
        // Unhealthy self never publishes, even with healthy peers.
        assert!(!k.should_publish(&KeepAliveContext {
            self_healthy: false,
            healthy_backends: 3,
            ..Default::default()
        }));
        // Healthy self publishes; survives if others die (count includes self).
        assert!(k.should_publish(&KeepAliveContext {
            self_healthy: true,
            healthy_backends: 1,
            ..Default::default()
        }));
    }

    #[test]
    fn strategy_builds_named_policy() {
        assert_eq!(Strategy::AlwaysOn.build().name(), "always-on");
        assert_eq!(Strategy::ClientAnchored.build().name(), "client-anchored");
        assert_eq!(
            Strategy::ReplicatedFailover.build().name(),
            "replicated-failover"
        );
    }
}
