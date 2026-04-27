use std::sync::OnceLock;

use super::PolicyTxCoordinator;

pub fn global_policy_tx() -> &'static PolicyTxCoordinator {
    static TX: OnceLock<PolicyTxCoordinator> = OnceLock::new();
    TX.get_or_init(PolicyTxCoordinator::default)
}
