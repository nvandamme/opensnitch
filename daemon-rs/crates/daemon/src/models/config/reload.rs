pub(crate) enum RuntimeApplyPolicy {
    ContinueOnError,
    StopAfterRulesError,
}

#[derive(Clone, Copy)]
pub(crate) enum RuntimeApplyMessageContext {
    // Reserved reload context for config command ingress in staged runtime-apply wiring.
    #[allow(dead_code)]
    ConfigCommand,
    ConfigWatch,
    Sighup,
}

pub(crate) struct RuntimeApplyStageMessages {
    pub(crate) log: &'static str,
    pub(crate) external: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RuntimeApplyStage {
    Logging,
    Rules,
    Firewall,
}

pub(crate) struct RuntimeApplyReport {
    pub(crate) logging_error: Option<anyhow::Error>,
    pub(crate) rules_error: Option<anyhow::Error>,
    pub(crate) firewall_error: Option<anyhow::Error>,
}
