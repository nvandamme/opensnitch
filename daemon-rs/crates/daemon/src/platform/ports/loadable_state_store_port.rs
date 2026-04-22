use std::{
    collections::HashMap,
    future::Future,
    path::Path,
    pin::Pin,
};

use anyhow::Result;

use crate::{
    config::Config,
    models::{
        firewall_config::FirewallConfig,
        firewall_state::FirewallBackend,
        rule_storage::RuleFile,
    },
};

pub(crate) trait ConfigStorePort {
    fn load_config<'a>(path: &'a Path) -> Pin<Box<dyn Future<Output = Result<Config>> + Send + 'a>>;
}

pub(crate) trait RuleStorePort {
    fn load_rule_file<'a>(
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<RuleFile>> + Send + 'a>>;
}

pub(crate) trait AliasStorePort {
    fn load_alias_map<'a>(
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<Option<HashMap<String, Vec<String>>>>> + Send + 'a>>;
}

pub(crate) trait FirewallStorePort {
    fn load_firewall(path: &Path, backend: FirewallBackend) -> Result<Option<FirewallConfig>>;

    fn save_firewall(path: &Path, config: &FirewallConfig, backend: FirewallBackend) -> Result<()>;
}
