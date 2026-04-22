use std::{future::Future, pin::Pin};

use anyhow::Result;
use opensnitch_proto::pb;

use crate::platform::adapters::{
    firewall_iptables::FirewallIptablesAdapter, firewall_nft::FirewallNftAdapter,
};

pub(crate) trait FirewallPlatformPort {
    fn ensure(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;

    fn disable(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;

    fn interception_rules_valid(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send>>;

    fn apply_system_firewall<'a>(
        sysfw: &'a pb::SysFirewall,
        queue_num: u16,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    fn clear_system_firewall<'a>(
        sysfw: &'a pb::SysFirewall,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

pub(crate) struct NftablesFirewallPort;

impl FirewallPlatformPort for NftablesFirewallPort {
    fn ensure(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move { FirewallNftAdapter::ensure(queue_num, queue_bypass).await })
    }

    fn disable(
        _queue_num: u16,
        _queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move { FirewallNftAdapter::disable().await })
    }

    fn interception_rules_valid(
        _queue_num: u16,
        _queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send>> {
        Box::pin(async move { FirewallNftAdapter::interception_rules_valid().await })
    }

    fn apply_system_firewall<'a>(
        sysfw: &'a pb::SysFirewall,
        queue_num: u16,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move { FirewallNftAdapter::apply_system_firewall(sysfw, queue_num).await })
    }

    fn clear_system_firewall<'a>(
        sysfw: &'a pb::SysFirewall,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move { FirewallNftAdapter::clear_system_firewall(sysfw).await })
    }
}

pub(crate) struct IptablesFirewallPort;

impl FirewallPlatformPort for IptablesFirewallPort {
    fn ensure(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move { FirewallIptablesAdapter::ensure(queue_num, queue_bypass).await })
    }

    fn disable(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move { FirewallIptablesAdapter::disable(queue_num, queue_bypass).await })
    }

    fn interception_rules_valid(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send>> {
        Box::pin(async move {
            FirewallIptablesAdapter::interception_rules_valid(queue_num, queue_bypass).await
        })
    }

    fn apply_system_firewall<'a>(
        sysfw: &'a pb::SysFirewall,
        _queue_num: u16,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move { FirewallIptablesAdapter::apply_system_firewall(sysfw).await })
    }

    fn clear_system_firewall<'a>(
        sysfw: &'a pb::SysFirewall,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move { FirewallIptablesAdapter::clear_system_firewall(sysfw).await })
    }
}
