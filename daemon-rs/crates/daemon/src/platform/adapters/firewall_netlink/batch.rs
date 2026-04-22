use anyhow::{Context, Result};
use netlink_bindings::nftables::{self, Nfgenmsg};
use netlink_socket2::NetlinkSocket;
use nix::libc;

use super::{
    FirewallNetlinkOperation, GenerationId, INTERCEPTION_DNS_TAG, INTERCEPTION_NON_TCP_TAG,
    INTERCEPTION_TCP_SYN_TAG, NetfilterRuleChain, NetfilterTransactionBuilder, SYSFW_TAG_PREFIX,
};

impl NetfilterTransactionBuilder {
    pub(super) fn new(sock: &mut NetlinkSocket, genid: GenerationId) -> Self {
        let seq = sock.reserve_seq(256);
        let mut inner = nftables::Chained::new(seq);
        inner
            .request()
            .op_batch_begin_do(&Self::batch_header())
            .encode()
            .push_genid(genid.0);
        Self {
            inner,
            has_operation: false,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        !self.has_operation
    }

    pub(super) async fn apply_operation(
        &mut self,
        sock: &mut NetlinkSocket,
        op: &FirewallNetlinkOperation,
    ) -> Result<bool> {
        match op {
            FirewallNetlinkOperation::EnsureBaseChains { .. } => {
                self.ensure_base_chains();
                Ok(true)
            }
            FirewallNetlinkOperation::DisableBaseTable => {
                self.delete_table("inet", "opensnitch");
                Ok(true)
            }
            FirewallNetlinkOperation::EnsureSystemChain {
                family,
                table,
                name,
                hook,
                priority,
                policy,
                chain_type,
            } => {
                self.ensure_table(family, table);
                self.ensure_base_chain(family, table, name, hook, priority, policy, chain_type)?;
                Ok(true)
            }
            FirewallNetlinkOperation::ApplySystemRule {
                family,
                table,
                chain,
                expression,
                tag,
            } => {
                if self
                    .has_rule_with_userdata(sock, family, table, chain, tag.as_bytes())
                    .await?
                {
                    return Ok(true);
                }

                let supported = self.add_system_rule(family, table, chain, expression, tag);
                if !supported {
                    tracing::debug!(
                        family,
                        table,
                        chain,
                        expression,
                        "system rule expression is not yet netlink-supported; delegating to CLI fallback"
                    );
                }
                Ok(supported)
            }
            FirewallNetlinkOperation::ClearTaggedSystemRules {
                family,
                table,
                chain,
            } => {
                self.clear_tagged_system_rules(sock, family, table, chain)
                    .await
            }
            FirewallNetlinkOperation::ValidateInterceptionRules => {
                self.validate_interception_rules(sock).await
            }
            FirewallNetlinkOperation::EnsureInterceptionRule {
                chain,
                expression,
                tag,
            } => {
                let (family, table, chain_name) = match chain {
                    NetfilterRuleChain::FilterInput => ("inet", "opensnitch", "filter_input"),
                    NetfilterRuleChain::MangleOutput => ("inet", "opensnitch", "mangle_output"),
                };

                if self
                    .has_rule_with_userdata(sock, family, table, chain_name, tag.as_bytes())
                    .await?
                {
                    return Ok(true);
                }

                let supported = self.add_system_rule(family, table, chain_name, expression, tag);
                if !supported {
                    tracing::debug!(
                        family,
                        table,
                        chain = chain_name,
                        expression,
                        "interception rule expression is not yet netlink-supported; delegating to CLI fallback"
                    );
                }
                Ok(supported)
            }
        }
    }

    pub(super) async fn commit(mut self, sock: &mut NetlinkSocket) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }

        self.inner.request().op_batch_end_do(&Self::batch_header());
        let chained = self.inner.finalize();
        sock.request_chained(&chained).await?.recv_all().await?;
        Ok(())
    }

    fn ensure_base_chains(&mut self) {
        self.ensure_table("inet", "opensnitch");
        let _ = self.ensure_base_chain(
            "inet",
            "opensnitch",
            "filter_input",
            "input",
            "0",
            "accept",
            "filter",
        );
        let _ = self.ensure_base_chain(
            "inet",
            "opensnitch",
            "mangle_output",
            "output",
            "0",
            "accept",
            "route",
        );
    }

    fn ensure_table(&mut self, family: &str, table: &str) {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        self.inner
            .request()
            .set_create()
            .op_newtable_do(&h)
            .encode()
            .push_name_bytes(table.as_bytes());
        self.has_operation = true;
    }

    fn ensure_base_chain(
        &mut self,
        family: &str,
        table: &str,
        chain: &str,
        hook: &str,
        priority: &str,
        policy: &str,
        chain_type: &str,
    ) -> Result<()> {
        let hook_num =
            chain_hook_num(hook).with_context(|| format!("unsupported nft hook: {hook}"))?;
        let priority = chain_priority(priority)?;
        let policy =
            chain_policy(policy).with_context(|| format!("unsupported nft policy: {policy}"))?;

        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        self.inner
            .request()
            .set_create()
            .op_newchain_do(&h)
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_name_bytes(chain.as_bytes())
            .nested_hook()
            .push_num(hook_num)
            .push_priority(priority)
            .end_nested()
            .push_policy(policy)
            .push_type_bytes(chain_type.as_bytes())
            .push_flags(nftables::ChainFlags::Base as u32);
        self.has_operation = true;
        Ok(())
    }

    fn delete_table(&mut self, family: &str, table: &str) {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        self.inner
            .request()
            .op_deltable_do(&h)
            .encode()
            .push_name_bytes(table.as_bytes());
        self.has_operation = true;
    }

    async fn clear_tagged_system_rules(
        &mut self,
        sock: &mut NetlinkSocket,
        family: &str,
        table: &str,
        chain: &str,
    ) -> Result<bool> {
        let handles = self
            .list_tagged_rule_handles(sock, family, table, chain)
            .await
            .context("list tagged system rule handles")?;
        for handle in handles {
            self.delete_rule(family, table, chain, handle);
        }
        Ok(true)
    }

    async fn has_rule_with_userdata(
        &self,
        sock: &mut NetlinkSocket,
        family: &str,
        table: &str,
        chain: &str,
        userdata: &[u8],
    ) -> Result<bool> {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        let mut request = nftables::Request::new().op_getrule_dump(&h);
        request
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_chain_bytes(chain.as_bytes());

        let mut iter = sock.request(&request).await?;
        while let Some(reply) = iter.recv().await {
            let (_, attrs) = reply?;
            if let Ok(existing) = attrs.get_userdata() {
                if existing == userdata {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn validate_interception_rules(&self, sock: &mut NetlinkSocket) -> Result<bool> {
        let dns = self
            .count_rules_with_userdata(
                sock,
                "inet",
                "opensnitch",
                "filter_input",
                INTERCEPTION_DNS_TAG.as_bytes(),
            )
            .await?;
        let non_tcp = self
            .count_rules_with_userdata(
                sock,
                "inet",
                "opensnitch",
                "mangle_output",
                INTERCEPTION_NON_TCP_TAG.as_bytes(),
            )
            .await?;
        let tcp_syn = self
            .count_rules_with_userdata(
                sock,
                "inet",
                "opensnitch",
                "mangle_output",
                INTERCEPTION_TCP_SYN_TAG.as_bytes(),
            )
            .await?;

        Ok(dns == 1 && non_tcp == 1 && tcp_syn == 1)
    }

    async fn count_rules_with_userdata(
        &self,
        sock: &mut NetlinkSocket,
        family: &str,
        table: &str,
        chain: &str,
        userdata: &[u8],
    ) -> Result<usize> {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        let mut request = nftables::Request::new().op_getrule_dump(&h);
        request
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_chain_bytes(chain.as_bytes());

        let mut count = 0;
        let mut iter = sock.request(&request).await?;
        while let Some(reply) = iter.recv().await {
            let (_, attrs) = reply?;
            if let Ok(existing) = attrs.get_userdata() {
                if existing == userdata {
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    async fn list_tagged_rule_handles(
        &self,
        sock: &mut NetlinkSocket,
        family: &str,
        table: &str,
        chain: &str,
    ) -> Result<Vec<u64>> {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        let mut request = nftables::Request::new().op_getrule_dump(&h);
        request
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_chain_bytes(chain.as_bytes());

        let mut iter = sock.request(&request).await?;
        let mut handles = Vec::new();
        while let Some(reply) = iter.recv().await {
            let (_, attrs) = reply?;
            let userdata = match attrs.get_userdata() {
                Ok(userdata) => userdata,
                Err(_) => continue,
            };
            if userdata.starts_with(SYSFW_TAG_PREFIX) {
                if let Ok(handle) = attrs.get_handle() {
                    handles.push(handle);
                }
            }
        }

        Ok(handles)
    }

    fn delete_rule(&mut self, family: &str, table: &str, chain: &str, handle: u64) {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        self.inner
            .request()
            .op_delrule_do(&h)
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_chain_bytes(chain.as_bytes())
            .push_handle(handle);
        self.has_operation = true;
    }

    fn batch_header() -> Nfgenmsg {
        let mut h = Nfgenmsg::new();
        h.set_res_id(10);
        h
    }

    pub(super) fn msg_header(family: &str) -> Nfgenmsg {
        Nfgenmsg {
            nfgen_family: family_to_af(family),
            ..Default::default()
        }
    }
}

fn chain_hook_num(hook: &str) -> Option<u32> {
    Some(match hook.to_ascii_lowercase().as_str() {
        "prerouting" => libc::NF_INET_PRE_ROUTING as u32,
        "input" => libc::NF_INET_LOCAL_IN as u32,
        "forward" => libc::NF_INET_FORWARD as u32,
        "output" => libc::NF_INET_LOCAL_OUT as u32,
        "postrouting" => libc::NF_INET_POST_ROUTING as u32,
        "ingress" => libc::NF_INET_INGRESS as u32,
        _ => return None,
    })
}

fn chain_priority(priority: &str) -> Result<i32> {
    if let Ok(value) = priority.parse::<i32>() {
        return Ok(value);
    }

    Ok(match priority.to_ascii_lowercase().as_str() {
        "" => 0,
        "raw" => libc::NF_IP_PRI_RAW,
        "conntrack" => libc::NF_IP_PRI_CONNTRACK,
        "mangle" => libc::NF_IP_PRI_MANGLE,
        "natdest" | "dnat" => libc::NF_IP_PRI_NAT_DST,
        "filter" => libc::NF_IP_PRI_FILTER,
        "security" => libc::NF_IP_PRI_SECURITY,
        "natsource" | "snat" => libc::NF_IP_PRI_NAT_SRC,
        other => anyhow::bail!("unsupported nft priority: {other}"),
    })
}

fn chain_policy(policy: &str) -> Option<u32> {
    match policy.to_ascii_lowercase().as_str() {
        "accept" => Some(nftables::VerdictCode::Accept as u32),
        "drop" => Some(nftables::VerdictCode::Drop as u32),
        _ => None,
    }
}

fn family_to_af(family: &str) -> u8 {
    match family {
        "ip" => libc::AF_INET as u8,
        "ip6" => libc::AF_INET6 as u8,
        "inet" => libc::AF_INET as u8,
        "bridge" => libc::AF_BRIDGE as u8,
        "netdev" => libc::AF_UNSPEC as u8,
        _ => libc::AF_INET as u8,
    }
}
