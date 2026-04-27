use anyhow::{Context, Result};
use netlink_bindings::nftables::{self, Nfgenmsg};
use nix::libc;

use super::{
    FirewallNetlinkOperation, GenerationId, INTERCEPTION_DNS_TAG, INTERCEPTION_NON_TCP_TAG,
    INTERCEPTION_TCP_SYN_TAG, NetfilterTransactionBuilder, NftTable, SYSFW_TAG_PREFIX,
};
use crate::platform::netlink::io::{
    NetlinkSocket, ReplyVisit, commit_chained_transaction, for_each_reply, for_each_reply_until,
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
            FirewallNetlinkOperation::DisableBaseTable { table } => {
                self.delete_table(table.family(), table.name());
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
            FirewallNetlinkOperation::ApplySystemRule { rule } => {
                if self
                    .has_rule_with_userdata(
                        sock,
                        rule.table().family(),
                        rule.table().name(),
                        rule.chain(),
                        rule.encoded_userdata(),
                    )
                    .await?
                {
                    return Ok(true);
                }

                let supported = self.add_system_rule(rule.table().family(), rule);
                if !supported {
                    tracing::debug!(
                        family = rule.table().family(),
                        table = rule.table().name(),
                        chain = rule.chain(),
                        expression_count = rule.expression_count(),
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
                let family = chain.family();
                let table = chain.table().name();
                let chain_name = chain.name();

                if self
                    .has_rule_with_userdata(sock, family, table, chain_name, tag.as_bytes())
                    .await?
                {
                    return Ok(true);
                }

                let supported =
                    if let Some(parsed_rules) = super::exprs::NftRule::parse_all(expression) {
                        let mut all_supported = true;
                        for parsed in parsed_rules {
                            let rule = parsed
                                .with_target(NftTable::new(family, table), chain_name)
                                .with_tag(tag);
                            all_supported &= self.add_system_rule(family, &rule);
                        }
                        all_supported
                    } else {
                        false
                    };
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
        commit_chained_transaction(sock, &chained).await?;
        Ok(())
    }

    fn ensure_base_chains(&mut self) {
        let opensnitch = NftTable::opensnitch();
        self.ensure_table(opensnitch.family(), opensnitch.name());
        let _ = self.ensure_base_chain(
            opensnitch.family(),
            opensnitch.name(),
            "filter_input",
            "input",
            "0",
            "accept",
            "filter",
        );
        let _ = self.ensure_base_chain(
            opensnitch.family(),
            opensnitch.name(),
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

        let found = for_each_reply_until(
            sock,
            &request,
            anyhow::Error::new,
            anyhow::Error::new,
            |(_, attrs)| {
                if let Ok(existing) = attrs.get_userdata() {
                    if existing == userdata {
                        return Ok(ReplyVisit::Break(true));
                    }
                }
                Ok(ReplyVisit::Continue)
            },
        )
        .await?;
        Ok(found.unwrap_or(false))
    }

    async fn validate_interception_rules(&self, sock: &mut NetlinkSocket) -> Result<bool> {
        let dns = self
            .count_rules_with_userdata(
                sock,
                NftTable::opensnitch().family(),
                NftTable::opensnitch().name(),
                "filter_input",
                INTERCEPTION_DNS_TAG.as_bytes(),
            )
            .await?;
        let non_tcp = self
            .count_rules_with_userdata(
                sock,
                NftTable::opensnitch().family(),
                NftTable::opensnitch().name(),
                "mangle_output",
                INTERCEPTION_NON_TCP_TAG.as_bytes(),
            )
            .await?;
        let tcp_syn = self
            .count_rules_with_userdata(
                sock,
                NftTable::opensnitch().family(),
                NftTable::opensnitch().name(),
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
        for_each_reply(
            sock,
            &request,
            anyhow::Error::new,
            anyhow::Error::new,
            |(_, attrs)| {
                if let Ok(existing) = attrs.get_userdata() {
                    if existing == userdata {
                        count += 1;
                    }
                }
                Ok(())
            },
        )
        .await?;
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

        let mut handles = Vec::new();
        for_each_reply(
            sock,
            &request,
            anyhow::Error::new,
            anyhow::Error::new,
            |(_, attrs)| {
                let userdata = match attrs.get_userdata() {
                    Ok(userdata) => userdata,
                    Err(_) => return Ok(()),
                };
                if userdata.starts_with(SYSFW_TAG_PREFIX) {
                    if let Ok(handle) = attrs.get_handle() {
                        handles.push(handle);
                    }
                }
                Ok(())
            },
        )
        .await?;
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
    Some(if hook.eq_ignore_ascii_case("prerouting") {
        libc::NF_INET_PRE_ROUTING as u32
    } else if hook.eq_ignore_ascii_case("input") {
        libc::NF_INET_LOCAL_IN as u32
    } else if hook.eq_ignore_ascii_case("forward") {
        libc::NF_INET_FORWARD as u32
    } else if hook.eq_ignore_ascii_case("output") {
        libc::NF_INET_LOCAL_OUT as u32
    } else if hook.eq_ignore_ascii_case("postrouting") {
        libc::NF_INET_POST_ROUTING as u32
    } else if hook.eq_ignore_ascii_case("ingress") {
        libc::NF_INET_INGRESS as u32
    } else {
        return None;
    })
}

fn chain_priority(priority: &str) -> Result<i32> {
    if let Ok(value) = priority.parse::<i32>() {
        return Ok(value);
    }

    if priority.is_empty() {
        return Ok(0);
    }

    Ok(if priority.eq_ignore_ascii_case("raw") {
        libc::NF_IP_PRI_RAW
    } else if priority.eq_ignore_ascii_case("conntrack") {
        libc::NF_IP_PRI_CONNTRACK
    } else if priority.eq_ignore_ascii_case("mangle") {
        libc::NF_IP_PRI_MANGLE
    } else if priority.eq_ignore_ascii_case("natdest") || priority.eq_ignore_ascii_case("dnat") {
        libc::NF_IP_PRI_NAT_DST
    } else if priority.eq_ignore_ascii_case("filter") {
        libc::NF_IP_PRI_FILTER
    } else if priority.eq_ignore_ascii_case("security") {
        libc::NF_IP_PRI_SECURITY
    } else if priority.eq_ignore_ascii_case("natsource") || priority.eq_ignore_ascii_case("snat") {
        libc::NF_IP_PRI_NAT_SRC
    } else {
        anyhow::bail!("unsupported nft priority: {priority}");
    })
}

fn chain_policy(policy: &str) -> Option<u32> {
    if policy.eq_ignore_ascii_case("accept") {
        Some(nftables::VerdictCode::Accept as u32)
    } else if policy.eq_ignore_ascii_case("drop") {
        Some(nftables::VerdictCode::Drop as u32)
    } else {
        None
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
