use std::{borrow::Cow, collections::HashSet, net::IpAddr, path::Path, sync::OnceLock};

use globset::GlobMatcher;

use crate::{
    models::{
        connection::state::ConnectionAttempt, process::state::ProcessInfo,
        rule::record::RuleOperator,
    },
    utils::name_parsing::case_folded,
};

use super::{
    ActiveRuleCompiled, CidrTrieIndex, DomainWildcardTrie, ListPathSlotCache, ListRegexCacheKey,
    RuleMatchCaches, RuleService,
    dispatch::{ActiveOperatorDispatch, CompiledListOperand},
};

pub(super) struct AttemptDerived {
    pub(super) src_addr: Option<IpAddr>,
    pub(super) dst_addr: Option<IpAddr>,
    src_ip_text: OnceLock<String>,
    dst_ip_text: OnceLock<String>,
    process_command: OnceLock<String>,
    process_id: OnceLock<String>,
    user_id_text: OnceLock<String>,
    dst_port_text: OnceLock<String>,
    src_port_text: OnceLock<String>,
}

#[derive(Default, Clone, Copy)]
pub(super) struct AttemptTextNeeds {
    pub(super) src_ip_text: bool,
    pub(super) dst_ip_text: bool,
}

impl Default for AttemptDerived {
    fn default() -> Self {
        Self {
            src_addr: None,
            dst_addr: None,
            src_ip_text: OnceLock::new(),
            dst_ip_text: OnceLock::new(),
            process_command: OnceLock::new(),
            process_id: OnceLock::new(),
            user_id_text: OnceLock::new(),
            dst_port_text: OnceLock::new(),
            src_port_text: OnceLock::new(),
        }
    }
}

impl AttemptDerived {
    pub(super) fn from_attempt(attempt: &ConnectionAttempt) -> Self {
        Self {
            src_addr: Some(attempt.src_addr),
            dst_addr: Some(attempt.dst_addr),
            src_ip_text: OnceLock::new(),
            dst_ip_text: OnceLock::new(),
            process_command: OnceLock::new(),
            process_id: OnceLock::new(),
            user_id_text: OnceLock::new(),
            dst_port_text: OnceLock::new(),
            src_port_text: OnceLock::new(),
        }
    }

    pub(super) fn src_ip_text(&self) -> &str {
        self.src_ip_text
            .get_or_init(|| {
                self.src_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default()
            })
            .as_str()
    }

    pub(super) fn dst_ip_text(&self) -> &str {
        self.dst_ip_text
            .get_or_init(|| {
                self.dst_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default()
            })
            .as_str()
    }

    pub(super) fn process_command<'a>(&'a self, args: &[String]) -> &'a str {
        self.process_command.get_or_init(|| args.join(" ")).as_str()
    }

    pub(super) fn process_id_text(&self, pid: u32) -> &str {
        self.process_id.get_or_init(|| pid.to_string()).as_str()
    }

    pub(super) fn user_id_text(&self, uid: u32) -> &str {
        self.user_id_text.get_or_init(|| uid.to_string()).as_str()
    }

    pub(super) fn dst_port_text(&self, port: u16) -> &str {
        self.dst_port_text.get_or_init(|| port.to_string()).as_str()
    }

    pub(super) fn src_port_text(&self, port: u16) -> &str {
        self.src_port_text.get_or_init(|| port.to_string()).as_str()
    }

    pub(super) fn prewarm(&self, needs: AttemptTextNeeds) {
        if needs.src_ip_text {
            let _ = self.src_ip_text();
        }
        if needs.dst_ip_text {
            let _ = self.dst_ip_text();
        }
    }
}

impl RuleService {
    pub(super) fn normalize_host<'a>(host: Option<&'a str>) -> Option<&'a str> {
        host.map(str::trim).filter(|value| !value.is_empty())
    }

    pub(super) fn prepare_host<'a>(host: Option<&'a str>, sensitive: bool) -> Option<Cow<'a, str>> {
        let host = Self::normalize_host(host)?;
        if !sensitive && Self::has_uppercase(host) {
            Some(Cow::Owned(host.to_lowercase()))
        } else {
            Some(Cow::Borrowed(host))
        }
    }

    pub(super) fn match_domain_list(
        host: &str,
        domains: Option<&HashSet<String>>,
        wildcards: Option<&DomainWildcardTrie>,
        globs: Option<&Vec<GlobMatcher>>,
    ) -> bool {
        domains.is_some_and(|s| s.contains(host))
            || wildcards.is_some_and(|t| t.matches_host(host))
            || globs.is_some_and(|g| g.iter().any(|glob| glob.is_match(host)))
    }

    pub(super) fn match_ip_or_net(
        ip_text: &str,
        ip_addr: Option<IpAddr>,
        values: Option<&HashSet<String>>,
        networks: Option<&CidrTrieIndex>,
    ) -> bool {
        if values.is_some_and(|s| s.contains(ip_text)) {
            return true;
        }
        ip_addr
            .and_then(|ip| networks.filter(|n| n.has_entries()).map(|n| n.contains(ip)))
            .unwrap_or(false)
    }

    pub(super) fn match_domain_regexp_slot(
        dst_host: Option<&str>,
        sensitive: bool,
        slot: &ListPathSlotCache,
    ) -> bool {
        let Some(host) = Self::prepare_host(dst_host, sensitive) else {
            return false;
        };
        let regex_cache = if sensitive {
            slot.regex_sensitive.as_ref()
        } else {
            slot.regex_insensitive.as_ref()
        };
        regex_cache
            .map(|cache| cache.matches(host.as_ref()))
            .unwrap_or(false)
    }

    pub(super) fn match_hash_md5(process: &ProcessInfo, values: Option<&HashSet<String>>) -> bool {
        let Some(hash) = process.process_hash_md5.as_deref() else {
            return false;
        };
        values.is_some_and(|set| set.contains(hash.trim()))
    }

    pub(super) fn resolve_user_name_uid(name: &str, caches: &RuleMatchCaches) -> Option<u32> {
        caches
            .user_name_uid
            .get(name)
            .copied()
            .flatten()
            .or_else(|| {
                nix::unistd::User::from_name(name)
                    .ok()
                    .flatten()
                    .map(|user| user.uid.as_raw())
            })
    }

    pub(super) fn match_domain_regexp_map(
        dst_host: Option<&str>,
        sensitive: bool,
        list_path: &Path,
        caches: &RuleMatchCaches,
    ) -> bool {
        let Some(host) = Self::prepare_host(dst_host, sensitive) else {
            return false;
        };
        let host = host.as_ref();
        let fast_map = if sensitive {
            &caches.list_regexes_sensitive_fast
        } else {
            &caches.list_regexes_insensitive_fast
        };
        fast_map
            .get(list_path)
            .map(|cache| cache.matches(host))
            .or_else(|| {
                caches
                    .list_regexes
                    .get(&ListRegexCacheKey::new(list_path, sensitive))
                    .map(|cache| cache.matches(host))
            })
            .unwrap_or(false)
    }

    pub(super) fn matches_range_spec(value: &str, range: &str) -> bool {
        let value = match value.trim().parse::<u64>() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let Some((min, max)) = Self::parse_range_bounds(range) else {
            return false;
        };
        value >= min && value <= max
    }

    pub(super) fn parse_range_bounds(range: &str) -> Option<(u64, u64)> {
        let (min_raw, max_raw) = range.split_once('-')?;
        let min = min_raw.trim().parse::<u64>().ok()?;
        let max = max_raw.trim().parse::<u64>().ok()?;
        Some((min, max))
    }

    pub(super) fn operator_numeric_value(
        operand: &str,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
    ) -> Option<u64> {
        let kind = Self::numeric_operand_from_str(operand)?;
        Some(Self::numeric_operand_value(kind, attempt, process))
    }

    pub(super) fn env_preview_get<'a>(process: &'a ProcessInfo, key: &str) -> Option<&'a str> {
        if let Some(value) = process.env_map.get(key) {
            return Some(value.as_str());
        }
        process.env_preview.iter().find_map(|item| {
            let (name, value) = item.split_once('=')?;
            (name == key).then_some(value)
        })
    }

    pub(super) fn compare_with(candidate: &str, expected: &str, sensitive: bool) -> bool {
        if sensitive {
            candidate == expected
        } else {
            // Inputs may be UTF-8 (JSON/protobuf); use Unicode-aware case folding.
            case_folded(candidate) == case_folded(expected)
        }
    }

    pub(super) fn has_uppercase(value: &str) -> bool {
        value.chars().any(|c| c.is_uppercase())
    }

    pub(super) fn matches_joined_args(args: &[String], expected: &str, sensitive: bool) -> bool {
        if args.is_empty() {
            return expected.is_empty();
        }

        if !sensitive {
            // UTF-8 aware case-insensitive compare for command-line text.
            return case_folded(&args.join(" ")) == case_folded(expected);
        }

        let expected_bytes = expected.as_bytes();
        let mut cursor = 0usize;

        for (idx, arg) in args.iter().enumerate() {
            if idx > 0 {
                if cursor >= expected_bytes.len() || expected_bytes[cursor] != b' ' {
                    return false;
                }
                cursor += 1;
            }

            let arg_bytes = arg.as_bytes();
            if cursor + arg_bytes.len() > expected_bytes.len() {
                return false;
            }

            let segment = &expected_bytes[cursor..cursor + arg_bytes.len()];
            let matches = segment == arg_bytes;
            if !matches {
                return false;
            }
            cursor += arg_bytes.len();
        }

        cursor == expected_bytes.len()
    }

    pub(super) fn matches_network_spec(ip: &IpAddr, spec: &str) -> bool {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return false;
        }

        let (network_ip, prefix_len) = match RuleService::parse_network_spec(trimmed) {
            Some(value) => value,
            None => return false,
        };

        Self::prefix_match(ip, &network_ip, prefix_len)
    }

    pub(crate) fn parse_network_spec(spec: &str) -> Option<(IpAddr, u8)> {
        if let Some((ip_raw, prefix_raw)) = spec.split_once('/') {
            let network_ip = ip_raw.trim().parse::<IpAddr>().ok()?;
            let prefix = prefix_raw.trim().parse::<u8>().ok()?;
            let max = match network_ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max {
                return None;
            }
            return Some((network_ip, prefix));
        }

        let ip = spec.parse::<IpAddr>().ok()?;
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Some((ip, prefix))
    }

    pub(super) fn prefix_match(ip: &IpAddr, network: &IpAddr, prefix_len: u8) -> bool {
        fn prefix_bytes_match(ip: &[u8], network: &[u8], prefix_len: u8) -> bool {
            if prefix_len == 0 {
                return true;
            }

            let full_bytes = usize::from(prefix_len / 8);
            let remaining_bits = prefix_len % 8;

            if ip[..full_bytes] != network[..full_bytes] {
                return false;
            }

            if remaining_bits == 0 {
                return true;
            }

            let mask = u8::MAX << (8 - remaining_bits);
            (ip[full_bytes] & mask) == (network[full_bytes] & mask)
        }

        match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(network)) => {
                let ip_octets = ip.octets();
                let network_octets = network.octets();
                prefix_bytes_match(&ip_octets, &network_octets, prefix_len)
            }
            (IpAddr::V6(ip), IpAddr::V6(network)) => {
                let ip_octets = ip.octets();
                let network_octets = network.octets();
                prefix_bytes_match(&ip_octets, &network_octets, prefix_len)
            }
            _ => false,
        }
    }
}

impl RuleService {
    pub(super) fn collect_attempt_text_needs(
        operator: &RuleOperator,
        needs: &mut AttemptTextNeeds,
    ) {
        match operator.operand.as_str() {
            "source.ip" => needs.src_ip_text = true,
            "dest.ip" => needs.dst_ip_text = true,
            "source.network" if !Self::operator_type_is(&operator.type_name, "network") => {
                needs.src_ip_text = true
            }
            "dest.network" if !Self::operator_type_is(&operator.type_name, "network") => {
                needs.dst_ip_text = true
            }
            "lists.ips" | "lists.nets"
                if Self::operator_type_is(&operator.type_name, "lists")
                    || operator.operand.starts_with("lists.") =>
            {
                if Self::list_scope_is_source(operator) {
                    needs.src_ip_text = true;
                } else {
                    needs.dst_ip_text = true;
                }
            }
            _ => {}
        }

        for sub in &operator.list {
            Self::collect_attempt_text_needs(sub, needs);
        }
    }

    pub(super) fn list_scope_is_source(operator: &RuleOperator) -> bool {
        let Some(scope) = operator.scope.as_deref() else {
            return false;
        };
        case_folded(scope) == "src"
    }

    pub(super) fn list_candidate_ip_text<'a>(derived: &'a AttemptDerived, source: bool) -> &'a str {
        if source {
            derived.src_ip_text()
        } else {
            derived.dst_ip_text()
        }
    }

    pub(super) fn list_candidate_ip_addr(derived: &AttemptDerived, source: bool) -> Option<IpAddr> {
        if source {
            derived.src_addr
        } else {
            derived.dst_addr
        }
    }

    pub(super) fn operator_matches_compiled_rule(
        compiled: &ActiveRuleCompiled,
        attempt: &ConnectionAttempt,
        derived: &AttemptDerived,
        process: &ProcessInfo,
        dst_host: Option<&str>,
        caches: &RuleMatchCaches,
    ) -> bool {
        match &compiled.dispatch {
            ActiveOperatorDispatch::AlwaysTrue => true,
            ActiveOperatorDispatch::SimpleHashOptional => {
                let Some(hash) = Self::operator_operand_value(
                    &compiled.operator,
                    attempt,
                    derived,
                    process,
                    dst_host,
                ) else {
                    // Hash not yet available (background computation in progress).
                    // Return false so the rule does not match on an unverified hash —
                    // the verdict flow will fall through to the configured default action.
                    return false;
                };
                Self::operator_matches_text(&compiled.operator, hash.as_ref(), caches)
            }
            ActiveOperatorDispatch::ListComposite => compiled.operator.list.iter().all(|item| {
                Self::operator_matches_against_with_derived(
                    item, attempt, derived, process, dst_host, caches,
                )
            }),
            ActiveOperatorDispatch::ProcessParentPath => {
                process.parent_chain.iter().any(|parent| {
                    Self::operator_matches_text(&compiled.operator, parent.path.as_str(), caches)
                })
            }
            ActiveOperatorDispatch::UserName => {
                let Some(uid) =
                    Self::resolve_user_name_uid(compiled.operator.data.as_str(), caches)
                else {
                    return false;
                };
                attempt.uid == uid
            }
            ActiveOperatorDispatch::ProcessEnv { key } => {
                let env_value = Self::env_preview_get(process, key).unwrap_or("");
                Self::operator_matches_text(&compiled.operator, env_value, caches)
            }
            ActiveOperatorDispatch::ProcessCommandDirect => Self::matches_joined_args(
                &process.args,
                &compiled.operator.data,
                compiled.operator.sensitive,
            ),
            ActiveOperatorDispatch::Lists {
                operand,
                slot_idx,
                source_scope,
            } => Self::operator_matches_lists_compiled(
                &compiled.operator,
                operand,
                *slot_idx,
                *source_scope,
                attempt,
                derived,
                process,
                dst_host,
                caches,
            ),
            ActiveOperatorDispatch::Network { source } => {
                Self::operator_matches_network_with_derived(
                    &compiled.operator,
                    *source,
                    derived,
                    caches,
                )
            }
            ActiveOperatorDispatch::Range {
                numeric_operand,
                bounds,
            } => {
                if let Some(kind) = numeric_operand {
                    let Some((min, max)) = bounds else {
                        return false;
                    };
                    let candidate = Self::numeric_operand_value(*kind, attempt, process);
                    return candidate >= *min && candidate <= *max;
                }

                let Some(candidate) = Self::operator_operand_value(
                    &compiled.operator,
                    attempt,
                    derived,
                    process,
                    dst_host,
                ) else {
                    return false;
                };
                Self::matches_range_spec(candidate.as_ref(), &compiled.operator.data)
            }
            ActiveOperatorDispatch::SimpleNumeric { operand, expected } => {
                Self::numeric_operand_value(*operand, attempt, process) == *expected
            }
            ActiveOperatorDispatch::Generic => Self::operator_matches_against_with_derived(
                &compiled.operator,
                attempt,
                derived,
                process,
                dst_host,
                caches,
            ),
        }
    }

    fn operator_matches_lists_compiled(
        operator: &RuleOperator,
        compiled_operand: &CompiledListOperand,
        slot_idx: Option<usize>,
        source_scope: bool,
        attempt: &ConnectionAttempt,
        derived: &AttemptDerived,
        process: &ProcessInfo,
        dst_host: Option<&str>,
        caches: &RuleMatchCaches,
    ) -> bool {
        let slot = match compiled_operand {
            CompiledListOperand::Other => {
                return Self::operator_matches_lists(
                    operator, attempt, derived, process, dst_host, caches,
                );
            }
            _ => {
                let Some(slot_idx) = slot_idx else {
                    return false;
                };
                let Some(slot) = caches.list_slots.get(slot_idx) else {
                    return false;
                };
                slot
            }
        };

        let ip_text = Self::list_candidate_ip_text(derived, source_scope);
        let ip_addr = Self::list_candidate_ip_addr(derived, source_scope);

        match compiled_operand {
            CompiledListOperand::Domains => {
                let Some(host) = Self::prepare_host(dst_host, operator.sensitive) else {
                    return false;
                };
                let host = host.as_ref();
                // Fast-path cascade: HashSet (O(1)) → trie (O(labels)) → globs → regex.
                // The regex sub-cache is reached only when all structural lookups miss,
                // so the hot path for plain/AdBlock domain lists is unaffected.
                Self::match_domain_list(
                    host,
                    Some(&slot.domains),
                    Some(&slot.domain_wildcards),
                    Some(&slot.domain_globs),
                ) || slot
                    .domains_regex
                    .as_ref()
                    .is_some_and(|cache| cache.matches(host))
            }
            CompiledListOperand::DomainsRegexp => {
                Self::match_domain_regexp_slot(dst_host, operator.sensitive, slot)
            }
            CompiledListOperand::IpsOrNets => Self::match_ip_or_net(
                ip_text,
                ip_addr,
                Some(&slot.trimmed_values),
                Some(&slot.networks),
            ),
            CompiledListOperand::HashMd5 => {
                Self::match_hash_md5(process, Some(&slot.trimmed_values))
            }
            CompiledListOperand::Other => false,
        }
    }

    #[cfg(test)]
    pub(super) fn operator_matches_against(
        operator: &RuleOperator,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
        caches: &RuleMatchCaches,
    ) -> bool {
        let derived = AttemptDerived::from_attempt(attempt);
        Self::operator_matches_against_with_derived(
            operator, attempt, &derived, process, dst_host, caches,
        )
    }
}
