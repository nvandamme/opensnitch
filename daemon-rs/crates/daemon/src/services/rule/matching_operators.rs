use std::borrow::Cow;
use std::path::Path;

use crate::models::{
    connection_state::{ConnectionAttempt, TransportProtocol},
    process_state::ProcessInfo,
    rule_record::RuleOperator,
};

use super::{ListPathSlotCache, RegexCacheKey, RuleMatchCaches, RuleService};

use super::matching::AttemptDerived;

impl RuleService {
    pub(super) fn operator_matches_against_with_derived(
        operator: &RuleOperator,
        attempt: &ConnectionAttempt,
        derived: &AttemptDerived,
        process: &ProcessInfo,
        dst_host: Option<&str>,
        caches: &RuleMatchCaches,
    ) -> bool {
        if operator.operand == "true" {
            return true;
        }

        if Self::operator_type_is(operator.type_name.as_str(), "simple")
            && matches!(
                operator.operand.as_str(),
                "process.hash.md5" | "process.hash.sha1"
            )
        {
            let Some(hash) =
                Self::operator_operand_value(operator, attempt, derived, process, dst_host)
            else {
                // Hash not yet available — do not match; fall through to default action.
                return false;
            };
            return Self::operator_matches_text(operator, hash.as_ref(), caches);
        }

        if operator.operand == "list" || Self::operator_type_is(operator.type_name.as_str(), "list")
        {
            return operator.list.iter().all(|item| {
                Self::operator_matches_against_with_derived(
                    item, attempt, derived, process, dst_host, caches,
                )
            });
        }

        if operator.operand == "process.parent.path" {
            return process
                .parent_chain
                .iter()
                .any(|parent| Self::operator_matches_text(operator, parent.path.as_str(), caches));
        }

        if operator.operand == "user.name" {
            let Some(uid) = Self::resolve_user_name_uid(operator.data.as_str(), caches) else {
                return false;
            };
            return attempt.uid == uid;
        }

        if let Some(env_key) = operator.operand.strip_prefix("process.env.") {
            let env_value = Self::env_preview_get(process, env_key).unwrap_or("");
            return Self::operator_matches_text(operator, env_value, caches);
        }

        if operator.operand == "process.command"
            && !Self::operator_type_is(operator.type_name.as_str(), "regexp")
            && !Self::operator_type_is(operator.type_name.as_str(), "range")
        {
            return Self::matches_joined_args(&process.args, &operator.data, operator.sensitive);
        }

        if Self::operator_is_lists(operator.type_name.as_str(), operator.operand.as_str()) {
            return Self::operator_matches_lists(
                operator, attempt, derived, process, dst_host, caches,
            );
        }

        if Self::operator_type_is(operator.type_name.as_str(), "network") {
            return Self::operator_matches_network(operator, derived, caches);
        }

        if Self::operator_type_is(operator.type_name.as_str(), "range") {
            if let Some(candidate) =
                Self::operator_numeric_value(&operator.operand, attempt, process)
            {
                let Some((min, max)) = caches
                    .range_bounds
                    .get(operator.data.as_str())
                    .copied()
                    .flatten()
                    .or_else(|| Self::parse_range_bounds(&operator.data))
                else {
                    return false;
                };
                return candidate >= min && candidate <= max;
            }
            let Some(candidate) =
                Self::operator_operand_value(operator, attempt, derived, process, dst_host)
            else {
                return false;
            };
            return Self::matches_range_spec(candidate.as_ref(), &operator.data);
        }

        if Self::operator_type_is(operator.type_name.as_str(), "simple")
            && let Some(candidate) =
                Self::operator_numeric_value(&operator.operand, attempt, process)
        {
            let Some(expected) = operator.data.trim().parse::<u64>().ok() else {
                return false;
            };
            return candidate == expected;
        }

        let Some(candidate) =
            Self::operator_operand_value(operator, attempt, derived, process, dst_host)
        else {
            return false;
        };

        Self::operator_matches_text(operator, candidate.as_ref(), caches)
    }

    pub(super) fn operator_operand_value<'a>(
        operator: &RuleOperator,
        attempt: &'a ConnectionAttempt,
        derived: &'a AttemptDerived,
        process: &'a ProcessInfo,
        dst_host: Option<&'a str>,
    ) -> Option<Cow<'a, str>> {
        match operator.operand.as_str() {
            "process.path" => Some(Cow::Borrowed(process.path.as_str())),
            "process.command" => Some(Cow::Borrowed(derived.process_command(&process.args))),
            "process.parent.path" => process
                .parent_chain
                .first()
                .map(|node| Cow::Borrowed(node.path.as_str())),
            "process.id" => Some(Cow::Borrowed(derived.process_id_text(process.pid))),
            "process.hash.sha1" => process.process_hash_sha1.as_deref().map(Cow::Borrowed),
            "process.hash.md5" => process.process_hash_md5.as_deref().map(Cow::Borrowed),
            "user.id" => Some(Cow::Borrowed(derived.user_id_text(attempt.uid))),
            "dest.ip" => Some(Cow::Borrowed(derived.dst_ip_text())),
            "dest.network" => Some(Cow::Borrowed(derived.dst_ip_text())),
            "dest.host" => dst_host.map(Cow::Borrowed),
            "dest.port" => Some(Cow::Borrowed(derived.dst_port_text(attempt.dst_port))),
            "source.ip" => Some(Cow::Borrowed(derived.src_ip_text())),
            "source.network" => Some(Cow::Borrowed(derived.src_ip_text())),
            "source.port" => Some(Cow::Borrowed(derived.src_port_text(attempt.src_port))),
            "iface.in" => {
                crate::platform::netlink::ifaces::NetIfaceAdapter::interface_name_by_index(
                    attempt.iface_in_idx,
                )
                .ok()
                .flatten()
                .map(Cow::Owned)
            }
            "iface.out" => {
                crate::platform::netlink::ifaces::NetIfaceAdapter::interface_name_by_index(
                    attempt.iface_out_idx,
                )
                .ok()
                .flatten()
                .map(Cow::Owned)
            }
            "protocol" => Some(Cow::Borrowed(match attempt.protocol {
                TransportProtocol::Tcp => "TCP",
                TransportProtocol::Udp => "UDP",
                TransportProtocol::UdpLite => "UDPLITE",
                TransportProtocol::Sctp => "SCTP",
                TransportProtocol::Icmp => "ICMP",
            })),
            _ => None,
        }
    }

    pub(super) fn operator_matches_text(
        operator: &RuleOperator,
        candidate: &str,
        caches: &RuleMatchCaches,
    ) -> bool {
        if Self::operator_type_is(operator.type_name.as_str(), "regexp") {
            let lowered;
            let value = if operator.sensitive {
                candidate
            } else if candidate.chars().any(|ch| ch.is_uppercase()) {
                lowered = candidate.to_lowercase();
                lowered.as_str()
            } else {
                candidate
            };

            let fast_map = if operator.sensitive {
                &caches.regexes_sensitive_fast
            } else {
                &caches.regexes_insensitive_fast
            };
            if let Some(regex) = fast_map.get(operator.data.as_str()) {
                return regex.is_match(value);
            }

            return caches
                .regexes
                .get(&RegexCacheKey::new(&operator.data, operator.sensitive))
                .map(|regex| regex.is_match(value))
                .unwrap_or(false);
        }

        Self::compare_with(candidate, &operator.data, operator.sensitive)
    }

    pub(super) fn operator_matches_network(
        operator: &RuleOperator,
        derived: &AttemptDerived,
        caches: &RuleMatchCaches,
    ) -> bool {
        Self::operator_matches_network_with_derived(
            operator,
            operator.operand == "source.network",
            derived,
            caches,
        )
    }

    pub(super) fn operator_matches_network_with_derived(
        operator: &RuleOperator,
        source: bool,
        derived: &AttemptDerived,
        caches: &RuleMatchCaches,
    ) -> bool {
        let Some(ip) = Self::list_candidate_ip_addr(derived, source) else {
            return false;
        };

        if let Some(specs) = caches.network_specs_compiled.get(operator.data.as_str()) {
            return specs
                .iter()
                .any(|(network_ip, prefix_len)| Self::prefix_match(&ip, network_ip, *prefix_len));
        }

        if let Some(alias_specs) = caches.network_aliases.get(operator.data.as_str()) {
            return alias_specs
                .iter()
                .any(|spec| Self::matches_network_spec(&ip, spec));
        }

        Self::matches_network_spec(&ip, &operator.data)
    }

    pub(super) fn list_slot_for_path<'a>(
        caches: &'a RuleMatchCaches,
        list_path: &Path,
    ) -> Option<&'a ListPathSlotCache> {
        caches
            .list_slot_by_path
            .get(list_path)
            .and_then(|idx| caches.list_slots.get(*idx))
    }

    pub(super) fn operator_matches_lists(
        operator: &RuleOperator,
        _attempt: &ConnectionAttempt,
        derived: &AttemptDerived,
        process: &ProcessInfo,
        dst_host: Option<&str>,
        caches: &RuleMatchCaches,
    ) -> bool {
        let source_scope = Self::list_scope_is_source(operator);
        let ip_text = Self::list_candidate_ip_text(derived, source_scope);
        let ip_addr = Self::list_candidate_ip_addr(derived, source_scope);

        let operand = operator.operand.as_str();
        let list_path = Path::new(operator.data.as_str());
        if let Some(slot) = Self::list_slot_for_path(caches, list_path) {
            return match operand {
                "lists.domains" => {
                    let Some(host) = Self::prepare_host(dst_host, operator.sensitive) else {
                        return false;
                    };
                    Self::match_domain_list(
                        host.as_ref(),
                        Some(&slot.domains),
                        Some(&slot.domain_wildcards),
                        Some(&slot.domain_globs),
                    )
                }
                "lists.domains_regexp" => {
                    Self::match_domain_regexp_slot(dst_host, operator.sensitive, slot)
                }
                "lists.ips" | "lists.nets" => Self::match_ip_or_net(
                    ip_text,
                    ip_addr,
                    Some(&slot.trimmed_values),
                    Some(&slot.networks),
                ),
                "lists.hash.md5" => Self::match_hash_md5(process, Some(&slot.trimmed_values)),
                _ => false,
            };
        }

        match operand {
            "lists.domains" => {
                let Some(host) = Self::prepare_host(dst_host, operator.sensitive) else {
                    return false;
                };
                Self::match_domain_list(
                    host.as_ref(),
                    caches.list_domains.get(list_path),
                    caches.list_domain_wildcards.get(list_path),
                    caches.list_domain_globs.get(list_path),
                )
            }
            "lists.domains_regexp" => {
                Self::match_domain_regexp_map(dst_host, operator.sensitive, list_path, caches)
            }
            "lists.ips" | "lists.nets" => Self::match_ip_or_net(
                ip_text,
                ip_addr,
                caches.list_trimmed_values.get(list_path),
                caches.list_networks.get(list_path),
            ),
            "lists.hash.md5" => {
                Self::match_hash_md5(process, caches.list_trimmed_values.get(list_path))
            }
            _ => false,
        }
    }
}
