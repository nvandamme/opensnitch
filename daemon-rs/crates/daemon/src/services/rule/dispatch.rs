use std::path::Path;

use crate::models::{
    connection_state::ConnectionAttempt, process_state::ProcessInfo, rule_record::RuleOperator,
};

use super::{RuleMatchCaches, RuleService};

pub(super) enum ActiveOperatorDispatch {
    Generic,
    AlwaysTrue,
    SimpleHashOptional,
    ListComposite,
    ProcessParentPath,
    UserName,
    ProcessEnv {
        key: String,
    },
    ProcessCommandDirect,
    Lists {
        operand: CompiledListOperand,
        slot_idx: Option<usize>,
        source_scope: bool,
    },
    Network {
        source: bool,
    },
    Range {
        numeric_operand: Option<NumericOperandKind>,
        bounds: Option<(u64, u64)>,
    },
    SimpleNumeric {
        operand: NumericOperandKind,
        expected: u64,
    },
}

pub(super) enum CompiledListOperand {
    Domains,
    DomainsRegexp,
    IpsOrNets,
    HashMd5,
    Other,
}

#[derive(Clone, Copy)]
pub(super) enum NumericOperandKind {
    ProcessId,
    UserId,
    DestPort,
    SourcePort,
}

impl RuleService {
    pub(super) fn compile_active_operator_dispatch(
        operator: &RuleOperator,
        caches: &RuleMatchCaches,
    ) -> ActiveOperatorDispatch {
        let operand = operator.operand.as_str();
        let type_name = operator.type_name.as_str();
        let is_simple = Self::operator_type_is(type_name, "simple");
        let is_list = Self::operator_type_is(type_name, "list");
        let is_regexp = Self::operator_type_is(type_name, "regexp");
        let is_range = Self::operator_type_is(type_name, "range");
        let is_network = Self::operator_type_is(type_name, "network");

        if operand == "true" {
            return ActiveOperatorDispatch::AlwaysTrue;
        }

        if is_simple && matches!(operand, "process.hash.md5" | "process.hash.sha1") {
            return ActiveOperatorDispatch::SimpleHashOptional;
        }

        if operand == "list" || is_list {
            return ActiveOperatorDispatch::ListComposite;
        }

        if operand == "process.parent.path" {
            return ActiveOperatorDispatch::ProcessParentPath;
        }

        if operand == "user.name" {
            return ActiveOperatorDispatch::UserName;
        }

        if let Some(key) = operand.strip_prefix("process.env.") {
            return ActiveOperatorDispatch::ProcessEnv {
                key: key.to_string(),
            };
        }

        if operand == "process.command" && !is_regexp && !is_range {
            return ActiveOperatorDispatch::ProcessCommandDirect;
        }

        if Self::operator_is_lists(type_name, operand) {
            let slot_idx = caches
                .list_slot_by_path
                .get(Path::new(operator.data.as_str()))
                .copied();
            let source_scope = Self::list_scope_is_source(operator);
            let operand = match operand {
                "lists.domains" => CompiledListOperand::Domains,
                "lists.domains_regexp" => CompiledListOperand::DomainsRegexp,
                "lists.ips" | "lists.nets" => CompiledListOperand::IpsOrNets,
                "lists.hash.md5" => CompiledListOperand::HashMd5,
                _ => CompiledListOperand::Other,
            };
            return ActiveOperatorDispatch::Lists {
                operand,
                slot_idx,
                source_scope,
            };
        }

        if is_network {
            return ActiveOperatorDispatch::Network {
                source: operand == "source.network",
            };
        }

        if is_range {
            return ActiveOperatorDispatch::Range {
                numeric_operand: Self::numeric_operand_from_str(operand),
                bounds: caches
                    .range_bounds
                    .get(operator.data.as_str())
                    .copied()
                    .flatten()
                    .or_else(|| Self::parse_range_bounds(&operator.data)),
            };
        }

        if is_simple
            && let Some(numeric_operand) = Self::numeric_operand_from_str(operand)
            && let Ok(expected) = operator.data.trim().parse::<u64>()
        {
            return ActiveOperatorDispatch::SimpleNumeric {
                operand: numeric_operand,
                expected,
            };
        }

        ActiveOperatorDispatch::Generic
    }

    pub(super) fn numeric_operand_from_str(operand: &str) -> Option<NumericOperandKind> {
        match operand {
            "process.id" => Some(NumericOperandKind::ProcessId),
            "user.id" => Some(NumericOperandKind::UserId),
            "dest.port" => Some(NumericOperandKind::DestPort),
            "source.port" => Some(NumericOperandKind::SourcePort),
            _ => None,
        }
    }

    pub(super) fn numeric_operand_value(
        kind: NumericOperandKind,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
    ) -> u64 {
        match kind {
            NumericOperandKind::ProcessId => u64::from(process.pid),
            NumericOperandKind::UserId => u64::from(attempt.uid),
            NumericOperandKind::DestPort => u64::from(attempt.dst_port),
            NumericOperandKind::SourcePort => u64::from(attempt.src_port),
        }
    }
}
