use opensnitch_proto::pb;
use opensnitch_transport_wire_core::{
    WireAlert, WireAlertData, WireAlertReply, WireConnection, WireEvent, WireFwChain,
    WireFwExpression, WireFwRule, WireFwStatement, WireFwStatementValue, WireNotification,
    WirePingReply, WirePingRequest, WireRule, WireRuleOperator, WireStatistics, WireStringInt,
    WireSubscribeConfig, WireSysFirewall,
};
#[cfg(feature = "subscriptions")]
use opensnitch_transport_wire_core::{
    WireSubscription, WireSubscriptionCommand, WireSubscriptionCommandAck,
    WireSubscriptionRefreshMetadata, WireSubscriptionReply, WireSubscriptionRequest,
};

pub(crate) fn pb_subscribe_config_from_wire(cfg: WireSubscribeConfig) -> pb::ClientConfig {
    pb::ClientConfig {
        id: cfg.id,
        name: cfg.name,
        version: cfg.version,
        is_firewall_running: cfg.is_firewall_running,
        config: cfg.config,
        log_level: cfg.log_level,
        rules: cfg.rules.into_iter().map(pb_rule_from_wire).collect(),
        system_firewall: cfg.system_firewall.map(wire_sys_firewall_to_proto),
    }
}

pub(crate) fn wire_subscribe_config_from_proto(cfg: pb::ClientConfig) -> WireSubscribeConfig {
    WireSubscribeConfig {
        id: cfg.id,
        name: cfg.name,
        version: cfg.version,
        is_firewall_running: cfg.is_firewall_running,
        config: cfg.config,
        log_level: cfg.log_level,
        rules: cfg.rules.into_iter().map(wire_rule_from_pb).collect(),
        system_firewall: cfg.system_firewall.map(wire_sys_firewall_from_pb),
    }
}

pub(crate) fn pb_ping_request_from_wire(req: WirePingRequest) -> pb::PingRequest {
    pb::PingRequest {
        id: req.id,
        stats: req.stats.map(pb_statistics_from_wire),
    }
}

pub(crate) fn wire_ping_reply_from_proto(reply: pb::PingReply) -> WirePingReply {
    WirePingReply { id: reply.id }
}

pub(crate) fn wire_alert_reply_from_proto(reply: pb::MsgResponse) -> WireAlertReply {
    WireAlertReply { id: reply.id }
}

pub(crate) fn wire_alert_to_proto(alert: WireAlert) -> pb::Alert {
    let data = alert.data.map(|payload| match payload {
        WireAlertData::Text(text) => pb::alert::Data::Text(text),
        WireAlertData::Connection(conn) => pb::alert::Data::Conn(pb::Connection {
            protocol: conn.protocol,
            src_ip: conn.src_ip,
            src_port: conn.src_port,
            dst_ip: conn.dst_ip,
            dst_host: conn.dst_host,
            dst_port: conn.dst_port,
            user_id: conn.user_id,
            process_id: conn.process_id,
            process_path: conn.process_path,
            process_cwd: conn.process_cwd,
            process_args: conn.process_args,
            process_env: conn.process_env,
            process_checksums: conn.process_checksums,
            process_tree: conn
                .process_tree
                .into_iter()
                .map(wire_string_int_to_proto)
                .collect(),
            ..Default::default()
        }),
        WireAlertData::Process(proc_info) => pb::alert::Data::Proc(pb::Process {
            pid: proc_info.pid,
            ppid: proc_info.ppid,
            uid: proc_info.uid,
            comm: proc_info.comm,
            path: proc_info.path,
            args: proc_info.args,
            env: proc_info.env,
            cwd: proc_info.cwd,
            checksums: proc_info.checksums,
            io_reads: proc_info.io_reads,
            io_writes: proc_info.io_writes,
            net_reads: proc_info.net_reads,
            net_writes: proc_info.net_writes,
            process_tree: proc_info
                .process_tree
                .into_iter()
                .map(wire_string_int_to_proto)
                .collect(),
            ..Default::default()
        }),
    });

    pb::Alert {
        id: alert.id,
        r#type: alert.alert_type,
        action: alert.action,
        priority: alert.priority,
        what: alert.what,
        data,
    }
}

pub(crate) fn wire_string_int_to_proto(entry: WireStringInt) -> pb::StringInt {
    pb::StringInt {
        key: entry.key,
        value: entry.value,
    }
}

pub(crate) fn pb_statistics_from_wire(stats: WireStatistics) -> pb::Statistics {
    pb::Statistics {
        daemon_version: stats.daemon_version,
        rules: stats.rules,
        uptime: stats.uptime,
        dns_responses: stats.dns_responses,
        connections: stats.connections,
        ignored: stats.ignored,
        accepted: stats.accepted,
        dropped: stats.dropped,
        rule_hits: stats.rule_hits,
        rule_misses: stats.rule_misses,
        by_proto: stats.by_proto,
        by_address: stats.by_address,
        by_host: stats.by_host,
        by_port: stats.by_port,
        by_uid: stats.by_uid,
        by_executable: stats.by_executable,
        events: stats.events.into_iter().map(pb_event_from_wire).collect(),
    }
}

pub(crate) fn pb_event_from_wire(event: WireEvent) -> pb::Event {
    pb::Event {
        time: event.time,
        connection: event.connection.map(pb_connection_from_wire),
        rule: event.rule.map(pb_rule_from_wire),
        unixnano: event.unixnano,
    }
}

pub(crate) fn pb_connection_from_wire(conn: WireConnection) -> pb::Connection {
    pb::Connection {
        protocol: conn.protocol,
        src_ip: conn.src_ip,
        src_port: conn.src_port,
        dst_ip: conn.dst_ip,
        dst_host: conn.dst_host,
        dst_port: conn.dst_port,
        user_id: conn.user_id,
        process_id: conn.process_id,
        process_path: conn.process_path,
        process_cwd: conn.process_cwd,
        process_args: conn.process_args,
        process_env: conn.process_env,
        process_checksums: conn.process_checksums,
        process_tree: conn
            .process_tree
            .into_iter()
            .map(wire_string_int_to_proto)
            .collect(),
    }
}

pub(crate) fn wire_notification_from_proto(notification: pb::Notification) -> WireNotification {
    WireNotification {
        id: notification.id,
        action: notification.r#type,
        data: notification.data,
        rules: notification
            .rules
            .into_iter()
            .map(wire_rule_from_pb)
            .collect(),
        sys_firewall: notification.sys_firewall.map(wire_sys_firewall_from_pb),
    }
}

pub(crate) fn wire_rule_from_pb(rule: pb::Rule) -> WireRule {
    WireRule {
        created: rule.created,
        name: rule.name,
        description: rule.description,
        enabled: rule.enabled,
        precedence: rule.precedence,
        nolog: rule.nolog,
        action: rule.action,
        duration: rule.duration,
        operator: rule.operator.map(wire_rule_operator_from_pb),
    }
}

pub(crate) fn pb_rule_from_wire(rule: WireRule) -> pb::Rule {
    pb::Rule {
        created: rule.created,
        name: rule.name,
        description: rule.description,
        enabled: rule.enabled,
        precedence: rule.precedence,
        nolog: rule.nolog,
        action: rule.action,
        duration: rule.duration,
        operator: rule.operator.map(pb_rule_operator_from_wire),
    }
}

pub(crate) fn wire_rule_operator_from_pb(operator: pb::Operator) -> WireRuleOperator {
    WireRuleOperator {
        type_name: operator.r#type,
        operand: operator.operand,
        data: operator.data,
        sensitive: operator.sensitive,
        list: operator
            .list
            .into_iter()
            .map(wire_rule_operator_from_pb)
            .collect(),
    }
}

pub(crate) fn pb_rule_operator_from_wire(operator: WireRuleOperator) -> pb::Operator {
    pb::Operator {
        r#type: operator.type_name,
        operand: operator.operand,
        data: operator.data,
        sensitive: operator.sensitive,
        list: operator
            .list
            .into_iter()
            .map(pb_rule_operator_from_wire)
            .collect(),
    }
}

pub(crate) fn wire_sys_firewall_from_pb(firewall: pb::SysFirewall) -> WireSysFirewall {
    let mut rules = Vec::new();
    let mut chains = Vec::new();

    for group in firewall.system_rules {
        if let Some(rule) = group.rule {
            rules.push(wire_fw_rule_from_pb(rule));
        }
        chains.extend(group.chains.into_iter().map(wire_fw_chain_from_pb));
    }

    WireSysFirewall {
        enabled: firewall.enabled,
        version: firewall.version,
        rules,
        chains,
    }
}
// Backward-compatible public conversion alias for external adapter call sites.
#[allow(dead_code)]
pub fn wire_sys_firewall_from_proto(firewall: pb::SysFirewall) -> WireSysFirewall {
    wire_sys_firewall_from_pb(firewall)
}

pub fn wire_sys_firewall_to_proto(firewall: WireSysFirewall) -> pb::SysFirewall {
    let mut system_rules = Vec::new();

    for rule in firewall.rules {
        system_rules.push(pb::FwChains {
            rule: Some(pb_fw_rule_from_wire(rule)),
            chains: Vec::new(),
        });
    }

    for chain in firewall.chains {
        system_rules.push(pb::FwChains {
            rule: None,
            chains: vec![pb_fw_chain_from_wire(chain)],
        });
    }

    pb::SysFirewall {
        enabled: firewall.enabled,
        version: firewall.version,
        system_rules,
    }
}

pub(crate) fn pb_fw_chain_from_wire(chain: WireFwChain) -> pb::FwChain {
    pb::FwChain {
        name: chain.name,
        table: chain.table,
        family: chain.family,
        priority: chain.priority,
        r#type: chain.type_name,
        hook: chain.hook,
        policy: chain.policy,
        rules: chain.rules.into_iter().map(pb_fw_rule_from_wire).collect(),
    }
}

pub(crate) fn pb_fw_rule_from_wire(rule: WireFwRule) -> pb::FwRule {
    pb::FwRule {
        table: rule.table,
        chain: rule.chain,
        uuid: rule.uuid,
        enabled: rule.enabled,
        position: rule.position,
        description: rule.description,
        parameters: rule.parameters,
        expressions: rule
            .expressions
            .into_iter()
            .map(pb_fw_expression_from_wire)
            .collect(),
        target: rule.target,
        target_parameters: rule.target_parameters,
    }
}

pub(crate) fn pb_fw_expression_from_wire(expression: WireFwExpression) -> pb::Expressions {
    pb::Expressions {
        statement: expression.statement.map(pb_fw_statement_from_wire),
    }
}

pub(crate) fn pb_fw_statement_from_wire(statement: WireFwStatement) -> pb::Statement {
    pb::Statement {
        op: statement.op,
        name: statement.name,
        values: statement
            .values
            .into_iter()
            .map(pb_fw_statement_value_from_wire)
            .collect(),
    }
}

pub(crate) fn pb_fw_statement_value_from_wire(value: WireFwStatementValue) -> pb::StatementValues {
    pb::StatementValues {
        key: value.key,
        value: value.value,
    }
}

pub(crate) fn wire_fw_chain_from_pb(chain: pb::FwChain) -> WireFwChain {
    WireFwChain {
        name: chain.name,
        table: chain.table,
        family: chain.family,
        priority: chain.priority,
        type_name: chain.r#type,
        hook: chain.hook,
        policy: chain.policy,
        rules: chain.rules.into_iter().map(wire_fw_rule_from_pb).collect(),
    }
}

pub(crate) fn wire_fw_rule_from_pb(rule: pb::FwRule) -> WireFwRule {
    WireFwRule {
        table: rule.table,
        chain: rule.chain,
        uuid: rule.uuid,
        enabled: rule.enabled,
        position: rule.position,
        description: rule.description,
        parameters: rule.parameters,
        expressions: rule
            .expressions
            .into_iter()
            .map(wire_fw_expression_from_pb)
            .collect(),
        target: rule.target,
        target_parameters: rule.target_parameters,
    }
}

pub(crate) fn wire_fw_expression_from_pb(expression: pb::Expressions) -> WireFwExpression {
    WireFwExpression {
        statement: expression.statement.map(wire_fw_statement_from_pb),
    }
}

pub(crate) fn wire_fw_statement_from_pb(statement: pb::Statement) -> WireFwStatement {
    WireFwStatement {
        op: statement.op,
        name: statement.name,
        values: statement
            .values
            .into_iter()
            .map(wire_fw_statement_value_from_pb)
            .collect(),
    }
}

pub(crate) fn wire_fw_statement_value_from_pb(value: pb::StatementValues) -> WireFwStatementValue {
    WireFwStatementValue {
        key: value.key,
        value: value.value,
    }
}

#[cfg(feature = "subscriptions")]
pub(crate) fn pb_subscription_request_from_wire(
    req: WireSubscriptionRequest,
) -> pb::SubscriptionRequest {
    pb::SubscriptionRequest {
        operation: req.operation,
        subscriptions: req
            .subscriptions
            .into_iter()
            .map(pb_subscription_from_wire)
            .collect(),
        targets: req.targets,
        force: req.force,
    }
}

#[cfg(feature = "subscriptions")]
pub(crate) fn pb_subscription_from_wire(sub: WireSubscription) -> pb::Subscription {
    pb::Subscription {
        id: sub.id,
        name: sub.name,
        url: sub.url,
        filename: sub.filename,
        groups: sub.groups,
        enabled: sub.enabled,
        format: sub.format,
        interval_seconds: sub.interval_seconds,
        timeout_seconds: sub.timeout_seconds,
        max_bytes: sub.max_bytes,
        node: sub.node,
        status: sub.status,
        last_updated: sub.last_updated,
        last_error: sub.last_error,
        refresh_meta: sub
            .refresh_meta
            .map(|meta| pb::SubscriptionRefreshMetadata {
                next_refresh_after: meta.next_refresh_after,
                consecutive_failures: meta.consecutive_failures,
                etag: meta.etag,
                last_modified: meta.last_modified,
            }),
    }
}

#[cfg(feature = "subscriptions")]
pub(crate) fn wire_subscription_reply_from_pb(
    reply: pb::SubscriptionReply,
) -> WireSubscriptionReply {
    WireSubscriptionReply {
        operation: reply.operation,
        subscriptions: reply
            .subscriptions
            .into_iter()
            .map(wire_subscription_from_pb)
            .collect(),
        errors: reply.errors,
        message: reply.message,
        accepted: reply.accepted,
    }
}

#[cfg(feature = "subscriptions")]
pub(crate) fn wire_subscription_from_pb(sub: pb::Subscription) -> WireSubscription {
    WireSubscription {
        id: sub.id,
        name: sub.name,
        url: sub.url,
        filename: sub.filename,
        groups: sub.groups,
        enabled: sub.enabled,
        format: sub.format,
        interval_seconds: sub.interval_seconds,
        timeout_seconds: sub.timeout_seconds,
        max_bytes: sub.max_bytes,
        node: sub.node,
        status: sub.status,
        last_updated: sub.last_updated,
        last_error: sub.last_error,
        refresh_meta: sub
            .refresh_meta
            .map(|meta| WireSubscriptionRefreshMetadata {
                next_refresh_after: meta.next_refresh_after,
                consecutive_failures: meta.consecutive_failures,
                etag: meta.etag,
                last_modified: meta.last_modified,
            }),
    }
}

#[cfg(feature = "subscriptions")]
pub(crate) fn pb_subscription_ack_from_wire(
    ack: WireSubscriptionCommandAck,
) -> pb::SubscriptionCommandAck {
    pb::SubscriptionCommandAck {
        id: ack.id,
        action: ack.action,
        accepted: ack.accepted,
        message: ack.message,
    }
}

#[cfg(feature = "subscriptions")]
pub(crate) fn wire_subscription_command_from_proto(
    cmd: pb::SubscriptionCommand,
) -> WireSubscriptionCommand {
    WireSubscriptionCommand {
        id: cmd.id,
        action: cmd.action,
        data: cmd.data,
    }
}
