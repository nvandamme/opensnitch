pub(crate) fn render_line_protocol(s: &super::http_push_influxdb::CompactSnapshot) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut buf = String::with_capacity(4096);

    buf.push_str("opensnitch_stats ");
    buf.push_str(&format!(
        "rules={rules}i,uptime={uptime}i,connections={connections}i,accepted={accepted}i,dropped={dropped}i,dns_responses={dns}i,ignored={ignored}i,rule_hits={rule_hits}i,rule_misses={rule_misses}i",
        rules = s.rules,
        uptime = s.uptime,
        connections = s.connections,
        accepted = s.accepted,
        dropped = s.dropped,
        dns = s.dns_responses,
        ignored = s.ignored,
        rule_hits = s.rule_hits,
        rule_misses = s.rule_misses,
    ));
    buf.push(' ');
    buf.push_str(&ts.to_string());
    buf.push('\n');

    if s.subscription_stats.is_some() {
        for (status, count) in &s.by_subscription_status {
            let st = escape_tag_value(status);
            buf.push_str(&format!(
                "opensnitch_subscription_by_status,status={st} count={count}i {ts}\n"
            ));
        }
        for (group, count) in &s.by_subscription_group {
            let g = escape_tag_value(group);
            buf.push_str(&format!(
                "opensnitch_subscription_by_group,group={g} count={count}i {ts}\n"
            ));
        }
        for (node, count) in &s.by_subscription_node {
            let n = escape_tag_value(node);
            buf.push_str(&format!(
                "opensnitch_subscription_by_node,node={n} count={count}i {ts}\n"
            ));
        }

        if let Some(sub) = &s.subscription_stats {
            for entry in &sub.rule_subscriptions {
                let rule = escape_tag_value(&entry.rule);
                for subscription in &entry.subscriptions {
                    let subscription = escape_tag_value(subscription);
                    buf.push_str(&format!(
                        "opensnitch_subscription_rule,rule={rule},subscription={subscription} info=1i {ts}\n"
                    ));
                }
            }
        }
    }

    breakdown(&mut buf, "opensnitch_by_proto", "proto", &s.by_proto, ts);
    breakdown(
        &mut buf,
        "opensnitch_by_address",
        "address",
        &s.by_address,
        ts,
    );
    breakdown(&mut buf, "opensnitch_by_host", "host", &s.by_host, ts);
    breakdown(&mut buf, "opensnitch_by_port", "port", &s.by_port, ts);
    breakdown(&mut buf, "opensnitch_by_uid", "uid", &s.by_uid, ts);
    breakdown(
        &mut buf,
        "opensnitch_by_executable",
        "executable",
        &s.by_executable,
        ts,
    );
    breakdown(&mut buf, "opensnitch_by_rule", "rule", &s.by_rule, ts);

    buf
}

fn breakdown(buf: &mut String, measurement: &str, tag_key: &str, pairs: &[(String, u64)], ts: u64) {
    for (key, value) in pairs {
        let escaped_key = escape_tag_value(key);
        buf.push_str(&format!(
            "{measurement},{tag_key}={escaped_key} connections={value}i {ts}\n"
        ));
    }
}

fn escape_tag_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            ',' => out.push_str("\\,"),
            ' ' => out.push_str("\\ "),
            '=' => out.push_str("\\="),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out
}
