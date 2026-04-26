use super::exprs::{
    NftExpression, NftRule,
    connlimit::parse_connlimit_condition,
    counter::parse_counter_condition,
    ct::parse_ct_conditions,
    dynset::parse_dynset_action,
    exthdr::{parse_exthdr_conditions, parse_ipv6_exthdr_condition},
    fib::parse_fib_conditions,
    hash::parse_hash_conditions,
    limit::parse_limit_condition,
    log::parse_log_condition,
    meta::parse_meta_conditions,
    nat::{parse_masq_action, parse_nat_action, parse_redirect_action, parse_tproxy_action},
    notrack::NftNotrack,
    numgen::parse_numgen_conditions,
    payload::parse_payload_family,
    queue::parse_queue_action,
    quota::parse_quota_condition,
    rt::parse_rt_conditions,
    shared::push_condition,
    socket::parse_socket_conditions,
    verdict::{NftVerdict, parse_reject_action},
};
use super::{ParseError, ParseFamily};
use crate::models::firewall_config::{FirewallRule, FirewallStatement, FirewallStatementValue};

impl NftRule {
    pub(super) fn parse_all(expression: &str) -> Option<Vec<Self>> {
        Self::parse_with_error(expression).ok()
    }

    pub(super) fn parse_with_error(expression: &str) -> Result<Vec<Self>, ParseError> {
        let token_strings = tokenize_nft_expression(expression);
        let token_refs = token_strings.iter().map(String::as_str).collect::<Vec<_>>();
        Self::parse_tokens_with_error(&token_refs)
    }

    pub(super) fn parse_tokens_with_error(tokens: &[&str]) -> Result<Vec<Self>, ParseError> {
        if tokens.is_empty() {
            return Err(ParseError::empty());
        }

        let expression = tokens.join(" ");
        let mut expansions: Vec<Vec<NftExpression>> = vec![Vec::new()];
        let mut i = 0;
        let end = tokens.len();
        while i < end {
            match tokens.get(i) {
                Some(&"counter") => {
                    let (condition, next) = parse_counter_condition(&tokens, i, end)
                        .ok_or(ParseError::invalid_value(ParseFamily::Objref))?;
                    push_condition(&mut expansions, condition);
                    i = next;
                    continue;
                }
                Some(&"accept") => {
                    let action = NftExpression::Verdict(NftVerdict::Accept);
                    return finish_expansions(
                        expansions,
                        action,
                        &tokens,
                        i + 1,
                        ParseFamily::Other,
                    );
                }
                Some(&"drop") => {
                    let action = NftExpression::Verdict(NftVerdict::Drop);
                    return finish_expansions(
                        expansions,
                        action,
                        &tokens,
                        i + 1,
                        ParseFamily::Other,
                    );
                }
                Some(&"return") => {
                    let action = NftExpression::Verdict(NftVerdict::Return);
                    return finish_expansions(
                        expansions,
                        action,
                        &tokens,
                        i + 1,
                        ParseFamily::Other,
                    );
                }
                Some(&"continue") => {
                    let action = NftExpression::Verdict(NftVerdict::Continue);
                    return finish_expansions(
                        expansions,
                        action,
                        &tokens,
                        i + 1,
                        ParseFamily::Other,
                    );
                }
                Some(&"break") => {
                    let action = NftExpression::Verdict(NftVerdict::Break);
                    return finish_expansions(
                        expansions,
                        action,
                        &tokens,
                        i + 1,
                        ParseFamily::Other,
                    );
                }
                Some(&"jump") => {
                    let chain = (*tokens
                        .get(i + 1)
                        .ok_or(ParseError::unsupported_shape(ParseFamily::Other))?)
                    .to_string();
                    let action = NftExpression::Verdict(NftVerdict::Jump { chain });
                    return finish_expansions(
                        expansions,
                        action,
                        &tokens,
                        i + 2,
                        ParseFamily::Other,
                    );
                }
                Some(&"goto") => {
                    let chain = (*tokens
                        .get(i + 1)
                        .ok_or(ParseError::unsupported_shape(ParseFamily::Other))?)
                    .to_string();
                    let action = NftExpression::Verdict(NftVerdict::Goto { chain });
                    return finish_expansions(
                        expansions,
                        action,
                        &tokens,
                        i + 2,
                        ParseFamily::Other,
                    );
                }
                Some(&"reject") => {
                    let (action, next) = parse_reject_action(&tokens, i, end)
                        .ok_or(ParseError::invalid_value(ParseFamily::Reject))?;
                    return finish_expansions(
                        expansions,
                        action,
                        &tokens,
                        next,
                        ParseFamily::Reject,
                    );
                }
                Some(&"queue") => {
                    let (action, next) = parse_queue_action(&tokens, i)
                        .ok_or(ParseError::invalid_value(ParseFamily::Queue))?;
                    return finish_expansions(
                        expansions,
                        action,
                        &tokens,
                        next,
                        ParseFamily::Queue,
                    );
                }
                Some(&"notrack") => {
                    push_condition(&mut expansions, NftExpression::Notrack(NftNotrack));
                    i += 1;
                    continue;
                }
                Some(&"quota") => {
                    let (condition, next) = parse_quota_condition(&tokens, i, end)
                        .ok_or(ParseError::invalid_value(ParseFamily::Quota))?;
                    push_condition(&mut expansions, condition);
                    i = next;
                    continue;
                }
                Some(&"limit") => {
                    let (condition, next) = parse_limit_condition(&tokens, i, end)
                        .ok_or(ParseError::invalid_value(ParseFamily::Limit))?;
                    push_condition(&mut expansions, condition);
                    i = next;
                    continue;
                }
                Some(&"masquerade") | Some(&"masq") => {
                    let (action, next) = parse_masq_action(&tokens, i, end)
                        .ok_or(ParseError::invalid_value(ParseFamily::Nat))?;
                    return finish_expansions(expansions, action, &tokens, next, ParseFamily::Nat);
                }
                Some(&"redirect") | Some(&"redir") => {
                    let (action, next) = parse_redirect_action(&tokens, i, end)
                        .ok_or(ParseError::invalid_value(ParseFamily::Nat))?;
                    return finish_expansions(expansions, action, &tokens, next, ParseFamily::Nat);
                }
                Some(&"tproxy") => {
                    let (action, next) = parse_tproxy_action(&tokens, i, end)
                        .ok_or(ParseError::invalid_value(ParseFamily::Nat))?;
                    return finish_expansions(expansions, action, &tokens, next, ParseFamily::Nat);
                }
                Some(&"snat") | Some(&"dnat") => {
                    let (action, next) = parse_nat_action(&tokens, i, end)
                        .ok_or(ParseError::invalid_value(ParseFamily::Nat))?;
                    return finish_expansions(expansions, action, &tokens, next, ParseFamily::Nat);
                }
                Some(&"log") => {
                    let (condition, next) = parse_log_condition(&tokens, i, end)
                        .ok_or(ParseError::invalid_value(ParseFamily::Log))?;
                    push_condition(&mut expansions, condition);
                    i = next;
                    continue;
                }
                Some(&"meta") => {
                    let (next_expansions, next) =
                        parse_meta_conditions(&tokens, i, end, expansions)
                            .ok_or(ParseError::invalid_value(ParseFamily::Meta))?;
                    expansions = next_expansions;
                    i = next;
                    continue;
                }
                Some(&"fib") if tokens.get(i + 2) == Some(&".") => {
                    let (next_expansions, next) = parse_fib_conditions(&tokens, i, end, expansions)
                        .ok_or(ParseError::invalid_value(ParseFamily::Fib))?;
                    expansions = next_expansions;
                    i = next;
                    continue;
                }
                Some(&"numgen") => {
                    let (next_expansions, next) =
                        parse_numgen_conditions(&tokens, i, end, expansions)
                            .ok_or(ParseError::invalid_value(ParseFamily::Numgen))?;
                    expansions = next_expansions;
                    i = next;
                    continue;
                }
                Some(&"ct") if tokens.get(i + 1) == Some(&"count") => {
                    let (condition, next) = parse_connlimit_condition(&tokens, i, end)
                        .ok_or(ParseError::invalid_value(ParseFamily::Connlimit))?;
                    push_condition(&mut expansions, condition);
                    i = next;
                    continue;
                }
                Some(&"ct") => {
                    let (next_expansions, next) = parse_ct_conditions(&tokens, i, end, expansions)
                        .ok_or(ParseError::invalid_value(ParseFamily::CtState))?;
                    expansions = next_expansions;
                    i = next;
                    continue;
                }
                Some(&"socket") => {
                    let (next_expansions, next) =
                        parse_socket_conditions(&tokens, i, end, expansions)
                            .ok_or(ParseError::invalid_value(ParseFamily::Socket))?;
                    expansions = next_expansions;
                    i = next;
                    continue;
                }
                Some(&"jhash") | Some(&"symhash") => {
                    let (next_expansions, next) =
                        parse_hash_conditions(&tokens, i, end, expansions)
                            .ok_or(ParseError::invalid_value(ParseFamily::Hash))?;
                    expansions = next_expansions;
                    i = next;
                    continue;
                }
                Some(&"rt") => {
                    let (next_expansions, next) =
                        parse_rt_conditions(&tokens, i, end, expansions)
                            .ok_or(ParseError::invalid_value(ParseFamily::Rt))?;
                    expansions = next_expansions;
                    i = next;
                    continue;
                }
                Some(&"add") | Some(&"update")
                    if tokens
                        .get(i + 1)
                        .is_some_and(|t| t.starts_with('@')) =>
                {
                    let (action, next) = parse_dynset_action(&tokens, i, end)
                        .ok_or(ParseError::invalid_value(ParseFamily::Dynset))?;
                    push_condition(&mut expansions, action);
                    i = next;
                    continue;
                }
                Some(&"tcp") if tokens.get(i + 1) == Some(&"option") => {
                    let (next_expansions, next) =
                        parse_exthdr_conditions(&tokens, i, end, expansions)
                            .ok_or(ParseError::invalid_value(ParseFamily::Exthdr))?;
                    expansions = next_expansions;
                    i = next;
                    continue;
                }
                Some(&"ip6") if tokens.get(i + 1) == Some(&"exthdr") => {
                    let (next_expansions, next) =
                        parse_ipv6_exthdr_condition(&tokens, i, expansions)
                            .ok_or(ParseError::invalid_value(ParseFamily::Exthdr))?;
                    expansions = next_expansions;
                    i = next;
                    continue;
                }
                Some(&"ip") | Some(&"ip6") | Some(&"th") | Some(&"tcp") | Some(&"udp")
                | Some(&"icmp") | Some(&"icmpv6") => {}
                _ => {}
            }

            if let Some((next_expansions, next)) =
                parse_payload_family(&tokens, i, end, expansions.clone())
            {
                if payload_expansions_are_terminal(&next_expansions) {
                    return finish_existing_expansions(
                        next_expansions,
                        tokens,
                        next,
                        classify_expression_family(&expression),
                    );
                }

                expansions = next_expansions;
                i = next;
                continue;
            }

            let family = classify_expression_family(&expression);
            return Err(if family == ParseFamily::SetOrList {
                ParseError::ambiguous_form(family)
            } else {
                ParseError::invalid_value(family)
            });
        }

        let family = classify_expression_family(&expression);
        Err(if family == ParseFamily::SetOrList {
            ParseError::ambiguous_form(family)
        } else {
            ParseError::unsupported_shape(family)
        })
    }

    pub(super) fn classify_expression_family(expression: &str) -> &'static str {
        classify_expression_family(expression).as_str()
    }

    pub(super) fn parse_failure(expression: &str) -> Option<ParseError> {
        Self::parse_with_error(expression).err()
    }

    pub(super) fn parse_structured_rule(rule: &FirewallRule, queue_num: u16) -> Option<Vec<Self>> {
        let mut tokens = Vec::<String>::new();
        for expression in &rule.expressions {
            let statement = expression.statement.as_ref()?;
            append_statement_tokens(&mut tokens, statement)?;
        }

        if tokens.is_empty() {
            return None;
        }

        let target = rule.target.trim().to_ascii_lowercase();
        if target.is_empty() {
            return None;
        }
        tokens.push(target.clone());

        let mut target_parameters = rule.target_parameters.trim().to_string();
        if target == "queue" && queue_num != 0 && target_parameters.contains("num 0") {
            target_parameters = target_parameters.replace("num 0", &format!("num {queue_num}"));
        }
        tokens.extend(tokenize_nft_expression(&target_parameters));

        let token_refs = tokens.iter().map(String::as_str).collect::<Vec<_>>();
        Self::parse_tokens_with_error(&token_refs).ok()
    }
}

fn append_statement_tokens(tokens: &mut Vec<String>, statement: &FirewallStatement) -> Option<()> {
    let name = statement.name.trim().to_ascii_lowercase();
    if name.is_empty() {
        return None;
    }

    if statement.values.is_empty() {
        tokens.push(name);
        return Some(());
    }

    let op = statement.op.trim();
    let op = if op == "==" { "" } else { op };

    if name == "quota" {
        return append_quota_statement_tokens(tokens, &statement.values);
    }
    if name == "limit" {
        return append_limit_statement_tokens(tokens, &statement.values);
    }

    let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
    for value in &statement.values {
        let key = value.key.trim().to_ascii_lowercase();
        let raw = value.value.trim();
        let normalized = if matches!(name.as_str(), "iifname" | "oifname") && raw.is_empty() {
            key.clone()
        } else {
            raw.to_string()
        };
        if normalized.is_empty() && key.is_empty() {
            continue;
        }

        if let Some((_, values)) = grouped.iter_mut().find(|(existing, _)| *existing == key) {
            values.push(normalized);
        } else {
            grouped.push((key, vec![normalized]));
        }
    }

    let mut parsed_any = false;
    for (key, values) in grouped {
        let (clause_name, clause_key) = if matches!(name.as_str(), "iifname" | "oifname") {
            ("meta".to_string(), name.clone())
        } else if name == "meta" && matches!(key.as_str(), "dport" | "sport") {
            ("th".to_string(), key.clone())
        } else {
            (name.clone(), key.clone())
        };

        let value_token = values
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        let value_token = if value_token.is_empty() {
            String::new()
        } else if value_token.len() > 1 {
            value_token.join(",")
        } else {
            value_token[0].clone()
        };

        tokens.push(clause_name);
        if !clause_key.is_empty() {
            tokens.push(clause_key);
        }
        if !op.is_empty() && !value_token.is_empty() {
            tokens.push(op.to_string());
        }
        if !value_token.is_empty() {
            tokens.extend(tokenize_nft_expression(&value_token));
        }
        parsed_any = true;
    }

    if parsed_any { Some(()) } else { None }
}

fn append_quota_statement_tokens(
    tokens: &mut Vec<String>,
    values: &[FirewallStatementValue],
) -> Option<()> {
    let mut over = false;
    let mut size = None::<(String, String)>;

    for value in values {
        let key = value.key.trim().to_ascii_lowercase();
        let raw = value.value.trim();
        match key.as_str() {
            "over" => over = true,
            "bytes" | "kbytes" | "mbytes" | "gbytes" => {
                if raw.is_empty() {
                    continue;
                }
                size = Some((raw.to_string(), key));
            }
            _ => {}
        }
    }

    let (amount, unit) = size?;
    tokens.push("quota".to_string());
    if over {
        tokens.push("over".to_string());
    }
    tokens.push(amount);
    tokens.push(unit);
    Some(())
}

fn append_limit_statement_tokens(
    tokens: &mut Vec<String>,
    values: &[FirewallStatementValue],
) -> Option<()> {
    let mut over = false;
    let mut units = None::<String>;
    let mut rate_units = None::<String>;
    let mut time_units = None::<String>;
    let mut burst = None::<String>;

    for value in values {
        let key = value.key.trim().to_ascii_lowercase();
        let raw = value.value.trim();
        match key.as_str() {
            "over" => over = true,
            "units" if !raw.is_empty() => units = Some(raw.to_string()),
            "rate-units" if !raw.is_empty() => rate_units = Some(raw.to_ascii_lowercase()),
            "time-units" if !raw.is_empty() => time_units = Some(raw.to_ascii_lowercase()),
            "burst" if !raw.is_empty() => burst = Some(raw.to_string()),
            _ => {}
        }
    }

    let units = units?;
    let rate_unit = rate_units.unwrap_or_else(|| "packets".to_string());
    let time_unit = time_units.unwrap_or_else(|| "second".to_string());

    tokens.push("limit".to_string());
    tokens.push("rate".to_string());
    if over {
        tokens.push("over".to_string());
    }
    tokens.push(units);
    tokens.push(format!("{rate_unit}/{time_unit}"));
    if let Some(burst) = burst {
        tokens.push("burst".to_string());
        tokens.push(burst);
    }
    Some(())
}

fn tokenize_nft_expression(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(ch) = chars.next() {
        if let Some(open) = quote {
            current.push(ch);
            if ch == open {
                quote = None;
            } else if ch == '\\' {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            continue;
        }

        if ch.is_whitespace() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }

        if ch == '"' || ch == '\'' {
            quote = Some(ch);
            current.push(ch);
            continue;
        }

        current.push(ch);
    }

    if !current.is_empty() {
        out.push(current);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::tokenize_nft_expression;

    #[test]
    fn tokenize_expression_keeps_quoted_and_splits_complex_fragments() {
        let tokens =
            tokenize_nft_expression("log prefix \"opensnitch test\" tcp flags & (fin|syn|rst|ack)");
        assert_eq!(
            tokens,
            vec![
                "log",
                "prefix",
                "\"opensnitch test\"",
                "tcp",
                "flags",
                "&",
                "(fin|syn|rst|ack)"
            ]
        );
    }
}

fn finish_expansions(
    expansions: Vec<Vec<NftExpression>>,
    action: NftExpression,
    tokens: &[&str],
    next: usize,
    family: ParseFamily,
) -> Result<Vec<NftRule>, ParseError> {
    let expansions = expansions
        .into_iter()
        .map(|mut expressions| {
            expressions.push(action.clone());
            expressions
        })
        .collect();

    finish_existing_expansions(expansions, tokens, next, family)
}

fn finish_existing_expansions(
    expansions: Vec<Vec<NftExpression>>,
    tokens: &[&str],
    next: usize,
    family: ParseFamily,
) -> Result<Vec<NftRule>, ParseError> {
    if next < tokens.len() {
        if tokens[next] != "comment" {
            return Err(ParseError::trailing_tokens(family));
        }
    }

    Ok(expansions
        .into_iter()
        .map(NftRule::from_expressions)
        .collect())
}

fn payload_expansions_are_terminal(expansions: &[Vec<NftExpression>]) -> bool {
    !expansions.is_empty()
        && expansions
            .iter()
            .all(|expressions| matches!(expressions.last(), Some(NftExpression::Verdict(_))))
}

fn classify_expression_family(expression: &str) -> ParseFamily {
    let expr = expression.to_ascii_lowercase();
    if expr.contains('/') {
        return ParseFamily::Cidr;
    }
    if expr.contains("ct count") {
        return ParseFamily::Connlimit;
    }
    if expr.contains("tcp option") || expr.contains("ip6 exthdr") {
        return ParseFamily::Exthdr;
    }
    if expr.starts_with("jhash ") || expr.contains(" jhash ") || expr.starts_with("symhash ") || expr.contains(" symhash ") {
        return ParseFamily::Hash;
    }
    if expr.starts_with("rt ") || expr.contains(" rt ") {
        return ParseFamily::Rt;
    }
    if expr.starts_with("add @") || expr.starts_with("update @") || expr.contains(" add @") || expr.contains(" update @") {
        return ParseFamily::Dynset;
    }
    if expr.starts_with("ct ") || expr.contains(" ct ") {
        return ParseFamily::CtState;
    }
    if expr.contains("queue") {
        return ParseFamily::Queue;
    }
    if expr.starts_with("notrack") || expr.contains(" notrack") {
        return ParseFamily::Notrack;
    }
    if expr.contains("reject") {
        return ParseFamily::Reject;
    }
    if expr.starts_with("log ") || expr == "log" || expr.contains(" log ") {
        return ParseFamily::Log;
    }
    if expr.starts_with("fib ") || expr.contains(" fib ") {
        return ParseFamily::Fib;
    }
    if expr.starts_with("numgen ") || expr.contains(" numgen ") {
        return ParseFamily::Numgen;
    }
    if expr.starts_with("counter ")
        && (expr.contains(" name ") || expr.contains(" packets") || expr.contains(" bytes"))
    {
        return ParseFamily::Objref;
    }
    if expr.starts_with("quota ") || expr == "quota" || expr.contains(" quota ") {
        return ParseFamily::Quota;
    }
    if expr.starts_with("limit ") || expr == "limit" || expr.contains(" limit ") {
        return ParseFamily::Limit;
    }
    if expr.contains("masquerade")
        || expr.contains(" masq")
        || expr.contains(" redirect")
        || expr.contains(" redir")
        || expr.starts_with("tproxy ")
        || expr.contains(" tproxy")
        || expr.contains(" snat")
        || expr.contains(" dnat")
    {
        return ParseFamily::Nat;
    }
    if expr.contains('@') {
        return ParseFamily::Lookup;
    }
    if expr.starts_with("socket ") || expr == "socket" || expr.contains(" socket ") {
        return ParseFamily::Socket;
    }
    if expr.contains('{') || expr.contains('}') {
        return ParseFamily::SetOrList;
    }
    if expr.contains("meta") {
        return ParseFamily::Meta;
    }
    if expr.contains("ip ") || expr.contains("ip6 ") {
        return ParseFamily::IpAddrOrProto;
    }
    if expr.contains("tcp") || expr.contains("udp") || expr.contains("th ") {
        return ParseFamily::Transport;
    }
    ParseFamily::Other
}
