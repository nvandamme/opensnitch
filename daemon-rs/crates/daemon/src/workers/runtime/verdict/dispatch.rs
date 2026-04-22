use crate::models::verdict_rpc::VerdictReply;
use std::borrow::Cow;

pub(crate) fn decision_label(verdict: &VerdictReply) -> &'static str {
    if verdict.allow {
        "allow"
    } else if verdict.reject {
        "reject"
    } else {
        "drop"
    }
}

pub(crate) fn source_label(verdict: &VerdictReply) -> Cow<'static, str> {
    match (verdict.source, verdict.rule_name.as_deref()) {
        (src, Some(rule_name)) if src.contains("rule") => format!("rule:[{rule_name}]").into(),
        (src, Some(rule_name)) => format!("{src}:[{rule_name}]").into(),
        ("runtime-fast-allow", None) => Cow::Borrowed("fast-allow"),
        ("runtime-fast-drop", None) | ("runtime-fast-deny", None) => Cow::Borrowed("fast-drop"),
        ("runtime-default", None) => Cow::Borrowed("default"),
        (src, None) => Cow::Borrowed(src),
    }
}

pub(crate) async fn try_send_or_enqueue(
    verdict_tx: &tokio::sync::mpsc::Sender<VerdictReply>,
    verdict: VerdictReply,
) {
    match verdict_tx.try_send(verdict) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(next)) => {
            let _ = verdict_tx.send(next).await;
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
    }
}

pub(crate) fn daemon_self_allow_verdict(request_id: u64) -> VerdictReply {
    VerdictReply {
        request_id,
        allow: true,
        reject: false,
        count_stats: false,
        source: "daemon-self-dispatch",
        rule_name: None,
    }
}
