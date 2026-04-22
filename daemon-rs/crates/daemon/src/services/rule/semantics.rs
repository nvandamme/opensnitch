use crate::models::rule_record::RuleDuration;

pub(crate) fn rule_duration_persists_to_disk(duration: &RuleDuration) -> bool {
    matches!(duration, RuleDuration::Permanent)
}

pub(crate) fn rule_duration_temporary_spec(duration: &RuleDuration) -> Option<&str> {
    match duration {
        RuleDuration::Temporary(value) => Some(value.as_str()),
        _ => None,
    }
}
