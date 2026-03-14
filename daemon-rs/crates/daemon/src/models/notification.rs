use opensnitch_proto::pb;

#[derive(Debug, Clone)]
pub enum ClientCommand {
    SetInterception(bool),
    SetFirewall(bool),
    ReloadFirewall,
    ApplyConfig(String),
    UpsertRules(Vec<pb::Rule>),
    DeleteRules(Vec<String>),
    ReloadRules,
    Shutdown,
}
