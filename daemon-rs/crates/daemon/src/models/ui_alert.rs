use opensnitch_proto::pb;

#[derive(Debug, Clone)]
pub enum UiAlertData {
    Text(String),
    Connection(pb::Connection),
    Process(pb::Process),
}

#[derive(Debug, Clone)]
pub struct UiAlert {
    pub alert_type: i32,
    pub what: i32,
    pub action: i32,
    pub priority: i32,
    pub data: UiAlertData,
}
