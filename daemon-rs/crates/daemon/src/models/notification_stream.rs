use opensnitch_proto::pb;
use tokio::sync::mpsc;

pub struct NotificationStream {
    pub inbound: tonic::Streaming<pb::Notification>,
    pub reply_tx: mpsc::Sender<pb::NotificationReply>,
}