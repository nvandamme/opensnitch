use anyhow::Result;
use opensnitch_proto::pb;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub use crate::models::notification_stream::NotificationStream;

use super::client::Client;

impl NotificationStream {
    pub async fn open(client: &mut Client) -> Result<Self> {
        let (reply_tx, reply_rx) = mpsc::channel::<pb::NotificationReply>(64);
        let outbound = ReceiverStream::new(reply_rx);

        let response = client.grpc_mut().notifications(outbound).await?;
        let inbound = response.into_inner();

        Ok(Self { inbound, reply_tx })
    }
}
