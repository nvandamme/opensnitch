use anyhow::Result;
use opensnitch_proto::pb;
use pb::ui_client::UiClient;
use tonic::transport::Channel;

use crate::config::Config;

#[derive(Clone)]
pub struct Client {
    grpc: UiClient<Channel>,
}

impl Client {
    pub async fn connect(addr: &str) -> Result<Self> {
        let grpc = UiClient::connect(addr.to_string()).await?;
        Ok(Self { grpc })
    }

    pub fn build_subscribe_config(
        &self,
        config: &Config,
        rules: Vec<pb::Rule>,
        is_firewall_running: bool,
        system_firewall: Option<pb::SysFirewall>,
    ) -> pb::ClientConfig {
        pb::ClientConfig {
            id: 1,
            name: "opensnitchd-rs".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            is_firewall_running,
            config: config.raw_json.clone(),
            log_level: config.log_level,
            rules,
            system_firewall,
        }
    }

    pub async fn subscribe(&mut self, cfg: pb::ClientConfig) -> Result<pb::ClientConfig> {
        Ok(self.grpc.subscribe(cfg).await?.into_inner())
    }

    pub async fn ping(&mut self, req: pb::PingRequest) -> Result<pb::PingReply> {
        Ok(self.grpc.ping(req).await?.into_inner())
    }

    pub async fn ask_rule(&mut self, conn: pb::Connection) -> Result<pb::Rule> {
        Ok(self.grpc.ask_rule(conn).await?.into_inner())
    }

    pub async fn post_alert(&mut self, alert: pb::Alert) -> Result<pb::MsgResponse> {
        Ok(self.grpc.post_alert(alert).await?.into_inner())
    }

    pub fn grpc_mut(&mut self) -> &mut UiClient<Channel> {
        &mut self.grpc
    }
}
