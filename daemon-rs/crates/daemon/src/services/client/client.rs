use anyhow::Result;
use opensnitch_proto::pb;
use pb::subscriptions_client::SubscriptionsClient;
use pb::ui_client::UiClient;
use std::sync::Arc;
use tonic::codec::CompressionEncoding;
use tonic::transport::Channel;

use super::transport::{
    SocketTarget, build_tls_config, classify_socket_target, connect_unix_abstract_channel,
    connect_unix_channel, connect_with_skip_verify, endpoint_with_keepalive,
};
use crate::config::{ClientAuthType, Config};

#[derive(Clone)]
pub struct Client {
    grpc: UiClient<Channel>,
    subscriptions_grpc: SubscriptionsClient<Channel>,
}

impl Client {
    pub async fn connect(addr: &str) -> Result<Self> {
        let channel = match classify_socket_target(addr) {
            SocketTarget::Tcp(target) => endpoint_with_keepalive(target)?.connect().await?,
            SocketTarget::UnixPath(path) => connect_unix_channel(path.to_string()).await?,
            SocketTarget::UnixAbstract(name) => {
                connect_unix_abstract_channel(name.to_string()).await?
            }
        };
        let grpc = UiClient::new(channel.clone());
        let subscriptions_grpc = SubscriptionsClient::new(channel);
        Ok(Self {
            grpc,
            subscriptions_grpc,
        })
    }

    pub async fn connect_with_config(config: &Config) -> Result<Self> {
        if matches!(config.client_auth.auth_type, ClientAuthType::Simple) {
            return Self::connect(&config.client_addr).await;
        }

        let addr = if config.client_addr.starts_with("http://") {
            format!("https://{}", &config.client_addr[7..])
        } else {
            config.client_addr.clone()
        };

        let endpoint = endpoint_with_keepalive(&addr)?;

        let channel = if config.client_auth.tls_options.skip_verify {
            connect_with_skip_verify(&endpoint, config).await?
        } else {
            endpoint
                .clone()
                .tls_config(build_tls_config(config)?)?
                .connect()
                .await?
        };

        let grpc = UiClient::new(channel.clone());
        let subscriptions_grpc = SubscriptionsClient::new(channel);
        Ok(Self {
            grpc,
            subscriptions_grpc,
        })
    }

    pub(crate) fn runtime_identity() -> (String, String) {
        let name = crate::utils::proc_fs::proc_sys_kernel_value("hostname")
            .unwrap_or_else(|| "opensnitchd-rs".to_string());

        let version = crate::utils::proc_fs::proc_sys_kernel_value("osrelease")
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

        (name, version)
    }

    pub(crate) fn build_subscribe_config_from_snapshots(
        config: &Config,
        rules: &Arc<Vec<pb::Rule>>,
        is_firewall_running: bool,
        system_firewall: &Arc<Option<pb::SysFirewall>>,
    ) -> pb::ClientConfig {
        let (name, version) = Self::runtime_identity();

        // Protobuf request messages are owned values. At the gRPC boundary,
        // clone once from Arc snapshots to preserve immutable runtime snapshots.
        pb::ClientConfig {
            id: 1,
            name,
            version,
            is_firewall_running,
            config: config.raw_json.clone(),
            log_level: config.log_level,
            rules: rules.as_ref().clone(),
            system_firewall: system_firewall.as_ref().clone(),
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
        Ok(self
            .grpc
            .clone()
            .send_compressed(CompressionEncoding::Gzip)
            .post_alert(alert)
            .await?
            .into_inner())
    }

    pub async fn subscription_command(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self
            .subscriptions_grpc
            .command(req)
            .await?
            .into_inner())
    }

    pub async fn subscription_list(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self
            .subscriptions_grpc
            .list(req)
            .await?
            .into_inner())
    }

    pub async fn subscription_apply(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self
            .subscriptions_grpc
            .apply(req)
            .await?
            .into_inner())
    }

    pub async fn subscription_delete(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self
            .subscriptions_grpc
            .delete(req)
            .await?
            .into_inner())
    }

    pub async fn subscription_refresh(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self
            .subscriptions_grpc
            .refresh(req)
            .await?
            .into_inner())
    }

    pub async fn subscription_deploy(
        &mut self,
        req: pb::SubscriptionRequest,
    ) -> Result<pb::SubscriptionReply> {
        Ok(self
            .subscriptions_grpc
            .deploy(req)
            .await?
            .into_inner())
    }

    pub fn grpc_mut(&mut self) -> &mut UiClient<Channel> {
        &mut self.grpc
    }
}
