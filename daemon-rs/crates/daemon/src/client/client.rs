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

    fn runtime_identity() -> (String, String) {
        let name = Self::read_text_file_trimmed("/proc/sys/kernel/hostname")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "opensnitchd-rs".to_string());

        let version = Self::read_text_file_trimmed("/proc/sys/kernel/osrelease")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

        (name, version)
    }

    fn read_text_file_trimmed(path: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()
            .map(|value| value.trim().to_string())
    }

    pub fn build_subscribe_config(
        &self,
        config: &Config,
        rules: Vec<pb::Rule>,
        is_firewall_running: bool,
        system_firewall: Option<pb::SysFirewall>,
    ) -> pb::ClientConfig {
        let (name, version) = Self::runtime_identity();

        pb::ClientConfig {
            id: 1,
            name,
            version,
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

    pub fn grpc_mut(&mut self) -> &mut UiClient<Channel> {
        &mut self.grpc
    }
}

#[cfg(test)]
mod tests {
    use opensnitch_proto::pb;
    use tonic::transport::Endpoint;

    use super::Client;
    use crate::config::Config;

    fn build_test_client() -> Client {
        let channel = Endpoint::from_static("http://127.0.0.1:50051").connect_lazy();
        Client {
            grpc: pb::ui_client::UiClient::new(channel),
        }
    }

    #[test]
    fn runtime_identity_returns_non_empty_fields() {
        let (name, version) = Client::runtime_identity();
        assert!(!name.trim().is_empty());
        assert!(!version.trim().is_empty());
    }

    #[tokio::test]
    async fn build_subscribe_config_keeps_expected_payload_fields() {
        let client = build_test_client();

        let mut cfg = Config::default();
        cfg.log_level = 7;
        cfg.raw_json = "{\"DefaultAction\":\"allow\"}".to_string();

        let rules = vec![pb::Rule {
            name: "allow_dns".to_string(),
            enabled: true,
            action: "allow".to_string(),
            duration: "once".to_string(),
            ..Default::default()
        }];

        let system_firewall = Some(pb::SysFirewall {
            enabled: true,
            version: 3,
            system_rules: Vec::new(),
        });

        let subscribe = client.build_subscribe_config(&cfg, rules.clone(), true, system_firewall);
        let (expected_name, expected_version) = Client::runtime_identity();

        assert_eq!(subscribe.id, 1);
        assert_eq!(subscribe.name, expected_name);
        assert_eq!(subscribe.version, expected_version);
        assert!(subscribe.is_firewall_running);
        assert_eq!(subscribe.config, cfg.raw_json);
        assert_eq!(subscribe.log_level, cfg.log_level);
        assert_eq!(subscribe.rules.len(), rules.len());
        assert_eq!(subscribe.rules[0].name, "allow_dns");
        assert_eq!(subscribe.system_firewall.as_ref().map(|fw| fw.version), Some(3));
    }
}
