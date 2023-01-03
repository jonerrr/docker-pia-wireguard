use anyhow::{bail, Result};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};
use wireguard_keys::{Privkey, Pubkey};

#[derive(Debug)]
pub struct Config {
    private_key: Privkey,
    address: IpAddr,
    dns: Vec<String>,
    public_key: Pubkey,
    allowed_ips: String,
    endpoint: SocketAddr,
    pub api: String,
}

#[derive(Debug, Deserialize)]
struct KeyStatus {
    status: String,
    server_key: String,
    server_port: i32,
    server_ip: IpAddr,
    server_vip: String,
    peer_ip: IpAddr,
    // peer_pubkey: String,
    dns_servers: Vec<String>,
    message: Option<String>,
}

impl Config {
    pub async fn new(cn: &str, token: &str, port: i32, client: &reqwest::Client) -> Result<Self> {
        let private_key = wireguard_keys::Privkey::generate();
        println!("[INFO] Wireguard private generated");

        let key_data: KeyStatus = client
            .get(format!("https://{cn}:{port}/addKey"))
            .query(&[("pt", token), ("pubkey", &private_key.pubkey().to_string())])
            .send()
            .await?
            .json()
            .await?;
        if key_data.status != "OK" {
            bail!(
                "[ERROR] Error occurred while adding key to PIA: {:?}",
                key_data.message
            )
        }
        println!("[INFO] Public key added to PIA");

        Ok(Config {
            private_key,
            address: key_data.peer_ip,
            dns: key_data.dns_servers,
            public_key: key_data.server_key.parse::<Pubkey>()?,
            allowed_ips: "0.0.0.0/0".into(),
            endpoint: format!("{}:{}", key_data.server_ip, key_data.server_port).parse()?,
            api: key_data.server_vip,
        })
    }

    pub async fn write(&self, path: PathBuf) {
        // this could probably be a macro
        let data = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}\nDNS = {}\n\n[Peer]\nPublicKey = {}\nAllowedIPs = {}\nEndpoint = {}\nPersistentKeepalive = 25",
            &self.private_key, &self.address, &self.dns.join(","), &self.public_key, &self.allowed_ips, &self.endpoint
        );
        tokio::fs::write(&path, data)
            .await
            .expect("[ERROR] failed to save wireguard configuration");
        println!("[INFO] Config saved to disk at: {:?}", path);
    }
}
