use anyhow::{bail, Result};
use interfaces::Interface;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::os::unix::process::CommandExt;
use std::time::Duration;
use std::{env, path, process::Command, str};
use sysctl::Sysctl;
use tokio::time::sleep;

mod config;

#[derive(Debug, Deserialize)]
struct ServerList {
    groups: HashMap<String, Vec<GroupDetails>>,
    regions: Vec<Region>,
}

#[derive(Debug, Deserialize)]
struct GroupDetails {
    ports: Vec<i32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Region {
    id: String,
    name: String,
    // dns: String,
    port_forward: bool,
    offline: bool,
    servers: HashMap<String, Vec<ServerDetails>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerDetails {
    ip: IpAddr,
    cn: String,
}

#[derive(Debug, Deserialize)]
struct Token {
    token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Signature {
    payload: String,
    signature: String,
    status: String,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Payload {
    // token: String,
    port: i32,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
struct BindPort {
    status: String,
    message: String,
}

const CONFIG_PATH: &str = "/config";

#[tokio::main]
async fn main() -> Result<()> {
    println!("----------------------------------------------------------------------\nENVIRONMENT\n----------------------------------------------------------------------");
    for (key, value) in env::vars() {
        println!("{key}: {value}");
    }
    println!("----------------------------------------------------------------------");

    if let Ok(Some(_)) = Interface::get_by_name("docker0") {
        bail!("[ERROR] Docker network mode 'host' is not supported")
    }
    if sysctl::Ctl::new("net.ipv4.conf.all.src_valid_mark")?.value_string()? != "1" {
        bail!("[ERROR] net.ipv4.conf.all.src_valid_mark is not set to 1")
    }

    if path::Path::new(&format!("{}/wg0.conf", CONFIG_PATH)).exists() {
        // make sure wireguard is not running
        Command::new("wg-quick")
            .args(["down", &format!("{}/wg0.conf", CONFIG_PATH)])
            .output()
            .ok();
        println!("[INFO] Stopped previous wireguard interface")
    }

    println!("[INFO] Removing src_valid_mark=1 from wg-quick");
    Command::new("sed")
        .args([
            "-i",
            r#"/net\.ipv4\.conf\.all\.src_valid_mark/d"#,
            "/usr/bin/wg-quick",
        ])
        .spawn()?;

    let region_id =
        env::var("PIA_REGION_ID").expect("[ERROR] Missing PIA_REGION_ID in environment variables");
    println!("[INFO] Fetching PIA server list");

    let list: ServerList = {
        let list_raw = reqwest::Client::new()
            .get("https://serverlist.piaservers.net/vpninfo/servers/v6")
            .send()
            .await?
            .text()
            .await?;
        // remove base64 data at the end of the request so only the JSON is left
        serde_json::from_str(list_raw.split_once('\n').unwrap().0)?
    };
    let region = list
        .regions
        .iter()
        .find(|r| r.id == region_id)
        .expect("[ERROR] Could not locate region");
    if region.offline {
        bail!("[ERROR] Selected server is offline")
    }
    if !region.port_forward {
        bail!("[ERROR] Selected server doesn't support port forwarding")
    }
    println!("[INFO] Region {} selected", region.name);

    let mut login = HashMap::new();
    login.insert(
        "username",
        env::var("PIA_USER").expect("[ERROR] Missing PIA_USER in environment variables"),
    );
    login.insert(
        "password",
        env::var("PIA_PASS").expect("[ERROR] Missing PIA_PASS in environment variables"),
    );
    let token: Token = reqwest::Client::new()
        .post("https://www.privateinternetaccess.com/api/client/v2/token")
        .form(&login)
        .send()
        .await?
        .json()
        .await
        .expect("[ERROR] Failed to login");
    println!("[INFO] Successfully logged in and created token");

    let data = reqwest::Client::new()
        .get("https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt")
        .send()
        .await?
        .bytes()
        .await?;
    println!("[INFO] Fetched PIA certificate");

    let server = region.servers.get("wg").unwrap().first().unwrap();
    let port = list
        .groups
        .get("wg")
        .unwrap()
        .first()
        .unwrap()
        .ports
        .first()
        .unwrap();

    // need to build custom reqwest client to add custom resolver and pia's root certificates
    let pia_client = reqwest::Client::builder()
        .resolve(
            &server.cn,
            format!("{}:{}", server.ip, port).parse().unwrap(),
        )
        .add_root_certificate(reqwest::Certificate::from_pem(&data)?)
        .build()?;

    let conf = config::Config::new(&server.cn, &token.token, *port, &pia_client)
        .await
        .expect("[ERROR] Failed to generate wireguard configuration");
    conf.write(format!("{}/wg0.conf", CONFIG_PATH).parse()?)
        .await;

    let old_ip = reqwest::Client::new()
        .get("https://icanhazip.com")
        .send()
        .await?
        .text()
        .await?;

    Command::new("wg-quick")
        .args(["up", &format!("{}/wg0.conf", CONFIG_PATH)])
        .status()
        .expect("[ERROR] Wireguard failed to start");

    loop {
        println!("[INFO] Waiting for wireguard interface to go up");
        let interface =
            Interface::get_by_name("wg0")?.expect("[ERROR] failed to find wireguard interface");
        if interface.is_up() {
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }
    println!("[INFO] Wireguard interface up");

    let default_route = String::from_utf8_lossy(
        &Command::new("ip")
            .args(["-o", "-4", "route", "show", "to", "default"])
            .output()
            .unwrap()
            .stdout,
    )
    .into_owned();

    let interface_name = default_route
        .split(' ')
        .nth(4)
        .expect("[ERROR] Failed to find the default interface");

    let gateway = default_route.split(' ').nth(2).unwrap();

    let network_cidr = {
        let inet_cmd = String::from_utf8_lossy(
            &Command::new("ip")
                .args(["-o", "-f", "inet", "addr", "show", interface_name])
                .output()
                .unwrap()
                .stdout,
        )
        .into_owned();
        let cidr_re = Regex::new(r#"(?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d{1,2}"#).unwrap();
        let cidr = cidr_re
            .find(&inet_cmd)
            .expect("Failed to find inet CIDR")
            .as_str();
        let ipcalc_cmd =
            String::from_utf8_lossy(&Command::new("ipcalc").args([cidr]).output().unwrap().stdout)
                .into_owned();
        cidr_re
            .find(ipcalc_cmd.split('\n').nth(1).unwrap())
            .expect("[ERROR] Failed to calculate inet CIDR")
            .as_str()
            .to_owned()
    };

    if let Ok(networks) = env::var("VPN_LAN_NETWORKS") {
        for lan_network in networks.split(',') {
            println!("[INFO] Adding {lan_network} as route via interface {interface_name}");
            Command::new("ip")
                .args([
                    "route",
                    "add",
                    lan_network,
                    "via",
                    gateway,
                    "dev",
                    interface_name,
                ])
                .spawn()
                .expect("[ERROR] Failed to add VPN_LAN_NETWORKS");
        }
    }

    let ipt = iptables::new(false).unwrap();

    // drop everything forwarded between network interfaces
    ipt.set_policy("filter", "FORWARD", "DROP").unwrap();
    // drop everything incoming
    ipt.set_policy("filter", "INPUT", "DROP").unwrap();
    // accept everything on udp through wireguard interface
    ipt.append("filter", "INPUT", "-i wg0 -p udp -j ACCEPT")
        .unwrap();
    // accept everything on tcp through wireguard interface
    ipt.append("filter", "INPUT", "-i wg0 -p tcp -j ACCEPT")
        .unwrap();
    // accept local traffic
    ipt.append(
        "filter",
        "INPUT",
        &format!("-s {network_cidr} -d {network_cidr} -j ACCEPT"),
    )
    .unwrap();
    // accept incoming udp connections on default interface
    ipt.append(
        "filter",
        "INPUT",
        &format!("-i {interface_name} -p udp --sport {port} -j ACCEPT"),
    )
    .unwrap();
    // accept incoming ICMP echo replies
    ipt.append(
        "filter",
        "INPUT",
        "-p icmp --icmp-type echo-reply -j ACCEPT",
    )
    .unwrap();
    // accept incoming on localhost
    ipt.append("filter", "INPUT", "-i lo -j ACCEPT").unwrap();
    // drop everything outgoing
    ipt.set_policy("filter", "OUTPUT", "DROP").unwrap();
    // accept all udp outputs through wireguard interface
    ipt.append("filter", "OUTPUT", "-o wg0 -p udp -j ACCEPT")
        .unwrap();
    // accept all tcp outputs through wireguard interface
    ipt.append("filter", "OUTPUT", "-o wg0 -p tcp -j ACCEPT")
        .unwrap();
    // accept local traffic
    ipt.append(
        "filter",
        "OUTPUT",
        &format!("-s {network_cidr} -d {network_cidr} -j ACCEPT"),
    )
    .unwrap();
    // accept outgoing udp traffic on default interface on vpn port
    ipt.append(
        "filter",
        "OUTPUT",
        &format!("-o {interface_name} -p udp --dport {port} -j ACCEPT"),
    )
    .unwrap();
    // allow outgoing icmp echo requests
    ipt.append(
        "filter",
        "OUTPUT",
        "-p icmp --icmp-type echo-request -j ACCEPT",
    )
    .unwrap();
    // accept outgoing for localhost
    ipt.append("filter", "OUTPUT", "-o lo -j ACCEPT").unwrap();

    if let Ok(ports) = env::var("BYPASS_PORTS") {
        for port in ports.split(",") {
            let (port_num, protocol) = port.split_once("/").unwrap();
            println!("[INFO] Bypassing {port}");
            // drop incoming on wireguard interface for specified port and protocol
            ipt.insert(
                "filter",
                "INPUT",
                &format!("-i wg0 -p {protocol} --dport {port_num} -j DROP"),
                1,
            )
            .unwrap();
            // accept incoming on default interface for specified port and protocol
            ipt.append(
                "filter",
                "INPUT",
                &format!("-i {interface_name} -p {protocol} --dport {port_num} -j ACCEPT"),
            )
            .unwrap();

            // drop outgoing on wireguard interface for specified port and protocol
            ipt.insert(
                "filter",
                "OUTPUT",
                &format!("-o wg0 -p {protocol} --sport {port_num} -j DROP"),
                1,
            )
            .unwrap();
            // accept outgoing on default interface for specified port and protocol
            ipt.append(
                "filter",
                "OUTPUT",
                &format!("-o {interface_name} -p {protocol} --sport {port_num} -j ACCEPT"),
            )
            .unwrap();
        }
    }

    println!("[INFO] iptables modified",);

    if let Ok(delay) = env::var("VPN_IP_CHECK_DELAY") {
        println!("[INFO] Delaying IP check by {delay} seconds");
        sleep(Duration::from_secs(delay.parse::<u64>().unwrap())).await;
    }

    let new_ip = reqwest::Client::new()
        .get("https://icanhazip.com")
        .send()
        .await?
        .text()
        .await?;
    println!(
        "[INFO] Successfully connected to PIA\n----------------------------------------------------------------------\nOld IP: {}\nNew IP: {}\n----------------------------------------------------------------------",
        old_ip, new_ip
    );

    if env::var("PORT_FORWARDING")
        .unwrap_or_else(|_| "true".to_string())
        .parse::<bool>()
        .unwrap()
    {
        let persist_port = env::var("PERSIST_PORT")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap();

        println!("[INFO] Port forwarding is enabled");
        let api_client = reqwest::Client::builder()
            .resolve(&server.cn, format!("{}:19999", conf.api).parse().unwrap())
            .add_root_certificate(reqwest::Certificate::from_pem(&data)?)
            .build()?;

        let sig: Signature = {
            if persist_port && path::Path::new(&format!("{}/signature.json", CONFIG_PATH)).exists()
            {
                println!("[INFO] Persisted port is being used");
                serde_json::from_str(
                    &tokio::fs::read_to_string(format!("{}/signature.json", CONFIG_PATH))
                        .await
                        .unwrap(),
                )
                .unwrap()
            } else {
                println!("[INFO] New port signature is being fetched");
                api_client
                    .get(format!("https://{}:19999/getSignature", server.cn))
                    .query(&[("token", token.token)])
                    .send()
                    .await?
                    .json()
                    .await?
            }
        };

        if sig.status != "OK" {
            bail!("[ERROR] Failed to get signature: {}", sig.message.unwrap())
        }
        let payload: Payload =
            serde_json::from_str(std::str::from_utf8(&base64::decode(&sig.payload)?).unwrap())?;
        println!(
            "[INFO] Got PIA signature, expires at: {}",
            payload.expires_at
        );

        if env::var("CONNECTION_FILE")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap()
        {
            tokio::fs::write(
                format!("{}/connection.json", CONFIG_PATH),
                serde_json::json!({
                    "port": payload.port,
                    "ip": new_ip
                }),
            )
            .await
            .expect("[ERROR] failed to save data to file");
            println!(
                "[INFO] Connection data saved to {}/connection.json",
                CONFIG_PATH
            );
        }
        if env::var("PERSIST_PORT")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap()
        {
            tokio::fs::write(
                format!("{}/signature.json", CONFIG_PATH),
                serde_json::to_string(&sig).unwrap(),
            )
            .await
            .expect("[ERROR] failed to save port signature to file");
            println!(
                "[INFO] Port signature saved to {}/signature.json",
                CONFIG_PATH
            );
        }

        if let Ok(mam_id) = env::var("MAM_ID") {
            println!("[INFO] Setting seedbox IP for MyAnonaMouse");
            match reqwest::Client::new()
                .get("https://t.myanonamouse.net/json/dynamicSeedbox.php")
                .header("Cookie", mam_id)
                .send()
                .await?
                .error_for_status()
            {
                Ok(_) => println!("[INFO] seedbox IP set for MyAnonaMouse"),
                Err(e) => println!("[ERROR] Failed to set seedbox IP for MyAnonaMouse: {}", e),
            }
        }

        if env::var("SET_QBITTORRENT_PORT")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap()
        {
            println!("[INFO] Setting QBittorrent port via API");

            // let mut qb_login = HashMap::new();
            // qb_login.insert(
            //     "username",
            //     env::var("QBITTORRENT_USERNAME")
            //         .expect("[ERROR] Missing QBITTORRENT_USERNAME in environment variables"),
            // );
            // qb_login.insert(
            //     "password",
            //     env::var("QBITTORRENT_PASSWORD")
            //         .expect("[ERROR] Missing QBITTORRENT_PASSWORD in environment variables"),
            // );
            // // qbt doesn't return error if invalid login
            // let auth_cookie = reqwest::Client::new()
            //     .post(format!("{qb_url}/api/v2/auth/login"))
            //     .form(&qb_login)
            //     .send()
            //     .await?
            //     .headers()
            //     .get("Set-Cookie")
            //     .unwrap()
            //     .to_owned();
            // println!("{:#?}", auth_cookie);

            let mut qb_prefs = HashMap::new();
            qb_prefs.insert(
                "json",
                serde_urlencoded::to_string(serde_json::json!({
                    "listen_port": payload.port
                }))
                .unwrap(),
            );
            match reqwest::Client::new()
                .post(format!("localhost:8080/api/v2/app/setPreferences"))
                .form(&qb_prefs)
                .send()
                .await?
                .error_for_status()
            {
                Ok(_) => println!("[INFO] QBittorrent port set to {}", payload.port),
                Err(_) => println!("[ERROR] Failed to update QBittorrent port"),
            };
        }

        println!("[INFO] Binding port, this will refresh every 15 minutes");
        loop {
            if payload.expires_at.timestamp() < chrono::Utc::now().timestamp() {
                // this might not be good but the token lasts months so you'll probably restart before this
                println!("[INFO] Port signature expired, restarting process");
                Command::new("/proc/self/exe").exec();
                break;
            }

            let pf_bind: BindPort = api_client
                .get(format!("https://{}:19999/bindPort", server.cn))
                .query(&[("payload", &sig.payload), ("signature", &sig.signature)])
                .send()
                .await?
                .json()
                .await?;
            if pf_bind.status != "OK" {
                bail!("[ERROR] Failed to bind port: {}", pf_bind.message)
            }
            println!(
                "[INFO] Successfully forwarded port: {}\n[INFO] Port signature expires at: {} UTC",
                payload.port,
                payload.expires_at.format("%d/%m/%Y %H:%M")
            );
            sleep(Duration::from_secs(900)).await;

            //TODO add shutdown behavior using tokio select to end incoming connections
        }
    }

    Ok(())
}
