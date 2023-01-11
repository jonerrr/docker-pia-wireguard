# Docker + Wireguard + Private Internet Access

This is a docker image that connects to Private Internet Access using wireguard. You can use this with other docker images to route all traffic through PIA. There also is optional port forwarding support.

## Environment Variables

| Variable                 | Description                                                                                                                                                                        | Example             | Default |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ------- |
| PIA_USER\*               | Your PIA username.                                                                                                                                                                 | `p12345`            | None    |
| PIA_PASS\*               | Your PIA password.                                                                                                                                                                 | `password123`       | None    |
| PIA_REGION_ID\*          | The ID of your PIA region, you can find a list of regions [here](https://i.jnr.cx/DrqIgrcvaJ).                                                                                     | `de-frankfurt`      | None    |
| VPN_IP_CHECK_DELAY       | The delay in seconds until the VPN IP is checked.                                                                                                                                  | `5`                 | None    |
| VPN_LAN_NETWORKS         | A comma separated list of the local networks used to route local traffic.                                                                                                          | `192.168.90.0/24`   | None    |
| PORT_FORWARDING          | Enable port forwarding. The selected region must have port forwarding support if you enable this.                                                                                  | `true`              | `true`  |
| CONNECTION_FILE          | Write a file that contains JSON data of the VPN IP and port (e.g. `{ "port": 1234, "ip": "127.0.0.1" }`). It will be located at `/config/connection.json`.                         | `true`              | `false` |
| PERSIST_PORT             | Persist the port signature so the same port can be reused. The data will be stored at `/config/signature.json`. This signature usually lasts for a couple of months                | `true`              | `false` |
| BYPASS_PORTS             | A comma separated list of ports that will send traffic through the local interface instead of PIA.                                                                                 | `8080/tcp,8080/udp` | None    |
| ~~SET_QBITTORRENT_PORT~~ | Currently Broken ~~Automatically set the listening port in QBittorrent to the forwarded port. The QBittorrent API must be accessible via `localhost:8080` (without credentials).~~ | `true`              | `false` |
| MAM_ID                   | If a `MAM_ID` is supplied, the dynamic seedbox IP for [MyAnonaMouse](https://www.myanonamouse.net/) will be set.                                                                   | `x2s__aaa...`       | None    |

`*` = Required

## Example

Here is an example of forwarding all QBittorrent traffic through PIA. Once you receive the forwarded port (check logs), you can set it inside of QBittorrent's settings.

```yml
services:
  qbittorrent:
    container_name: qbittorrent
    image: hotio/qbittorrent
    restart: unless-stopped
    environment:
      - PUID=1000
      - PGID=1000
      - UMASK=022
      - TZ=America/New_York
      - VPN_ENABLED=false
      - PRIVOXY_ENABLED=false
    volumes:
      - ${VOLUMES}/qbittorrent:/config
      - ${VOLUMES}/downloads:/downloads
    network_mode: service:vpn
    depends_on:
      - vpn
  vpn:
    image: j0ner/pia-wireguard
    container_name: vpn
    restart: unless-stopped
    environment:
      - PIA_USER=p123
      - PIA_PASS=p123
      - PIA_REGION_ID=de-frankfurt
      - VPN_IP_CHECK_DELAY=5
      - PORT_FORWARDING=true
      - VPN_LAN_NETWORKS=192.168.90.0/24
      - CONNECTION_FILE=false
      - PERSIST_PORT=true
      - BYPASS_PORTS=8080/tcp,8080/udp
    volumes:
      - ${VOLUMES}/pia-wireguard:/config
    cap_add:
      - NET_ADMIN
    ports:
      - 8080:8080
    sysctls:
      - net.ipv4.conf.all.src_valid_mark=1
      - net.ipv6.conf.default.disable_ipv6=1
      - net.ipv6.conf.all.disable_ipv6=1
      - net.ipv6.conf.lo.disable_ipv6=1
```
