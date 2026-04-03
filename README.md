# Closeli Camera Local Streaming

A reverse-engineered local streaming solution for Eoolii/Closeli IP cameras. This project bypasses the cloud dependency and enables fully local, peer-to-peer streaming without internet access.

If you are only looking for a client to intercept the camera stream, you might be interested in https://github.com/radzki/CloseliStreamServerRemote

## Overview

Eoolii cameras are designed to communicate with `closeli.com` cloud servers. This project intercepts and emulates that communication, allowing you to:

- Stream video/audio locally without internet
- Support multiple cameras simultaneously
- View streams in VLC or any MJPEG-compatible player

### Architecture

```
┌─────────────┐    ARP Spoof + DNS     ┌──────────────────┐
│   Camera    │ ──────────────────────▶│  dns-redirect    │
│ 192.168.x.x │   Camera thinks we     │  (dnsmasq +      │
└─────────────┘   are the gateway,      │   arpspoof)      │
       │          DNS spoofed to        └──────────────────┘
       │          resolve closeli.com          │
       │          to local IP                  │
       ▼                                       ▼
┌──────────────────┐                  ┌──────────────────┐
│ mock_api_server  │ :443             │  Camera resolves │
│  (HTTPS API)     │◀─────────────────│  closeli.com to  │
└──────────────────┘                  │  local server    │
       │                              └──────────────────┘
       │ Returns local relay IP
       ▼
┌──────────────────┐
│ local_relay_server│ :50721
│  (XMPP + CCAM)   │
└──────────────────┘
       │
       │ Forwards video stream
       ▼
┌──────────────────┐
│  stream_server   │ :8081/8082/...
│  (HTTP Server)   │
└──────────────────┘
       │
       │ MJPEG / WAV
       ▼
┌──────────────────┐
│   VLC / Browser  │
│   / Frigate      │
└──────────────────┘
```

## Quick Start (Docker)

### 1. Configure `.env`

```bash
cp .env.example .env
# Edit .env with your values:
#   LOCAL_IP       - Your server's LAN IP
#   CAMERA_IPS     - Comma-separated camera IPs
#   GATEWAY_IP     - Your router's IP
#   CAMERA1_DEVICE_ID - Camera device ID (format: xxxxS_<mac>)
```

### 2. Start Everything

```bash
docker compose up -d                          # Core services + DNS redirect
docker compose --profile camera1 up -d        # Add camera 1 stream
```

That's it. The `dns-redirect` container handles ARP spoofing and DNS automatically.

### 3. View the Stream

Open in VLC or browser:

```
http://<server-ip>:8081/camera/video
http://<server-ip>:8081/camera/audio
```

## DNS Redirect (ARP Spoofing)

The cameras hardcode `8.8.8.8` as their DNS server and have no open ports for direct local access. To redirect them to the local relay, we use ARP spoofing.

### How it Works

1. **ARP Spoof**: The `dns-redirect` container tells each camera that our server is the default gateway. The camera's traffic now flows through us.
2. **iptables DNAT**: DNS queries (port 53) from the cameras are redirected to a local dnsmasq instance.
3. **dnsmasq**: Resolves `*.closeli.com` / `*.icloseli.com` to the local server IP. All other DNS queries are forwarded to `1.1.1.1` normally.
4. **IP Forwarding**: All non-DNS camera traffic is forwarded to the real gateway, so the camera still has internet for NTP, firmware checks, etc.

### Spoofed Domains

| Domain | Redirected To |
|--------|--------------|
| `*.closeli.com` | `LOCAL_IP` |
| `*.icloseli.com` | `LOCAL_IP` |
| `*.closeli.cn` | `LOCAL_IP` |
| `*.icloseli.cn` | `LOCAL_IP` |

### Multiple Cameras

Set comma-separated IPs in `.env`:

```
CAMERA_IPS=192.168.15.21,192.168.15.22,192.168.15.30
```

Each camera gets its own arpspoof process and iptables rules.

### Docker Requirements

The `dns-redirect` container requires:
- `network_mode: host` (L2 access for ARP spoofing)
- `NET_ADMIN` + `NET_RAW` capabilities (iptables + raw sockets)
- IP forwarding enabled on the host (`sysctl net.ipv4.ip_forward=1`)

### Manual DNS Redirect (without Docker)

If you prefer to run it manually:

```bash
sudo ./dns_redirect.sh start 192.168.15.21
sudo ./dns_redirect.sh status
sudo ./dns_redirect.sh stop
```

### Troubleshooting DNS Redirect

**Camera goes offline after starting:**
- Check `sysctl net.ipv4.ip_forward` is `1`
- Check iptables FORWARD chain isn't dropping camera traffic:
  ```bash
  sudo iptables -L FORWARD -n -v | head -10
  ```
- If FORWARD policy is DROP (e.g. Docker), the container adds ACCEPT rules automatically

**No DNS queries from camera:**
- Camera may have cached DNS. Reboot the camera.
- Camera may have changed IP after reboot. Check your router's DHCP leases and update `CAMERA_IPS`.

**Docker build fails with DNS errors:**
- Stop dns-redirect first, restart Docker, then rebuild:
  ```bash
  docker compose down
  sudo systemctl restart docker
  docker compose build
  ```

## Requirements

- Docker and Docker Compose
- OpenSSL certificates (`server.crt`, `server.key`)
- Host with IP forwarding enabled

### Without Docker

- Python 3.8+
- `dnsmasq`, `dsniff` (arpspoof), `iptables`
- VLC or any MJPEG player

## Components

### `dns_redirect_entrypoint.sh`

Docker entrypoint for the `dns-redirect` container. Runs dnsmasq + arpspoof and sets up iptables rules. Cleans up on container stop.

### `local_relay_server.py`

The main relay server that handles camera connections. Emulates the Closeli cloud server.

- **Port 50721**: TLS connections from cameras and apps
- **Port 50722**: Management interface for CLI

**Features:**
- Multi-camera session management
- XMPP control protocol handling
- CCAM media stream forwarding
- Automatic device identification

### `stream_server.py`

Connects to the relay as an "app" and serves video/audio over HTTP.

```bash
python3 stream_server.py [OPTIONS]

Options:
  -d, --device_id    Camera device ID to connect to
  -p, --port         HTTP server port (default: 8080)
  -r, --relay_host   Relay server host (default: 127.0.0.1)
  --relay_port       Relay server port (default: 50721)
  -e, --email        User email for auth
```

### `mock_api_server.py`

HTTPS server that responds to camera bootstrap API requests.

- **Port 443**: HTTPS API endpoints

**Endpoints:**
- `/sentry/dns/camera/services` - Service discovery
- `/lookup/v6/assignRelayIp` - Relay server assignment
- `/ntp` - Time synchronization
- `/magik/v1/schema/multi` - Camera settings

### `relay_cli.py`

Command-line interface for managing the relay server.

```bash
python3 relay_cli.py [COMMAND]

Commands:
  list        List all connections (grouped by IP)
  sessions    List identified device sessions
  status      Show server status
  info        Show device details
  query       Query a connection for device info
  query-all   Query all unidentified connections
  set-device  Manually assign device_id to an IP
```

## Multi-Camera Setup

### 1. Configure `.env`

```env
CAMERA_IPS=192.168.15.21,192.168.15.22
CAMERA1_DEVICE_ID=xxxxS_189e2d5b3216
CAMERA2_DEVICE_ID=xxxxS_189e2d446d47
```

### 2. Start Services

```bash
docker compose --profile camera1 --profile camera2 up -d
```

### 3. View Streams

| Camera | Video | Audio |
|--------|-------|-------|
| Camera 1 | `http://server:8081/camera/video` | `http://server:8081/camera/audio` |
| Camera 2 | `http://server:8082/camera/video` | `http://server:8082/camera/audio` |

## Protocol Details

### Control Protocol (XMPP-based)

The camera uses a custom XMPP-like protocol over TLS for command and control.

**Handshake Sequence:**
1. **UDI Config**: Camera sends device info + capabilities
2. **GDL (Get Device List)**: Camera polls for status
3. **S_GET/S_SAVE**: Configuration sync

### Media Protocol (CCAM v4)

Video and audio are transmitted using the CCAM protocol.

| Field | Size | Description |
|-------|------|-------------|
| Length | 4 bytes | Packet length (big-endian) |
| Magic | 4 bytes | `CCAM` |
| Version | 1 byte | `0x04` |
| Type | 1 byte | `0x02` (video), `0x01` (audio) |
| Fragments | 1 byte | Total fragments for frame |
| Fragment # | 1 byte | Current fragment index |
| Frame ID | 2 bytes | Sequence ID |
| Payload | N bytes | Media data |

**Video Format:** MJPEG (Motion JPEG), unencrypted
**Audio Format:** G.711 A-law (PCMA), 8000 Hz, mono

## File Structure

```
.
├── docker-compose.yml            # Docker Compose services
├── Dockerfile                    # Main app image
├── Dockerfile.dns-redirect       # DNS redirect image (dnsmasq + arpspoof)
├── dns_redirect_entrypoint.sh    # DNS redirect container entrypoint
├── local_relay_server.py         # Main relay server
├── stream_server.py              # Stream proxy (HTTP MJPEG/WAV)
├── mock_api_server.py            # Mock HTTPS API server
├── relay_cli.py                  # CLI management tool
├── server.crt                    # TLS certificate
├── server.key                    # TLS private key
├── .env                          # Configuration
└── README.md                     # This file
```

## License

This project is for educational and research purposes only. Use responsibly and only on devices you own.
