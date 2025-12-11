# Eoolii Camera Local Streaming

A reverse-engineered local streaming solution for Eoolii/Closeli IP cameras. This project bypasses the cloud dependency and enables fully local, peer-to-peer streaming without internet access.

## Overview

Eoolii cameras are designed to communicate with `closeli.com` cloud servers. This project intercepts and emulates that communication, allowing you to:

- Stream video/audio locally without internet
- Support multiple cameras simultaneously
- View streams in VLC or any MJPEG-compatible player

### Architecture

```
┌─────────────┐     DNS Redirect      ┌──────────────────┐
│   Camera    │ ──────────────────▶   │  mock_api_server │ :443
│ 192.168.x.x │                       │  (HTTPS API)     │
└─────────────┘                       └──────────────────┘
       │                                      │
       │ TLS Connection                       │ Returns local relay IP
       ▼                                      ▼
┌──────────────────┐                  ┌──────────────────┐
│ local_relay_server│ :50721 ◀────────│  Camera connects │
│  (XMPP + CCAM)   │                  │  to local relay  │
└──────────────────┘                  └──────────────────┘
       │
       │ Forwards video stream
       ▼
┌──────────────────┐
│  stream_to_vlc   │ :8080/8081/...
│  (HTTP Server)   │
└──────────────────┘
       │
       │ MJPEG / WAV
       ▼
┌──────────────────┐
│   VLC Player     │
│   or Browser     │
└──────────────────┘
```

## Requirements

- Python 3.8+
- OpenSSL (for certificate generation)
- VLC or any MJPEG player
- DNS redirection capability (router or local DNS server)

### Python Dependencies

```bash
pip install cryptography
```

## Quick Start

### 1. DNS Redirection

Redirect these domains to your server IP (e.g., `192.168.15.249`):

```
*.closeli.com
*.icloseli.com
*.closeli.cn
```

### 2. Start the Servers

```bash
# Terminal 1: Start the mock API server (requires sudo for port 443)
sudo python3 mock_api_server.py

# Terminal 2: Start the relay server
python3 local_relay_server.py

# Terminal 3: Start the stream proxy (one per camera)
python3 stream_to_vlc.py --device_id xxxxS_189e2d446d47 --port 8081
```

### 3. View the Stream

Open in VLC: **Media → Open Network Stream**

```
http://localhost:8081/camera/video
http://localhost:8081/camera/audio
```

## Components

### `local_relay_server.py`

The main relay server that handles camera connections. Emulates the Closeli cloud server.

- **Port 50721**: TLS connections from cameras and apps
- **Port 50722**: Management interface for CLI

**Features:**
- Multi-camera session management
- XMPP control protocol handling
- CCAM media stream forwarding
- Automatic device identification

### `stream_to_vlc.py`

Connects to the relay as an "app" and serves video/audio over HTTP.

```bash
python3 stream_to_vlc.py [OPTIONS]

Options:
  -d, --device_id    Camera device ID to connect to
  -p, --port         HTTP server port (default: 8080)
  -r, --relay_host   Relay server host (default: 192.168.15.249)
  --relay_port       Relay server port (default: 50721)
  -e, --email        User email for auth (default: configured email)
```

**Examples:**

```bash
# Single camera (default settings)
python3 stream_to_vlc.py

# Multiple cameras on different ports
python3 stream_to_vlc.py --device_id xxxxS_camera1 --port 8081
python3 stream_to_vlc.py --device_id xxxxS_camera2 --port 8082

# Custom relay server
python3 stream_to_vlc.py --relay_host 192.168.1.100 --relay_port 50721
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

**Examples:**

```bash
# See all connected cameras
python3 relay_cli.py list

# Check server status
python3 relay_cli.py status

# Manually assign a device ID to a camera IP
python3 relay_cli.py set-device 192.168.25.64 xxxxS_189e2d446d47

# Get details for a specific device
python3 relay_cli.py info xxxxS_189e2d446d47
```

## Multi-Camera Setup

### Step 1: Check Connected Cameras

```bash
$ python3 relay_cli.py list

IP Address         Connections  Device ID                 Uptime
-----------------------------------------------------------------
192.168.25.64      1            (unidentified)            5m 30s
192.168.15.39      1            (unidentified)            5m 28s

Total: 2 camera(s), 2 connection(s)
```

### Step 2: Assign Device IDs

If cameras show as "(unidentified)", assign their device IDs:

```bash
python3 relay_cli.py set-device 192.168.25.64 xxxxS_189e2d446d47
python3 relay_cli.py set-device 192.168.15.39 xxxxS_189e2d438ea9
```

### Step 3: Start Stream Proxies

```bash
# Terminal for Camera 1
python3 stream_to_vlc.py -d xxxxS_189e2d446d47 -p 8081

# Terminal for Camera 2
python3 stream_to_vlc.py -d xxxxS_189e2d438ea9 -p 8082
```

### Step 4: View Streams

| Camera | Video URL | Audio URL |
|--------|-----------|-----------|
| Camera 1 | `http://localhost:8081/camera/video` | `http://localhost:8081/camera/audio` |
| Camera 2 | `http://localhost:8082/camera/video` | `http://localhost:8082/camera/audio` |

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

## Troubleshooting

### Camera not connecting

1. Verify DNS redirection is working:
   ```bash
   nslookup auto-link.closeli.com
   # Should return your server IP
   ```

2. Check mock_api_server is running on port 443

3. Verify certificates are in place (`server.crt`, `server.key`)

### No video stream

1. Check relay server logs for connection errors

2. Verify camera is registered:
   ```bash
   python3 relay_cli.py list
   ```

3. Try triggering the stream manually via the app

### Device shows as "(unidentified)"

Cameras that were already configured before the relay started won't re-send their device ID. Manually assign it:

```bash
python3 relay_cli.py set-device <camera_ip> <device_id>
```

## File Structure

```
.
├── local_relay_server.py   # Main relay server
├── stream_to_vlc.py        # Stream proxy for VLC
├── mock_api_server.py      # Mock HTTPS API server
├── relay_cli.py            # CLI management tool
├── server.crt              # TLS certificate
├── server.key              # TLS private key
└── README.md               # This file
```

## License

This project is for educational and research purposes only. Use responsibly and only on devices you own.

## Acknowledgments

This project was developed through reverse engineering of the Eoolii camera protocol. Special thanks to the security research community for tools and techniques that made this possible.
