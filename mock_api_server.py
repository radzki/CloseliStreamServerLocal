#!/usr/bin/env python3
"""
Mock API Server for Camera Auto-Link Endpoints
Responds to camera's bootstrap API requests with local relay server info

Usage:
    python mock_api_server.py

Endpoints:
    /sentry/dns/camera/services - Service discovery
    /lookup/v6/assignRelayIp - Relay server IP assignment
    /ntp - NTP time service

This must run with HTTPS (even with self-signed cert) since camera expects HTTPS.

Multi-Camera Support:
    This server queries the local relay's management interface to get
    the list of connected cameras dynamically, instead of using hardcoded device IDs.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import json
import time
import socket
from datetime import datetime
import os
from pathlib import Path
import urllib.request
import urllib.parse


# ============================================================================
# Environment Loading
# ============================================================================
def load_dotenv():
    """Load environment variables from .env file if it exists"""
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    if value and value[0] in ('"', "'") and value[-1] == value[0]:
                        value = value[1:-1]
                    os.environ.setdefault(key, value)

load_dotenv()

# Configuration
API_PORT = int(os.environ.get("API_PORT", "443"))
API_HOST = "0.0.0.0"
LOCAL_RELAY_IP = os.environ.get("LOCAL_IP", "192.168.1.100")
RELAY_PORT = int(os.environ.get("RELAY_PORT", "50721"))
RELAY_MGMT_PORT = int(os.environ.get("MGMT_PORT", "50722"))

# Proxy mode - forward to real server to capture responses
PROXY_MODE = False  # Set to True to proxy to real server (for testing)
REAL_SERVER = "auto-link.closeli.com"
ESD_SERVER = "esd.icloseli.com"


def query_relay_server(command, params=None):
    """Query the relay server's management interface"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)  # Timeout applies to all operations
        sock.connect(("127.0.0.1", RELAY_MGMT_PORT))

        request = {"command": command, "params": params or {}}
        request_bytes = json.dumps(request).encode('utf-8')
        sock.sendall(len(request_bytes).to_bytes(4, 'big') + request_bytes)

        resp_len_bytes = sock.recv(4)
        if len(resp_len_bytes) < 4:
            return None
        resp_len = int.from_bytes(resp_len_bytes, 'big')

        # Sanity check - don't try to read absurdly large responses
        if resp_len > 1024 * 1024:  # 1MB max
            print(f"[RELAY] Response too large: {resp_len} bytes")
            return None

        resp_data = b""
        while len(resp_data) < resp_len:
            chunk = sock.recv(min(4096, resp_len - len(resp_data)))
            if not chunk:
                break
            resp_data += chunk

        return json.loads(resp_data.decode('utf-8'))
    except socket.timeout:
        print(f"[RELAY] Timeout querying relay server")
        return None
    except ConnectionRefusedError:
        # Relay not running - this is expected sometimes
        return None
    except Exception as e:
        print(f"[RELAY] Error querying relay: {e}")
        return None
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


def get_connected_devices():
    """Get list of connected device IDs from relay server"""
    # First try sessions (identified devices)
    response = query_relay_server("list_sessions")
    if response and "sessions" in response:
        devices = list(response["sessions"].keys())
        if devices:
            print(f"[RELAY] Found {len(devices)} identified device(s): {devices}")
            return devices

    # Fallback: try connections (may have IPs but no device IDs yet)
    response = query_relay_server("list_connections")
    if response and "connections" in response:
        # Extract unique device_ids from connections
        devices = set()
        for conn in response["connections"]:
            if conn.get("device_id"):
                devices.add(conn["device_id"])
        if devices:
            print(f"[RELAY] Found {len(devices)} device(s) from connections: {list(devices)}")
            return list(devices)

    print("[RELAY] No connected devices found, relay may not be running")
    return []

class CameraAPIHandler(BaseHTTPRequestHandler):
    """Handle camera API requests"""

    # Timeout for slow clients (prevents hanging connections)
    timeout = 30

    def log_message(self, format, *args):
        """Override to add timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {self.address_string()} - {format % args}")

    def proxy_to_real_server(self, method='GET', post_data=None, server=None):
        """Forward request to real server and capture response"""
        try:
            # Determine which server to use
            if server is None:
                # Auto-detect based on path or Host header
                # Use the Host header from camera if present
                host_header = self.headers.get('Host', '')
                if 'esd.icloseli.com' in host_header or 'esd.closeli.cn' in host_header:
                    server = ESD_SERVER
                elif '/lecam/' in self.path or '/getProductkeyInfo' in self.path or '/lookup/v6/assignRelayIp' in self.path:
                    server = ESD_SERVER
                else:
                    server = REAL_SERVER

            # Build the real URL
            real_url = f"https://{server}{self.path}"

            print(f"\n[PROXY] Forwarding {method} request to: {real_url}")

            # Prepare headers - forward ALL headers from camera except a few
            headers = {}
            skip_headers = ['Host', 'Content-Length', 'Connection']  # These are set automatically

            for header_name, header_value in self.headers.items():
                if header_name not in skip_headers:
                    headers[header_name] = header_value

            # Ensure Host header matches the destination server
            headers['Host'] = server

            print(f"[PROXY] Forwarding headers: {headers}")

            # Make request
            if method == 'POST' and post_data:
                req = urllib.request.Request(real_url, data=post_data, headers=headers, method='POST')
            else:
                req = urllib.request.Request(real_url, headers=headers, method='GET')

            # Send request and get response
            with urllib.request.urlopen(req, timeout=10) as response:
                response_data = response.read()
                response_text = response_data.decode('utf-8', errors='replace')

                print(f"[PROXY] Real server responded ({len(response_data)} bytes):")
                print(f"[PROXY] Response: {response_text}")

                # Save to file for analysis
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"real_server_response_{timestamp}.txt"
                with open(filename, 'w') as f:
                    f.write(f"URL: {real_url}\n")
                    f.write(f"Method: {method}\n")
                    f.write(f"Headers: {dict(self.headers)}\n")
                    if post_data:
                        f.write(f"POST Data: {post_data.decode('utf-8', errors='replace')}\n")
                    f.write(f"\nResponse:\n{response_text}\n")
                print(f"[PROXY] Response saved to: {filename}")

                # INTERCEPT: Modify assignRelayIp response to redirect camera to our local relay proxy
                if '/assignRelayIp' in self.path:
                    try:
                        real_response = json.loads(response_text)
                        original_host = real_response.get('relayhost', 'N/A')
                        original_port = real_response.get('relayport', 'N/A')

                        print(f"\n[INTERCEPT] Original relay: {original_host}:{original_port}")

                        # Replace with our local relay proxy
                        real_response['relayhost'] = LOCAL_RELAY_IP
                        real_response['relayport'] = str(RELAY_PORT)
                        real_response['downloadPort'] = str(RELAY_PORT)

                        print(f"[INTERCEPT] Modified relay: {real_response['relayhost']}:{real_response['relayport']}")
                        print(f"[INTERCEPT] Camera will connect to our proxy at {LOCAL_RELAY_IP}:{RELAY_PORT}")
                        print(f"[INTERCEPT] Proxy will forward to real server at {original_host}:{original_port}\n")

                        # Re-encode modified response
                        response_text = json.dumps(real_response, separators=(',', ':'))
                        response_data = response_text.encode('utf-8')
                    except Exception as e:
                        print(f"[INTERCEPT] ERROR modifying response: {e}, using original")

                # Send response back to camera
                self.send_response(200)
                self.send_header('Content-Type', response.headers.get('Content-Type', 'application/json'))
                self.send_header('Content-Length', len(response_data))
                self.end_headers()
                self.wfile.write(response_data)

                return True

        except Exception as e:
            print(f"[PROXY] Error forwarding to real server: {e}")
            print(f"[PROXY] Falling back to local response")
            return False

    def send_json_response(self, data, status=200):
        """Send JSON response"""
        # Send compact JSON (no indentation) like real server
        json_data = json.dumps(data, separators=(',', ':'))
        json_bytes = json_data.encode('utf-8')

        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(json_bytes)))
        self.end_headers()

        self.wfile.write(json_bytes)

        # Print pretty version for readability
        print(f"Response ({len(json_bytes)} bytes): {json.dumps(data, indent=2)}")

    def do_GET(self):
        """Handle GET requests"""
        print(f"\n{'='*70}")
        print(f"GET {self.path}")
        print(f"Headers: {dict(self.headers)}")

        # NTP endpoint - proxy if enabled
        if '/ntp' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='GET'):
                    return
            self.handle_ntp()

        # Service discovery - proxy if enabled
        elif '/sentry/dns/camera/services' in self.path or '/services' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='GET'):
                    return
            self.handle_services()

        # Relay IP assignment - proxy to see real format
        elif '/lookup/v6/assignRelayIp' in self.path or '/assignRelayIp' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='GET'):
                    return
            self.handle_assign_relay_ip()

        # Relay IP lookup - /lookup/v6/getRelayIPList (PRIMARY ENDPOINT FOR APP)
        elif '/lookup/v6/getRelayIPList' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='GET', server=ESD_SERVER):
                    return
            self.handle_v6_relay_ip_list(post_data=None)

        # App's relay IP lookup endpoint (alternative)
        elif '/lecam/service/device/getRelayIPList' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='GET'):
                    return
            self.handle_get_relay_ip_list()

        # Camera settings/schema endpoint (NEW - for P2P mode)
        elif '/magik/v1/schema/multi' in self.path or '/schema/multi' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='GET', server='link-us-aws.icloseli.com'):
                    return
            self.handle_camera_schema_multi()

        # Default response
        else:
            print(f"Unknown endpoint: {self.path}")
            self.send_json_response({
                "status": "unknown_endpoint",
                "path": self.path,
                "message": "Endpoint not implemented, logging for analysis"
            }, 404)

    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b''

        print(f"\n{'='*70}")
        print(f"POST {self.path}")
        print(f"Headers: {dict(self.headers)}")

        if post_data:
            print(f"Body: {post_data.decode('utf-8', errors='replace')}")

        # Service discovery - camera version
        if '/sentry/dns/camera/services' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='POST', post_data=post_data):
                    return  # Successfully proxied
                # If proxy failed, fall through to local handler
            self.handle_services()

        # Service discovery - app version (NEW)
        elif '/sentry/dns/app/services' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='POST', post_data=post_data):
                    return  # Successfully proxied
            self.handle_app_services()

        # Product key info - app endpoint (NEW)
        elif '/lecam/service/support/getProductkeyInfo' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='POST', post_data=post_data, server=ESD_SERVER):
                    return  # Successfully proxied
            self.handle_product_key_info()

        # Generic /services fallback
        elif '/services' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='POST', post_data=post_data):
                    return
            self.handle_services()

        # Relay IP assignment (might be POST) - proxy to see real format
        elif '/assignRelayIp' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='POST', post_data=post_data):
                    return
            self.handle_assign_relay_ip()

        # Relay IP lookup - /lookup/v6/getRelayIPList (PRIMARY ENDPOINT FOR APP)
        elif '/lookup/v6/getRelayIPList' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='POST', post_data=post_data, server=ESD_SERVER):
                    return
            self.handle_v6_relay_ip_list(post_data=post_data)

        # App's relay IP lookup endpoint (alternative, might be POST)
        elif '/lecam/service/device/getRelayIPList' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='POST', post_data=post_data):
                    return
            self.handle_get_relay_ip_list()

        # Camera settings/schema endpoint (NEW - for P2P mode)
        elif '/magik/v1/schema/multi' in self.path or '/schema/multi' in self.path:
            if PROXY_MODE:
                if self.proxy_to_real_server(method='POST', post_data=post_data, server='link-us-aws.icloseli.com'):
                    return
            self.handle_camera_schema_multi(post_data=post_data)

        # Default response
        else:
            print(f"Unknown POST endpoint: {self.path}")
            self.send_json_response({
                "status": "unknown_endpoint",
                "path": self.path,
                "message": "Endpoint not implemented, logging for analysis"
            }, 404)

    def handle_ntp(self):
        """Handle NTP time request"""
        # Real server returns plain text millisecond timestamp, not JSON
        current_time_ms = int(time.time() * 1000)

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()

        response_text = str(current_time_ms)
        self.wfile.write(response_text.encode('utf-8'))

        print(f"Response: {response_text}")

    def handle_services(self):
        """Handle service discovery request"""
        # Match real server's JSON structure exactly
        # Real server only returns 2 services: lecam_purchase_server_ip and doorbell_server_ip
        current_time_ms = int(time.time() * 1000)

        response = {
            "code": "200",
            "msg": "success",
            "data": {
                "addresses": [
                    {
                        "service_name": "lecam_purchase_server_ip",
                        "url": f"{LOCAL_RELAY_IP}"
                    },
                    {
                        "service_name": "doorbell_server_ip",
                        "url": f"{LOCAL_RELAY_IP}:{RELAY_PORT},{LOCAL_RELAY_IP}:{RELAY_PORT}"
                    }
                ],
                "gateway_url": "https://auto-link.closeli.com",
                "version": "v1",
                "request_utc_time": current_time_ms,
                "dns_v4": [""],
                "dns_v6": [""]
            }
        }

        self.send_json_response(response)

    def handle_assign_relay_ip(self):
        """Handle relay IP assignment request"""
        # Real format from captured working response
        response = {
            "failflag": "0",
            "failmsg": "success",
            "relayhost": LOCAL_RELAY_IP,
            "relayport": str(RELAY_PORT),
            "publicIPV6": "",
            "relayDomainName": "local-relay.closeli.com",
            "downloadPort": str(RELAY_PORT)
        }

        self.send_json_response(response)

    def handle_get_relay_ip_list(self):
        """Handle app's relay IP list request"""
        # Format for app's getRelayIPList endpoint
        # Return our local relay server
        response = {
            "code": "200",
            "msg": "success",
            "data": {
                "relayIPList": [
                    {
                        "relayIp": LOCAL_RELAY_IP,
                        "relayPort": RELAY_PORT,
                        "relayHost": LOCAL_RELAY_IP,
                        "relayDomainName": "local-relay.closeli.com"
                    }
                ],
                # Alternative flat format in case app expects it differently
                "relayIp": LOCAL_RELAY_IP,
                "relayPort": RELAY_PORT,
                "relayhost": LOCAL_RELAY_IP,
                "relayport": str(RELAY_PORT)
            }
        }

        self.send_json_response(response)

    def handle_app_services(self):
        """Handle app's service discovery request (different from camera's)"""
        # This will be populated after we capture the real response
        # For now, return similar to camera's version but for app
        current_time_ms = int(time.time() * 1000)

        response = {
            "code": "200",
            "msg": "success",
            "data": {
                "addresses": [
                    {
                        "service_name": "lecam_purchase_server_ip",
                        "url": f"{LOCAL_RELAY_IP}"
                    },
                    {
                        "service_name": "doorbell_server_ip",
                        "url": f"{LOCAL_RELAY_IP}:{RELAY_PORT},{LOCAL_RELAY_IP}:{RELAY_PORT}"
                    }
                ],
                "gateway_url": "https://auto-link.closeli.com",
                "version": "v1",
                "request_utc_time": current_time_ms,
                "dns_v4": [""],
                "dns_v6": [""]
            }
        }

        self.send_json_response(response)

    def handle_product_key_info(self):
        """Handle product key info request"""
        # This endpoint may contain camera online status
        # Will be populated after capturing real response
        response = {
            "code": "200",
            "msg": "success",
            "data": {
                "online": True,  # Make camera appear online
                "relayIp": LOCAL_RELAY_IP,
                "relayPort": RELAY_PORT
            }
        }

        self.send_json_response(response)

    def handle_v6_relay_ip_list(self, post_data=None):
        """Handle /lookup/v6/getRelayIPList - PRIMARY app endpoint for relay info"""
        # This endpoint has TWO modes:
        # 1. General service list (no device_list in POST)
        # 2. Device-specific relay assignments (with device_list in POST)

        # Check if this is a device-specific query
        device_list = None
        if post_data:
            try:
                # Try to parse as form data
                import urllib.parse
                post_str = post_data.decode('utf-8', errors='replace')
                print(f"[DEBUG] POST data: {post_str}")

                # Check if device_list is in the POST data
                if 'device_list' in post_str:
                    # Parse form data
                    parsed = urllib.parse.parse_qs(post_str)
                    if 'device_list' in parsed:
                        device_list_str = parsed['device_list'][0]
                        print(f"[DEBUG] Device list found: {device_list_str}")

                        # Parse device list JSON
                        import json as json_module
                        device_list = json_module.loads(device_list_str)
                        print(f"[DEBUG] Parsed device list: {device_list}")
            except Exception as e:
                print(f"[DEBUG] Error parsing POST data: {e}")

        # If device_list is present, return device-specific relay assignments
        if device_list:
            print(f"[!] Device-specific relay query for {len(device_list)} devices")

            # Build response with local relay for each requested device
            # Format matches exact response from esd.icloseli.com/lookup/v6/getRelayIPList
            device_data = {}
            for device in device_list:
                device_id = device.get('device_id', '')
                if device_id:
                    # Generate a fake WSS domain name (similar to real format)
                    # Real format: br-hw-85bae3999b12622a.closeli-stream-01.com:50721
                    import hashlib
                    device_hash = hashlib.md5(device_id.encode()).hexdigest()[:16]
                    wss_domain = f"local-{device_hash}.closeli-stream-01.com"

                    device_data[device_id] = [{
                        "public_ip": LOCAL_RELAY_IP,
                        "public_ipv6": "",  # IPv6 optional
                        "private_ip": LOCAL_RELAY_IP,
                        "channel_no": "0",
                        "channel_name": "720p",
                        "download_port": str(RELAY_PORT),
                        "region": "local",  # Region identifier
                        "zone": "",  # Zone (empty in real response)
                        "private_port": str(RELAY_PORT),
                        "up_time": str(int(time.time() * 1000)),  # Milliseconds timestamp
                        "wss": f"{wss_domain}:{RELAY_PORT}"  # WebSocket Secure domain
                    }]
                    print(f"  [{device_id}] → {LOCAL_RELAY_IP}:{RELAY_PORT} (wss://{wss_domain}:{RELAY_PORT})")

            response = {
                "failflag": "0",
                "failmsg": "success",
                "data": device_data
            }

            print(f"[!] Returning relay assignments for {len(device_data)} devices")
            self.send_json_response(response)

        else:
            # No device_list - return general service list
            print(f"[!] General service list query")
            current_time_ms = int(time.time() * 1000)

            response = {
                "code": "200",
                "msg": "success",
                "data": {
                    "domestic_services": [
                        {"service_name": "doorbell_server_ip", "url": f"{LOCAL_RELAY_IP}:{RELAY_PORT},{LOCAL_RELAY_IP}:{RELAY_PORT}"},
                        {"service_name": "relay_server_ip", "url": LOCAL_RELAY_IP},
                        {"service_name": "lecam_purchase_server_ip", "url": "esd.closeli.cn"},
                        {"service_name": "camera_setting_server_ip", "url": "esd.closeli.cn"}
                    ],
                    "abroad_services": [
                        {"service_name": "doorbell_server_ip", "url": f"{LOCAL_RELAY_IP}:{RELAY_PORT},{LOCAL_RELAY_IP}:{RELAY_PORT}"},
                        {"service_name": "relay_server_ip", "url": LOCAL_RELAY_IP},
                        {"service_name": "lecam_purchase_server_ip", "url": "esd.icloseli.com"},
                        {"service_name": "camera_setting_server_ip", "url": "esd.icloseli.com"}
                    ],
                    "version": "v1",
                    "domestic_gateway_url": "",
                    "abroad_gateway_url": f"https://{LOCAL_RELAY_IP}"
                }
            }

            self.send_json_response(response)

    def handle_camera_schema_multi(self, post_data=None):
        """
        Handle /magik/v1/schema/multi - Camera settings endpoint

        This endpoint returns ALL camera settings including localPlaybackMode.
        We'll modify it to return localPlaybackMode=1 (P2P enabled) instead of 2 (relay only)
        """
        print(f"\n[!] Camera schema/settings request")

        # Parse POST data to see which devices are requested
        device_ids = []
        if post_data:
            try:
                post_str = post_data.decode('utf-8', errors='replace')
                print(f"[DEBUG] POST data: {post_str[:200]}...")
                # Try to extract device IDs from request
                import re
                ids = re.findall(r'ipc://[^"]+', post_str)
                device_ids = ids if ids else []
            except Exception as e:
                print(f"[DEBUG] Error parsing POST: {e}")

        # If no specific devices requested, query relay for connected devices
        if not device_ids:
            connected = get_connected_devices()
            if connected:
                # Convert device IDs to ipc:// format
                device_ids = [f"ipc://{d}" if not d.startswith("ipc://") else d for d in connected]
                print(f"[RELAY] Using {len(device_ids)} connected device(s) from relay")
            else:
                print(f"[WARN] No devices found - relay may not be running or no cameras connected")
                # Return empty response
                self.send_json_response({"code": "0", "message": "success", "data": {}})
                return

        print(f"[!] Returning P2P-enabled settings for {len(device_ids)} devices")

        # Build response with P2P-enabled settings
        device_data = {}

        for device_id in device_ids:
            device_data[device_id] = {
                "json": {
                    "alerts": {
                        "sendAlerts": {"support": "1", "value": "On"},
                        "sendMotionAlerts": {"support": "1", "value": "On"},
                        "sendSoundAlerts": {"support": "1", "value": "On"},
                        "sendOfflineAlerts": {"support": "1", "value": "On"}
                    },
                    "general": {
                        # ============================================
                        # KEY SETTING: Force P2P mode!
                        # ============================================
                        "localPlaybackMode": {
                            "support": "1",
                            "value": "1"  # 1 = P2P enabled, 2 = relay only
                        },

                        # Enable P2P support explicitly
                        "newp2p": {
                            "support": "1",
                            "value": "On"
                        },

                        # LAN connection support (for local P2P)
                        "lanIP": {
                            "support": "1",
                            "value": LOCAL_RELAY_IP  # Your Kali IP
                        },
                        "lanPort": {
                            "support": "1",
                            "value": str(RELAY_PORT)
                        },

                        # Other standard settings
                        "title": {"support": "1", "value": "Local P2P Camera"},
                        "status": {"support": "1", "value": "On"},
                        "deviceType": {"value": "IPC"},
                        "model": {"value": "IPC"},
                        "SDKVersion": {"value": "2559"},
                        "motionDetection": {"support": "1", "value": "On"},
                        "soundDetection": {"support": "1", "value": "On"},
                        "volumeMute": {"support": "1", "value": "On"},
                        "HDVideo": {"support": "1", "value": "On"},
                        "videoQuality": {"support": "1", "value": "high"},
                        "infraredLight": {"support": "1", "value": "Auto"},
                        "nightVision": {"support": "0", "value": "Auto"},
                        "autoTracking": {"support": "1", "value": "On"},
                        "faceDetection": {"support": "1", "value": "On"},

                        # SD Card settings
                        "sdCard": {
                            "support": "1",
                            "recordModel": {"value": "3"},
                            "status": {"value": "1"}
                        },

                        # Device-specific settings
                        "dvb_HWSP": {"support": "1", "value": "QZ_XR872AT"},
                        "dvc_resolutionL": {"support": "1", "value": "2"},
                        "dvc_BRL": {"support": "1", "value": "6"},
                        "description": {"support": "1", "value": "audio=2,videomain=0"},
                        "timeZone": {"support": "1", "value": "America/Sao_Paulo GMT-3:00 offset -10800"}
                    }
                }
            }

        response = {
            "code": "0",
            "message": "success",
            "data": device_data
        }

        print(f"\n[✓] Returning P2P-ENABLED settings:")
        print(f"    localPlaybackMode: 1 (P2P direct connection)")
        print(f"    newp2p: On")
        print(f"    lanIP: {LOCAL_RELAY_IP}")
        print(f"    lanPort: {RELAY_PORT}")

        self.send_json_response(response)

def generate_self_signed_cert():
    """Generate self-signed certificate for HTTPS"""
    cert_file = "server.crt"
    key_file = "server.key"

    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"Using existing certificate: {cert_file}, {key_file}")
        return cert_file, key_file

    print("Generating self-signed certificate...")
    print("NOTE: Camera may reject this. If so, extract real cert from APK/firmware.")

    os.system(f'''openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout {key_file} -out {cert_file} -days 365 \
        -subj "/C=CN/ST=Beijing/L=Beijing/O=Closeli/CN=auto-link.closeli.cn" \
        2>/dev/null''')

    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"Certificate generated: {cert_file}, {key_file}")
        return cert_file, key_file
    else:
        print("ERROR: Failed to generate certificate")
        print("Install openssl and try again, or provide your own cert/key files")
        return None, None

def main():
    """Main entry point"""
    print("=" * 70)
    print("Mock Camera API Server")
    print("=" * 70)
    print()
    print("This server responds to camera bootstrap API requests:")
    print("  - /sentry/dns/camera/services (service discovery)")
    print("  - /lookup/v6/assignRelayIp (relay server assignment)")
    print("  - /ntp (time service)")
    print()
    print(f"Configuration:")
    print(f"  Listen: {API_HOST}:{API_PORT} (HTTPS)")
    print(f"  Relay IP to return: {LOCAL_RELAY_IP}:{RELAY_PORT}")
    print()

    # Check if we need root for port 443
    if API_PORT < 1024 and os.geteuid() != 0:
        print("WARNING: Port 443 requires root privileges")
        print("Run with: sudo python mock_api_server.py")
        print("Or modify API_PORT to use >1024 (e.g., 8443)")
        return

    # Generate or load certificate
    cert_file, key_file = generate_self_signed_cert()
    if not cert_file or not key_file:
        print("ERROR: Cannot start HTTPS server without certificate")
        return

    print()
    print("Starting HTTPS server...")
    print("=" * 70)
    print()

    server = None
    try:
        server = HTTPServer((API_HOST, API_PORT), CameraAPIHandler)
        server.daemon_threads = True  # Don't wait for handler threads on shutdown

        # Wrap with SSL
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        # Disable certificate verification (accept any client)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        server.socket = context.wrap_socket(server.socket, server_side=True)

        print(f"Server ready on https://{API_HOST}:{API_PORT}")
        print("Press Ctrl+C to stop")
        print()

        server.serve_forever()

    except KeyboardInterrupt:
        print("\nServer shutdown requested...")
    except PermissionError:
        print(f"\nERROR: Permission denied for port {API_PORT}")
        print("Run with sudo or use a port >1024")
    except Exception as e:
        print(f"\nERROR: {e}")
    finally:
        if server:
            server.shutdown()
            server.server_close()
        print("Server stopped.")

if __name__ == "__main__":
    main()
