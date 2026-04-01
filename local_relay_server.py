#!/usr/bin/env python3
import socket
import ssl
import struct
import json
import threading
import time
import os
import sys
from copy import deepcopy
from pathlib import Path

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
                    # Remove quotes if present
                    if value and value[0] in ('"', "'") and value[-1] == value[0]:
                        value = value[1:-1]
                    os.environ.setdefault(key, value)

# Load .env before reading config
load_dotenv()

# ============================================================================
# Configuration & Constants
# ============================================================================
RELAY_HOST = os.environ.get("RELAY_HOST", "0.0.0.0")
LOCAL_IP = os.environ.get("LOCAL_IP", "192.168.1.100")
RELAY_PORT = int(os.environ.get("RELAY_PORT", "50721"))
MGMT_PORT = int(os.environ.get("MGMT_PORT", "50722"))

# Certificate paths - resolve relative to script directory
_script_dir = Path(__file__).parent
SERVER_CERT = os.environ.get("SERVER_CERT", "./server.crt")
SERVER_KEY = os.environ.get("SERVER_KEY", "./server.key")

# Make paths absolute if relative
if not os.path.isabs(SERVER_CERT):
    SERVER_CERT = str(_script_dir / SERVER_CERT)
if not os.path.isabs(SERVER_KEY):
    SERVER_KEY = str(_script_dir / SERVER_KEY)

# Default Device ID if not parsed
DEFAULT_DEVICE_ID = os.environ.get("DEFAULT_DEVICE_ID", "xxxxS_000000000000")

# Known camera IPs (from CAMERA_IPS or CAMERA_IP env var, comma-separated)
CAMERA_IPS = set()
_cam_ips_str = os.environ.get("CAMERA_IPS", os.environ.get("CAMERA_IP", ""))
if _cam_ips_str:
    CAMERA_IPS = {ip.strip() for ip in _cam_ips_str.split(",") if ip.strip()}

# Debug Flag
DEBUG_MODE = os.environ.get("DEBUG_MODE", "false").lower() in ("true", "1", "yes")

# Color Codes for Logging
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ============================================================================
# Helpers
# ============================================================================
def log(message, category="INFO", color=Colors.ENDC):
    if category == "DEBUG" and not DEBUG_MODE:
        return
    timestamp = time.strftime("%H:%M:%S", time.localtime())
    
    # Simple color mapping
    cat_color = Colors.BLUE # Default
    if category == "ERROR": cat_color = Colors.FAIL
    elif category == "SUCCESS": cat_color = Colors.GREEN
    elif category == "WARNING": cat_color = Colors.WARNING
    elif category == "VIDEO": cat_color = Colors.CYAN
    elif category == "XMPP": cat_color = Colors.BLUE
    
    print(f"{Colors.HEADER}[{timestamp}]{Colors.ENDC} {cat_color}[{category}]{Colors.ENDC} {color}{message}{Colors.ENDC}")

def encode_varint(value):
    """Encode integer as protobuf varint"""
    result = []
    while value > 0x7f:
        result.append((value & 0x7f) | 0x80)
        value >>= 7
    result.append(value & 0x7f)
    return bytes(result)

def decode_varint(buffer, offset):
    """Decode varint starting at offset; returns (value, new_offset) or (None, offset)."""
    result = 0
    shift = 0
    while offset < len(buffer):
        byte = buffer[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, offset
        shift += 7
    return None, offset

# ============================================================================
# XMPP Protocol Builder
# ============================================================================
class XMPPProtocol:
    @staticmethod
    def extract_message_id(raw_data):
        """Extract 31-byte message ID from field 11 (5a 1f ...)."""
        marker = b'\x5a\x1f'
        idx = raw_data.find(marker)
        if idx >= 0 and idx + 2 + 31 <= len(raw_data):
            return raw_data[idx + 2:idx + 2 + 31].decode('ascii', errors='ignore').rstrip('\x00')
        return None

    @staticmethod
    def build_action_response(json_payload, message_id):
        """Build UDI/GDL response (Type 7)."""
        if isinstance(json_payload, dict):
            json_payload = json.dumps(json_payload, separators=(',', ':'))
        json_bytes = json_payload.encode('utf-8')

        # Field 8 inner content
        inner = b'\x08\x00'  # f1=0
        inner += b'\x10\x64' # f2=100
        inner += b'\x20\x00' # f4=0
        inner += b'\x32' + encode_varint(len(json_bytes)) + json_bytes # f6=JSON
        
        if message_id:
            msg_id_bytes = message_id.encode('ascii')[:31].ljust(31, b'\x00')
            inner += b'\x5a\x1f' + msg_id_bytes # f11=msgId
            
        inner += b'\x60\x1f' # f12=31

        # Outer wrapper (Type 7)
        outer = b'\x08\x07'
        outer += b'\x42' + encode_varint(len(inner)) + inner
        return struct.pack('>I', len(outer)) + outer

    @staticmethod
    def build_udi_config_message(json_payload, timestamp, token):
        """Build UDI Config Push (Type 2)."""
        if isinstance(json_payload, dict):
            json_payload = json.dumps(json_payload, separators=(',', ':'))
        json_bytes = json_payload.encode('utf-8')
        ts_bytes = timestamp.encode('ascii')
        tok_bytes = token.encode('ascii')

        inner = b'\x08\x00' # f1=0
        inner += b'\x12' + encode_varint(len(ts_bytes)) + ts_bytes
        inner += b'\x18\x00'
        inner += b'\x2a' + encode_varint(len(tok_bytes)) + tok_bytes
        inner += b'\x30\x97\xd1\xbf\x29' # f6=magic varint
        inner += b'\x40\x05\x48\x02' # f8=5, f9=2
        inner += b'\x60\xdb\x0f' # f12
        inner += b'\x78\xe0\xd4\x03' # f15
        inner += b'\x80\x01\x03\x88\x01\x18\x90\x01\x0f\x98\x01\xd8\x04\xa0\x01\x01' # misc fields
        inner += b'\xaa\x01' + encode_varint(len(json_bytes)) + json_bytes # f21=JSON

        outer = b'\x08\x02' # Type 2
        outer += b'\x1a' + encode_varint(len(inner)) + inner
        return struct.pack('>I', len(outer)) + outer

# ============================================================================
# Message Payload Generators
# ============================================================================
def build_initial_gdl_response(device_id):
    """Build Initial GDL response (sent during UDI phases) - Single Object."""
    return {
        "data": {
            "whiteListConfig": {
                "expireRecording": "0", "faceDetection": "0", "highlights": "0",
                "speechRecognition": "0", "flayvr": "0", "faceRecognition": "0", "wechatPush": "0"
            },
            "deviceId": device_id,
            "msgProtoType": "1"
        },
        "action": "GDL"
    }

def build_udi_response():
    """Build UDI Action Response."""
    return {"data":{"failflag":0,"failmsg":""},"action":"UDI"}

def build_gdl_response(device_id):
    """
    Build Standard GDL Response (Nested List).
    The camera expects this structure to know the device is registered.
    """

    device_entry = {
        "whiteListConfig": {
            "expireRecording": "0", "faceDetection": "0", "highlights": "0",
            "speechRecognition": "0", "flayvr": "0", "faceRecognition": "0", "wechatPush": "0"
        },
        "deviceId": device_id,
        "msgProtoType": "1"
    }
    
    return {
        "data": {
            "data": [device_entry], # ARRAY IS CRITICAL
            "failflag": "0",
            "failmsg": ""
        },
        "action": "GDL"
    }

def build_udi_config():
    """Build UDI Configuration Push payload."""
    return {
        "eventRawLimit": 6, "motionValueInterval": 500, "soundStartSpan": 0, "sd2hdpktmissing": 0,
        "udpPingSpan": 30, "motionStartSpan": 0, "callTimeout": 30, "sd2hdminspan": 300,
        "needH264": False, "abilities": 262160, "tcpPingSpan": 60, "passengerFlowStatistics": 10,
        "sentry_ip": "link-br-hw.closeli.com", "logLevel": 0, "autohdsd": 1, "hd2sdpktmissing": 10,
        "qosSpan": 3600, "uploadDelaySpan": 8, "hd2sdcheckspan": 120, "sd2hdcheckspan": 120
    }

# Default Camera Settings (Full Structure from local_relay_server.py)
DEFAULT_CAMERA_SETTINGS = {
    "alerts": {
        "scheduleNotSendAlerts": {"schedules": [], "support": "1", "status": {"value": "On"}},
        "sendAlerts": {"support": "1", "value": "On"},
        "sendMotionAlerts": {"support": "1", "value": "On"},
        "sendSoundAlerts": {"support": "1", "value": "On"},
        "sendOfflineAlerts": {"support": "1", "value": "On"}
    },
    "general": {
        "phoneNotification": {"support": "1", "value": "On"},
        "dvb_json": {"support": "1", "value": ""},
        "motionDetection": {"support": "1", "value": "On"},
        "deviceId": {"support": "1", "value": ""},
        "videoQuality": {"support": "1", "value": "high"},
        "cameraImageRotate": {"support": "1", "value": "180"},
        "scheduleMute": {"schedules": [], "support": "1", "status": {"value": "On"}},
        "statusLight": {"support": "0", "value": "On"},
        "dvc_hdv3": {"support": "1", "value": "Off"},
        "talkVolume": {"support": "1", "value": "100"},
        "dvc_resolutionLSD": {"support": "1", "value": "2"},
        "model": {"value": "IPC"},
        "motionRegions": {"support": "0"},
        "nightVisionSensitivity": {"close": {"value": "848"}, "support": "0", "open": {"value": "934"}},
        "deviceType": {"value": "IPC"},
        "motionSensitivity": {"support": "1", "value": "90"},
        "infraredLight": {"support": "1", "value": "Auto"},
        "volumeMute": {"support": "1", "value": "On"},
        "dvc_BRL": {"support": "1", "value": "6"},
        "alarmTimes": {"supportKey": "1-5", "support": "1", "value": "1"},
        "fullColorNightVisionModel": {"support": "1", "value": "1"},
        "timeZone": {"support": "1", "value": "America/Sao_Paulo GMT-3:00 offset -10800"},
        "voiceAlarmArgs": {"args": {"seconds": "8", "size": "64000", "count": "3", "format": "g711a"}, "support": "1"},
        "dvc_appscene": {"supportKey": "1|2", "support": "1", "value": "1"},
        "alarmStatus": {"support": "1", "value": "Off"},
        "macAddress": {"support": "1", "value": ""},
        "dvc_netdtn": {"support": "1", "value": ""},
        "light": {"support": "1", "value": "0"},
        "networkQuality": {"support": "0", "value": "0"},
        "voiceAlarm": {"support": "1", "value": "On"},
        "soundDetectStatus": {"support": "1", "value": "Off"},
        "dvc_rtlog": {"support": "1"},
        "wifiQuality": {"support": "0", "value": "0"},
        "status": {"support": "1", "value": "On"},
        "magicZoom": {"yOffset": {"value": "0"}, "xOffset": {"value": "0"}, "support": "0", "ratio": {"value": "1000"}},
        "soundDetection": {"support": "1", "value": "On"},
        "description": {"support": "1", "value": "audio=2,videomain=0"},
        "title": {"support": "1", "value": "LAB"},
        "notificationInterval": {"support": "0", "value": "10"},
        "localPlaybackMode": {"support": "1", "value": "1"},  # Changed from 2 to 1 (P2P enabled per MITM)
        "webSocket": {"support": "1", "value": ""},
        "motionDetectStatus": {"support": "1", "value": "Off"},
        "soundSensitivity": {"support": "1", "value": "90"},
        "dvb_HWSP": {"support": "1", "value": "QZ_XR872AT"},
        "nightVision": {"support": "0", "value": "Auto"},
        "DVRPlan": {"support": "1", "value": "2-Week trial"},
        "autoTracking": {"support": "1", "value": "Off"},
        "playIdle": {"value": "15"},
        "sdCard": {"support": "1", "recordModel": {"value": "3"}, "status": {"value": "1"}},
        "emailNotification": {"support": "1", "value": "Off"},
        "faceDetection": {"support": "1", "value": "On"},
        "reboot": {"support": "1", "value": ""},
        "wifiNetWork": {"support": "1", "value": "LABWIFI"},
        "dvc_resolutionL": {"support": "1", "value": "2"},
        "HDVideo": {"support": "1", "value": "On"},
        "dvc_interAccord872": {"support": "1", "value": "5"},
        "dvc_BRLSD": {"support": "1", "value": "2"},
        "recordTo": {"support": "1", "value": "ArcSoftCloud"},
        "scheduleTurnOff": {"schedules": [], "support": "1", "status": {"value": "On"}},
        "dvc_hdv3t": {"supportKey": "HD|UHD", "support": "1", "value": ""},
        "offlineConfig": {"support": "0", "value": "On"},
        "cameraSound": {"support": "1", "value": "On"},
        "dvc_loglevel": {"support": "1", "value": "1"},
        "lightFeature": {"support": "1", "value": "6"},
        "SDKVersion": {"value": "2559"},
        "antiFlicker": {"support": "1", "value": "50"},
        "dvb_sdsr": {"support": "1", "value": ""},
        "dvc_sds": {"support": "1", "value": ""}
    },
    "base": {"sys": {"version": "1.0"}}
}

def build_s_get_response(schema_name="camera", device_id=None):
    """Build S_GET response for settings using full default settings."""
    settings = deepcopy(DEFAULT_CAMERA_SETTINGS)
    
    # Inject Device ID if available (Critical for validation)
    if device_id and "general" in settings and "deviceId" in settings["general"]:
        settings["general"]["deviceId"]["value"] = device_id
        
    return {
        "data": {
            "code": "0",
            "data": {
                schema_name: { "json": settings }
            },
            "message": "success"
        },
        "action": "S_GET"
    }

def build_s_save_response(schema_name="camera"):
    return {
        "data": { "code": "0", "message": "success" },
        "action": "S_SAVE"
    }

def build_peer_hint_response(host, port):
    """Craft protobuf message mirroring cloud relay URL response."""
    url_str = f"{host}:{port}"
    url_bytes = url_str.encode("utf-8")

    url_payload = b"\x0a\x03url"
    url_payload += b"\x12" + encode_varint(len(url_bytes)) + url_bytes

    field5 = b"\x08\x05"
    field5 += b"\x12" + encode_varint(len(url_payload)) + url_payload

    inner = b"\x08\x06"
    inner += b"\x12" + encode_varint(len(field5)) + field5

    body = b"\x08\x0f\x82\x01"
    body += encode_varint(len(inner)) + inner

    return struct.pack('>I', len(body)) + body

def build_ccam_trigger(app_login_info):
    """Build CCAM 'Start Streaming' Trigger (Type 0xBC)."""
    peer_info = {
        "deviceId": app_login_info.get("deviceId", "xxxxS_189e2d446d47"),
        "channel": app_login_info.get("channel", "720p"),
        "streamType": app_login_info.get("streamType", "main"),
        "email": app_login_info.get("email", ""),
        "platform": app_login_info.get("platform", "android"),
        "peerConnected": True
    }
    
    trigger_json = json.dumps(peer_info, separators=(',', ':')).encode('utf-8')
    
    header = bytearray(20)
    header[0] = 0x05  # Version
    header[1] = 0x00
    header[2] = 0xBC  # Message type: 188 = start streaming! (0xBC)
    header[3] = 0x00  # Flags
    
    body = b'CCAM' + bytes(header) + trigger_json
    return struct.pack('>I', len(body)) + body

def build_xmpp_live_view(device_id, client_id_str="ANDRC_14716d80f38f"):
    """Build XMPP Command 1792/222 (Start Live View) - Correct format from MITM.
    
    From relay_log_AFTER_STREAM_DIFF.log line 22-46:
    {
      "msgSession": 77937047,
      "msgSequence": 0,
      "msgCategory": "camera",
      "msgTimeStamp": 1765309026717,
      "msgContent": {
        "request": 1792,
        "subRequest": 222,
        "requestParams": {}
      }
    }
    
    Wrapped in Type 7 protobuf: 08 07 42 ...
    """
    import random
    
    payload = {
        "msgSession": random.randint(10000000, 99999999),
        "msgSequence": 0,
        "msgCategory": "camera",
        "msgTimeStamp": int(time.time() * 1000),
        "msgContent": {
            "request": 1792,
            "subRequest": 222,
            "requestParams": {}
        }
    }
    
    json_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    
    # Build Type 7 wrapper (same as UDI/GDL responses)
    # From hex: 08 07 42 bf 01 08 00 10 21 1a 12 ... 50 97 f3 94 25
    # Field 1 = 7 (Type 7)
    # Field 8 (0x42) = inner message
    
    # Inner message structure:
    # Field 1 = 0
    # Field 2 = 33 (0x21)
    # Field 3 = client ID (dynamic!)
    # Field 4 = 0
    # Field 6 = JSON
    # Field 10 = msgSession (CRITICAL - was missing!)
    
    # Ensure lowercase for bytes if that's what capture had? 
    # Capture had: 61 6e 64 72 63 5f ... -> "andrc_..."
    # If client_id_str is "ANDRC_...", we should convert to lower?
    # Actually, let's keep it as is, but maybe lowercase matching MITM?
    # MITM Log Step 13 line 1573: "andrc_..." (hex 61...) in wrapper?
    # Wait, line 1573 hex dump: 1a 12 61 6e 64 72 63 ... -> 'andrc_...' (lowercase)
    # But JSON body had "ANDRC_..." (uppercase).
    # Line 1575: "clientid" : "ANDRC_..."
    
    client_id_bytes = client_id_str.lower().encode('utf-8') # Header uses lowercase
    msg_session = payload["msgSession"]  # Use the same session ID as in JSON
    
    inner = b'\x08\x00'  # Field 1 = 0
    inner += b'\x10\x21'  # Field 2 = 33
    inner += b'\x1a' + encode_varint(len(client_id_bytes)) + client_id_bytes  # Field 3 = client ID
    inner += b'\x20\x00'  # Field 4 = 0
    inner += b'\x32' + encode_varint(len(json_bytes)) + json_bytes  # Field 6 = JSON
    inner += b'\x50' + encode_varint(msg_session)  # Field 10 = msgSession (0x50 = (10 << 3) | 0)
    
    # Outer Type 7 wrapper
    outer = b'\x08\x07'  # Type 7
    outer += b'\x42' + encode_varint(len(inner)) + inner
    
    return struct.pack('>I', len(outer)) + outer



def build_xmpp_short_ack():
    """Build the short 19-byte ack message sent immediately after 1792.
    
    From relay_log_AFTER_STREAM_DIFF.log line 47-50:
    00 00 00 0f 08 07 42 0b 08 00 10 10 48 e0 d4 03 70 98 75
    
    Structure:
    - Type 7
    - Field 8 (11 bytes):
      - Field 1 = 0
      - Field 2 = 16 (0x10)
      - Field 9 = 60000 (0xe0d403 varint)
      - Field 14 = 15000 (0x9875 varint)
    """
    inner = b'\x08\x00'  # Field 1 = 0
    inner += b'\x10\x10'  # Field 2 = 16
    inner += b'\x48\xe0\xd4\x03'  # Field 9 = 60000 (varint)
    inner += b'\x70\x98\x75'  # Field 14 = 15000 (varint)
    
    outer = b'\x08\x07'  # Type 7
    outer += b'\x42' + encode_varint(len(inner)) + inner
    
    return struct.pack('>I', len(outer)) + outer

def build_xmpp_timeline_query(client_id_str="ANDRC_14716d80f38f"):
    """Build the timeline query message sent after the short ack.
    
    From relay_log_AFTER_STREAM_DIFF.log line 51-75:
    {
      "clientid": "ANDRC_14716d80f38f",
      "endtime": 1765335599999,
      "lastid": 0,
      "pagesize": 500,
      "starttime": 1765292399999,
      "type": 100
    }
    
    Note: Field 2 = 10 (0x0a), not 33 like in 1792.
    """
    # Calculate time ranges (start of day, end of day in milliseconds)
    now_ms = int(time.time() * 1000)
    start_of_day = (now_ms // 86400000) * 86400000 - 86400000  # Yesterday
    end_of_day = start_of_day + (2 * 86400000) - 1  # Tomorrow
    
    # Format with newlines and spaces like the capture
    # JSON uses the ID as provided (UPPERCASE for ANDRC)
    json_str = "{\n   \"clientid\" : \"" + client_id_str + "\",\n   \"endtime\" : " + str(end_of_day) + ",\n   \"lastid\" : 0,\n   \"pagesize\" : 500,\n   \"starttime\" : " + str(start_of_day) + ",\n   \"type\" : 100\n}\n"
    json_bytes = json_str.encode('utf-8')
    
    # Header uses LOWERCASE
    client_id_bytes = client_id_str.lower().encode('utf-8')
    
    inner = b'\x08\x00'  # Field 1 = 0
    inner += b'\x10\x0a'  # Field 2 = 10 (NOT 33!)
    inner += b'\x1a' + encode_varint(len(client_id_bytes)) + client_id_bytes  # Field 3 = client ID
    inner += b'\x20\x00'  # Field 4 = 0
    inner += b'\x32' + encode_varint(len(json_bytes)) + json_bytes  # Field 6 = JSON
    
    outer = b'\x08\x07'  # Type 7
    outer += b'\x42' + encode_varint(len(inner)) + inner
    
    return struct.pack('>I', len(outer)) + outer

def build_xmpp_relay_count(client_id_str="ANDRC_14716d80f38f"):
    """Build XMPP Command 1793/152 (Relay Connection Count) - Sent after 1792.
    
    From relay_log_AFTER_STREAM_DIFF.log line 121-132:
    {
      ...
    }
    """
    import random
    
    payload = {
        "msgSession": random.randint(10000000, 99999999),
        "msgTimeStamp": int(time.time() * 1000),
        "msgSequence": 0,
        "msgContent": {
            "subRequest": 152,
            "request": 1793,
            "requestParams": {
                "Max_count": 3,
                "Relay_max_count": 1,
                "Relay_live_count": 1
            },
            "channelName": "720p"
        },
        "msgCategory": "camera"
    }
    
    json_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    
    client_id_bytes = client_id_str.lower().encode('utf-8')
    msg_session = payload["msgSession"]  # Use the same session ID as in JSON
    
    inner = b'\x08\x00'  # Field 1 = 0
    inner += b'\x10\x21'  # Field 2 = 33
    inner += b'\x1a' + encode_varint(len(client_id_bytes)) + client_id_bytes  # Field 3 = client ID
    inner += b'\x20\x00'  # Field 4 = 0
    inner += b'\x32' + encode_varint(len(json_bytes)) + json_bytes  # Field 6 = JSON
    inner += b'\x50' + encode_varint(msg_session)  # Field 10 = msgSession
    
    outer = b'\x08\x07'  # Type 7
    outer += b'\x42' + encode_varint(len(inner)) + inner
    
    return struct.pack('>I', len(outer)) + outer

# ============================================================================
# Relay Server Logic
# ============================================================================
class LocalRelayServer:
    def __init__(self):
        self.running = False
        self.lock = threading.Lock()
        
    def start(self):
        self.running = True
        
        # Setup TLS Context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
            context.check_hostname = False
        except Exception as e:
            log(f"Certificate error: {e}", "ERROR")
            log("Ensure server.crt and server.key are in the certs directory.", "ERROR")
            return

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_sock.bind((RELAY_HOST, RELAY_PORT))
            server_sock.listen(5)
            log(f"Listening on {RELAY_HOST}:{RELAY_PORT} (TLS Enabled)", "SUCCESS")
            log("Check 'stream_to_vlc.py' for client logic.", "INFO")
            
            while self.running:
                try:
                    client, addr = server_sock.accept()
                    log(f"New connection from {addr[0]}:{addr[1]}", "INFO")
                    
                    # Wrap with TLS
                    threading.Thread(target=self.handle_client, args=(client, addr, context), daemon=True).start()
                except Exception as e:
                    if self.running: log(f"Accept error: {e}", "ERROR")

        except Exception as e:
            log(f"Server startup failed: {e}", "ERROR")
        finally:
            server_sock.close()

    def handle_client(self, raw_sock, addr, context):
        conn_id = f"{addr[0]}:{addr[1]}"
        conn = None
        # Track device_id for this connection (will be set when identified)
        conn_device_id = None
        conn_role = None  # 'camera_control', 'camera_stream', 'app_stream', etc.

        try:
            conn = context.wrap_socket(raw_sock, server_side=True)
            log(f"TLS handshake success: {conn_id}", "SUCCESS")

            # Register connection in global registry
            register_connection(conn, addr)

            conn.settimeout(60.0) # Reasonable timeout

            device_id = DEFAULT_DEVICE_ID
            
            # Always use LOCAL_IP for Peer Hint - this is the externally reachable IP
            # getsockname() returns Docker internal IPs which clients can't reach
            server_ip = LOCAL_IP
            server_port = RELAY_PORT
                
            log(f"Peer Hint Configured: {server_ip}:{server_port}", "INFO")

            while True:
                # Read 4-byte header
                header = conn.recv(4)
                if len(header) < 4:
                    break  # Clean disconnect

                msg_len = struct.unpack('>I', header)[0]
                if msg_len > 1024*1024: # Sanity check
                    log(f"Message too large: {msg_len}", "WARNING")
                    break
                    
                payload = b""
                while len(payload) < msg_len:
                    chunk = conn.recv(msg_len - len(payload))
                    if not chunk: break
                    payload += chunk
                    
                if len(payload) != msg_len: break
                
                # Analyze Message
                
                # 0. Check for CCAM Stream Protocol
                if payload.startswith(b'CCAM'):
                    # Log first 50 bytes of EVERY CCAM packet for debugging
                    hex_preview = payload[:50].hex()
                    log(f"CCAM Packet (Type: {payload[6] if len(payload) > 6 else '?'}): {hex_preview}...", "DEBUG")
                    
                    if len(payload) >= 24:
                        # Header Analysis for CCAM v4 vs v5
                        # V5: payload[4]=05, payload[6]=type
                        # V4: payload[4]=04, payload[5]=type (02=video, 01=audio)
                        ccam_version = payload[4]
                        
                        if ccam_version == 0x04:
                            # CCAM v4: type is at byte 5
                            ccam_type = payload[5]
                            log(f"CCAM v4 detected: type={ccam_type}", "DEBUG")
                        else:
                            # CCAM v5: type is at byte 6
                            ccam_type = payload[6]
                            log(f"CCAM v5 detected: version={ccam_version}, type={ccam_type}", "DEBUG")
                        
                        # === HANDLE CAMERA PROTOCOL NEGOTIATION (Type 3) ===
                        # CRITICAL: Camera sends this on boot, expects {"pingSpan":20,"useProtocols":"TLS_MSG_MEDIA_V2"}
                        # Without this response, camera will not stream!
                        if ccam_type == 0x03:
                            log(f"CCAM Protocol Negotiation (Type 3, Ver {ccam_version})", "STREAM")

                            # Parse the JSON from the camera (using raw_decode to handle trailing binary data)
                            # Look for actual JSON start ({"  or {\n) to avoid false { in header
                            j_start = payload.find(b'{"')
                            if j_start == -1:
                                j_start = payload.find(b'{\n')
                            if j_start > 0:
                                try:
                                    json_str = payload[j_start:].decode('utf-8', 'ignore')
                                    decoder = json.JSONDecoder()
                                    handshake_json, _ = decoder.raw_decode(json_str)
                                    log(f"CCAM Handshake: {handshake_json}", "STREAM")

                                    # Extract device_id from handshake
                                    # Camera sends 'ipcamId', app sends 'deviceId'
                                    handshake_device_id = handshake_json.get('ipcamId') or handshake_json.get('deviceId')
                                    if handshake_device_id:
                                        device_id = handshake_device_id
                                        conn_device_id = device_id

                                    # Register this as camera_stream in session registry
                                    register_socket(conn, device_id, 'camera_stream')
                                    conn_role = 'camera_stream'
                                    # Legacy registry for backward compatibility
                                    CLIENT_REGISTRY["camera_stream"] = conn
                                    log(f"Registered CAMERA Stream for {device_id}", "STREAM")

                                    # Auto-discover camera_control: find unidentified connection from same IP
                                    # This handles the case where the camera reconnects after relay restart
                                    # and skips UDI/GDL (only sends heartbeats on control + CCAM handshake on stream)
                                    session = get_session(device_id)
                                    if session and not session.get('camera_control'):
                                        try:
                                            cam_ip = conn.getpeername()[0]
                                        except:
                                            cam_ip = None
                                        if cam_ip:
                                            with CONNECTIONS_LOCK:
                                                for cid, cinfo in CONNECTIONS.items():
                                                    if cinfo['ip'] == cam_ip and cinfo['socket'] != conn and cinfo['role'] is None:
                                                        register_socket(cinfo['socket'], device_id, 'camera_control')
                                                        CLIENT_REGISTRY["camera"] = cinfo['socket']
                                                        CLIENT_REGISTRY["camera_control"] = cinfo['socket']
                                                        log(f"Auto-discovered camera_control for {device_id} from {cid}", "STREAM")
                                                        break
                                    
                                    # Build response: {"pingSpan":20,"useProtocols":"TLS_MSG_MEDIA_V2"}
                                    resp_json = json.dumps({
                                        "pingSpan": 20,
                                        "useProtocols": "TLS_MSG_MEDIA_V2"
                                    }, separators=(',', ':')).encode('utf-8')
                                    
                                    # Build CCAM response header (mimicking MITM: 02 02 03 00...)
                                    # payload[4:8] from capture: 02 02 03 00
                                    resp_header = bytearray(20)
                                    resp_header[0] = 0x02  # Version 2 (response)
                                    resp_header[1] = 0x02  # ?
                                    resp_header[2] = 0x03  # Type 3 (handshake response)
                                    resp_header[3] = 0x00  # ?
                                    
                                    # Copy timestamp from request if present (bytes 16-24)
                                    if len(payload) >= 28:
                                        resp_header[12:20] = payload[16:24]
                                    
                                    resp_body = b'CCAM' + bytes(resp_header) + resp_json
                                    resp_pkt = struct.pack('>I', len(resp_body)) + resp_body
                                    
                                    conn.sendall(resp_pkt)
                                    log(f"Sent CCAM Handshake Response ({len(resp_pkt)} bytes)", "STREAM")

                                    # If app is already waiting, send 0xBC trigger now
                                    # This handles the race where LIVE_VIEW fired before camera stream was ready
                                    session = get_session(device_id)
                                    app_stream = session.get('app_stream') if session else CLIENT_REGISTRY.get("app_stream")
                                    if app_stream:
                                        try:
                                            app_info = session.get('app_login_info') if session else CLIENT_REGISTRY.get("app_login_info", {})
                                            time.sleep(0.2)
                                            trigger = build_ccam_trigger(app_info or {})
                                            conn.sendall(trigger)
                                            log(f"Sent 0xBC Start Streaming to camera (app was waiting)", "STREAM")

                                            # Also send XMPP trigger if we have camera_control
                                            cam_ctrl = session.get('camera_control') if session else CLIENT_REGISTRY.get("camera_control")
                                            if cam_ctrl:
                                                session_client_id = "ANDRC_14716d80f38f"
                                                timeline_query = build_xmpp_timeline_query(session_client_id)
                                                cam_ctrl.sendall(timeline_query)
                                                time.sleep(0.04)
                                                short_ack_mitm = bytes.fromhex("0000000f0807420b0800101048e0d403709875")
                                                cam_ctrl.sendall(short_ack_mitm)
                                                log(f"Sent XMPP trigger (Timeline+Ack) on CCAM handshake", "STREAM")
                                        except Exception as e:
                                            log(f"Failed to send 0xBC on handshake: {e}", "ERROR")

                                except Exception as e:
                                    log(f"CCAM Handshake parse error: {e}", "ERROR")
                            continue
                        
                        if ccam_type == 0x00:
                            # CCAM Keepalive
                            # Auto-register as camera_stream if not yet set
                            if conn_role is None:
                                if conn_device_id:
                                    register_socket(conn, conn_device_id, 'camera_stream')
                                    conn_role = 'camera_stream'
                                elif CLIENT_REGISTRY.get("app_stream") != conn:
                                    if not CLIENT_REGISTRY.get("camera_stream"):
                                        CLIENT_REGISTRY["camera_stream"] = conn
                                        log("Auto-registered CAMERA Stream (from keepalive) [legacy]", "STREAM")
                                        conn_role = 'camera_stream'

                            # Determine Sender and Target
                            target_sock = None
                            session = get_session(conn_device_id or device_id)
                            
                            if conn_role == 'camera_stream':
                                # Forward to App
                                if session: target_sock = session.get('app_stream')
                                if not target_sock: target_sock = CLIENT_REGISTRY.get("app_stream")
                                
                            elif conn_role == 'app_stream':
                                # Forward to Camera
                                if session: target_sock = session.get('camera_stream')
                                if not target_sock: target_sock = CLIENT_REGISTRY.get("camera_stream")

                            # Forward or Drop (End-to-End Keepalive)
                            if target_sock:
                                try:
                                    full_pkt = struct.pack('>I', len(payload)) + payload
                                    target_sock.sendall(full_pkt)
                                    log(f"Forwarded Keepalive ({conn_role} -> Target)", "STREAM")
                                except Exception as e:
                                    log(f"Keepalive forward failed: {e}", "ERROR")
                            else:
                                # No target (e.g. App closed) -> Drop to save bandwidth
                                log(f"Dropped Keepalive from {conn_role} (No listener)", "DEBUG")
                            
                            continue
                        
                        # CCAM v4 Video (type 0x02) or Audio (type 0x01) - Forward to App
                        if ccam_version == 0x04 and ccam_type in [0x01, 0x02]:
                            # Find the app_stream for this device's session
                            app_stream = None
                            target_device = conn_device_id or device_id

                            # Try session-based routing first
                            session = get_session(target_device)
                            if session:
                                app_stream = session.get('app_stream')

                            # Fallback to legacy registry
                            if not app_stream:
                                app_stream = CLIENT_REGISTRY.get("app_stream")

                            if app_stream:
                                try:
                                    full_pkt = struct.pack('>I', len(payload)) + payload
                                    app_stream.sendall(full_pkt)
                                    # Only log occasionally to reduce spam
                                    # log(f"Forwarded CCAM v4 Media to {target_device} ({len(payload)} bytes)", "VIDEO")
                                except Exception as e:
                                    log(f"Forward failed: {e}", "ERROR")
                            continue

                    # Check if it's a LOGIN packet (Video packets usually don't have JSON)
                    # Heuristic: Check for JSON start '{' in header area
                    j_start = payload.find(b'{')
                    is_login = False
                    json_login = {}
                    
                    if j_start > 0:
                         try:
                             json_login = json.loads(payload[j_start:].decode('utf-8', 'ignore'))
                             # If we successfully parsed JSON, it's a login
                             is_login = True
                         except: pass

                    if is_login:
                        if len(payload) >= 24:
                            ccam_header = payload[4:24]
                            log(f"CCAM Login: {json_login}", "STREAM")

                            # Extract device_id from login JSON - THIS IS KEY FOR MULTI-CAMERA
                            login_device_id = json_login.get('deviceId', device_id)
                            if login_device_id:
                                device_id = login_device_id
                                conn_device_id = login_device_id

                            # Build CCAM Login Response
                            # Use a clean header (don't copy request flags)
                            resp_header = bytearray(20)
                            resp_header[0] = 0x05 # Version 5
                            resp_header[2] = 0x04 # Type 4 = Login Response

                            resp_json = json.dumps({"result": 0, "message": "success"}).encode('utf-8')

                            resp_body = b'CCAM' + resp_header + resp_json
                            resp_pkt = struct.pack('>I', len(resp_body)) + resp_body

                            conn.sendall(resp_pkt)
                            log("Sent CCAM Login Response (Clean Header)", "STREAM")

                            # Register Stream Connection
                            # Check platform to distinguish Camera vs App
                            platform = json_login.get('platform', '')
                            if 'android' in platform or 'ios' in platform:
                                # APP Stream - register with session
                                register_socket(conn, device_id, 'app_stream')
                                conn_role = 'app_stream'

                                # Store login info in session
                                session = get_session(device_id)
                                if session:
                                    session['app_login_info'] = json_login

                                # Legacy registry
                                CLIENT_REGISTRY["app_stream"] = conn
                                CLIENT_REGISTRY["app_login_info"] = json_login
                                log(f"Registered APP Stream for device {device_id}", "STREAM")

                                # NOTE: Don't send 0xBC here - we'll send it after XMPP messages
                                # The trigger sequence should be: XMPP 1792 → 0xBC (not 0xBC → XMPP)
                            else:
                                # CAMERA Stream - register with session
                                register_socket(conn, device_id, 'camera_stream')
                                conn_role = 'camera_stream'

                                # Legacy registry
                                CLIENT_REGISTRY["camera_stream"] = conn
                                log(f"Registered CAMERA Stream for device {device_id}", "STREAM")

                                # REVERSE TRIGGER: If App is waiting for THIS device, trigger Camera!
                                session = get_session(device_id)
                                app_stream = session.get('app_stream') if session else CLIENT_REGISTRY.get("app_stream")

                                if app_stream:
                                    try:
                                        app_info = session.get('app_login_info') if session else CLIENT_REGISTRY.get("app_login_info", {})
                                        if not app_info:
                                            app_info = {}
                                        cam_control = session.get('camera_control') if session else CLIENT_REGISTRY.get("camera_control")

                                        # 1. Send CCAM 0xBC Trigger (Physical Stream)
                                        trigger = build_ccam_trigger(app_info)
                                        conn.sendall(trigger)
                                        log(f"Sent Start Streaming Trigger (0xBC) to Camera {device_id} (Reverse Trigger)", "STREAM")

                                        if cam_control and device_id:
                                            # 2. Send XMPP 1792 Trigger (Logical Authorization)
                                            xmpp_req = build_xmpp_live_view(device_id)
                                            cam_control.sendall(xmpp_req)
                                            log(f"Sent XMPP Live View Request (1792/222) to {device_id} Control (Reverse Trigger)", "XMPP")

                                            # 3. Send 1793/152 (Relay Connection Count)
                                            time.sleep(0.5)
                                            relay_count_req = build_xmpp_relay_count()
                                            cam_control.sendall(relay_count_req)
                                            log(f"Sent XMPP Relay Count (1793/152) to {device_id} Control (Reverse Trigger)", "XMPP")
                                        else:
                                            log(f"Cannot send XMPP trigger for {device_id} - Control not found", "WARN")

                                    except Exception as e:
                                        log(f"Failed to reverse trigger for {device_id}: {e}", "ERROR")
                    else:
                        # NOT Login -> Video Data?
                        # Forward to App Stream using session-based routing
                        target_device = conn_device_id or device_id
                        app_stream = None

                        # Try session-based routing first
                        session = get_session(target_device)
                        if session:
                            app_stream = session.get('app_stream')

                        # Fallback to legacy registry
                        if not app_stream:
                            app_stream = CLIENT_REGISTRY.get("app_stream")

                        if app_stream:
                            try:
                                # Reconstruct full packet
                                full_pkt = struct.pack('>I', len(payload)) + payload
                                app_stream.sendall(full_pkt)
                                # log(f"Forwarded Video Frame to {target_device} ({len(payload)} bytes)", "VIDEO")
                            except Exception as e:
                                log(f"Forward failed: {e}", "ERROR")
                        else:
                            # log(f"Dropped Video Frame ({len(payload)} bytes) - No App for {target_device}", "WARN")
                            pass
                             
                    continue

                # 1. Check for JSON (XMPP)
                json_part = None
                json_start = payload.find(b'{')
                if json_start >= 0:
                    try:
                        dec = json.JSONDecoder()
                        obj, end = dec.raw_decode(payload[json_start:].decode('utf-8', 'ignore'))
                        json_part = obj
                    except: pass
                    
                if json_part:
                    # Debug: Log full payload to see what schema is requested
                    try:
                        log(f"Full XMPP Payload: {json.dumps(json_part)}", "XMPP")
                    except: pass

                    # Extract deviceId from JSON payload - CRITICAL for multi-camera routing
                    action = json_part.get('action')
                    xmpp_device_id = None
                    if 'data' in json_part and 'deviceId' in json_part['data']:
                        xmpp_device_id = json_part['data']['deviceId']
                    elif 'deviceId' in json_part:
                        xmpp_device_id = json_part['deviceId']

                    # Fallback: extract device ID from schema field (e.g. "ipc://xxxxS_189e2d438ea9")
                    if not xmpp_device_id and 'data' in json_part:
                        schema = json_part['data'].get('schema', '')
                        if not schema:
                            schemas_str = json_part['data'].get('schemas', '')
                            if schemas_str:
                                try:
                                    schemas_list = json.loads(schemas_str)
                                    if schemas_list:
                                        schema = schemas_list[0]
                                except: pass
                        if schema and 'xxxxS_' in schema:
                            xmpp_device_id = schema.split('xxxxS_', 1)[1]
                            xmpp_device_id = 'xxxxS_' + xmpp_device_id.split('"')[0].strip()

                    if xmpp_device_id:
                        device_id = xmpp_device_id
                        conn_device_id = xmpp_device_id

                    # Register Client Type (carefully - don't overwrite camera_control!)
                    if 'platform' in json_part:
                        # App connection
                        if xmpp_device_id:
                            register_socket(conn, xmpp_device_id, 'app_control')
                            conn_role = 'app_control'
                        CLIENT_REGISTRY["app"] = conn
                        log(f"Registered APP Client: {conn_id} for device {xmpp_device_id or 'unknown'}", "SUCCESS")
                    elif action in ["UDI", "GDL", "S_GET", "S_SAVE"]:
                        # These are camera-only actions - register with session
                        if xmpp_device_id:
                            register_socket(conn, xmpp_device_id, 'camera_control')
                            conn_role = 'camera_control'
                        CLIENT_REGISTRY["camera"] = conn
                        CLIENT_REGISTRY["camera_control"] = conn
                        log(f"Registered CAMERA Client: {conn_id} for device {xmpp_device_id or 'unknown'}", "INFO")
                    else:
                        # For other actions (like LIVE_VIEW from app), don't overwrite camera_control
                        log(f"XMPP from {conn_id} (action: {action}) for device {xmpp_device_id or 'unknown'}", "DEBUG")

                    # === PROTOCOL HANDLING ===
                    msg_id = XMPPProtocol.extract_message_id(payload)
                    
                    if action == "UDI":
                        log(f"Handling UDI for {device_id} (MsgId: {msg_id})", "XMPP")

                        # Send UDI Response ONLY
                        udi_resp = build_udi_response()
                        resp_bytes2 = XMPPProtocol.build_action_response(udi_resp, msg_id)
                        conn.sendall(resp_bytes2)
                        log(f"Sent UDI Action Response for {device_id}", "XMPP")

                        # Register Camera Control with session
                        register_socket(conn, device_id, 'camera_control')
                        conn_role = 'camera_control'
                        CLIENT_REGISTRY["camera_control"] = conn
                        log(f"Registered CAMERA Control for {device_id}", "XMPP")
                        
                    elif action == "GDL":
                        log(f"Handling GDL (MsgId: {msg_id})", "XMPP")
                        
                        # 1. Send Standard GDL Response (Nested List)
                        gdl_resp = build_gdl_response(device_id) 
                        resp_bytes = XMPPProtocol.build_action_response(gdl_resp, msg_id)
                        conn.sendall(resp_bytes)
                        log("Sent GDL Response", "XMPP")
                        
                        time.sleep(0.1)
                        
                        # 2. Push Configuration
                        config = build_udi_config()
                        ts = str(int(time.time() * 1000))
                        tok = "313814f499374a219d4c8dccf0258372"
                        conf_bytes = XMPPProtocol.build_udi_config_message(config, ts, tok)
                        conn.sendall(conf_bytes)
                        log("Sent UDI Config Push", "XMPP")
                        
                    elif action == "S_GET":
                        schema = "camera" # Default
                        
                        # Extract requested schema
                        data_in = json_part.get('data', {})
                        if 'schemas' in data_in:
                            try:
                                # Parsing "[\"ipc://...\"]"
                                s_list = json.loads(data_in['schemas'])
                                if s_list and len(s_list) > 0:
                                    schema = s_list[0]
                            except: pass
                        elif 'schema' in data_in:
                            schema = data_in['schema']

                        s_get_resp = build_s_get_response(schema, device_id)
                        resp_bytes = XMPPProtocol.build_action_response(s_get_resp, msg_id)
                        conn.sendall(resp_bytes)
                        log(f"Sent S_GET Response ({schema})", "XMPP")
                        
                    elif action == "S_SAVE":
                        s_save_resp = build_s_save_response()
                        resp_bytes = XMPPProtocol.build_action_response(s_save_resp, msg_id)
                        conn.sendall(resp_bytes)
                        log("Sent S_SAVE Response", "XMPP")

                    elif action == "LIVE_VIEW":
                        # Get device_id from LIVE_VIEW request data
                        lv_device_id = json_part.get('data', {}).get('deviceId', device_id)
                        log(f"LIVE_VIEW request for device: {lv_device_id}", "XMPP")

                        # Ack the App's request
                        lv_resp = {"data": {"code": "0", "message": "success"}, "action": "LIVE_VIEW"}
                        resp_bytes = XMPPProtocol.build_action_response(lv_resp, msg_id)
                        conn.sendall(resp_bytes)
                        log(f"Sent LIVE_VIEW Response for {lv_device_id}", "XMPP")

                        # Trigger Camera Stream: MITM-Verified Sequence (Timeline + Short Ack ONLY)
                        # Use session-based routing to find the camera control for THIS device
                        cam_ctrl = None
                        session = get_session(lv_device_id)
                        if session:
                            cam_ctrl = session.get('camera_control')

                        # Fallback to legacy registry
                        if not cam_ctrl:
                            cam_ctrl = CLIENT_REGISTRY.get("camera_control")

                        # Fallback: find unidentified connection from a known camera IP
                        if not cam_ctrl and CAMERA_IPS:
                            with CONNECTIONS_LOCK:
                                for cid, cinfo in CONNECTIONS.items():
                                    if cinfo['ip'] in CAMERA_IPS and cinfo.get('role') is None and cinfo.get('socket'):
                                        cam_ctrl = cinfo['socket']
                                        log(f"Using unidentified connection from camera IP {cinfo['ip']} as control fallback", "STREAM")
                                        break

                        # Use EXACT clientID from successful MITM capture
                        session_client_id = "ANDRC_14716d80f38f"
                        log(f"Using Client ID: {session_client_id} for device {lv_device_id}", "INFO")

                        if cam_ctrl:
                            try:
                                # DEFINITIVE TEST: Send EXACT bytes from successful MITM capture
                                # If this doesn't work, the issue is NOT message format but cloud auth/session state
                                
                                # Timeline Query: 196 bytes exactly as captured (lines 62-74 of MITM log)
                                # Note: The timestamps might be stale but let's test
                                timeline_hex = (
                                    "000000c0"  # 4-byte length prefix (192 bytes)
                                    "080742bb01"  # Type 7, Field 8 length 187
                                    "0800"  # Field 1 = 0
                                    "100a"  # Field 2 = 10
                                    "1a12616e6472635f3134373136643830663338"  # clientid (lowercase)
                                    "662000"  # rest of header
                                    "329e01"  # JSON field tag + length
                                    # JSON body with MITM timestamps (may not work due to timestamp validation)
                                    "7b0a202020226368656e746964222" 
                                    "03a2022414e4452435f3134373136"
                                    "6438306633386622"  # ...abbreviated, use dynamic for now
                                )
                                
                                # Actually, let's use our dynamic Timeline Query but WITHOUT the 1792
                                # The MITM shows Timeline + Short Ack only, no prior 1792
                                
                                # MITM Short Ack: EXACT 19 bytes
                                short_ack_mitm = bytes.fromhex("0000000f0807420b0800101048e0d403709875")
                                
                                log(f"Sending trigger WITHOUT 1792 (MITM sequence)", "XMPP")
                                
                                # CRITICAL DEBUG: Verify we're sending to the right socket!
                                try:
                                    cam_peer = cam_ctrl.getpeername()
                                    log(f"*** SENDING TO CAMERA CONTROL AT: {cam_peer[0]}:{cam_peer[1]} ***", "DEBUG")
                                except:
                                    log(f"*** CAMERA CONTROL SOCKET INVALID! ***", "ERROR")
                                
                                # 1. Send Timeline Query (using our dynamic builder but same format as MITM)
                                timeline_query = build_xmpp_timeline_query(session_client_id)
                                cam_ctrl.sendall(timeline_query)
                                log(f"Sent Timeline Query ({len(timeline_query)} bytes)", "XMPP")
                                log(f"Timeline HEX: {timeline_query[:50].hex()}...", "DEBUG")
                                
                                # 2. Send EXACT Short Ack from MITM (40ms delay)
                                time.sleep(0.04)
                                cam_ctrl.sendall(short_ack_mitm)
                                log(f"Sent EXACT MITM Short Ack ({len(short_ack_mitm)} bytes)", "XMPP")
                                log(f"Short Ack HEX: {short_ack_mitm.hex()}", "DEBUG")

                                # 3. Send 0xBC CCAM trigger
                                # Try camera stream first, fall back to camera control
                                cam_stream = None
                                if session:
                                    cam_stream = session.get('camera_stream')
                                if not cam_stream:
                                    cam_stream = CLIENT_REGISTRY.get("camera_stream")

                                trigger_target = cam_stream or cam_ctrl
                                if trigger_target:
                                    time.sleep(0.1)
                                    app_info = {}
                                    if session:
                                        app_info = session.get('app_login_info') or {}
                                    if not app_info:
                                        app_info = CLIENT_REGISTRY.get("app_login_info", {})
                                    trigger = build_ccam_trigger(app_info)
                                    trigger_target.sendall(trigger)
                                    target_type = "camera_stream" if trigger_target == cam_stream else "camera_control"
                                    log(f"Sent 0xBC Start Streaming via {target_type} for {lv_device_id}", "STREAM")
                                else:
                                    log(f"No target for 0xBC trigger (no stream or control)", "WARN")

                            except Exception as e:
                                log(f"Failed to send Trigger Sequence: {e}", "ERROR")
                        else:
                            log("Camera Control not found, skipping Trigger", "WARN")

                    continue



                # 2. Check for Protobuf Types
                # Type 4: MediaPackage | Type 15: PeerHint | Type 1: Heartbeat
                if len(payload) > 2:
                    tag1, offset1 = decode_varint(payload, 0)
                    field1 = tag1 >> 3
                    
                    if field1 == 4: # MediaPackage (Encrypted Video)
                        # Forward to App using session-based routing
                        target_device = conn_device_id or device_id
                        app_conn = None

                        # Try session-based routing first
                        session = get_session(target_device)
                        if session:
                            app_conn = session.get('app_stream') or session.get('app_control')

                        # Fallback to legacy registry
                        if not app_conn:
                            app_conn = CLIENT_REGISTRY.get("app")

                        if app_conn:
                            try:
                                full_packet = struct.pack('>I', len(payload)) + payload
                                app_conn.sendall(full_packet)
                                # log(f"Forwarded Video Packet to {target_device} ({len(payload)} bytes)", "VIDEO")
                            except Exception as e:
                                log(f"Forwarding failed: {e}", "ERROR")
                                CLIENT_REGISTRY["app"] = None
                        else:
                            # log(f"Received Video ({len(payload)} bytes) - No App for {target_device}", "VIDEO")
                            pass
                            
                    elif field1 == 1: # Heartbeat / Peer Hint
                        field1_val, _ = decode_varint(payload, offset1)
                        
                        # Heartbeat Handling (Type 1)
                        if field1_val == 15:
                            # Peer Hint Request
                            log("Received Peer Hint Request (Val: 15)", "INFO")
                            peer_hint_resp = build_peer_hint_response(server_ip, server_port)
                            conn.sendall(peer_hint_resp)
                            log(f"Sent Peer Hint Response (Val: 15) -> {server_ip}:{server_port}", "SUCCESS")
                            continue
                        
                        elif field1_val in [1, 5, 12]:
                            # Standard Ping (1=Ping, 5=Ping, 12=Ping?) - ECHO BACK
                            # The camera expects the exact same packet back (sequence numbers etc.)
                            log(f"Received Heartbeat Type 1 Val: {field1_val}", "INFO")
                            full_pkt = struct.pack('>I', len(payload)) + payload
                            conn.sendall(full_pkt)
                            log(f"Sent Pong (Echo Val: {field1_val})", "SUCCESS")
                            continue
                            
                        elif field1_val == 16:
                            # Pong from Camera? Ignore
                            continue
                        elif field1_val == 6:
                            # Type 6 = Camera's Pong response - ignore
                            log(f"Received Pong (Type 1 Val 6)", "DEBUG")
                            continue
                        elif field1_val == 10:
                            # Type 10 embedded in Type 1 - Resolution Announcement
                            # Decode: 08 0a 5a 08 08 05 28 c0 07 30 9c 04
                            # This is Field 1=10, Field 11 contains: Field 1=5, Field 5=960, Field 6=540
                            log(f"Received Resolution Announcement (Type 10): {payload.hex()}", "DEBUG")
                            # TODO: Parse resolution and acknowledge if needed
                            continue
                        else:
                            # Unknown Type 1 value
                            log(f"Unknown Type 1 Value: {field1_val}, Hex: {payload[:50].hex()}", "DEBUG")
                            
                    elif field1 == 10: # Type 10 - Resolution/Media announcement?
                        log(f"Received Type 10 Message: {payload.hex()}", "DEBUG")
                        # TODO: Parse and respond if needed
                        
                    else:
                        # Unknown protobuf type
                        log(f"Unknown Protobuf Field={field1}, Hex: {payload[:50].hex()}", "DEBUG")

                    # ... handle others ...

        except Exception as e:
            log(f"Client error {conn_id}: {e}", "ERROR")
        finally:
            log(f"Connection closed: {conn_id} (device: {conn_device_id}, role: {conn_role})", "INFO")

            # APP STREAM DISCONNECT
            # Don't force-close camera stream - the stream server will reconnect quickly
            # (e.g. when Frigate restarts) and the camera takes a long time to re-establish CCAM.
            # Just let the camera keep its stream connection alive. Video frames will be
            # dropped (no app_stream target) until the stream server reconnects.
            if conn_role == 'app_stream' and conn_device_id:
                log(f"App stream disconnected for {conn_device_id} - camera stream kept alive", "STREAM")
                cam_stream_sock = None  # Skip force-close

                if False and cam_stream_sock:  # Disabled: was force-closing camera stream
                    try:
                        log(f"Force closing Camera Stream for {conn_device_id} to stop video...", "STREAM")
                        cam_stream_sock.shutdown(socket.SHUT_RDWR)
                        cam_stream_sock.close()
                    except Exception as e:
                        log(f"Error closing camera stream: {e}", "DEBUG")
                    
                    # Also explicitly clear the session entry so the thread exits cleanly
                    # (Though close() usually triggers the recv() loop to break)


            # Cleanup Connection Registry
            unregister_connection(conn_id)

            # Cleanup Session Registry
            if conn:
                unregister_socket(conn)

            # Cleanup Legacy Registry
            keys_to_remove = [k for k, v in CLIENT_REGISTRY.items() if v == conn]
            for k in keys_to_remove:
                del CLIENT_REGISTRY[k]
                log(f"Removed {k} from legacy registry", "INFO")

            try:
                if conn:
                    conn.close()
            except:
                pass

# ============================================================================
# Session Registry for Multi-Camera Support
# ============================================================================
# Key: device_id (string)
# Value: {
#     'camera_control': socket,     # XMPP control connection from camera
#     'camera_stream': socket,      # CCAM media connection from camera
#     'app_control': socket,        # XMPP control connection from app (optional)
#     'app_stream': socket,         # CCAM media connection from app
#     'app_login_info': dict,       # Login info from app (deviceId, channel, etc.)
# }
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()

# Socket-to-DeviceID mapping for reverse lookups
SOCKET_TO_DEVICE = {}

# ============================================================================
# Connection Registry - Track ALL connections (even unidentified)
# ============================================================================
# Key: conn_id (string like "192.168.1.1:12345")
# Value: {
#     'socket': socket,
#     'ip': str,
#     'port': int,
#     'device_id': str or None,
#     'role': str or None,
#     'connected_at': float (timestamp),
# }
CONNECTIONS = {}
CONNECTIONS_LOCK = threading.Lock()


def register_connection(conn, addr):
    """Register a new connection (before device_id is known)"""
    conn_id = f"{addr[0]}:{addr[1]}"
    with CONNECTIONS_LOCK:
        CONNECTIONS[conn_id] = {
            'socket': conn,
            'ip': addr[0],
            'port': addr[1],
            'device_id': None,
            'role': None,
            'connected_at': time.time(),
        }
    return conn_id


def update_connection(conn_id, device_id=None, role=None):
    """Update connection info once device_id is identified"""
    with CONNECTIONS_LOCK:
        if conn_id in CONNECTIONS:
            if device_id:
                CONNECTIONS[conn_id]['device_id'] = device_id
            if role:
                CONNECTIONS[conn_id]['role'] = role


def unregister_connection(conn_id):
    """Remove connection from registry"""
    with CONNECTIONS_LOCK:
        if conn_id in CONNECTIONS:
            del CONNECTIONS[conn_id]


def list_connections():
    """List all active connections"""
    with CONNECTIONS_LOCK:
        result = []
        for conn_id, info in CONNECTIONS.items():
            result.append({
                'conn_id': conn_id,
                'ip': info['ip'],
                'port': info['port'],
                'device_id': info['device_id'],
                'role': info['role'],
                'connected_at': info['connected_at'],
                'uptime_secs': int(time.time() - info['connected_at']),
            })
        return result


def get_connection_socket(conn_id):
    """Get socket for a connection by conn_id"""
    with CONNECTIONS_LOCK:
        if conn_id in CONNECTIONS:
            return CONNECTIONS[conn_id].get('socket')
    return None


def get_or_create_session(device_id):
    """Get existing session or create new one for device_id"""
    with SESSIONS_LOCK:
        if device_id not in SESSIONS:
            SESSIONS[device_id] = {
                'camera_control': None,
                'camera_stream': None,
                'app_control': None,
                'app_stream': None,
                'app_login_info': None
            }
            log(f"Created new session for device: {device_id}", "SESSION")
        return SESSIONS[device_id]


def register_socket(conn, device_id, role):
    """Register a socket with a device_id and role"""
    with SESSIONS_LOCK:
        if device_id not in SESSIONS:
            SESSIONS[device_id] = {
                'camera_control': None,
                'camera_stream': None,
                'app_control': None,
                'app_stream': None,
                'app_login_info': None
            }
            log(f"Created new session for device: {device_id}", "SESSION")
        SESSIONS[device_id][role] = conn
        SOCKET_TO_DEVICE[conn] = (device_id, role)
        log(f"Registered {role} for device {device_id}", "SESSION")

    # Also update the connection registry
    try:
        peer = conn.getpeername()
        conn_id = f"{peer[0]}:{peer[1]}"
        update_connection(conn_id, device_id=device_id, role=role)
    except:
        pass


def unregister_socket(conn):
    """Remove socket from all registrations"""
    with SESSIONS_LOCK:
        if conn in SOCKET_TO_DEVICE:
            device_id, role = SOCKET_TO_DEVICE[conn]
            if device_id in SESSIONS and SESSIONS[device_id].get(role) == conn:
                SESSIONS[device_id][role] = None
                log(f"Unregistered {role} for device {device_id}", "SESSION")
            del SOCKET_TO_DEVICE[conn]


def get_device_for_socket(conn):
    """Get device_id and role for a socket"""
    with SESSIONS_LOCK:
        return SOCKET_TO_DEVICE.get(conn, (None, None))


def get_session(device_id):
    """Get session for device_id (or None if not found)"""
    with SESSIONS_LOCK:
        return SESSIONS.get(device_id)


def list_sessions():
    """List all active sessions (for debugging)"""
    with SESSIONS_LOCK:
        return {
            dev_id: {
                'camera_control': bool(s.get('camera_control')),
                'camera_stream': bool(s.get('camera_stream')),
                'app_stream': bool(s.get('app_stream')),
            }
            for dev_id, s in SESSIONS.items()
        }


# Legacy CLIENT_REGISTRY for backward compatibility during transition
# TODO: Remove after full migration
CLIENT_REGISTRY = {"camera": None, "app": None}

# Server start time for uptime calculation
SERVER_START_TIME = None


# ============================================================================
# Management Interface Server
# ============================================================================
class ManagementServer:
    """Simple TCP server for CLI management commands"""

    def __init__(self, host=RELAY_HOST, port=MGMT_PORT):
        self.host = host
        self.port = port
        self.running = False

    def start(self):
        """Start the management server in a background thread"""
        self.running = True
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        log(f"Management interface listening on {self.host}:{self.port}", "SUCCESS")

    def _run(self):
        """Main server loop"""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_sock.bind((self.host, self.port))
            server_sock.listen(5)

            while self.running:
                try:
                    server_sock.settimeout(1.0)
                    client, addr = server_sock.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client,),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        log(f"Management accept error: {e}", "ERROR")

        except Exception as e:
            log(f"Management server error: {e}", "ERROR")
        finally:
            server_sock.close()

    def _handle_client(self, conn):
        """Handle a single management client connection"""
        try:
            conn.settimeout(5.0)

            # Read request length (4 bytes)
            len_bytes = conn.recv(4)
            if len(len_bytes) < 4:
                return

            req_len = int.from_bytes(len_bytes, 'big')
            if req_len > 65536:  # Sanity check
                return

            # Read request data
            req_data = b""
            while len(req_data) < req_len:
                chunk = conn.recv(req_len - len(req_data))
                if not chunk:
                    break
                req_data += chunk

            # Parse JSON request
            request = json.loads(req_data.decode('utf-8'))
            command = request.get('command', '')
            params = request.get('params', {})

            # Process command
            response = self._process_command(command, params)

            # Send response
            resp_bytes = json.dumps(response).encode('utf-8')
            conn.sendall(len(resp_bytes).to_bytes(4, 'big') + resp_bytes)

        except Exception as e:
            log(f"Management client error: {e}", "ERROR")
        finally:
            try:
                conn.close()
            except:
                pass

    def _process_command(self, command, params):
        """Process a management command and return response"""
        if command == "list_sessions":
            return {"sessions": list_sessions()}

        elif command == "list_connections":
            # Filter out App connections by default to show only Cameras
            all_conns = list_connections()
            filtered_conns = [
                c for c in all_conns 
                if c['role'] not in ['app_control', 'app_stream']
            ]
            return {"connections": filtered_conns}

        elif command == "status":
            # Calculate uptime
            uptime_str = "unknown"
            if SERVER_START_TIME:
                uptime_secs = int(time.time() - SERVER_START_TIME)
                hours, remainder = divmod(uptime_secs, 3600)
                minutes, seconds = divmod(remainder, 60)
                uptime_str = f"{hours}h {minutes}m {seconds}s"

            # Count from connections registry
            connections = list_connections()
            identified = [c for c in connections if c.get('device_id')]
            unidentified = [c for c in connections if not c.get('device_id')]

            # Count cameras and apps from sessions
            sessions = list_sessions()
            camera_count = sum(1 for s in sessions.values() if s.get('camera_control') or s.get('camera_stream'))
            app_count = sum(1 for s in sessions.values() if s.get('app_stream'))

            return {
                "uptime": uptime_str,
                "total_connections": len(connections),
                "identified_connections": len(identified),
                "unidentified_connections": len(unidentified),
                "session_count": len(sessions),
                "camera_count": camera_count,
                "app_count": app_count
            }

        elif command == "session_info":
            device_id = params.get('device_id')
            if not device_id:
                return {"error": "device_id parameter required"}

            session = get_session(device_id)
            if not session:
                return {"error": f"No session found for device: {device_id}"}

            # Build session info (don't include socket objects)
            session_info = {
                'camera_control': bool(session.get('camera_control')),
                'camera_stream': bool(session.get('camera_stream')),
                'app_stream': bool(session.get('app_stream')),
                'app_login_info': session.get('app_login_info')
            }

            return {"session": session_info}

        elif command == "query_device":
            # Send S_GET to a connection to discover its device_id
            conn_id = params.get('conn_id')
            if not conn_id:
                return {"error": "conn_id parameter required"}

            sock = get_connection_socket(conn_id)
            if not sock:
                return {"error": f"No connection found: {conn_id}"}

            try:
                # Build and send S_GET request
                s_get_request = {
                    "action": "S_GET",
                    "data": {
                        "schemas": "[\"camera\"]"
                    }
                }
                json_bytes = json.dumps(s_get_request, separators=(',', ':')).encode('utf-8')

                # Build Type 7 protobuf wrapper
                inner = b'\x08\x00'  # f1=0
                inner += b'\x10\x64'  # f2=100
                inner += b'\x20\x00'  # f4=0
                inner += b'\x32' + encode_varint(len(json_bytes)) + json_bytes

                outer = b'\x08\x07'
                outer += b'\x42' + encode_varint(len(inner)) + inner

                packet = struct.pack('>I', len(outer)) + outer
                sock.sendall(packet)

                return {"status": "S_GET sent", "conn_id": conn_id}

            except Exception as e:
                return {"error": f"Failed to send S_GET: {e}"}

        elif command == "set_device_id":
            # Manually assign device_id to all connections from an IP
            ip = params.get('ip')
            device_id = params.get('device_id')

            if not ip or not device_id:
                return {"error": "Both 'ip' and 'device_id' parameters required"}

            updated = 0
            with CONNECTIONS_LOCK:
                for conn_id, info in CONNECTIONS.items():
                    if info.get('ip') == ip:
                        info['device_id'] = device_id
                        updated += 1

                        # Also register in session registry
                        sock = info.get('socket')
                        if sock:
                            # Determine role based on existing connections
                            # If no camera_control for this device, assume this is it
                            role = 'camera_control'
                            if device_id in SESSIONS:
                                if SESSIONS[device_id].get('camera_control'):
                                    role = 'camera_stream'

                            if device_id not in SESSIONS:
                                SESSIONS[device_id] = {
                                    'camera_control': None,
                                    'camera_stream': None,
                                    'app_control': None,
                                    'app_stream': None,
                                    'app_login_info': None
                                }
                            SESSIONS[device_id][role] = sock
                            SOCKET_TO_DEVICE[sock] = (device_id, role)
                            info['role'] = role

            return {"status": "ok", "updated": updated}

        elif command == "trigger_stream":
            # Send stream trigger to a camera by device_id or IP
            device_id = params.get('device_id')
            ip = params.get('ip')

            if not device_id and not ip:
                return {"error": "Either 'device_id' or 'ip' parameter required"}

            cam_ctrl = None

            # Try to find camera control socket
            if device_id:
                session = get_session(device_id)
                if session:
                    cam_ctrl = session.get('camera_control')

            # If not found by device_id, try by IP
            if not cam_ctrl and ip:
                with CONNECTIONS_LOCK:
                    for conn_id, info in CONNECTIONS.items():
                        if info.get('ip') == ip and info.get('socket'):
                            cam_ctrl = info.get('socket')
                            device_id = info.get('device_id') or device_id or "unknown"
                            break

            # Fallback to legacy registry
            if not cam_ctrl:
                cam_ctrl = CLIENT_REGISTRY.get("camera_control")

            if not cam_ctrl:
                return {"error": f"No camera control socket found for device_id={device_id} ip={ip}"}

            try:
                # Get camera's actual address for logging
                try:
                    peer = cam_ctrl.getpeername()
                    peer_str = f"{peer[0]}:{peer[1]}"
                except:
                    peer_str = "unknown"

                # Send Timeline Query + Short Ack (same as LIVE_VIEW handler)
                session_client_id = "ANDRC_14716d80f38f"

                timeline_query = build_xmpp_timeline_query(session_client_id)
                cam_ctrl.sendall(timeline_query)

                time.sleep(0.04)

                short_ack = bytes.fromhex("0000000f0807420b0800101048e0d403709875")
                cam_ctrl.sendall(short_ack)

                log(f"Sent stream trigger to {peer_str} (device: {device_id})", "XMPP")

                return {
                    "status": "ok",
                    "device_id": device_id,
                    "target": peer_str,
                    "message": "Stream trigger sent"
                }

            except Exception as e:
                return {"error": f"Failed to send trigger: {e}"}

        elif command == "list_all":
            # Return both sessions and connections for debugging
            return {
                "sessions": list_sessions(),
                "connections": list_connections()
            }

        elif command == "reboot_camera":
            # Send reboot command to a camera
            # Uses Request_DoRebootDevice (1829) from XMPP protocol
            device_id = params.get('device_id')
            ip = params.get('ip')

            if not device_id and not ip:
                return {"error": "Either 'device_id' or 'ip' parameter required"}

            cam_ctrl = None

            # Try to find camera control socket
            if device_id:
                session = get_session(device_id)
                if session:
                    cam_ctrl = session.get('camera_control')

            # If not found by device_id, try by IP
            candidate_sockets = []
            
            if cam_ctrl:
                candidate_sockets.append(cam_ctrl)
            elif ip:
                with CONNECTIONS_LOCK:
                    for conn_id, info in CONNECTIONS.items():
                        if info.get('ip') == ip and info.get('socket'):
                            s = info.get('socket')
                            role = info.get('role')
                            # Prioritize camera_control, but accept unknown roles too
                            if role == 'camera_control':
                                candidate_sockets = [s] # Found the definitive one
                                break
                            elif role == 'camera_stream':
                                continue # Skip known stream sockets
                            else:
                                candidate_sockets.append(s)

            if not candidate_sockets:
                return {"error": f"No suitable sockets found for device_id={device_id} ip={ip}"}
            
            # Use the first candidate to determine peer_str for the first log
            # We will iterate over all candidates below
            # cam_ctrl is now just used as a reference if non-empty
            
            results = []

            effective_device_id = device_id
            if not effective_device_id or effective_device_id == "unknown":
                effective_device_id = DEFAULT_DEVICE_ID


            import random
            msg_session = random.randint(1000000000, 2000000000)
            msg_timestamp = int(time.time() * 1000)

            # Inner Message
            reboot_payload = {
                "msgSession": msg_session,
                "msgTimeStamp": msg_timestamp,
                "msgSequence": 0,
                "msgContent": {
                    "subRequest": -2,
                    "request": 1829,
                    "requestParams": {"value": 1},
                    "msgVersion": 1  # Changed to 1 (Matches Capture)
                },
                "msgCategory": "camera"
            }

            reboot_json = json.dumps(reboot_payload, separators=(',', ':'))

            # Prepare context info (userId, token)
            # Try to get from session if available
            # Generate placeholder values if no session (CLI only mode)
            user_id = f"local_user_{msg_timestamp}"
            token = "00000000000000000000000000000000"
            
            session = get_session(effective_device_id)
            if session and session.get('app_login_info'):
                info = session.get('app_login_info')
                email = info.get('email', 'local')
                user_id = f"{email}{msg_timestamp}"
                token = info.get('token', token)
            
            # Outer Wrapper JSON - SKIP FOR CAMERA?
            # Hypothesis: Camera (Type 33) expects Inner Payload directly
            # "has no msgContent" implies it couldn't find it in the Outer Wrapper
            # so let's send 'reboot_payload' directly as Field 6.
            
            # Use inner payload directly
            payload_bytes = reboot_json.encode('utf-8')

            # Build protobuf wrapper using Type 33 (Device Target):
            # Field 2 = 33 (0x21) -> Target Device
            # Field 3 = Device ID
            # Field 6 = JSON Payload (Direct)

            device_id_bytes = effective_device_id.encode('utf-8')

            inner = b'\x08\x00'  # field 1 = 0
            inner += b'\x10\x21'  # field 2 = 33 (0x21)
            inner += b'\x1a' + encode_varint(len(device_id_bytes)) + device_id_bytes  # field 3 = device_id
            inner += b'\x20\x00'  # field 4 = 0
            inner += b'\x32' + encode_varint(len(payload_bytes)) + payload_bytes  # field 6 = JSON

            outer = b'\x08\x07'  # Type 7
            outer += b'\x42' + encode_varint(len(inner)) + inner

            packet = struct.pack('>I', len(outer)) + outer
            
            failed_count = 0
            for sock in candidate_sockets:
                try:
                    # Get camera's actual address for logging
                    try:
                        peer = sock.getpeername()
                        peer_str = f"{peer[0]}:{peer[1]}"
                    except:
                        peer_str = "unknown"

                    # Log hex dump for verification
                    log(f"Sending REBOOT Packet ({len(packet)} bytes) to {peer_str}:", "DEBUG")
                    for i in range(0, len(packet), 16):
                        chunk_hex = ' '.join(f'{b:02x}' for b in packet[i:i+16])
                        chunk_ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in packet[i:i+16])
                        print(f"  {i:04x}: {chunk_hex:<48} {chunk_ascii}")

                    sock.sendall(packet)

                    log(f"Sent REBOOT command to {peer_str} (device: {effective_device_id})", "XMPP")
                    results.append(f"Sent to {peer_str}")

                except Exception as e:
                    failed_count += 1
                    results.append(f"Failed {peer_str}: {e}")

            return {
                "status": "ok",
                "device_id": effective_device_id,
                "target": ip if ip else device_id,
                "message": f"Reboot command sent to {len(candidate_sockets)} socket(s): {', '.join(results)}"
            }

        elif command == "ptz":
            # Send PTZ command to camera
            # Uses Request_Set (1793) with Subrequest_LensPan (5), LensTilt (6), LensZoom (7)
            device_id = params.get('device_id')
            ip = params.get('ip')
            direction = params.get('direction', '').lower()
            action = params.get('action', 'move')  # 'move' or 'stop'

            # Continuous move uses subRequest=82 (LensPanContinue)
            # Step move uses subRequest=5 (LensPan) with {"value": dir, "step": N}
            # Values: left=1, right=2, up=3, down=4, stop=0
            PTZ_DIRECTIONS = {
                'left':  1,
                'right': 2,
                'up':    3,
                'down':  4,
                'stop':  0,
                'zoomin':  1,
                'zoomout': -1,
            }
            PTZ_ZOOM = {'zoomin', 'zoomout'}

            duration_ms = params.get('duration', 0)

            if action == 'stop':
                direction = 'stop'

            if direction not in PTZ_DIRECTIONS:
                return {"error": f"Invalid direction: '{direction}'. Valid: {', '.join(PTZ_DIRECTIONS.keys())}"}

            if not device_id and not ip:
                return {"error": "Either 'device_id' or 'ip' parameter required"}

            # Find camera control socket (same logic as reboot)
            cam_ctrl = None
            if device_id:
                session = get_session(device_id)
                if session:
                    cam_ctrl = session.get('camera_control')

            candidate_sockets = []
            if cam_ctrl:
                candidate_sockets.append(cam_ctrl)
            elif ip:
                with CONNECTIONS_LOCK:
                    for conn_id, info in CONNECTIONS.items():
                        if info.get('ip') == ip and info.get('socket'):
                            role = info.get('role')
                            if role == 'camera_control':
                                candidate_sockets = [info['socket']]
                                break
                            elif role == 'camera_stream':
                                continue
                            else:
                                candidate_sockets.append(info['socket'])

            if not candidate_sockets:
                return {"error": f"No camera connection found for device_id={device_id} ip={ip}"}

            effective_device_id = device_id or DEFAULT_DEVICE_ID

            import random

            ptz_value = PTZ_DIRECTIONS[direction]

            if direction in PTZ_ZOOM:
                sub_request = 7  # LensZoom
                request_params = {"value": ptz_value}
            else:
                sub_request = 82  # LensPanContinue (continuous move)
                request_params = {"value": ptz_value}

            ptz_payload = {
                "msgSession": random.randint(1000000000, 2000000000),
                "msgTimeStamp": int(time.time() * 1000),
                "msgSequence": 0,
                "msgContent": {
                    "request": 1793,
                    "subRequest": sub_request,
                    "channelName": "720p",
                    "requestParams": request_params
                },
                "msgCategory": "camera"
            }

            payload_bytes = json.dumps(ptz_payload, separators=(',', ':')).encode('utf-8')
            device_id_bytes = effective_device_id.encode('utf-8')

            inner = b'\x08\x00'
            inner += b'\x10\x21'
            inner += b'\x1a' + encode_varint(len(device_id_bytes)) + device_id_bytes
            inner += b'\x20\x00'
            inner += b'\x32' + encode_varint(len(payload_bytes)) + payload_bytes

            outer = b'\x08\x07'
            outer += b'\x42' + encode_varint(len(inner)) + inner

            packet = struct.pack('>I', len(outer)) + outer

            def _build_ptz_packet(ptz_json, dev_id_bytes):
                pb = ptz_json.encode('utf-8')
                inn = b'\x08\x00'
                inn += b'\x10\x21'
                inn += b'\x1a' + encode_varint(len(dev_id_bytes)) + dev_id_bytes
                inn += b'\x20\x00'
                inn += b'\x32' + encode_varint(len(pb)) + pb
                out = b'\x08\x07'
                out += b'\x42' + encode_varint(len(inn)) + inn
                return struct.pack('>I', len(out)) + out

            results = []
            for sock in candidate_sockets:
                try:
                    peer = sock.getpeername()
                    peer_str = f"{peer[0]}:{peer[1]}"
                    sock.sendall(packet)
                    log(f"Sent PTZ {direction} to {peer_str} (device: {effective_device_id})", "XMPP")
                    results.append(f"Sent to {peer_str}")

                    # Auto-stop after duration
                    if duration_ms > 0 and direction != 'stop':
                        def _delayed_stop(s, dur, dev_bytes):
                            time.sleep(dur / 1000.0)
                            stop_payload = {
                                "msgSession": random.randint(1000000000, 2000000000),
                                "msgTimeStamp": int(time.time() * 1000),
                                "msgSequence": 0,
                                "msgContent": {
                                    "request": 1793,
                                    "subRequest": 82,
                                    "channelName": "720p",
                                    "requestParams": {"value": 0}
                                },
                                "msgCategory": "camera"
                            }
                            stop_pkt = _build_ptz_packet(json.dumps(stop_payload, separators=(',', ':')), dev_bytes)
                            try:
                                s.sendall(stop_pkt)
                                log(f"PTZ auto-stop after {dur}ms", "XMPP")
                            except Exception as e:
                                log(f"PTZ auto-stop failed: {e}", "ERROR")

                        threading.Thread(
                            target=_delayed_stop,
                            args=(sock, duration_ms, device_id_bytes),
                            daemon=True
                        ).start()
                        results[-1] += f" (auto-stop in {duration_ms}ms)"

                except Exception as e:
                    results.append(f"Failed: {e}")

            return {
                "status": "ok",
                "device_id": effective_device_id,
                "direction": direction,
                "duration_ms": duration_ms,
                "message": f"PTZ {direction} sent: {', '.join(results)}"
            }

        else:
            return {"error": f"Unknown command: {command}"}


if __name__ == "__main__":
    SERVER_START_TIME = time.time()
    
    # Check for debug flag
    if "--debug" in sys.argv:
        DEBUG_MODE = True
        print(f"{Colors.WARNING}*** DEBUG MODE ACTIVE ***{Colors.ENDC}")

    # Start management interface
    mgmt_server = ManagementServer()
    mgmt_server.start()

    # Start main relay server
    server = LocalRelayServer()
    try:
        server.start()
    except KeyboardInterrupt:
        log("Shutting down...", "WARNING")
