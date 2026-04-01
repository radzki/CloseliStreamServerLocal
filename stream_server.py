#!/usr/bin/env python3
"""
Stream Server - Connects to relay as "app" and serves video/audio via HTTP

Multi-Camera Support:
  python3 stream_server.py --device_id CAM_A --port 8081
  python3 stream_server.py --device_id CAM_B --port 8082

Endpoints:
  http://localhost:8080/camera/video  - MJPEG video stream
  http://localhost:8080/camera/audio  - WAV audio stream (G.711 A-law)
"""

import argparse
import os
import socket
import ssl
import struct
import json
import threading
import time
import queue
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from io import BytesIO


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTPServer that handles each request in a new thread"""
    daemon_threads = True  # Don't block shutdown waiting for threads

# ============================================================================
# Environment Loading
# ============================================================================
def load_dotenv():
    """Load environment variables from .env file if it exists"""
    from pathlib import Path
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

# Default Configuration (can be overridden by command line args or .env)
DEFAULT_RELAY_HOST = os.environ.get("LOCAL_IP", "192.168.1.100")
DEFAULT_RELAY_PORT = int(os.environ.get("RELAY_PORT", "50721"))
DEFAULT_HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
DEFAULT_DEVICE_ID = os.environ.get("DEFAULT_DEVICE_ID", "xxxxS_000000000000")
DEFAULT_PRODUCT_KEY = os.environ.get("PRODUCT_KEY", "")
DEFAULT_USER_EMAIL = os.environ.get("USER_EMAIL", "user@example.com")

# Runtime configuration (set from args)
RELAY_HOST = DEFAULT_RELAY_HOST
RELAY_PORT = DEFAULT_RELAY_PORT
HTTP_PORT = DEFAULT_HTTP_PORT
DEVICE_ID = DEFAULT_DEVICE_ID
PRODUCT_KEY = DEFAULT_PRODUCT_KEY
USER_EMAIL = DEFAULT_USER_EMAIL

# Global variables
relay_socket = None


def encode_varint(value):
    """Encode integer as protobuf varint"""
    result = []
    while value > 127:
        result.append((value & 0x7f) | 0x80)
        value >>= 7
    result.append(value & 0x7f)
    return bytes(result)


def _decode_varint(buffer, offset):
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


def build_xmpp_handshake():
    """Build initial handshake message - mimics Android app

    Format matches camera's protobuf structure but with 'android' platform
    """
    payload = {
        "platform": "android",
        "deviceId": DEVICE_ID,
        "channel": "720p",
        "timestamp": str(int(time.time() * 1000)),
        "productKey": PRODUCT_KEY,
        "email": USER_EMAIL,
        "appVersion": "6.1107.0.9824"
    }

    json_data = json.dumps(payload, separators=(',', ':')).encode('utf-8')

    # Build protobuf message similar to camera format:
    # field 1 = 1 (message type)
    # field 2 = JSON payload (length-delimited)
    inner = b'\x08\x01'  # field 1 = 1
    inner += b'\x12'  # field 2, wire type 2 (length-delimited)
    inner += encode_varint(len(json_data))
    inner += json_data

    # 4-byte big-endian length prefix
    message = struct.pack('>I', len(inner)) + inner
    return message


def build_ping():
    """Build ping packet - exact format from captured traffic

    Format: 00 00 00 06 08 05 32 02 08 00
    - 4-byte length = 6
    - field 1 = 5 (ping message type)
    - field 6, length 2, inner field 1 = 0
    """
    return bytes.fromhex('00000006080532020800')


def build_ccam_keepalive():
    """Build CCAM keepalive (Type 0) to keep video stream connection alive
    
    From captured traffic: CCAM + version 05 + type 00 + padding + timestamp
    """
    import time
    timestamp = int(time.time() * 1000)
    
    header = bytearray(20)
    header[0] = 0x05  # Version 5
    header[1] = 0x00  # ?
    header[2] = 0x00  # Type 0 = Keepalive
    header[3] = 0x00  # Flags
    # Rest is zeros/timestamp - camera echoes this back
    
    body = b'CCAM' + bytes(header)
    return struct.pack('>I', len(body)) + body


def build_xmpp_command(action, data_payload):
    """Build XMPP command message in proper protobuf format"""
    payload = {
        "action": action,
        "data": data_payload
    }

    json_data = json.dumps(payload, separators=(',', ':')).encode('utf-8')

    # Build protobuf wrapper like build_action_response format:
    # field 1 = 7
    # field 8 = nested message with JSON
    inner = b'\x08\x00'  # field 1 = 0
    inner += b'\x10\x64'  # field 2 = 100
    inner += b'\x20\x00'  # field 4 = 0
    inner += b'\x32'  # field 6, wire type 2
    inner += encode_varint(len(json_data))
    inner += json_data

    outer = b'\x08\x07'  # field 1 = 7
    outer += b'\x42'  # field 8, wire type 2
    outer += encode_varint(len(inner))
    outer += inner

    return struct.pack('>I', len(outer)) + outer


def build_live_view_request():
    """Build live view request command"""
    return build_xmpp_command("LIVE_VIEW", {
        "deviceId": DEVICE_ID,
        "channel": "720p",
        "streamType": "main",
        "useremail": USER_EMAIL
    })


def extract_jpeg_frame(decrypted_data):
    """Extract JPEG from decrypted packet (skip 35-byte protobuf header)"""
    if len(decrypted_data) < 37:
        return None

    # Skip 35-byte protobuf header
    jpeg_data = decrypted_data[35:]

    # Verify JPEG signature (FFD8)
    if jpeg_data[:2] != b'\xff\xd8':
        print(f"[WARN] Invalid JPEG signature: {jpeg_data[:4].hex()}")
        return None

    return jpeg_data


def build_ccam_login():
    """Build CCAM stream login request

    Format: [4-byte length][CCAM magic][20-byte header][JSON payload]
    """
    login_json = json.dumps({
        "deviceId": DEVICE_ID,
        "channel": "720p",
        "streamType": "main",
        "email": USER_EMAIL,
        "platform": "android"  # Identify as app (not camera)
    }, separators=(',', ':')).encode('utf-8')

    # CCAM header (20 bytes) - based on captured traffic
    header = bytearray(20)
    header[0] = 0x05  # Version?
    header[1] = 0x00
    header[2] = 0x01  # Request type
    header[3] = 0x00

    body = b'CCAM' + bytes(header) + login_json
    return struct.pack('>I', len(body)) + body


# Audio/Video Globals
video_lock = threading.Lock()
latest_video_frame = None

class StreamBroadcaster:
    """Simple one-to-many stream broadcaster using Queues"""
    def __init__(self):
        self.listeners = []
        self.lock = threading.Lock()
        self.broadcast_count = 0
        self.log_interval = 100  # Log queue sizes every N broadcasts

    def add_listener(self):
        q = queue.Queue(maxsize=100) # Buffer ~3 seconds of audio (320 bytes * 100 packets)
        with self.lock:
            self.listeners.append(q)
        print(f"[AUDIO] Listener added. Total listeners: {len(self.listeners)}")
        return q

    def remove_listener(self, q):
        with self.lock:
            if q in self.listeners:
                self.listeners.remove(q)
        print(f"[AUDIO] Listener removed. Total listeners: {len(self.listeners)}")

    def broadcast(self, data):
        with self.lock:
            self.broadcast_count += 1
            dropped_count = 0
            queue_sizes = []

            for q in self.listeners:
                queue_sizes.append(q.qsize())
                try:
                    q.put_nowait(data)
                except queue.Full:
                    # If client is too slow, we might drop data or drop client
                    # For now just drop packet for that client (glitch)
                    dropped_count += 1

            # Log queue sizes periodically
            if self.broadcast_count % self.log_interval == 0 and self.listeners:
                sizes_str = ', '.join(f'{s}/100' for s in queue_sizes)
                print(f"[AUDIO] Broadcast #{self.broadcast_count}: {len(self.listeners)} listeners, queue sizes: [{sizes_str}]" +
                      (f", dropped: {dropped_count}" if dropped_count else ""))

audio_broadcaster = StreamBroadcaster()


def _relay_client_impl():
    """Connect to relay server and receive video stream (internal implementation)

    Protocol sequence (based on UART analysis):
    1. App opens CONTROL connection, sends handshake (marks app_waiting=True)
    2. Camera's next GDL poll sees has_peer=True
    3. Camera opens CCAM stream to relay
    4. App opens CCAM stream to relay
    5. Relay bridges the two CCAM streams
    6. App sends LIVE_VIEW to trigger streaming

    OR alternative sequence:
    1. App opens CONTROL + CCAM connections
    2. App sends LIVE_VIEW
    3. Camera receives trigger and streams to existing CCAM bridge
    """
    global relay_socket, latest_video_frame

    print(f"[INFO] Connecting to relay server at {RELAY_HOST}:{RELAY_PORT}...")

    control_socket = None
    stream_socket = None

    def cleanup_sockets():
        """Close all sockets safely"""
        nonlocal control_socket, stream_socket
        for sock in [control_socket, stream_socket]:
            if sock:
                try:
                    sock.close()
                except:
                    pass

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # ============ CONNECTION 1: CONTROL ============
        print("[INFO] === Opening CONTROL connection ===")
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock1.connect((RELAY_HOST, RELAY_PORT))

        control_socket = context.wrap_socket(sock1, server_hostname=RELAY_HOST)
        print("[INFO] Control TLS connection established")

        # Send handshake (identify as app)
        handshake = build_xmpp_handshake()
        control_socket.sendall(handshake)
        print(f"[INFO] Sent control handshake ({len(handshake)} bytes)")

        time.sleep(0.5)

        # Send ping
        ping = build_ping()
        control_socket.sendall(ping)
        print(f"[INFO] Sent ping ({len(ping)} bytes)")

        # Wait for camera to see has_peer=True in next GDL poll
        # Camera polls every ~30-60 seconds, but our relay tells camera immediately
        print("[INFO] Waiting 2 seconds for camera to see peer and open CCAM...")
        time.sleep(2.0)

        # ============ CONNECTION 2: STREAM (CCAM) ============
        # Open CCAM BEFORE sending LIVE_VIEW so camera has somewhere to stream
        print("[INFO] === Opening STREAM (CCAM) connection ===")
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect((RELAY_HOST, RELAY_PORT))

        stream_socket = context.wrap_socket(sock2, server_hostname=RELAY_HOST)
        print("[INFO] Stream TLS connection established")

        # Send CCAM login
        ccam_login = build_ccam_login()
        stream_socket.sendall(ccam_login)
        print(f"[INFO] Sent CCAM login ({len(ccam_login)} bytes)")
        
        # Check for existing stream activity
        # If relay is already streaming video to us, we should see large packets immediately
        print("[INFO] Checking for existing video stream...")
        stream_socket.settimeout(2.0)
        
        existing_data = b""
        stream_active = False
        
        try:
            # We expect Login Response first, then maybe video
            # Read a chunk
            chunk1 = stream_socket.recv(65536)
            existing_data += chunk1
            print(f"[INFO] Received initial data: {len(chunk1)} bytes")
            
            # Try reading more to see if video flows
            stream_socket.settimeout(1.0)
            chunk2 = stream_socket.recv(65536)
            existing_data += chunk2
            print(f"[INFO] Received more data: {len(chunk2)} bytes")
            
            # Heuristic: If we received significant data (>1000 bytes), it's likely video
            if len(existing_data) > 1000:
                print("[INFO] Large data volume detected - Stream likely active!")
                stream_active = True
                
        except socket.timeout:
            print("[INFO] No ongoing stream data detected (Timeout).")
        except Exception as e:
            print(f"[WARN] Error checking stream: {e}")
            
        
        if not stream_active:
            # NOW send LIVE_VIEW to trigger streaming (camera has CCAM bridge ready)
            print("[INFO] === Sending LIVE_VIEW to trigger streaming ===")
            live_view_cmd = build_live_view_request()
            control_socket.sendall(live_view_cmd)
            print(f"[INFO] Sent LIVE_VIEW request ({len(live_view_cmd)} bytes)")
        else:
            print("[INFO] Skipping LIVE_VIEW trigger (Stream already active)")

        # Use stream socket for receiving video
        relay_socket = stream_socket

        # Receive responses and video stream
        print("[INFO] Entering stream loop...")
        frame_count = 0
        total_frags = 1 # default
        frame_buffer = {}  # For reassembling fragmented JPEG frames
        consecutive_timeouts = 0
        max_consecutive_timeouts = 4  # ~20 seconds without data = reconnect

        relay_socket.settimeout(5.0)  # 5 second timeout for faster keepalives

        while True:
            try:
                if existing_data:
                    data = existing_data
                    existing_data = None
                else:
                    data = relay_socket.recv(65536)  # Larger buffer for video

                # Reset timeout counter on successful receive
                consecutive_timeouts = 0

            except socket.timeout:
                consecutive_timeouts += 1

                if consecutive_timeouts >= max_consecutive_timeouts:
                    print(f"[WARN] No data for {consecutive_timeouts * 5}s - stream appears dead, reconnecting...")
                    break

                # Send CCAM keepalive to keep video stream alive
                try:
                    relay_socket.sendall(build_ccam_keepalive())
                    print(f"[INFO] Sent CCAM keepalive ({consecutive_timeouts}/{max_consecutive_timeouts})")
                except Exception as e:
                    print(f"[ERROR] Failed to send keepalive: {e}")
                    break
                continue

            if not data:
                print("[WARN] Connection closed by server")
                break

            # packet_count += 1 # Removed

            # Log ALL packets for debugging (first 20 at least) # Removed
            # if packet_count <= 20: # Removed
            #     # Try to identify message type # Removed
            #     msg_type = "UNKNOWN" # Removed
            #     if len(data) >= 6: # Removed
            #         if data[4:6] == b'\x08\x05': # Removed
            #             msg_type = "PONG" # Removed
            #         elif data[4:6] == b'\x08\x07': # Removed
            #             msg_type = "ACTION_RESP" # Removed
            #         elif data[4:6] == b'\x08\x02': # Removed
            #             msg_type = "CONFIG" # Removed
            #         elif data[4:6] == b'\x08\x01': # Removed
            #             msg_type = "HANDSHAKE_RESP" # Removed
            #         elif len(data) >= 8 and data[4:8] == b'CCAM': # Removed
            #             msg_type = "CCAM" # Removed

            #     print(f"[PKT #{packet_count:03d}] {msg_type}: {len(data)} bytes") # Removed
            #     print(f"         First 64: {data[:64].hex()}") # Removed

            #     # Try to extract JSON if present # Removed
            #     json_start = data.find(b'{') # Removed
            #     if json_start >= 0: # Removed
            #         try: # Removed
            #             json_str = data[json_start:].decode('utf-8', errors='ignore') # Removed
            #             decoder = json.JSONDecoder() # Removed
            #             parsed, _ = decoder.raw_decode(json_str) # Removed
            #             print(f"         JSON: {json.dumps(parsed, indent=2)[:200]}...") # Removed
            #         except: # Removed
            #             pass # Removed

            # Check if this is CCAM stream data
            if len(data) >= 28 and data[4:8] == b'CCAM':
                # Parse CCAM Header to find Video Packets (Type 1)
                # Header Format (based on logs):
                # 0-3: Packet Length (Big Endian)
                # 4-7: CCAM Magic
                # 8: Version (04 or 05)
                # For Version 4:
                #   Bytes 8-9: 04 TYPE (02=video, 01=audio)
                #   Bytes 12-13: TOTAL_FRAGS, FRAG_NUM (1-indexed)
                #   Bytes 28+: payload
                
                ccam_version = data[8]
                
                if ccam_version == 0x04:
                    # CCAM Version 4: Fragmented video!
                    # Header: CCAM 04 02 01 00 00 00 0d 01 00 00 ...
                    #         4-7  8  9  10 11 12 13 14 15 16 17
                    # Byte 14 = total_frags, Byte 15 = frag_num
                    ccam_type = data[9]
                    
                    # Ensure we have enough bytes for header
                    if len(data) < 16: continue
                    
                    total_frags = data[14]
                    frag_num = data[15]
                    frame_id = struct.unpack('>H', data[16:18])[0] if len(data) >= 18 else 0
                    
                    # Type 02 = Video, Type 01 = Audio
                    if ccam_type == 0x01:
                        # Extract payload (after 28 byte header usually)
                        if len(data) > 28:
                            payload = data[28:]
                            # Broadcast to all audio listeners
                            audio_broadcaster.broadcast(payload)
                        
                    if ccam_type == 0x02 and len(data) > 28:
                        payload = data[28:]
                        
                        # Initialize frame buffer if needed
                        if frag_num == 1:
                            frame_buffer.clear()
                            
                        # Store fragment
                        frame_buffer[frag_num] = payload
                        
                        # Check if we have all fragments
                        if len(frame_buffer) == total_frags:
                            # Reassemble complete frame
                            complete_data = b''
                            for i in range(1, total_frags + 1):
                                if i in frame_buffer:
                                    complete_data += frame_buffer[i]
                            
                            # Find JPEG in reassembled data
                            jpeg_start = complete_data.find(b'\xff\xd8')
                            jpeg_end = complete_data.rfind(b'\xff\xd9')
                            
                            if (jpeg_start != -1):
                                # If end missing, still try to use it
                                end_pos = jpeg_end + 2 if jpeg_end != -1 else len(complete_data)
                                jpeg_data = complete_data[jpeg_start:end_pos]
                                
                                with video_lock:
                                    latest_video_frame = jpeg_data
                                
                                frame_count += 1
                                if frame_count % 30 == 0:
                                    print(f"[VIDEO] Frame {frame_count} ({len(jpeg_data)} bytes)")
                            
                            frame_buffer.clear()
                            
                else:
                    # CCAM Version 5 or other: Log but ignore for now since we confirmed v4
                    # print(f"[CCAM] Unknown version: {ccam_version}")
                    pass

            # Check for large packets (potential video data) if not handled
            elif len(data) > 1000:
                # Try to find JPEG marker (in case it's unencrypted/raw)
                jpeg_start = data.find(b'\xff\xd8\xff\xe0')
                if jpeg_start != -1:
                    jpeg_data = data[jpeg_start:]
                    with video_lock:
                        latest_video_frame = jpeg_data
                    frame_count += 1
                    print(f"[VIDEO] Found raw JPEG frame! Count: {frame_count}, Size: {len(jpeg_data)}")

    except Exception as e:
        print(f"[ERROR] Relay client error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        cleanup_sockets()
        relay_socket = None

    return False  # Indicate disconnection


def relay_client():
    """Auto-reconnecting wrapper for relay client"""
    retry_count = 0
    max_retries = 100  # Essentially infinite
    
    while retry_count < max_retries:
        if retry_count > 0:
            print(f"\n[RECONNECT] Attempting reconnection #{retry_count}...")
            time.sleep(2)  # Wait before reconnecting
        
        try:
            _relay_client_impl()
        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
        
        retry_count += 1
        print("[INFO] Connection lost, will reconnect...")
    
    print("[ERROR] Max retries exceeded")
def create_wav_header():
    """Create a generic WAV header for G.711 A-law 8000Hz Mono"""
    # RIFF chunk
    header = b'RIFF'
    header += b'\xff\xff\xff\xff' # Size (unknown/streaming)
    header += b'WAVE'
    
    # fmt chunk
    header += b'fmt '
    header += struct.pack('<I', 18) # Size of fmt chunk (18 for extra param)
    header += struct.pack('<H', 6)  # AudioFormat 6 = A-law (7 = mu-law)
    header += struct.pack('<H', 1)  # NumChannels = 1
    header += struct.pack('<I', 8000) # SampleRate = 8000
    header += struct.pack('<I', 8000) # ByteRate = 8000 * 1 * 1
    header += struct.pack('<H', 1)  # BlockAlign = 1
    header += struct.pack('<H', 8)  # BitsPerSample = 8
    header += struct.pack('<H', 0)  # cbSize = 0
    
    # data chunk
    header += b'data'
    header += b'\xff\xff\xff\xff' # Size (unknown)
    
    return header


class MJPEGHandler(BaseHTTPRequestHandler):
    """HTTP handler to serve streams"""

    # Reduce socket lingering for cleaner shutdown
    timeout = 5

    def log_message(self, format, *args):
        # Suppress HTTP request logs
        pass

    def do_GET(self):
        if self.path == '/camera/video':
            self.send_response(200)
            self.send_header('Content-Type', 'multipart/x-mixed-replace; boundary=frame')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'close')
            self.end_headers()

            print("[HTTP] Client connected to VIDEO stream")
            last_frame_id = None
            no_data_count = 0
            try:
                while True:
                    with video_lock:
                        frame = latest_video_frame

                    if frame:
                        # Only send if it's a new frame (avoid sending duplicates)
                        frame_id = id(frame)
                        if frame_id != last_frame_id:
                            self.wfile.write(b'--frame\r\n')
                            self.wfile.write(b'Content-Type: image/jpeg\r\n')
                            self.wfile.write(f'Content-Length: {len(frame)}\r\n\r\n'.encode())
                            self.wfile.write(frame)
                            self.wfile.write(b'\r\n')
                            last_frame_id = frame_id
                            no_data_count = 0
                    else:
                        no_data_count += 1
                        # If no frames for ~10 seconds, close connection so client retries
                        if no_data_count > 300:  # 300 * 0.033s ≈ 10s
                            print("[HTTP] No video data for 10s, closing connection to force client retry")
                            break

                    time.sleep(0.033) # 30 FPS cap
            except:
                print("[HTTP] Video client disconnected")

        elif self.path == '/camera/audio':
            self.send_response(200)
            # audio/wav works well for streaming if header is sent
            self.send_header('Content-Type', 'audio/wav') 
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'close')
            self.end_headers()
            
            print("[HTTP] Client connected to AUDIO stream")
            
            # Send WAV Header
            self.wfile.write(create_wav_header())
            
            # Create a listener queue
            q = audio_broadcaster.add_listener()
            
            try:
                while True:
                    # Get audio chunk (blocking)
                    chunk = q.get(timeout=5.0)
                    self.wfile.write(chunk)
            except Exception as e:
                print(f"[HTTP] Audio client disconnected: {e}")
            finally:
                audio_broadcaster.remove_listener(q)
                
        else:
            self.send_response(404)
            self.end_headers()


def parse_args():
    """Parse command line arguments for multi-camera support"""
    parser = argparse.ArgumentParser(
        description='Stream Server - Connect to relay and serve video/audio streams via HTTP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single camera (default):
  python3 stream_server.py

  # Multiple cameras on different ports:
  python3 stream_server.py --device_id xxxxS_camera1 --port 8081
  python3 stream_server.py --device_id xxxxS_camera2 --port 8082

  # Custom relay server:
  python3 stream_server.py --relay_host 192.168.1.100 --relay_port 50721
        """
    )

    parser.add_argument(
        '--device_id', '-d',
        type=str,
        default=DEFAULT_DEVICE_ID,
        help=f'Camera device ID to connect to (default: {DEFAULT_DEVICE_ID})'
    )

    parser.add_argument(
        '--port', '-p',
        type=int,
        default=DEFAULT_HTTP_PORT,
        help=f'HTTP server port for video/audio streams (default: {DEFAULT_HTTP_PORT})'
    )

    parser.add_argument(
        '--relay_host', '-r',
        type=str,
        default=DEFAULT_RELAY_HOST,
        help=f'Relay server host (default: {DEFAULT_RELAY_HOST})'
    )

    parser.add_argument(
        '--relay_port',
        type=int,
        default=DEFAULT_RELAY_PORT,
        help=f'Relay server port (default: {DEFAULT_RELAY_PORT})'
    )

    parser.add_argument(
        '--email', '-e',
        type=str,
        default=DEFAULT_USER_EMAIL,
        help=f'User email for authentication (default: {DEFAULT_USER_EMAIL})'
    )

    return parser.parse_args()


def main():
    global RELAY_HOST, RELAY_PORT, HTTP_PORT, DEVICE_ID, USER_EMAIL

    # Parse command line arguments
    args = parse_args()

    # Update global configuration from args
    RELAY_HOST = args.relay_host
    RELAY_PORT = args.relay_port
    HTTP_PORT = args.port
    DEVICE_ID = args.device_id
    USER_EMAIL = args.email

    print("=" * 70)
    print("Stream Server - MJPEG Video & WAV Audio")
    print("=" * 70)
    print(f"Device ID: {DEVICE_ID}")
    print(f"Relay:     {RELAY_HOST}:{RELAY_PORT}")
    print(f"Video:     http://localhost:{HTTP_PORT}/camera/video")
    print(f"Audio:     http://localhost:{HTTP_PORT}/camera/audio")
    print()
    print("Open in VLC or Browser.")
    print("=" * 70)

    # Start relay client in background thread
    relay_thread = threading.Thread(target=relay_client, daemon=True)
    relay_thread.start()

    # Start HTTP server (threaded to handle multiple clients)
    server = ThreadingHTTPServer(('0.0.0.0', HTTP_PORT), MJPEGHandler)
    print(f"[HTTP] Starting HTTP server on port {HTTP_PORT}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Received CTRL+C, shutting down...")
    finally:
        server.shutdown()
        server.server_close()
    print("[INFO] Server stopped.")


if __name__ == "__main__":
    main()
