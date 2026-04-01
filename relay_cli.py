#!/usr/bin/env python3
"""
Relay CLI - Command line interface for managing the local relay server

Usage:
  python3 relay_cli.py list                    # List all connections
  python3 relay_cli.py sessions                # List identified device sessions
  python3 relay_cli.py status                  # Show server status
  python3 relay_cli.py info <device_id>        # Show details for a specific device
  python3 relay_cli.py query <conn_id>         # Query a connection for device info
  python3 relay_cli.py query-all               # Query all unidentified connections
"""

import socket
import json
import argparse
import sys
import time
import os
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
                    if value and value[0] in ('"', "'") and value[-1] == value[0]:
                        value = value[1:-1]
                    os.environ.setdefault(key, value)

load_dotenv()

# Default configuration
DEFAULT_CLI_HOST = "127.0.0.1"
DEFAULT_CLI_PORT = int(os.environ.get("MGMT_PORT", "50722"))


class RelayClient:
    """Client to communicate with relay server management interface"""

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def send_command(self, command, params=None):
        """Send a command to the relay server and get response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((self.host, self.port))

            # Build request
            request = {
                "command": command,
                "params": params or {}
            }

            # Send JSON request
            request_bytes = json.dumps(request).encode('utf-8')
            sock.sendall(len(request_bytes).to_bytes(4, 'big') + request_bytes)

            # Receive response
            resp_len = int.from_bytes(sock.recv(4), 'big')
            resp_data = b""
            while len(resp_data) < resp_len:
                chunk = sock.recv(resp_len - len(resp_data))
                if not chunk:
                    break
                resp_data += chunk

            sock.close()
            return json.loads(resp_data.decode('utf-8'))

        except ConnectionRefusedError:
            return {"error": f"Cannot connect to relay server at {self.host}:{self.port}"}
        except socket.timeout:
            return {"error": "Connection timed out"}
        except Exception as e:
            return {"error": str(e)}


def cmd_list(client, args):
    """List all connections grouped by IP"""
    response = client.send_command("list_connections")

    if "error" in response:
        print(f"Error: {response['error']}")
        return 1

    connections = response.get("connections", [])

    if not connections:
        print("No connections.")
        return 0

    # Group connections by IP address
    by_ip = {}
    for conn in connections:
        ip = conn.get('ip', 'unknown')
        if ip not in by_ip:
            by_ip[ip] = []
        by_ip[ip].append(conn)

    print(f"\n{'IP Address':<18} {'Connections':<5} {'Device ID':<25} {'Uptime':<10}")
    print("-" * 65)

    for ip, conns in sorted(by_ip.items()):
        # Find device_id if any connection has it
        device_id = None
        for c in conns:
            if c.get('device_id'):
                device_id = c.get('device_id')
                break

        # Get longest uptime
        max_uptime = max(c.get('uptime_secs', 0) for c in conns)

        # Format uptime
        if max_uptime >= 3600:
            uptime_str = f"{max_uptime // 3600}h {(max_uptime % 3600) // 60}m"
        elif max_uptime >= 60:
            uptime_str = f"{max_uptime // 60}m {max_uptime % 60}s"
        else:
            uptime_str = f"{max_uptime}s"

        device_str = device_id or '(unidentified)'
        print(f"{ip:<18} {len(conns):<5} {device_str:<25} {uptime_str:<10}")

    identified_ips = sum(1 for ip, conns in by_ip.items() if any(c.get('device_id') for c in conns))
    print(f"\nTotal: {len(by_ip)} camera(s), {len(connections)} connection(s)")

    return 0


def cmd_sessions(client, args):
    """List identified device sessions"""
    response = client.send_command("list_sessions")

    if "error" in response:
        print(f"Error: {response['error']}")
        return 1

    sessions = response.get("sessions", {})

    if not sessions:
        print("No identified device sessions.")
        print("\nTip: Use 'relay_cli.py list' to see all connections")
        return 0

    print(f"\n{'Device ID':<30} {'Camera Ctrl':<12} {'Camera Stream':<14} {'App Stream':<12}")
    print("-" * 70)

    for device_id, status in sessions.items():
        cam_ctrl = "Yes" if status.get('camera_control') else "No"
        cam_stream = "Yes" if status.get('camera_stream') else "No"
        app_stream = "Yes" if status.get('app_stream') else "No"

        print(f"{device_id:<30} {cam_ctrl:<12} {cam_stream:<14} {app_stream:<12}")

    print(f"\nTotal: {len(sessions)} device(s)")
    return 0


def cmd_status(client, args):
    """Show server status"""
    response = client.send_command("status")

    if "error" in response:
        print(f"Error: {response['error']}")
        return 1

    print("\n=== Relay Server Status ===")
    print(f"Uptime:                 {response.get('uptime', 'unknown')}")
    print(f"Total Connections:      {response.get('total_connections', 0)}")
    print(f"  Identified:           {response.get('identified_connections', 0)}")
    print(f"  Unidentified:         {response.get('unidentified_connections', 0)}")
    print(f"Device Sessions:        {response.get('session_count', 0)}")
    print(f"  Cameras:              {response.get('camera_count', 0)}")
    print(f"  Apps:                 {response.get('app_count', 0)}")
    return 0


def cmd_info(client, args):
    """Show details for a specific device"""
    if not args.device_id:
        print("Error: device_id is required")
        return 1

    response = client.send_command("session_info", {"device_id": args.device_id})

    if "error" in response:
        print(f"Error: {response['error']}")
        return 1

    session = response.get("session", {})

    if not session:
        print(f"No session found for device: {args.device_id}")
        return 1

    print(f"\n=== Device: {args.device_id} ===")
    print(f"Camera Control:  {'Connected' if session.get('camera_control') else 'Not connected'}")
    print(f"Camera Stream:   {'Connected' if session.get('camera_stream') else 'Not connected'}")
    print(f"App Stream:      {'Connected' if session.get('app_stream') else 'Not connected'}")

    if session.get('app_login_info'):
        info = session['app_login_info']
        print(f"\nApp Login Info:")
        print(f"  Channel:    {info.get('channel', 'unknown')}")
        print(f"  Platform:   {info.get('platform', 'unknown')}")
        print(f"  Email:      {info.get('email', 'unknown')}")

    return 0


def cmd_query(client, args):
    """Query a specific connection for device info"""
    if not args.conn_id:
        print("Error: conn_id is required (e.g., 192.168.1.100:12345)")
        return 1

    response = client.send_command("query_device", {"conn_id": args.conn_id})

    if "error" in response:
        print(f"Error: {response['error']}")
        return 1

    print(f"Sent S_GET query to {args.conn_id}")
    print("The device should respond and be identified shortly.")
    print("\nRun 'relay_cli.py list' to see updated connections.")
    return 0


def cmd_query_all(client, args):
    """Query all unidentified connections"""
    # First get list of connections
    response = client.send_command("list_connections")

    if "error" in response:
        print(f"Error: {response['error']}")
        return 1

    connections = response.get("connections", [])
    unidentified = [c for c in connections if not c.get('device_id')]

    if not unidentified:
        print("No unidentified connections to query.")
        return 0

    print(f"Querying {len(unidentified)} unidentified connection(s)...")

    for conn in unidentified:
        conn_id = conn.get('conn_id')
        response = client.send_command("query_device", {"conn_id": conn_id})

        if "error" in response:
            print(f"  {conn_id}: Failed - {response['error']}")
        else:
            print(f"  {conn_id}: S_GET sent")

        time.sleep(0.1)  # Small delay between queries

    print("\nWaiting for responses...")
    time.sleep(1.0)

    # Show updated list
    print("\nUpdated connection list:")
    return cmd_list(client, args)


def cmd_set_device(client, args):
    """Manually assign a device_id to an IP address"""
    if not args.ip or not args.device_id:
        print("Error: Both IP and device_id are required")
        return 1

    response = client.send_command("set_device_id", {
        "ip": args.ip,
        "device_id": args.device_id
    })

    if "error" in response:
        print(f"Error: {response['error']}")
        return 1

    updated = response.get('updated', 0)
    print(f"Assigned device_id '{args.device_id}' to IP {args.ip}")
    print(f"Updated {updated} connection(s)")

    return 0


def cmd_trigger(client, args):
    """Send stream trigger to a camera"""
    params = {}

    if hasattr(args, 'target') and args.target:
        # Check if it looks like an IP or a device_id
        if args.target.count('.') == 3:  # Looks like IP
            params['ip'] = args.target
        else:
            params['device_id'] = args.target

    if not params:
        print("Error: Provide a device_id or IP address")
        return 1

    response = client.send_command("trigger_stream", params)

    if "error" in response:
        print(f"Error: {response['error']}")
        return 1

    print(f"Stream trigger sent!")
    print(f"  Device: {response.get('device_id', 'unknown')}")
    print(f"  Target: {response.get('target', 'unknown')}")

    return 0


def cmd_debug(client, args):
    """Show detailed debug info (sessions + connections)"""
    response = client.send_command("list_all")

    if "error" in response:
        print(f"Error: {response['error']}")
        return 1

    print("\n=== SESSIONS ===")
    sessions = response.get("sessions", {})
    if sessions:
        for dev_id, status in sessions.items():
            print(f"  {dev_id}:")
            print(f"    camera_control: {status.get('camera_control')}")
            print(f"    camera_stream:  {status.get('camera_stream')}")
            print(f"    app_stream:     {status.get('app_stream')}")
    else:
        print("  (none)")

    print("\n=== CONNECTIONS ===")
    connections = response.get("connections", [])
    if connections:
        for conn in connections:
            print(f"  {conn.get('conn_id')}:")
            print(f"    device_id: {conn.get('device_id') or '(unidentified)'}")
            print(f"    role:      {conn.get('role') or '-'}")
            print(f"    uptime:    {conn.get('uptime_secs')}s")
    else:
        print("  (none)")

    return 0


def cmd_ptz(client, args):
    """Send PTZ command to a camera"""
    params = {}

    if args.target.count('.') == 3:
        params['ip'] = args.target
    else:
        params['device_id'] = args.target

    params['direction'] = args.direction
    if args.duration:
        params['duration'] = args.duration

    response = client.send_command("ptz", params)

    if "error" in response:
        print(f"Error: {response['error']}")
        return 1

    print(f"PTZ {args.direction}: {response.get('message', 'OK')}")
    return 0


def cmd_reboot(client, args):
    """Send reboot command to a camera"""
    params = {}

    if hasattr(args, 'target') and args.target:
        # Check if it looks like an IP or a device_id
        if args.target.count('.') == 3:  # Looks like IP
            params['ip'] = args.target
        else:
            params['device_id'] = args.target

    if not params:
        print("Error: Provide a device_id or IP address")
        return 1

    # Confirm before rebooting
    if not args.force:
        confirm = input(f"Reboot camera {args.target}? [y/N]: ")
        if confirm.lower() != 'y':
            print("Cancelled.")
            return 0

    response = client.send_command("reboot_camera", params)

    if "error" in response:
        print(f"Error: {response['error']}")
        return 1

    print(f"Reboot command sent!")
    print(f"  Device: {response.get('device_id', 'unknown')}")
    print(f"  Target: {response.get('target', 'unknown')}")
    print(f"  {response.get('message', '')}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Relay CLI - Manage the local relay server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  relay_cli.py list              # Show all connections
  relay_cli.py sessions          # Show identified device sessions
  relay_cli.py status            # Server status
  relay_cli.py query-all         # Query all unidentified connections
  relay_cli.py query 192.168.1.100:12345  # Query specific connection
        """
    )

    parser.add_argument(
        '--host', '-H',
        default=DEFAULT_CLI_HOST,
        help=f'Relay server host (default: {DEFAULT_CLI_HOST})'
    )

    parser.add_argument(
        '--port', '-p',
        type=int,
        default=DEFAULT_CLI_PORT,
        help=f'Relay server management port (default: {DEFAULT_CLI_PORT})'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # list command - shows all connections
    list_parser = subparsers.add_parser('list', help='List all connections (including unidentified)')

    # sessions command - shows only identified sessions
    sessions_parser = subparsers.add_parser('sessions', help='List identified device sessions')

    # status command
    status_parser = subparsers.add_parser('status', help='Show server status')

    # info command
    info_parser = subparsers.add_parser('info', help='Show device details')
    info_parser.add_argument('device_id', help='Device ID to query')

    # query command - query a specific connection
    query_parser = subparsers.add_parser('query', help='Query a connection for device info')
    query_parser.add_argument('conn_id', help='Connection ID (e.g., 192.168.1.100:12345)')

    # query-all command - query all unidentified connections
    query_all_parser = subparsers.add_parser('query-all', help='Query all unidentified connections')

    # set-device command - manually assign device_id to IP
    set_device_parser = subparsers.add_parser('set-device', help='Manually assign device_id to an IP')
    set_device_parser.add_argument('ip', help='IP address of the camera')
    set_device_parser.add_argument('device_id', help='Device ID to assign')

    # trigger command - send stream trigger to camera
    trigger_parser = subparsers.add_parser('trigger', help='Send stream trigger to a camera')
    trigger_parser.add_argument('target', help='Device ID or IP address of the camera')

    # debug command - show detailed info
    debug_parser = subparsers.add_parser('debug', help='Show detailed debug info')

    # reboot command - reboot a camera
    reboot_parser = subparsers.add_parser('reboot', help='Reboot a camera')
    reboot_parser.add_argument('target', help='Device ID or IP address of the camera')
    reboot_parser.add_argument('-f', '--force', action='store_true', help='Skip confirmation prompt')

    # ptz command - PTZ control
    ptz_parser = subparsers.add_parser('ptz', help='PTZ camera control')
    ptz_parser.add_argument('target', help='Device ID or IP address of the camera')
    ptz_parser.add_argument('direction', choices=['left', 'right', 'up', 'down', 'stop', 'zoomin', 'zoomout'],
                           help='PTZ direction')
    ptz_parser.add_argument('-t', '--duration', type=int, default=0,
                           help='Duration in ms, then auto-stop (0 = continuous until manual stop)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    client = RelayClient(args.host, args.port)

    commands = {
        'list': cmd_list,
        'sessions': cmd_sessions,
        'status': cmd_status,
        'info': cmd_info,
        'query': cmd_query,
        'query-all': cmd_query_all,
        'set-device': cmd_set_device,
        'trigger': cmd_trigger,
        'debug': cmd_debug,
        'reboot': cmd_reboot,
        'ptz': cmd_ptz,
    }

    return commands[args.command](client, args)


if __name__ == "__main__":
    sys.exit(main())
