#!/usr/bin/env bash
#
# DNS Redirect entrypoint for Docker container
# Runs with network_mode: host so it can ARP spoof on the physical interface
#
# Supports multiple cameras via comma-separated CAMERA_IPS env var:
#   CAMERA_IPS=192.168.15.21,192.168.15.22,192.168.15.23
#
set -euo pipefail

# ============================================================
# Configuration from environment
# ============================================================
CAMERA_IPS="${CAMERA_IPS:-${CAMERA_IP:-}}"
if [ -z "$CAMERA_IPS" ]; then
    echo "[-] CAMERA_IPS (or CAMERA_IP) must be set"
    exit 1
fi
LOCAL_IP="${LOCAL_IP:?LOCAL_IP must be set}"
IFACE="${IFACE:-eth0}"
GATEWAY_IP="${GATEWAY_IP:-$(ip route | grep default | awk '{print $3}')}"

DNSMASQ_CONF="/tmp/eoolii-dnsmasq.conf"

# Closeli domains to spoof
SPOOF_DOMAINS="closeli.com icloseli.com closeli.cn icloseli.cn"

# Parse comma-separated IPs into array
IFS=',' read -ra CAMERAS <<< "$CAMERA_IPS"

# ============================================================
# Functions
# ============================================================
log()  { echo "[+] $1"; }
info() { echo "[*] $1"; }
err()  { echo "[-] $1"; }
warn() { echo "[!] $1"; }

cleanup() {
    log "Shutting down..."
    killall arpspoof 2>/dev/null || true
    killall dnsmasq 2>/dev/null || true

    # Remove iptables rules
    iptables -t nat -S PREROUTING 2>/dev/null | grep "EOOLII" | sed 's/^-A/-D/' | while read -r rule; do
        iptables -t nat $rule 2>/dev/null || true
    done
    iptables -S FORWARD 2>/dev/null | grep "EOOLII" | sed 's/^-A/-D/' | while read -r rule; do
        iptables $rule 2>/dev/null || true
    done

    log "Cleanup complete"
}
trap cleanup EXIT INT TERM

# ============================================================
# Main
# ============================================================
info "Cameras:  ${CAMERAS[*]} (${#CAMERAS[@]} total)"
info "Local IP: $LOCAL_IP ($IFACE)"
info "Gateway:  $GATEWAY_IP"
echo ""

# --- 1. Enable IP forwarding ---
sysctl -q net.ipv4.ip_forward=1 2>/dev/null || true
log "IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"

# --- 2. Write dnsmasq config ---
cat > "$DNSMASQ_CONF" <<EOF
port=53
listen-address=${LOCAL_IP}
bind-interfaces
no-dhcp-interface=${IFACE}
no-hosts
no-resolv
server=1.1.1.1
server=9.9.9.9
$(for domain in $SPOOF_DOMAINS; do echo "address=/${domain}/${LOCAL_IP}"; done)
log-queries
log-facility=-
EOF

# Kill anything on port 53 first
fuser -k 53/udp 2>/dev/null || true
fuser -k 53/tcp 2>/dev/null || true
sleep 0.5

dnsmasq --conf-file="$DNSMASQ_CONF" --keep-in-foreground &
DNSMASQ_PID=$!
sleep 1

# Verify dnsmasq is running
if kill -0 $DNSMASQ_PID 2>/dev/null; then
    log "dnsmasq started (pid $DNSMASQ_PID)"
else
    err "dnsmasq failed to start"
    exit 1
fi

# --- 3. iptables + arpspoof per camera ---
SPOOF_PIDS=()

for cam_ip in "${CAMERAS[@]}"; do
    # Trim whitespace
    cam_ip="$(echo "$cam_ip" | tr -d '[:space:]')"
    [ -z "$cam_ip" ] && continue

    info "Setting up camera: $cam_ip"

    # FORWARD rules
    iptables -I FORWARD 1 -s "$cam_ip" -j ACCEPT -m comment --comment "EOOLII_FWD"
    iptables -I FORWARD 1 -d "$cam_ip" -j ACCEPT -m comment --comment "EOOLII_FWD"

    # DNAT: redirect DNS to our dnsmasq
    iptables -t nat -I PREROUTING 1 -s "$cam_ip" -p udp --dport 53 \
        -j DNAT --to-destination "${LOCAL_IP}:53" \
        -m comment --comment "EOOLII_DNS"
    iptables -t nat -I PREROUTING 1 -s "$cam_ip" -p tcp --dport 53 \
        -j DNAT --to-destination "${LOCAL_IP}:53" \
        -m comment --comment "EOOLII_DNS"

    # ARP spoof this camera
    arpspoof -i "$IFACE" -t "$cam_ip" "$GATEWAY_IP" > /dev/null 2>&1 &
    SPOOF_PIDS+=($!)
    log "ARP spoof + iptables for $cam_ip"
done

echo ""
log "DNS redirect active for ${#CAMERAS[@]} camera(s)"
info "Logs visible via: docker compose logs -f dns-redirect"
echo ""

# Wait for any arpspoof to exit (or signal kills us)
wait "${SPOOF_PIDS[@]}" 2>/dev/null || true
