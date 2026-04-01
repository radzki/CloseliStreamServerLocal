#!/usr/bin/env bash
#
# DNS Redirect entrypoint for Docker container
# Runs with network_mode: host so it can ARP spoof on the physical interface
#
set -euo pipefail

# ============================================================
# Configuration from environment
# ============================================================
CAMERA_IP="${CAMERA_IP:?CAMERA_IP must be set}"
LOCAL_IP="${LOCAL_IP:?LOCAL_IP must be set}"
IFACE="${IFACE:-eth0}"
GATEWAY_IP="${GATEWAY_IP:-$(ip route | grep default | awk '{print $3}')}"

DNSMASQ_CONF="/tmp/eoolii-dnsmasq.conf"
DNSMASQ_LOG="/tmp/eoolii-dnsmasq.log"

# Closeli domains to spoof
SPOOF_DOMAINS="closeli.com icloseli.com closeli.cn icloseli.cn"

# ============================================================
# Functions
# ============================================================
log()  { echo "[+] $1"; }
info() { echo "[*] $1"; }
err()  { echo "[-] $1"; }

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
info "Camera:   $CAMERA_IP"
info "Local IP: $LOCAL_IP ($IFACE)"
info "Gateway:  $GATEWAY_IP"
echo ""

# --- 1. Enable IP forwarding ---
sysctl -q net.ipv4.ip_forward=1 2>/dev/null || true
log "IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"

# --- 2. Write dnsmasq config ---
touch "$DNSMASQ_LOG"
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
log-facility=${DNSMASQ_LOG}
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

# --- 3. iptables rules ---
# FORWARD: allow camera traffic through
iptables -I FORWARD 1 -s "$CAMERA_IP" -j ACCEPT -m comment --comment "EOOLII_FWD"
iptables -I FORWARD 1 -d "$CAMERA_IP" -j ACCEPT -m comment --comment "EOOLII_FWD"
log "FORWARD rules added"

# DNAT: redirect camera's DNS to our dnsmasq
iptables -t nat -I PREROUTING 1 -s "$CAMERA_IP" -p udp --dport 53 \
    -j DNAT --to-destination "${LOCAL_IP}:53" \
    -m comment --comment "EOOLII_DNS"
iptables -t nat -I PREROUTING 1 -s "$CAMERA_IP" -p tcp --dport 53 \
    -j DNAT --to-destination "${LOCAL_IP}:53" \
    -m comment --comment "EOOLII_DNS"
log "iptables DNS redirect active"

# --- 4. ARP spoof (foreground, blocks until killed) ---
log "Starting ARP spoof: telling $CAMERA_IP that we ($LOCAL_IP) are $GATEWAY_IP"
info "DNS redirect active - monitoring..."
echo ""

# Run arpspoof in background, tail dnsmasq log in foreground
arpspoof -i "$IFACE" -t "$CAMERA_IP" "$GATEWAY_IP" > /dev/null 2>&1 &
ARPSPOOF_PID=$!

# Keep alive by tailing the DNS log - shows what the camera is querying
tail -f "$DNSMASQ_LOG" &
TAIL_PID=$!

# Wait for arpspoof to exit (or signal)
wait $ARPSPOOF_PID 2>/dev/null || true
