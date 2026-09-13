#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  SWARM Simple Test Setup — 1 Broker, 10 Clients                   ║
# ║  Mosquitto 2.x (Trixie/Bookworm) compatible                        ║
# ║  Run as: sudo bash setup_simple.sh                                 ║
# ╚══════════════════════════════════════════════════════════════════════╝
set -e
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

echo ""; echo "  SWARM Simple Test Environment Setup"; echo ""

# ── Dirs ──────────────────────────────────────────────────────────────
log "Creating directories..."
mkdir -p /etc/mosquitto /var/log/mosquitto /var/lib/mosquitto
chown mosquitto:mosquitto /var/log/mosquitto /var/lib/mosquitto

# ── Copy configs ──────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log "Installing config files..."
cp "$SCRIPT_DIR/mosquitto_simple.conf"  /etc/mosquitto/mosquitto.conf
cp "$SCRIPT_DIR/acl_simple.conf"        /etc/mosquitto/acl_simple.conf
chown mosquitto:mosquitto /etc/mosquitto/acl_simple.conf

# ── Create password file — 10 clients ────────────────────────────────
log "Creating password file..."
PF=/etc/mosquitto/passwd; rm -f $PF
add() { mosquitto_passwd -b $PF "$1" "$2"; }

# VULNERABLE — 8 clients with weak/default credentials
add admin_user  admin          # CRITICAL: default credential
add esp32_sensor esp32         # CRITICAL: default credential
add hvac_ctrl   password       # HIGH: dictionary word
add camera_01   camera_01      # HIGH: same as username
add plc_ctrl    12345          # HIGH: sequential digits
add energy_mgr  energy_mgr     # HIGH: same as username
add gateway     raspberry      # CRITICAL: Raspberry Pi default
add ota_server  ota_server     # HIGH: same as username

# SECURE — 2 clients with strong unique passwords
add monitor_svc "xK9#mP2\$vL8nQr"   # Strong random password
add audit_svc   "yR4@nQ7!wZ3kTs"    # Strong random password

chown mosquitto:mosquitto $PF
chmod 640 $PF
# VULNERABILITY: log dir world-readable (SWARM will flag)
chmod 644 /var/log/mosquitto
log "Password file: $(wc -l < $PF) users"

# ── Start broker ──────────────────────────────────────────────────────
log "Starting Mosquitto..."
systemctl restart mosquitto
sleep 2

if systemctl is-active --quiet mosquitto; then
    log "Mosquitto running"
else
    err "Mosquitto failed — checking logs:"
    journalctl -u mosquitto -n 10 --no-pager
    exit 1
fi

# ── Verify port ───────────────────────────────────────────────────────
if ss -tlnp | grep -q ":1883 "; then
    log "Port 1883 listening"
else
    err "Port 1883 not open"; exit 1
fi

# ── Quick connectivity tests ──────────────────────────────────────────
log "Testing connections..."
# Should succeed — valid cred
if mosquitto_pub -h localhost -p 1883 -u admin_user -P admin \
   -t "test/setup" -m "swarm_ok" 2>/dev/null; then
    log "  admin_user (default cred admin/admin): login OK"
fi
# Should fail — anon blocked
if ! mosquitto_pub -h localhost -p 1883 \
   -t "test/setup" -m "anon" 2>/dev/null; then
    log "  Anonymous access: BLOCKED (as expected for this broker)"
fi
# Should succeed — secure client
if mosquitto_pub -h localhost -p 1883 -u monitor_svc \
   -P "xK9#mP2\$vL8nQr" -t "test/setup" -m "ok" 2>/dev/null; then
    log "  monitor_svc (secure client): login OK"
fi

PI_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "  ══════════════════════════════════════════════════════════"
echo "  Test environment ready!  Pi IP: $PI_IP"
echo ""
echo "  Run SWARM from your Mac:"
echo "  python3 swarm.py audit \\"
echo "    --host $PI_IP \\"
echo "    --mqtt-user admin_user --mqtt-pass admin \\"
echo "    --ssh-user pi --ssh-pass <your-pi-password> \\"
echo "    --api-key sk-ant-..."
echo ""
echo "  Run simulator:"
echo "  python3 simulate_10_nodes.py --host $PI_IP"
echo "  ══════════════════════════════════════════════════════════"
echo ""
