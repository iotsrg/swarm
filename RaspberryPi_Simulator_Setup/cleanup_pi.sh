#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  SWARM — Clean Slate Script                                        ║
# ║  Removes ALL previous test setup from Raspberry Pi                 ║
# ║  Run as: sudo bash cleanup_pi.sh                                   ║
# ╚══════════════════════════════════════════════════════════════════════╝
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

echo ""; echo "  SWARM — Cleaning up Raspberry Pi..."; echo ""

# ── Stop all mosquitto processes ──────────────────────────────────────
warn "Stopping mosquitto..."
sudo systemctl stop mosquitto     2>/dev/null || true
sudo systemctl disable mosquitto  2>/dev/null || true
sudo pkill -f "mosquitto -c"      2>/dev/null || true
sleep 1; log "Mosquitto stopped"

# ── Remove all mosquitto config files ─────────────────────────────────
warn "Removing config files..."
sudo rm -f /etc/mosquitto/mosquitto.conf
sudo rm -f /etc/mosquitto/acl_primary.conf
sudo rm -f /etc/mosquitto/acl_secondary.conf
sudo rm -f /etc/mosquitto/acl_simple.conf
sudo rm -f /etc/mosquitto/acl.conf
sudo rm -f /etc/mosquitto/passwd
sudo rm -f /etc/mosquitto/broker1.conf
sudo rm -f /etc/mosquitto/broker2.conf
sudo rm -f /etc/mosquitto/broker3.conf
sudo rm -f /etc/mosquitto/start_brokers.sh
sudo rm -f /etc/mosquitto/conf.d/*.conf
log "Config files removed"

# ── Remove logs and persistence databases ─────────────────────────────
warn "Removing logs and persistence..."
sudo rm -f /var/log/mosquitto/*.log
sudo rm -f /var/lib/mosquitto/*.db
sudo rm -f /var/lib/mosquitto/mosquitto.db
log "Logs and DBs cleared"

# ── Remove test files from common locations ───────────────────────────
warn "Removing test scripts..."
for DIR in ~/Downloads ~/Desktop ~; do
    rm -f $DIR/simulate_30_nodes.py
    rm -f $DIR/simulate_10_nodes.py
    rm -f $DIR/setup_swarm_test.sh
    rm -f $DIR/setup_swarm_test_157.sh
    rm -f $DIR/setup_simple.sh
    rm -f $DIR/mosquitto_test.conf
    rm -f $DIR/mosquitto_simple.conf
    rm -f $DIR/acl_primary.conf
    rm -f $DIR/acl_secondary.conf
    rm -f $DIR/acl_simple.conf
    rm -f $DIR/cleanup_pi.sh
    rm -f $DIR/build_mosquitto2.sh
done
log "Test scripts removed"

# ── Reinstall fresh mosquitto (clean default config) ──────────────────
warn "Reinstalling mosquitto cleanly..."
sudo apt-get install --reinstall -y mosquitto mosquitto-clients -qq
log "Fresh mosquitto installed: $(mosquitto --version 2>&1 | head -1)"

echo ""
echo "  ══════════════════════════════════════════════════════════"
log "Pi is clean! Ready for fresh SWARM setup."
echo ""
echo "  Next step:"
echo "  sudo bash setup_simple.sh"
echo "  ══════════════════════════════════════════════════════════"
echo ""
