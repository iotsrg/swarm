#!/usr/bin/env python3
"""
SWARM — 10-Node IoT Simulator (paho-mqtt 1.x and 2.x compatible)

Simulates 8 vulnerable + 2 secure MQTT clients for SWARM auditor demo.

USAGE:
    python3 simulate_10_nodes.py --host 192.168.1.100
    python3 simulate_10_nodes.py --host 192.168.1.100 --verbose
"""

import json, random, signal, sys, threading, time, argparse
from datetime import datetime
import paho.mqtt.client as mqtt

# ── paho-mqtt version compatibility ───────────────────────────────────
_PAHO_V2 = tuple(int(x) for x in mqtt.__version__.split(".")[:2]) >= (2, 0)

def _make_client(client_id):
    """Create paho client compatible with both v1.x and v2.x."""
    if _PAHO_V2:
        return mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
            client_id=client_id, clean_session=True)
    return mqtt.Client(client_id=client_id, clean_session=True)

# ── ANSI ──────────────────────────────────────────────────────────────
G="\033[92m"; Y="\033[93m"; R="\033[91m"; C="\033[96m"
DIM="\033[2m"; B="\033[1m"; RS="\033[0m"

running = True
stats = {"connected": 0, "published": 0, "errors": 0}
lock   = threading.Lock()

def ts(): return datetime.now().strftime("%H:%M:%S")
def log(name, msg, c=G): print(f"  {DIM}[{ts()}]{RS} {c}{name:<18}{RS} {msg}")

# ── 10-node definitions ───────────────────────────────────────────────
NODES = [
    # ── VULNERABLE CLIENTS (8) ────────────────────────────────────────
    {
        "id":       "admin_user",
        "user":     "admin_user",
        "password": "admin",                    # DEFAULT CREDENTIAL
        "color":    R,
        "label":    "VULNERABLE — default cred admin/admin",
        "publishes": ["admin/cmd", "sensors/admin/status"],
        "subscribes": ["#"],                    # wildcard — sees everything
        "retained_topics": ["admin/cmd"],
        "interval": 8,
    },
    {
        "id":       "esp32_sensor",
        "user":     "esp32_sensor",
        "password": "esp32",                    # DEFAULT CREDENTIAL
        "color":    R,
        "label":    "VULNERABLE — writes to admin/cmd",
        "publishes": ["sensors/esp32/data",
                      "admin/cmd",              # ACL ABUSE: device writes admin
                      "control/esp32/commands"],
        "subscribes": [],
        "retained_topics": ["sensors/esp32/data"],
        "interval": 3,
    },
    {
        "id":       "hvac_ctrl",
        "user":     "hvac_ctrl",
        "password": "password",                 # WEAK: dictionary word
        "color":    Y,
        "label":    "VULNERABLE — over-reads all sensors",
        "publishes": ["control/hvac/setpoint", "control/hvac/mode"],
        "subscribes": ["sensors/#",             # ACL ABUSE: reads all sensors
                       "control/hvac/#"],
        "retained_topics": ["control/hvac/setpoint"],
        "interval": 5,
    },
    {
        "id":       "camera_01",
        "user":     "camera_01",
        "password": "camera_01",                # WEAK: same as username
        "color":    Y,
        "label":    "VULNERABLE — wildcard read (eavesdropping)",
        "publishes": ["camera/01/events", "camera/01/motion"],
        "subscribes": ["#"],                    # ACL ABUSE: reads ALL topics
        "retained_topics": [],
        "interval": 4,
    },
    {
        "id":       "plc_ctrl",
        "user":     "plc_ctrl",
        "password": "12345",                    # WEAK: sequential digits
        "color":    R,
        "label":    "VULNERABLE — writes to all control + admin/cmd",
        "publishes": ["plc/line_01/status",
                      "control/actuators/valve_01",  # ACL ABUSE
                      "control/actuators/pump_02",   # ACL ABUSE
                      "admin/cmd"],                  # ACL ABUSE: PLC writes admin
        "subscribes": ["plc/#"],
        "retained_topics": ["control/actuators/valve_01"],
        "interval": 6,
    },
    {
        "id":       "energy_mgr",
        "user":     "energy_mgr",
        "password": "energy_mgr",               # WEAK: same as username
        "color":    Y,
        "label":    "VULNERABLE — reads $SYS broker internals",
        "publishes": ["energy/meter/reading",
                      "admin/cmd"],             # ACL ABUSE
        "subscribes": ["$SYS/#",               # ACL ABUSE: broker internals
                       "energy/meter/#"],
        "retained_topics": ["energy/meter/reading"],
        "interval": 5,
    },
    {
        "id":       "gateway",
        "user":     "gateway",
        "password": "raspberry",                # DEFAULT: Pi default password
        "color":    R,
        "label":    "VULNERABLE — full wildcard, owns everything",
        "publishes": ["gateway/status",
                      "sensors/gateway/forward",
                      "admin/cmd"],
        "subscribes": ["#"],                    # Full wildcard both ways
        "retained_topics": ["gateway/status"],
        "interval": 7,
    },
    {
        "id":       "ota_server",
        "user":     "ota_server",
        "password": "ota_server",               # WEAK: same as username
        "color":    R,
        "label":    "VULNERABLE — reads all, pushes firmware everywhere",
        "publishes": ["admin/ota/esp32_sensor/update",
                      "admin/ota/hvac_ctrl/update",
                      "admin/cmd"],             # ACL ABUSE: OTA pushes to all
        "subscribes": ["#"],                    # Reads all traffic
        "retained_topics": ["admin/ota/esp32_sensor/update"],
        "interval": 15,
    },

    # ── SECURE CLIENTS (2) ────────────────────────────────────────────
    {
        "id":       "monitor_svc",
        "user":     "monitor_svc",
        "password": "xK9#mP2$vL8nQr",          # STRONG: random password
        "color":    G,
        "label":    "SECURE — read-only, specific topics",
        "publishes": [],                         # Never publishes — read only
        "subscribes": ["sensors/#",
                       "energy/meter/#"],        # Only what it needs
        "retained_topics": [],
        "interval": 0,                           # No publishing
    },
    {
        "id":       "audit_svc",
        "user":     "audit_svc",
        "password": "yR4@nQ7!wZ3kTs",           # STRONG: random password
        "color":    G,
        "label":    "SECURE — specific read + specific write",
        "publishes": ["audit/reports/daily"],    # Only its own namespace
        "subscribes": ["logs/#"],                # Only reads logs
        "retained_topics": [],
        "interval": 20,
    },
]

# ── Payload generators ─────────────────────────────────────────────────

def make_payload(node_id, topic):
    ts_ = datetime.now().isoformat()
    if "sensors" in topic:
        return json.dumps({"id":node_id,"ts":ts_,
                           "temp":round(random.uniform(18,35),2),
                           "humidity":round(random.uniform(30,80),2)})
    if "admin/cmd" in topic:
        return json.dumps({"src":node_id,"ts":ts_,
                           "cmd":random.choice(["status","reset","update","exec"]),
                           "target":"all"})
    if "admin/ota" in topic:
        return json.dumps({"src":node_id,"ts":ts_,
                           "version":"v2.1.0",
                           "url":"http://ota.local/firmware.bin",
                           "target":"all_devices"})
    if "control" in topic:
        return json.dumps({"src":node_id,"ts":ts_,
                           "value":round(random.uniform(0,100),1),
                           "mode":random.choice(["auto","manual","override"])})
    if "energy" in topic:
        return json.dumps({"id":node_id,"ts":ts_,
                           "kwh":round(random.uniform(0,500),2),
                           "voltage":round(random.uniform(218,242),1)})
    if "camera" in topic:
        return json.dumps({"id":node_id,"ts":ts_,
                           "motion":random.choice([True,False]),
                           "confidence":round(random.uniform(0.5,0.99),2)})
    if "plc" in topic or "actuator" in topic:
        return json.dumps({"id":node_id,"ts":ts_,
                           "rpm":random.randint(800,3600),
                           "status":random.choice(["running","idle","fault"])})
    if "audit" in topic:
        return json.dumps({"id":node_id,"ts":ts_,
                           "events":random.randint(10,500),
                           "anomalies":random.randint(0,5)})
    return json.dumps({"id":node_id,"ts":ts_,"status":"active"})

# ── Node thread ─────────────────────────────────────────────────────────

def node_thread(node, host, port, verbose):
    nid      = node["id"]
    color    = node["color"]
    interval = node["interval"]

    client = _make_client(f"swarm_{nid}")
    client.username_pw_set(node["user"], node["password"])

    connected = threading.Event()

    def on_connect(c, ud, flags, rc):
        if rc == 0:
            connected.set()
            with lock: stats["connected"] += 1
            # Subscribe to declared topics
            for topic in node["subscribes"]:
                c.subscribe(topic, qos=0)
                if verbose:
                    log(nid, f"SUB → {topic}", C)
        else:
            with lock: stats["errors"] += 1
            log(nid, f"connect failed rc={rc} "
                     f"({node['user']}/{node['password']})", R)

    def on_message(c, ud, msg):
        pass   # Receive silently

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(host, port, keepalive=60)
        client.loop_start()
        if not connected.wait(timeout=8):
            with lock: stats["errors"] += 1
            log(nid, "connect timed out", R)
            client.loop_stop()
            return

        log(nid, f"connected  [{node['label']}]", color)

        cycle = 0
        while running:
            if interval > 0 and node["publishes"]:
                topic = random.choice(node["publishes"])
                payload = make_payload(nid, topic)
                retain  = topic in node["retained_topics"]
                info    = client.publish(topic, payload, qos=0, retain=retain)
                if info.rc == 0:
                    with lock: stats["published"] += 1
                    if verbose:
                        retain_flag = " [RETAIN]" if retain else ""
                        log(nid, f"PUB → {topic}{retain_flag}", color)
                time.sleep(interval + random.uniform(-1, 1))
            else:
                time.sleep(5)
            cycle += 1

    except Exception as e:
        with lock: stats["errors"] += 1
        log(nid, f"error: {e}", R)
    finally:
        try: client.loop_stop(); client.disconnect()
        except: pass

# ── Main ─────────────────────────────────────────────────────────────────

def print_banner():
    print(f"""
{C}╔══════════════════════════════════════════════════════════════════════╗
║  SWARM — 10-Node IoT Simulator                                     ║
║  8 vulnerable clients  +  2 secure clients                         ║
╚══════════════════════════════════════════════════════════════════════╝{RS}""")

def main():
    global running
    parser = argparse.ArgumentParser(description="SWARM 10-Node Simulator")
    parser.add_argument("--host",    default="localhost")
    parser.add_argument("--port",    type=int, default=1883)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    print_banner()
    print(f"  paho-mqtt {mqtt.__version__}  |  {'v2 API' if _PAHO_V2 else 'v1 API'}")
    print(f"  Broker: {C}{args.host}:{args.port}{RS}")
    print(f"  {R}Vulnerable clients: 8{RS}  |  {G}Secure clients: 2{RS}")
    print(f"\n  Starting nodes...  {DIM}Ctrl+C to stop{RS}\n")

    threads = []
    for node in NODES:
        t = threading.Thread(target=node_thread,
                             args=(node, args.host, args.port, args.verbose),
                             daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.2)

    def stop(sig, frame):
        global running
        print(f"\n\n  {Y}Stopping...{RS}")
        running = False
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)

    while True:
        time.sleep(10)
        with lock:
            vuln_conn  = sum(1 for n in NODES[:8]
                             if stats["connected"] > 0)  # rough estimate
            color_conn = G if stats["errors"] == 0 else Y
            print(f"  {DIM}[stats]{RS}  "
                  f"connected:{color_conn}{stats['connected']}{RS}  "
                  f"published:{G}{stats['published']}{RS}  "
                  f"errors:{R if stats['errors'] else G}{stats['errors']}{RS}")

if __name__ == "__main__":
    main()
