#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ SWARM - Security Weakness Analyser for MQTT Reconnaissance and Mapping v1.11 ║
║      Black Hat Arsenal India  |  For authorised security testing only        ║
╚══════════════════════════════════════════════════════════════════════════════╝

MODES:
  manual      Open MQTT manual testing guide
  audit       Full AI-powered security audit  (Sonnet analysis + Haiku judge)
  fume        Fuzz broker with FUME fuzzer
  smartfuzz   AI-powered targeted fuzzing strategy  (context-aware)
  chat        Expert AI chatbot  (MQTT security assistant)
  diagram     Generate security topology  (DOT / PNG / SVG)

QUICK START:
  python3 swarm.py                       # interactive menu
  python3 swarm.py audit  --host 192.168.1.100 --mqtt-user admin --mqtt-pass secret \\
                           --ssh-user pi --ssh-pass raspberry --api-key sk-ant-...
  python3 swarm.py chat   --host 192.168.1.100 --ssh-user pi --ssh-pass raspberry \\
                           --api-key sk-ant-...
  python3 swarm.py smartfuzz --api-key sk-ant-...
  python3 swarm.py fume   --host 192.168.1.100
  python3 swarm.py diagram --host 192.168.1.100 --api-key sk-ant-...
  python3 swarm.py manual

INSTALL:
  pip install paho-mqtt reportlab anthropic paramiko
"""

# ── Imports ───────────────────────────────────────────────────────────────────
import argparse, json, os, queue, random, re, socket, ssl, string
import subprocess, sys, threading, time, textwrap
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

try:    import paho.mqtt.client as mqtt;   PAHO_OK = True
except ImportError:                         PAHO_OK = False; mqtt = None

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, HRFlowable,
                                     PageBreak, KeepTogether)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_OK = True
except ImportError: REPORTLAB_OK = False

try:    import paramiko;                   PARAMIKO_OK = True
except ImportError:                         PARAMIKO_OK = False

try:    import anthropic as _anthropic_sdk; ANTHROPIC_SDK_OK = True
except ImportError:                         ANTHROPIC_SDK_OK = False

# ── Constants ─────────────────────────────────────────────────────────────────
TOOL_NAME    = "SWARM"
TOOL_VER     = "1.0"
TOOL_DESC    = "Security Weakness Analyser for MQTT Reconnaissance and Mapping"
MQTT_UST_URL = "https://github.com/iotsrg/mqtt-ust"
FUME_URL     = "https://github.com/PBearson/FUME-Fuzzing-MQTT-Brokers"
SONNET_MODEL = "claude-sonnet-4-6"
HAIKU_MODEL  = "claude-haiku-4-5-20251001"

R="\033[91m"; O="\033[93m"; Y="\033[33m"; G="\033[92m"
C="\033[96m"; M="\033[95m"; DIM="\033[2m"; B="\033[1m"; RS="\033[0m"

SEV_ORDER  = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4,"PASS":5}
SEV_WEIGHT = {"CRITICAL":30,"HIGH":15,"MEDIUM":7,"LOW":3,"INFO":0,"PASS":0}
SEV_COL    = {"CRITICAL":R,"HIGH":O,"MEDIUM":Y,"LOW":C,"INFO":DIM,"PASS":G}
RC_MSG     = {0:"Accepted",1:"Bad protocol",2:"ID rejected",
              3:"Server unavailable",4:"Bad credentials",5:"Not authorised"}

# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class RawProbeResult:
    host: str; port: int; timestamp: str = ""
    tcp_open: bool = False
    port_1883_open: bool = False;  port_8883_open: bool = False
    anonymous_accepted: bool = False; anonymous_rc: int = -1
    cred_accepted: bool = False;      cred_rc: int = -1
    default_creds_found: list = field(default_factory=list)
    tls_port_open: bool = False;  tls_handshake_ok: bool = False
    tls_cipher: str = "";         tls_version: str = "";  tls_error: str = ""
    wildcard_messages: list = field(default_factory=list)
    sys_topics_seen:   list = field(default_factory=list)
    retained_persists: bool = False; retained_test_topic: str = ""
    flood_count: int = 0; flood_elapsed: float = 0.0; flood_rate: float = 0.0
    large_payload_accepted: bool = False; large_payload_size_kb: int = 0
    client_id_collision_kick: bool = False
    config_content: str = ""; acl_content: str = ""; log_content: str = ""
    errors:     dict = field(default_factory=dict)
    ssh_notes:  list = field(default_factory=list)

# ═══════════════════════════════════════════════════════════════════════════════
# MQTT LIVE PROBE HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _rand_id(n=8):
    return "swarm_" + "".join(random.choices(string.ascii_lowercase+string.digits, k=n))

def _tcp_probe(host, port, timeout=3):
    try:
        s = socket.create_connection((host, port), timeout=timeout); s.close(); return True
    except Exception: return False

def _connect(host, port, username=None, password=None, tls=False,
             client_id=None, timeout=6, on_disconnect=None):
    if not PAHO_OK: return False, None, "paho-mqtt not installed"
    cid = client_id or _rand_id()
    c   = mqtt.Client(client_id=cid, clean_session=True, protocol=mqtt.MQTTv311)
    if username:      c.username_pw_set(username, password)
    if on_disconnect: c.on_disconnect = on_disconnect
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        c.tls_set_context(ctx)
    ev = threading.Event(); result = {"rc": None}
    def _oc(cl, ud, fl, rc): result["rc"] = rc; ev.set()
    c.on_connect = _oc
    try:
        c.connect(host, port, keepalive=10)
        c.loop_start(); ev.wait(timeout=timeout); c.loop_stop()
    except Exception as e: return False, c, str(e)
    rc = result["rc"]
    return rc == 0, c, rc

def probe_ports(data):
    print(f"  {C}[→]{RS} Probing ports...")
    data.port_1883_open = _tcp_probe(data.host, 1883)
    data.port_8883_open = _tcp_probe(data.host, 8883)
    data.tcp_open       = _tcp_probe(data.host, data.port)
    print(f"     1883:{G if data.port_1883_open else R}{'open' if data.port_1883_open else 'closed'}{RS}  "
          f"8883:{G if data.port_8883_open else Y}{'open' if data.port_8883_open else 'closed'}{RS}  "
          f"Target {data.port}:{G if data.tcp_open else R}{'open' if data.tcp_open else 'closed'}{RS}")

def probe_anonymous(data, tls):
    print(f"  {C}[→]{RS} Testing anonymous access...")
    ok, c, rc = _connect(data.host, data.port, tls=tls)
    data.anonymous_accepted = ok
    data.anonymous_rc = rc if isinstance(rc, int) else -1
    if c:
        try: c.disconnect()
        except: pass
    status = f"{R}ACCEPTED — CRITICAL!{RS}" if ok else f"{G}Rejected (rc={rc}){RS}"
    print(f"     {status}")

def probe_credentials(data, username, password, tls):
    if not username: return
    print(f"  {C}[→]{RS} Testing credentials ({username})...")
    ok, c, rc = _connect(data.host, data.port, username=username, password=password, tls=tls)
    data.cred_accepted = ok; data.cred_rc = rc if isinstance(rc, int) else -1
    if c:
        try: c.disconnect()
        except: pass
    print(f"     {G+'Accepted'+RS if ok else f'Rejected (rc={rc})'}")

def probe_default_creds(data, tls):
    DEFAULTS = [("admin","admin"),("admin","password"),("admin","1234"),("admin",""),
                ("mqtt","mqtt"),("mqtt","password"),("guest","guest"),("user","user"),
                ("test","test"),("pi","raspberry"),("root","root"),("root",""),
                ("esp32","esp32"),("espuser","espuser"),("device","device")]
    print(f"  {C}[→]{RS} Testing {len(DEFAULTS)} default credential pairs...")
    found = []
    for u, p in DEFAULTS:
        ok, c, rc = _connect(data.host, data.port, username=u, password=p, tls=tls, timeout=3)
        if c:
            try: c.disconnect()
            except: pass
        if ok: found.append(f"{u} / {'(empty)' if not p else p}"); time.sleep(0.05)
    data.default_creds_found = found
    print(f"     {R+str(len(found))+' pair(s) found: '+', '.join(found[:3])+RS if found else G+'None found'+RS}")

def probe_tls(data):
    print(f"  {C}[→]{RS} Probing TLS (port 8883)...")
    data.tls_port_open = data.port_8883_open
    if not data.tls_port_open: print(f"     {Y}Port 8883 closed{RS}"); return
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((data.host, 8883), timeout=4) as raw:
            with ctx.wrap_socket(raw) as ts:
                cipher = ts.cipher()
                data.tls_handshake_ok = True
                data.tls_cipher  = cipher[0] if cipher else ""
                data.tls_version = cipher[1] if cipher else ""
        print(f"     {G}TLS OK{RS} — {data.tls_cipher} / {data.tls_version}")
    except Exception as e:
        data.tls_error = str(e); print(f"     {Y}Handshake failed: {e}{RS}")

def probe_wildcard(data, username, password, tls):
    print(f"  {C}[→]{RS} Testing wildcard subscription (#, $SYS/#)...")
    msgs = []; sys_msgs = []; q = queue.Queue()
    def on_msg(c, ud, msg):
        q.put((msg.topic, msg.payload.decode(errors="replace")[:120]))
        if msg.topic.startswith("$SYS"): sys_msgs.append(msg.topic)
    ok, c, rc = _connect(data.host, data.port, username=username, password=password, tls=tls)
    if not ok or c is None: data.errors["wildcard"] = f"rc={rc}"; return
    c.on_message = on_msg; c.loop_start()
    c.subscribe([("#", 0), ("$SYS/#", 0)]); time.sleep(3)
    c.loop_stop()
    try: c.disconnect()
    except: pass
    while not q.empty():
        t, p = q.get_nowait()
        if t.startswith("$SYS"):
            if t not in sys_msgs: sys_msgs.append(t)
        else: msgs.append((t, p))
    data.wildcard_messages = msgs[:15]; data.sys_topics_seen = sys_msgs[:10]
    print(f"     # messages:{R if msgs else G}{len(msgs)}{RS}  "
          f"$SYS topics:{Y if sys_msgs else G}{len(sys_msgs)}{RS}")

def probe_retained(data, username, password, tls):
    print(f"  {C}[→]{RS} Testing retained message persistence...")
    topic = f"swarm/ret/{_rand_id(4)}"; data.retained_test_topic = topic
    ok, pub, rc = _connect(data.host, data.port, username=username, password=password, tls=tls)
    if not ok or pub is None: data.errors["retained"] = f"rc={rc}"; return
    pub.loop_start(); pub.publish(topic, "SWARM_RETAINED_PROBE", qos=0, retain=True)
    time.sleep(0.8); pub.loop_stop()
    try: pub.disconnect()
    except: pass
    time.sleep(0.4); received = threading.Event()
    def on_msg(c, ud, msg):
        if msg.retain: received.set()
    ok2, sub, rc2 = _connect(data.host, data.port, username=username, password=password, tls=tls)
    if not ok2 or sub is None: data.errors["retained_sub"] = f"rc={rc2}"; return
    sub.on_message = on_msg; sub.loop_start()
    sub.subscribe(topic, qos=0); received.wait(timeout=3)
    sub.publish(topic, "", qos=0, retain=True); time.sleep(0.3)
    sub.loop_stop()
    try: sub.disconnect()
    except: pass
    data.retained_persists = received.is_set()
    print(f"     Persists: {R+'YES — vulnerable'+RS if data.retained_persists else G+'No'+RS}")

def probe_flood(data, username, password, tls):
    print(f"  {C}[→]{RS} Testing rate limiting (200-msg burst)...")
    topic = f"swarm/flood/{_rand_id(4)}"
    ok, c, rc = _connect(data.host, data.port, username=username, password=password, tls=tls)
    if not ok or c is None: data.errors["flood"] = f"rc={rc}"; return
    c.loop_start(); start = time.time(); sent = 0
    for i in range(200):
        info = c.publish(topic, f"x{i}", qos=0)
        if info.rc == 0: sent += 1
    elapsed = time.time() - start
    c.loop_stop()
    try: c.disconnect()
    except: pass
    data.flood_count = sent; data.flood_elapsed = round(elapsed, 3)
    data.flood_rate  = round(sent/elapsed, 1) if elapsed > 0 else 0
    print(f"     {sent} msgs in {elapsed:.2f}s = {O if data.flood_rate>100 else G}{data.flood_rate} msg/s{RS}")

def probe_large_payload(data, username, password, tls):
    SIZE_KB = 512
    print(f"  {C}[→]{RS} Testing oversized payload ({SIZE_KB} KB)...")
    topic = f"swarm/payload/{_rand_id(4)}"
    ok, c, rc = _connect(data.host, data.port, username=username, password=password, tls=tls)
    if not ok or c is None: data.errors["payload"] = f"rc={rc}"; return
    c.loop_start(); c.publish(topic, b"X" * SIZE_KB * 1024, qos=0)
    time.sleep(1.5); still_on = c.is_connected()
    c.loop_stop()
    try: c.disconnect()
    except: pass
    data.large_payload_accepted = still_on; data.large_payload_size_kb = SIZE_KB
    print(f"     {SIZE_KB}KB accepted: {O+'YES — no limit set'+RS if still_on else G+'Rejected (limit enforced)'+RS}")

def probe_client_id_collision(data, username, password, tls):
    print(f"  {C}[→]{RS} Testing client ID collision...")
    if not PAHO_OK: return
    shared_id = "swarm_collision_probe"; kicked = threading.Event()
    c1 = mqtt.Client(client_id=shared_id, clean_session=True)
    if username: c1.username_pw_set(username, password)
    c1.on_disconnect = lambda cl, ud, rc: kicked.set()
    try:
        c1.connect(data.host, data.port, keepalive=10); c1.loop_start(); time.sleep(0.6)
    except Exception as e: data.errors["collision"] = str(e); return
    ok2, c2, rc2 = _connect(data.host, data.port, username=username, password=password,
                             tls=tls, client_id=shared_id)
    time.sleep(1.2); result = kicked.is_set()
    c1.loop_stop()
    try: c1.disconnect()
    except: pass
    if c2:
        try: c2.disconnect()
        except: pass
    data.client_id_collision_kick = result
    print(f"     First client kicked: {O+'YES — session hijack risk'+RS if result else G+'No'+RS}")

def run_all_probes(data, username, password, tls):
    probe_ports(data)
    if not data.tcp_open:
        print(f"\n  {R}[✗] Cannot reach {data.host}:{data.port}{RS}\n"); return False
    probe_anonymous(data, tls)
    probe_credentials(data, username, password, tls)
    probe_default_creds(data, tls)
    probe_tls(data)
    probe_wildcard(data, username, password, tls)
    probe_retained(data, username, password, tls)
    probe_flood(data, username, password, tls)
    probe_large_payload(data, username, password, tls)
    probe_client_id_collision(data, username, password, tls)
    return True

# ═══════════════════════════════════════════════════════════════════════════════
# SSH AUTO-FETCH
# ═══════════════════════════════════════════════════════════════════════════════

def ssh_fetch_files(data, ssh_host, ssh_port, ssh_user, ssh_pass=None, ssh_key=None):
    if not PARAMIKO_OK:
        print(f"  {Y}[!]{RS} paramiko not installed (pip install paramiko) — skipping SSH")
        data.errors["ssh"] = "paramiko not installed"; return
    print(f"  {C}[→]{RS} SSH → {ssh_user}@{ssh_host}:{ssh_port}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kw = dict(hostname=ssh_host, port=ssh_port, username=ssh_user,
                  timeout=10, allow_agent=False, look_for_keys=False)
        if ssh_key:   kw.update(key_filename=os.path.expanduser(ssh_key), look_for_keys=True)
        elif ssh_pass: kw["password"] = ssh_pass
        else:          kw.update(look_for_keys=True, allow_agent=True)
        client.connect(**kw)
        print(f"  {G}[✓]{RS} SSH connected")
    except Exception as e:
        data.errors["ssh"] = str(e)
        print(f"  {R}[✗]{RS} SSH failed: {e}"); return

    def run(cmd, sudo=False):
        if sudo and ssh_pass: cmd = f"echo {ssh_pass!r} | sudo -S sh -c {cmd!r}"
        elif sudo:             cmd = f"sudo {cmd}"
        try:
            _, out, _ = client.exec_command(cmd, timeout=10)
            return out.read().decode(errors="replace").strip()
        except: return ""

    def read_file(path, sudo=False):
        try:
            sftp = client.open_sftp()
            with sftp.open(path) as f: content = f.read(80_000).decode(errors="replace")
            sftp.close(); return content
        except: return run(f"cat {path}", sudo=sudo)

    # ── mosquitto.conf ────────────────────────────────────────────────
    CONF_PATHS = ["/etc/mosquitto/mosquitto.conf",
                  "/etc/mosquitto/conf.d/default.conf",
                  "/usr/local/etc/mosquitto/mosquitto.conf"]
    conf_path = None
    for p in CONF_PATHS:
        c = read_file(p, sudo=True)
        if c: conf_path = p; data.config_content = c; break
    if not conf_path:
        found = run("find /etc /usr/local/etc -name 'mosquitto.conf' 2>/dev/null", sudo=True)
        if found:
            p = found.splitlines()[0].strip(); c = read_file(p, sudo=True)
            if c: conf_path = p; data.config_content = c
    if conf_path: print(f"  {G}[✓]{RS} mosquitto.conf → {conf_path} ({len(data.config_content)} chars)")
    else:         print(f"  {Y}[!]{RS} mosquitto.conf not found")

    # ── Parse conf for ALL ACL/passwd/log paths + include_dir ────────
    # Collect EVERY acl_file directive across ALL listeners (not just the first)
    all_acl_paths = []   # preserve order, deduplicate
    passwd_path = log_file_path = None
    conf_full = data.config_content
    for line in conf_full.splitlines():
        line = line.strip()
        if line.startswith("#") or not line: continue
        parts = line.split(None, 1)
        if len(parts) < 2: continue
        k, v = parts[0].lower(), parts[1].strip()
        if k == "include_dir":
            extra = run(f"cat {v}/*.conf 2>/dev/null", sudo=True)
            if extra: conf_full += "\n"+extra; data.config_content += f"\n# --- {v} ---\n{extra}"
        if k == "acl_file" and v not in all_acl_paths:
            all_acl_paths.append(v)
        if k == "password_file" and not passwd_path: passwd_path = v
        if k == "log_dest" and "file" in v:
            parts2 = v.split(None, 1)
            if len(parts2) > 1: log_file_path = parts2[1].strip()

    # ── Fetch ALL ACL files (one per listener) ────────────────────────
    if all_acl_paths:
        combined_acl = ""
        for acl_path in all_acl_paths:
            c = read_file(acl_path, sudo=True)
            if c:
                combined_acl += f"\n\n# {'='*60}\n# ACL FILE: {acl_path}\n# {'='*60}\n{c}"
                print(f"  {G}[✓]{RS} ACL → {acl_path} ({len(c)} chars)")
            else:
                print(f"  {Y}[!]{RS} ACL listed but unreadable: {acl_path}")
        if combined_acl:
            data.acl_content = combined_acl.strip()
            print(f"  {G}[✓]{RS} Total: {len(all_acl_paths)} ACL file(s) fetched, "
                  f"{len(data.acl_content)} chars combined")
    else:
        # Fallback: scan common locations
        for p in ["/etc/mosquitto/acl", "/etc/mosquitto/aclfile",
                  "/etc/mosquitto/acl_primary.conf", "/etc/mosquitto/acl_secondary.conf"]:
            c = read_file(p, sudo=True)
            if c:
                data.acl_content += f"\n\n# ACL FILE: {p}\n{c}"
                print(f"  {G}[✓]{RS} ACL → {p} (scan, {len(c)} chars)")
        if not data.acl_content:
            data.ssh_notes.append("No acl_file in config — all authenticated users access all topics")
            print(f"  {Y}[!]{RS} No ACL file found — unrestricted topic access likely")

    # ── Password file (user list only) ────────────────────────────────
    if passwd_path:
        c = read_file(passwd_path, sudo=True)
        if c:
            users = [l.split(":")[0] for l in c.splitlines() if l.strip() and not l.startswith("#")]
            data.config_content += (f"\n\n# --- passwd ({passwd_path}): {len(users)} user(s) ---\n"
                                    + "\n".join(f"# user: {u}" for u in users[:20]))
            print(f"  {G}[✓]{RS} Password file → {passwd_path} ({len(users)} user(s))")

    # ── Logs ──────────────────────────────────────────────────────────
    for p in filter(None, [log_file_path,
                            "/var/log/mosquitto/mosquitto.log",
                            "/var/log/mosquitto.log"]):
        c = run(f"tail -n 500 {p} 2>/dev/null", sudo=True)
        if c: data.log_content = c; print(f"  {G}[✓]{RS} Logs → {p} (500 lines)"); break
    if not data.log_content:
        c = run("journalctl -u mosquitto --no-pager -n 300 2>/dev/null", sudo=True)
        if c: data.log_content = c; print(f"  {G}[✓]{RS} Logs → journalctl (300 lines)")
        else: print(f"  {Y}[!]{RS} No logs found")

    # ── Extra: version / service / listeners / world-readable ────────
    # SSH non-interactive sessions have a stripped PATH — try full paths
    ver = (run("/usr/sbin/mosquitto --version 2>&1 | head -2") or
           run("/usr/bin/mosquitto --version 2>&1 | head -2")  or
           run("mosquitto --version 2>&1 | head -2")           or
           run("dpkg -l mosquitto 2>/dev/null | grep ^ii | awk '{print $2,$3}'"))
    svc = run("systemctl is-active mosquitto 2>/dev/null || service mosquitto status 2>/dev/null | head -3")
    # Active listeners — shows all 3 ports if running
    listeners = run("ss -tlnp 2>/dev/null | grep -E '1883|1884|1885' || "
                    "netstat -tlnp 2>/dev/null | grep -E '1883|1884|1885'")
    wr  = run("find /etc/mosquitto -type f -perm /o+r 2>/dev/null | head -5", sudo=True)
    # Number of MQTT users
    user_count = run(f"wc -l < {passwd_path} 2>/dev/null" if passwd_path else "echo 0")

    if ver:        data.config_content += f"\n\n# Mosquitto version: {ver.splitlines()[0]}"
    if svc:        data.config_content += f"\n# Service status: {svc.splitlines()[0]}"
    if listeners:  data.config_content += f"\n# Active listeners:\n" + \
                                           "\n".join(f"#   {l}" for l in listeners.splitlines())
    if wr:         data.config_content += f"\n# World-readable files: {wr.replace(chr(10), ', ')}"
    if user_count: data.config_content += f"\n# Password file entries: {user_count.strip()}"

    if ver:       print(f"  {G}[✓]{RS} Version: {ver.splitlines()[0]}")
    if svc:       print(f"  {G}[✓]{RS} Service: {svc.splitlines()[0]}")
    if listeners: print(f"  {G}[✓]{RS} Listeners: {', '.join(l.split()[-1] for l in listeners.splitlines() if l.strip())}")

    client.close()
    print(f"  {G}[✓]{RS} SSH session closed")

# ═══════════════════════════════════════════════════════════════════════════════
# CLAUDE API HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _call_claude(model, system_prompt, user_or_history, api_key, max_tokens=4096):
    """Generic Claude call. user_or_history = str or list of {role,content}."""
    messages = ([{"role":"user","content":user_or_history}]
                if isinstance(user_or_history, str) else user_or_history)
    if ANTHROPIC_SDK_OK:
        client = _anthropic_sdk.Anthropic(api_key=api_key)
        resp   = client.messages.create(model=model, max_tokens=max_tokens,
                                         system=system_prompt, messages=messages)
        return resp.content[0].text
    import urllib.request
    payload = json.dumps({"model":model,"max_tokens":max_tokens,
                          "system":system_prompt,"messages":messages}).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=payload,
        headers={"Content-Type":"application/json","x-api-key":api_key,
                 "anthropic-version":"2023-06-01"})
    with urllib.request.urlopen(req, timeout=90) as r:
        body = json.loads(r.read())
    return body["content"][0]["text"]

def _compress_config(text):
    """Strip comments and blank lines from mosquitto.conf / ACL files.
    Cuts token count by 40-60% with zero information loss for security analysis."""
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            lines.append(s)
    return "\n".join(lines)

def _filter_logs(text, max_lines=150):
    """Keep only security-relevant log lines and cap at max_lines.
    Replaces 500 generic lines with ~150 high-signal lines."""
    KEYWORDS = ["error","warning","warn","denied","failed","invalid","unauthori",
                "not authoris","connect","disconnect","subscribe","publish",
                "auth","password","username","tls","ssl","certificate","anonymous",
                "flood","rate","timeout","socket","refused","blocked"]
    relevant = [l for l in text.splitlines()
                if any(kw in l.lower() for kw in KEYWORDS)]
    # Take most recent relevant lines, fall back to tail if nothing matched
    chosen = relevant[-max_lines:] if relevant else text.splitlines()[-50:]
    return "\n".join(chosen)

def _compact(obj):
    """Compact JSON — no whitespace. Saves ~20% vs indent=2."""
    return json.dumps(obj, separators=(",", ":"))

def _strip_md(text):
    """Strip markdown formatting for clean terminal output."""
    # Code fences
    text = re.sub(r'```[\w]*\n?', '', text)
    text = re.sub(r'```',         '', text)
    # Bold / italic
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text, flags=re.DOTALL)
    text = re.sub(r'__(.+?)__',     r'\1', text, flags=re.DOTALL)
    text = re.sub(r'\*(.+?)\*',     r'\1', text)
    text = re.sub(r'_(.+?)_',       r'\1', text)
    # Inline code
    text = re.sub(r'`(.+?)`', r'\1', text)
    # Headers  →  plain text (keep the text, drop the #)
    text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
    # Bullet asterisks  →  dash
    text = re.sub(r'^\s*\*\s+', '  - ', text, flags=re.MULTILINE)
    # Horizontal rules
    text = re.sub(r'^[-*_]{3,}\s*$', '', text, flags=re.MULTILINE)
    # Collapse 3+ blank lines to 2
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()

def _slim_findings_for_judge(findings):
    """Slim findings for Haiku — keeps enough context for real validation
    without sending full remediation text. ~50% smaller than full findings."""
    return [{"id":   f.get("id",""),
             "sev":  f.get("severity",""),
             "title":f.get("title",""),
             "desc": f.get("description","")[:180],
             "evid": f.get("evidence","")[:200]}
            for f in findings]

def _parse_json_response(raw):
    """Strip markdown fences and parse JSON."""
    raw = raw.strip()
    if raw.startswith("```"): raw = "\n".join(raw.split("\n")[1:])
    if raw.endswith("```"):   raw = "\n".join(raw.split("\n")[:-1])
    return json.loads(raw.strip())

# ── Sonnet audit analysis ─────────────────────────────────────────────────────
AUDIT_SYSTEM = """You are a world-class MQTT and IoT security auditor.
Analyse ALL provided data (live probe results + static file contents) holistically.
Cross-reference probe results with config: e.g. if config says auth enabled but
anonymous probe succeeded → discrepancy → CRITICAL finding.

Return ONLY valid JSON (no markdown, no preamble):
{
  "executive_summary": "3-4 sentences for a manager",
  "technical_summary": "3-4 sentences for the security engineer",
  "overall_score": <0-100>,
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|SECURE",
  "findings": [
    {
      "id": "LIVE-001",
      "category": "Authentication|Authorization|Encryption|Availability|Configuration|Logging",
      "title": "Short title (max 60 chars)",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "description": "Security impact (max 200 chars)",
      "evidence": "Exact proof from data (max 150 chars)",
      "remediation": "Exact config fix (max 250 chars)",
      "reference": "CVE or standard (max 60 chars)"
    }
  ],
  "positive_findings": [{"title":"...","detail":"..."}],
  "recommendations": ["Actionable rec (max 100 chars each — max 5 recs)"]
}
TOKEN BUDGET: Be precise and concise. Every field has a character limit above. Obey them."""

def analyse_with_sonnet(data, api_key):
    print(f"  {M}[Sonnet]{RS} Running deep analysis...")
    probe_dict = {
        "host": data.host, "port": data.port, "timestamp": data.timestamp,
        "connectivity":    {"tcp_open":data.tcp_open, "port_1883":data.port_1883_open, "port_8883":data.port_8883_open},
        "authentication":  {"anonymous_accepted":data.anonymous_accepted, "anonymous_rc":data.anonymous_rc,
                            "cred_accepted":data.cred_accepted, "cred_rc":data.cred_rc,
                            "default_creds_found":data.default_creds_found},
        "tls":             {"port_8883_open":data.tls_port_open, "handshake_ok":data.tls_handshake_ok,
                            "cipher":data.tls_cipher, "version":data.tls_version, "error":data.tls_error},
        "acl_wildcard":    {"wildcard_msg_count":len(data.wildcard_messages),
                            "sample_topics":[t for t,_ in data.wildcard_messages[:8]],
                            "sys_accessible":bool(data.sys_topics_seen), "sys_topics":data.sys_topics_seen[:5]},
        "retained":        {"persists":data.retained_persists},
        "flood":           {"msg_count":data.flood_count, "elapsed_s":data.flood_elapsed, "rate_msg_s":data.flood_rate},
        "payload":         {"large_accepted":data.large_payload_accepted, "size_kb":data.large_payload_size_kb},
        "client_id":       {"collision_kick":data.client_id_collision_kick},
        "probe_errors":    data.errors, "ssh_notes":data.ssh_notes,
    }
    # ── Token optimisations ───────────────────────────────────────────
    # 1. Strip comments/blanks from config files  (~40% smaller)
    # 2. Filter logs to security-relevant lines only  (~70% smaller)
    # 3. Compact JSON serialisation — no indent whitespace  (~20% smaller)
    if data.config_content:
        probe_dict["mosquitto_conf"] = _compress_config(data.config_content)
    if data.acl_content:
        probe_dict["acl_files"] = _compress_config(data.acl_content)
    if data.log_content:
        probe_dict["broker_logs"] = _filter_logs(data.log_content)

    before = len(json.dumps(probe_dict))
    user_msg = "Analyse this MQTT broker audit data and return the JSON report:\n\n" + _compact(probe_dict)
    after  = len(user_msg)
    print(f"  {DIM}[tokens]{RS} Payload: {after:,} chars  "
          f"(saved {before-after:,} chars vs uncompressed)")

    raw = _call_claude(SONNET_MODEL, AUDIT_SYSTEM, user_msg, api_key, max_tokens=6000)
    try:
        result = _parse_json_response(raw)
    except json.JSONDecodeError:
        print(f"  {Y}[!]{RS} Response truncated — retrying with tighter limits...")
        retry_system = AUDIT_SYSTEM + "\nHARD LIMIT: Max 10 findings. Max 80 chars per field."
        raw = _call_claude(SONNET_MODEL, retry_system, user_msg, api_key, max_tokens=6000)
        result = _parse_json_response(raw)
    print(f"  {G}[✓]{RS} Sonnet: {len(result.get('findings',[]))} findings  |  Score: {result.get('overall_score','?')}/100")
    return result

# ── Haiku judge ───────────────────────────────────────────────────────────────
JUDGE_SYSTEM = """You are a precise security validation judge reviewing MQTT audit findings.
Your only job: validate that each finding is accurate and well-calibrated.

For each finding check:
1. Does the evidence actually prove what is claimed? (evidence_matches: true/false)
2. Is severity correctly calibrated for the actual impact? (severity_ok: true/false)
3. Is this a genuine issue or potential false positive? (genuine: true/false)
4. Confidence score 0-100

Return ONLY valid JSON:
{
  "validated": [
    {"id":"LIVE-001","confidence":95,"evidence_matches":true,"severity_ok":true,"genuine":true,"note":"brief note"}
  ],
  "false_positives": ["id1"],
  "summary": "X/Y findings confirmed. Z flagged as low confidence."
}"""

def haiku_judge(findings, evidence_summary, api_key):
    print(f"  {C}[Haiku]{RS} Cross-checking findings for accuracy...")
    # Send only id/severity/title/evidence to Haiku — cuts input by ~70%
    slim = _slim_findings_for_judge(findings)
    user_msg = (f"Evidence:{_compact(evidence_summary)}\n\nFindings:{_compact(slim)}")
    try:
        raw    = _call_claude(HAIKU_MODEL, JUDGE_SYSTEM, user_msg, api_key, max_tokens=1800)
        result = _parse_json_response(raw)
        print(f"  {G}[✓]{RS} Haiku judge: {result.get('summary','done')}")
        return result
    except Exception as e:
        print(f"  {Y}[!]{RS} Haiku validation failed: {e}")
        return {"validated": [], "false_positives": [], "summary": "Validation skipped"}

def merge_judge(findings, judge_result):
    jmap = {v["id"]: v for v in judge_result.get("validated", [])}
    fps  = set(judge_result.get("false_positives", []))
    for f in findings:
        fid = f.get("id","")
        j   = jmap.get(fid, {})
        f["haiku_confidence"] = j.get("confidence", 50)
        f["haiku_genuine"]    = fid not in fps
        f["haiku_note"]       = j.get("note", "")
    return findings

def _evidence_summary(data):
    return {
        "anonymous_rc": data.anonymous_rc,
        "default_creds": data.default_creds_found,
        "tls_ok": data.tls_handshake_ok,
        "wildcard_msgs": len(data.wildcard_messages),
        "retained_persists": data.retained_persists,
        "flood_rate": data.flood_rate,
        "large_payload_accepted": data.large_payload_accepted,
        "client_id_collision": data.client_id_collision_kick,
        "sys_topics": data.sys_topics_seen,
    }

# ── SmartFuzz strategy ────────────────────────────────────────────────────────
SMARTFUZZ_SYSTEM = """You are an elite MQTT fuzzing strategist.
Given deployment context and optionally live broker data, generate a precision
fuzzing strategy targeting the specific weaknesses of this deployment.

Return ONLY valid JSON. No markdown, no preamble, no code fences.
CRITICAL JSON RULES:
- Use only double quotes for strings
- No unescaped quotes, backslashes, or newlines inside string values
- Keep every string value under 120 characters
- No special shell characters in command strings that would break JSON
- All strings must be valid JSON strings (escape backslashes as \\\\)

{
  "summary": "2-3 sentence overview (max 200 chars)",
  "risk_profile": "1-2 sentence risk surface description (max 150 chars)",
  "priority_targets": [
    {"target":"topic or feature (max 60 chars)","reason":"why high priority (max 100 chars)","fuzz_approach":"technique (max 100 chars)"}
  ],
  "fume_commands": [
    {"command":"python3 fuzz.py --broker IP --port 1883 --fuzz-connect (max 100 chars)", "purpose":"what this tests (max 80 chars)", "expected_result":"expected outcome (max 80 chars)"}
  ],
  "custom_payloads": [
    {"payload":"payload description no special chars (max 80 chars)","target_field":"field name (max 50 chars)","expected_impact":"impact (max 80 chars)"}
  ],
  "manual_test_cases": [
    {"test":"test description (max 100 chars)", "tool":"mosquitto_pub or custom (max 40 chars)","expected":"expected result (max 80 chars)"}
  ],
  "crown_jewel_attack_paths": [
    {"path":"attack path description (max 100 chars)","steps":["step1 (max 80 chars)","step2"],"severity":"CRITICAL|HIGH"}
  ]
}

Limit output: max 5 priority_targets, max 5 fume_commands, max 4 custom_payloads,
max 4 manual_test_cases, max 3 crown_jewel_attack_paths."""

def smartfuzz_strategy(context, api_key):
    user_msg = f"Generate a targeted MQTT fuzzing strategy:\n{_compact(context)}"
    raw = _call_claude(SONNET_MODEL, SMARTFUZZ_SYSTEM, user_msg, api_key, max_tokens=6000)
    try:
        return _parse_json_response(raw)
    except Exception as e:
        print(f"  {Y}[!]{RS} JSON parse failed ({e}) — retrying with stricter constraints...")
        retry_system = SMARTFUZZ_SYSTEM + (
            "\n\nCRITICAL: Previous response had invalid JSON. "
            "This time: max 3 items per array, max 60 chars per string value, "
            "absolutely no special characters inside strings."
        )
        raw2 = _call_claude(SONNET_MODEL, retry_system, user_msg, api_key, max_tokens=4000)
        return _parse_json_response(raw2)

SMARTFUZZ_JUDGE_SYSTEM = """You are a fuzzing strategy validator.
Review this MQTT fuzzing strategy for accuracy and completeness.
Return ONLY valid JSON:
{
  "approved_commands": ["command1", "command2"],
  "flagged_commands": [{"command":"...", "issue":"why it might not work"}],
  "missing_tests": ["important test not covered"],
  "overall_quality": "EXCELLENT|GOOD|ADEQUATE|NEEDS_REVISION",
  "summary": "Brief validation summary"
}"""

def haiku_judge_strategy(strategy, context, api_key):
    user_msg = f"Context:{_compact(context)}\n\nStrategy:{_compact(strategy)}"
    try:
        raw = _call_claude(HAIKU_MODEL, SMARTFUZZ_JUDGE_SYSTEM, user_msg, api_key, max_tokens=1000)
        return _parse_json_response(raw)
    except Exception as e:
        return {"summary": f"Validation skipped: {e}", "overall_quality": "UNKNOWN"}

# ── Chat system prompt ────────────────────────────────────────────────────────
def build_chat_system_prompt(context_files):
    prompt = f"""You are SWARM Expert — an elite MQTT and IoT security specialist.
You have deep expertise in:
- MQTT protocol (v3.1, v3.1.1, v5.0) vulnerabilities and security
- Mosquitto broker hardening, ACL design, TLS configuration
- IoT/OT/ICS attack vectors and penetration testing methodology
- MQTT Mayhem attack scenarios: auth bypass, ACL abuse, retained message injection,
  wildcard snooping, DoS flooding
- CVE-2021-34432 and all known MQTT broker CVEs
- OWASP IoT Top 10, IEC 62443, NIST IoT guidance
- Secure MQTT architecture design for industrial and consumer deployments

You are connected to the target broker's live configuration.
Give precise, targeted advice — reference specific config lines, exact directives,
and actual file paths. Be direct, technical, and actionable.
Never give generic advice when you have specific context available.

OUTPUT FORMAT: Plain text only. No markdown. No bold (**text**), no italic (*text*),
no headers (## text), no code fences (```), no bullet asterisks (* item).
Use plain dashes (  - item) for lists. Use plain text for emphasis.
Write as if you are speaking directly in a terminal — clean, readable prose."""

    if context_files.get("config"):
        prompt += f"\n\n## LIVE mosquitto.conf:\n```\n{context_files['config'][:8000]}\n```"
    if context_files.get("acl"):
        prompt += f"\n\n## LIVE ACL file:\n```\n{context_files['acl'][:4000]}\n```"
    if context_files.get("logs"):
        prompt += f"\n\n## Recent broker logs:\n```\n{context_files['logs'][:5000]}\n```"
    return prompt

# ═══════════════════════════════════════════════════════════════════════════════
# PDF REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

DARK_BG = colors.HexColor("#0d1520") if REPORTLAB_OK else None
ACCENT  = colors.HexColor("#00bcd4") if REPORTLAB_OK else None
GREEN_  = colors.HexColor("#00c853") if REPORTLAB_OK else None
TEXT_   = colors.HexColor("#1a1a2e") if REPORTLAB_OK else None
MUTED_  = colors.HexColor("#555577") if REPORTLAB_OK else None
RULE_   = colors.HexColor("#cce8ee") if REPORTLAB_OK else None

SEV_PDF = {
    "CRITICAL":(colors.HexColor("#ff3b5c"), colors.HexColor("#fff0f3")),
    "HIGH":    (colors.HexColor("#e65100"), colors.HexColor("#fff8f0")),
    "MEDIUM":  (colors.HexColor("#cc8800"), colors.HexColor("#fffdf0")),
    "LOW":     (colors.HexColor("#5c6bc0"), colors.HexColor("#f5f5ff")),
    "INFO":    (colors.HexColor("#607d8b"), colors.HexColor("#f5f7f8")),
} if REPORTLAB_OK else {}

def _sc(score):
    if not REPORTLAB_OK: return None
    if score>=75: return GREEN_
    if score>=50: return colors.HexColor("#ff9800")
    if score>=25: return colors.HexColor("#e65100")
    return colors.HexColor("#c62828")

def _rc(risk):
    if not REPORTLAB_OK: return None
    return {"SECURE":GREEN_,"LOW":colors.HexColor("#388e3c"),
            "MEDIUM":colors.HexColor("#f57c00"),"HIGH":colors.HexColor("#e64a19"),
            "CRITICAL":colors.HexColor("#c62828")}.get(risk, MUTED_)

def _styles():
    base = getSampleStyleSheet()
    def S(n,**kw): return ParagraphStyle(n, parent=base["Normal"], **kw)
    return {
        "cover_title": S("ct",fontSize=28,textColor=colors.white,fontName="Helvetica-Bold",
                         spaceAfter=6,leading=34,alignment=TA_CENTER),
        "cover_sub":   S("cs",fontSize=12,textColor=colors.HexColor("#aaddee"),
                         fontName="Helvetica",alignment=TA_CENTER,spaceAfter=4),
        "section":     S("sec",fontSize=14,textColor=ACCENT,fontName="Helvetica-Bold",
                         spaceBefore=16,spaceAfter=5),
        "sub":         S("ss",fontSize=11,textColor=TEXT_,fontName="Helvetica-Bold",
                         spaceBefore=8,spaceAfter=3),
        "body":        S("bd",fontSize=10,textColor=TEXT_,fontName="Helvetica",
                         leading=15,spaceAfter=4),
        "mono":        S("mo",fontSize=8.5,textColor=colors.HexColor("#1a2a3a"),
                         fontName="Courier",leading=13,spaceAfter=2,
                         backColor=colors.HexColor("#f4f6f8"),
                         leftIndent=8,rightIndent=8),
        "label":       S("lb",fontSize=8.5,fontName="Helvetica-Bold",
                         textColor=MUTED_,spaceAfter=1),
        "positive":    S("pos",fontSize=10,textColor=colors.HexColor("#1b5e20"),
                         fontName="Helvetica",leading=14),
        "rec":         S("rec",fontSize=10,textColor=TEXT_,fontName="Helvetica",leading=14),
        "footer":      S("ft",fontSize=8,textColor=MUTED_,fontName="Helvetica",
                         alignment=TA_CENTER),
        "haiku_tag":   S("ht",fontSize=8,fontName="Helvetica",
                         textColor=colors.HexColor("#888"),alignment=TA_RIGHT),
    }

def generate_pdf(analysis, data, output_path, mode_label="Audit"):
    if not REPORTLAB_OK:
        print(f"  {Y}[!]{RS} reportlab not installed — skipping PDF"); return
    print(f"  {C}[→]{RS} Generating PDF → {output_path}")
    st  = _styles()
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             leftMargin=18*mm, rightMargin=18*mm,
                             topMargin=14*mm,  bottomMargin=14*mm)
    story = []; W = A4[0] - 36*mm
    score = analysis.get("overall_score", 0)
    risk  = analysis.get("risk_level", "UNKNOWN")

    # Cover
    cover_t = Table([[Paragraph(f"🔒  SWARM — {mode_label} Report", st["cover_title"])]],
                    colWidths=[W])
    cover_t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),DARK_BG),
                                  ("ROWPADDING",(0,0),(-1,-1),28),
                                  ("ALIGN",(0,0),(-1,-1),"CENTER")]))
    story.extend([cover_t, Spacer(1, 6*mm)])
    meta = [["Target", f"{data.host}:{data.port}"],["Date", data.timestamp],
             ["Score",  f"{score} / 100"],["Risk",   risk]]
    mt = Table(meta, colWidths=[38*mm, W-38*mm])
    mt.setStyle(TableStyle([("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
                              ("FONTSIZE",(0,0),(-1,-1),10),
                              ("TEXTCOLOR",(0,0),(0,-1),MUTED_),
                              ("LINEBELOW",(0,0),(-1,-2),0.4,RULE_),
                              ("TOPPADDING",(0,0),(-1,-1),5),
                              ("BOTTOMPADDING",(0,0),(-1,-1),5)]))
    story.extend([mt, Spacer(1,5*mm),
                  HRFlowable(width=W, thickness=2, color=ACCENT), PageBreak()])

    # Executive summary
    sc_col = _sc(score); rc_col = _rc(risk)
    story.append(Paragraph("EXECUTIVE SUMMARY", st["section"]))
    story.append(HRFlowable(width=W, thickness=1, color=RULE_))
    story.append(Spacer(1,3*mm))
    story.append(Paragraph(analysis.get("executive_summary",""), st["body"]))
    story.append(Spacer(1,4*mm))
    # Score box
    sc_hex = sc_col.hexval()[2:] if sc_col else "888888"
    rc_hex = rc_col.hexval()[2:] if rc_col else "888888"
    sb = Table([[
        Paragraph(f"<font color='#{sc_hex}' size='34'><b>{score}</b></font>",
                  ParagraphStyle("x",alignment=TA_CENTER,fontSize=34,fontName="Helvetica-Bold")),
        Paragraph(f"<b>Security Score</b><br/>"
                  f"<font color='#{rc_hex}'><b>{risk}</b></font><br/>"
                  f"<font size='9' color='#666'>out of 100</font>",
                  ParagraphStyle("y",alignment=TA_LEFT,fontSize=12,fontName="Helvetica",leading=18)),
    ]], colWidths=[42*mm, W-42*mm])
    sb.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#f0fafc")),
                              ("BOX",(0,0),(-1,-1),1,ACCENT),
                              ("ROWPADDING",(0,0),(-1,-1),12),
                              ("VALIGN",(0,0),(-1,-1),"MIDDLE")]))
    story.extend([sb, Spacer(1,4*mm)])
    story.append(Paragraph("Technical Overview", st["sub"]))
    story.append(Paragraph(analysis.get("technical_summary",""), st["body"]))

    # Findings summary table
    findings = analysis.get("findings", [])
    counts   = {}
    for f in findings: counts[f["severity"]] = counts.get(f["severity"],0)+1
    sev_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    cr = [["Severity","Count","Score Impact","Haiku Verified"]]
    for sev in sev_order:
        if sev not in counts: continue
        verified = sum(1 for f in findings
                       if f.get("severity")==sev and f.get("haiku_genuine",True)
                       and f.get("haiku_confidence",50) >= 60)
        cr.append([sev, str(counts[sev]),
                   f"-{SEV_WEIGHT.get(sev,0)} pts each",
                   f"{verified}/{counts[sev]}"])
    ct = Table(cr, colWidths=[45*mm, 22*mm, 45*mm, W-112*mm])
    ct_s = [("BACKGROUND",(0,0),(-1,0),DARK_BG),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),10),
            ("ROWPADDING",(0,0),(-1,-1),6),("LINEBELOW",(0,0),(-1,-2),0.4,RULE_)]
    for i, sev in enumerate([s for s in sev_order if s in counts], start=1):
        fc, bg = SEV_PDF.get(sev,(MUTED_,colors.white))
        ct_s += [("BACKGROUND",(0,i),(0,i),bg),("TEXTCOLOR",(0,i),(0,i),fc),
                 ("FONTNAME",(0,i),(0,i),"Helvetica-Bold")]
    ct.setStyle(TableStyle(ct_s))
    story.extend([Spacer(1,5*mm), ct, PageBreak()])

    # ── RECONNAISSANCE SECTION ────────────────────────────────────────────
    import re as _re

    def _rtable(rows, cw, full_w=W):
        t = Table(rows, colWidths=cw)
        ts = [
            ("BACKGROUND",  (0,0), (-1,0),  DARK_BG),
            ("TEXTCOLOR",   (0,0), (-1,0),  colors.white),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 10),
            ("ROWPADDING",  (0,0), (-1,-1), 5),
            ("LINEBELOW",   (0,0), (-1,-2), 0.4, RULE_),
            ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
            ("BACKGROUND",  (0,1), (-1,-1), colors.white),
        ]
        t.setStyle(TableStyle(ts))
        return t

    def _risk_cell(label, col):
        hex_str = col.hexval()[2:] if hasattr(col, 'hexval') else str(col).lstrip('#')
        return Paragraph(
            f"<font color='#{hex_str}'><b>{label}</b></font>",
            ParagraphStyle("rc", fontSize=10, fontName="Helvetica-Bold", alignment=TA_CENTER)
        )

    # ── Parse helpers ─────────────────────────────────────────────────────
    ver_m    = _re.search(r'[Mm]osquitto[^\d]*(\d+\.\d+\.\d+)', data.config_content)
    mosq_ver = f"Mosquitto {ver_m.group(1)}" if ver_m else "Not detected"
    svc_m    = _re.search(r'Service[:\s]+([^\n#]{2,40})', data.config_content)
    svc_stat = svc_m.group(1).strip() if svc_m else "Unknown"
    lsnr_m   = _re.search(r'Active listeners[:\s]*\n?((?:#\s*.+\n?)+)', data.config_content)
    listeners= []
    if lsnr_m:
        listeners = [l.lstrip('#').strip() for l in lsnr_m.group(1).splitlines() if l.strip().lstrip('#').strip()]

    passwd_users = _re.findall(r'#\s*user:\s*(.+)', data.config_content)
    passwd_count_m = _re.search(r'passwd[^\n]*:\s*(\d+)\s*user', data.config_content)
    passwd_count   = passwd_count_m.group(1) if passwd_count_m else str(len(passwd_users))

    # ACL user parse
    acl_users_raw = {}
    cur_user = None
    for line in data.acl_content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        parts = line.split()
        if not parts: continue
        if parts[0] == 'user' and len(parts) >= 2:
            cur_user = parts[1]
            acl_users_raw.setdefault(cur_user, {'r':[], 'w':[]})
        elif parts[0] == 'topic' and cur_user:
            if len(parts) == 2:   perm, topic = 'readwrite', parts[1]
            elif len(parts) >= 3: perm, topic = parts[1], parts[2]
            else: continue
            if perm in ('read','readwrite'):    acl_users_raw[cur_user]['r'].append(topic)
            if perm in ('write','readwrite'):   acl_users_raw[cur_user]['w'].append(topic)

    def _user_risk(ud):
        writes = ud.get('w', [])
        reads  = ud.get('r', [])
        sens   = ['cmd','admin','ota','exec','firmware','control']
        if '#' in ' '.join(writes): return 'CRITICAL', colors.HexColor('#ff3b5c')
        if any(s in t for t in writes for s in sens): return 'HIGH', colors.HexColor('#e65100')
        if '#' in ' '.join(reads): return 'HIGH', colors.HexColor('#e65100')
        if any('$SYS' in t for t in reads): return 'MEDIUM', colors.HexColor('#cc8800')
        return 'LOW', colors.HexColor('#388e3c')

    # Sensitivity of a topic
    sens_kw = ['cmd','admin','ota','exec','firmware','control','actuator','set']
    def _topic_risk(t):
        tl = t.lower()
        if any(k in tl for k in sens_kw):  return 'SENSITIVE', colors.HexColor('#ff3b5c')
        if t.startswith('$SYS'):            return '$SYS',      colors.HexColor('#cc8800')
        return 'DATA', colors.HexColor('#5c6bc0')

    # ── 1. BROKER OVERVIEW ────────────────────────────────────────────────
    story.append(Paragraph("RECONNAISSANCE SUMMARY", st["section"]))
    story.append(HRFlowable(width=W, thickness=1, color=RULE_))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Broker Overview", st["sub"]))

    anon_txt  = "ACCEPTED — CRITICAL" if data.anonymous_accepted else "Blocked"
    anon_col  = colors.HexColor('#ff3b5c') if data.anonymous_accepted else colors.HexColor('#007700')
    tls_txt   = f"Enabled — {data.tls_cipher} / {data.tls_version}" if data.tls_handshake_ok else "DISABLED — plain-text only"
    tls_col   = colors.HexColor('#007700') if data.tls_handshake_ok else colors.HexColor('#ff3b5c')

    def _p(txt, col=None, bold=False):
        c = f"color='#{col.hexval()[2:]}'" if col else ""
        b = "b" if bold else "font"
        return Paragraph(f"<{b} {c}>{txt}</{b}>",
                         ParagraphStyle("rc2", fontSize=10, fontName="Helvetica-Bold" if bold else "Helvetica"))

    overview_rows = [
        ["Property", "Value"],
        ["Target Host", f"{data.host}:{data.port}"],
        ["Broker Software", mosq_ver],
        ["Service Status",  svc_stat],
        ["Audit Timestamp", data.timestamp],
        ["Anonymous Access", _p(anon_txt, anon_col, bold=True)],
        ["TLS Encryption",   _p(tls_txt,  tls_col,  bold=True)],
        ["Port 1883 (plain)", "Open" if data.port_1883_open else "Closed"],
        ["Port 8883 (TLS)",   "Open" if data.port_8883_open else "Closed"],
        ["Retained Messages", _p("Persist on reconnect — VULNERABLE", colors.HexColor('#ff3b5c'), True)
            if data.retained_persists else "Not persistent"],
        ["Flood Rate",        f"{data.flood_rate:,.0f} msg/s ({data.flood_count} msgs in {data.flood_elapsed}s)"
            if data.flood_rate else "Not tested"],
        ["Oversized Payload (512 KB)", _p("ACCEPTED — no message_size_limit", colors.HexColor('#e65100'), True)
            if data.large_payload_accepted else "Rejected (limit enforced)"],
        ["Client ID Collision", _p("Session hijack risk confirmed", colors.HexColor('#e65100'), True)
            if data.client_id_collision_kick else "Not confirmed"],
        ["Password File Users", f"{passwd_count} account(s) defined"],
        ["ACL Files Fetched", f"{data.acl_content.count('ACL FILE:')} file(s)" if 'ACL FILE:' in data.acl_content
            else ("1 file" if data.acl_content else "None fetched")],
    ]
    if listeners:
        for l in listeners[:4]:
            overview_rows.append(["Active Listener", l])

    ov = _rtable(overview_rows, [55*mm, W-55*mm])
    story.extend([ov, Spacer(1, 5*mm)])

    # ── 2. DEFAULT CREDENTIALS FOUND ─────────────────────────────────────
    if data.default_creds_found:
        story.append(Paragraph(f"Default / Weak Credentials Found  ({len(data.default_creds_found)} pair(s))", st["sub"]))
        cred_rows = [["#", "Username", "Password", "Risk"]]
        for i, c in enumerate(data.default_creds_found, 1):
            parts = c.split('/')
            user  = parts[0].strip() if parts else c
            pwd   = parts[1].strip() if len(parts) > 1 else "(empty)"
            cred_rows.append([str(i), user, pwd,
                              _risk_cell("CRITICAL", colors.HexColor('#ff3b5c').hexval()[2:])])
        ct2 = _rtable(cred_rows, [15*mm, 60*mm, 60*mm, W-135*mm])
        story.extend([ct2, Spacer(1, 5*mm)])

    # ── 3. ACL USERS & PERMISSIONS ────────────────────────────────────────
    if acl_users_raw:
        story.append(Paragraph(f"ACL Users & Permission Profiles  ({len(acl_users_raw)} user(s))", st["sub"]))
        acl_rows = [["Username", "Readable Topics", "Writable Topics", "Risk"]]
        for user, ud in sorted(acl_users_raw.items()):
            risk_lbl, risk_col = _user_risk(ud)
            reads  = ', '.join(ud['r'][:4]) + ('…' if len(ud['r'])>4 else '') if ud['r'] else '—'
            writes = ', '.join(ud['w'][:4]) + ('…' if len(ud['w'])>4 else '') if ud['w'] else '—'
            acl_rows.append([user, reads, writes, _risk_cell(risk_lbl, risk_col.hexval()[2:])])

        at = Table(acl_rows, colWidths=[38*mm, 55*mm, 55*mm, 22*mm])
        at_style = [
            ("BACKGROUND",  (0,0), (-1,0),  DARK_BG),
            ("TEXTCOLOR",   (0,0), (-1,0),  colors.white),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 9.5),
            ("ROWPADDING",  (0,0), (-1,-1), 5),
            ("LINEBELOW",   (0,0), (-1,-2), 0.4, RULE_),
            ("VALIGN",      (0,0), (-1,-1), "TOP"),
            ("BACKGROUND",  (0,1), (-1,-1), colors.white),
            ("WORDWRAP",    (0,0), (-1,-1), "LTR"),
        ]
        at.setStyle(TableStyle(at_style))
        story.extend([at, Spacer(1, 5*mm)])

    # ── 4. PASSWORD FILE USERS ────────────────────────────────────────────
    if passwd_users:
        story.append(Paragraph(f"Password File Accounts  ({len(passwd_users)} user(s))", st["sub"]))
        cols = 4
        padded = passwd_users + [''] * (cols - len(passwd_users) % cols if len(passwd_users) % cols else 0)
        pw_rows = [["Username"] * cols]
        for i in range(0, len(padded), cols):
            pw_rows.append(padded[i:i+cols])
        pw_t = _rtable(pw_rows, [W/cols]*cols)
        story.extend([pw_t, Spacer(1, 5*mm)])

    # ── 5. OBSERVED TOPICS ────────────────────────────────────────────────
    all_topics = [(t, p) for t, p in data.wildcard_messages]
    sys_topics = [(t, '') for t in data.sys_topics_seen]

    if all_topics or sys_topics:
        story.append(Paragraph(
            f"Observed Topics  ({len(all_topics)} data + {len(sys_topics)} $SYS topics via wildcard probe)",
            st["sub"]))

        topic_rows = [["Topic", "Classification", "Sample Payload / Notes"]]
        for t, p in (all_topics[:20]):
            lbl, col = _topic_risk(t)
            sample = (str(p)[:80] + '…') if len(str(p)) > 80 else str(p)
            topic_rows.append([
                Paragraph(f"<font name='Courier'>{t}</font>",
                          ParagraphStyle("tc", fontSize=9, fontName="Courier")),
                _risk_cell(lbl, col.hexval()[2:]),
                sample or '—'
            ])
        for t, _ in sys_topics[:10]:
            topic_rows.append([
                Paragraph(f"<font name='Courier'>{t}</font>",
                          ParagraphStyle("tc2", fontSize=9, fontName="Courier")),
                _risk_cell('$SYS', colors.HexColor('#cc8800').hexval()[2:]),
                'Broker internal metric — exposed to all authenticated users'
            ])

        tt = Table(topic_rows, colWidths=[65*mm, 24*mm, W-89*mm])
        tt.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0),  DARK_BG),
            ("TEXTCOLOR",   (0,0), (-1,0),  colors.white),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 9.5),
            ("ROWPADDING",  (0,0), (-1,-1), 5),
            ("LINEBELOW",   (0,0), (-1,-2), 0.4, RULE_),
            ("VALIGN",      (0,0), (-1,-1), "TOP"),
            ("BACKGROUND",  (0,1), (-1,-1), colors.white),
        ]))
        story.extend([tt, Spacer(1, 5*mm)])

    # ── 6. LOG HIGHLIGHTS ─────────────────────────────────────────────────
    if data.log_content:
        KEYWORDS = ['error','denied','failed','unauthori','anonymous','invalid',
                    'disconnect','flood','timeout','refused','pwfile','passwd']
        notable = [l for l in data.log_content.splitlines()
                   if any(k in l.lower() for k in KEYWORDS)][:15]
        if notable:
            story.append(Paragraph(f"Notable Log Entries  ({len(notable)} security-relevant lines shown)", st["sub"]))
            for line in notable:
                clean = (line[:140] + '…') if len(line) > 140 else line
                story.append(Paragraph(
                    f"<font name='Courier' size='8.5' color='#234'>{clean}</font>",
                    ParagraphStyle("lp", backColor=colors.HexColor('#f4f6f8'),
                                   leftIndent=8, rightIndent=8,
                                   spaceBefore=2, spaceAfter=2,
                                   borderPad=4, fontSize=8.5, fontName="Courier")))
            story.append(Spacer(1, 5*mm))

    story.append(PageBreak())

    # Findings
    story.append(Paragraph("SECURITY FINDINGS", st["section"]))
    story.append(HRFlowable(width=W, thickness=1, color=RULE_))
    story.append(Spacer(1,3*mm))
    sorted_f = sorted(findings, key=lambda f: SEV_ORDER.get(f.get("severity","INFO"),99))
    for f in sorted_f:
        sev = f.get("severity","INFO")
        fc, bg = SEV_PDF.get(sev,(MUTED_,colors.white))
        conf   = f.get("haiku_confidence", 50)
        genuine= f.get("haiku_genuine", True)
        conf_color = "#00c853" if conf>=80 else "#ff9800" if conf>=50 else "#ff3b5c"
        haiku_badge = (f"[Haiku: {'✓' if genuine else '⚠'} {conf}% confidence]"
                       f"{' — ' + f['haiku_note'] if f.get('haiku_note') else ''}")
        hdr = Table([[
            Paragraph(f"<b>{sev}</b>",
                      ParagraphStyle("sh",fontSize=9,fontName="Helvetica-Bold",
                                     textColor=fc,alignment=TA_CENTER)),
            Paragraph(f"<font color='#888'>{f.get('id','')}</font>  <b>{f.get('title','')}</b>",
                      ParagraphStyle("fh",fontSize=10.5,fontName="Helvetica-Bold",textColor=TEXT_)),
            Paragraph(f"<font color='{conf_color}'>{haiku_badge}</font>",
                      ParagraphStyle("hb",fontSize=7.5,fontName="Helvetica",
                                     textColor=colors.HexColor(conf_color),alignment=TA_RIGHT)),
        ]], colWidths=[22*mm, W-22*mm-42*mm, 42*mm])
        hdr.setStyle(TableStyle([("BACKGROUND",(0,0),(0,0),bg),
                                   ("BACKGROUND",(1,0),(-1,0),colors.HexColor("#f8f9fa")),
                                   ("BOX",(0,0),(-1,-1),0.8,fc),
                                   ("LINEAFTER",(0,0),(0,0),0.8,fc),
                                   ("ROWPADDING",(0,0),(-1,-1),8),
                                   ("VALIGN",(0,0),(-1,-1),"MIDDLE")]))
        rows = []
        def add_row(lbl, val, mono=False):
            s = st["mono"] if mono else st["body"]
            rows.append([Paragraph(lbl,st["label"]),
                         Paragraph(str(val).replace("<","&lt;").replace(">","&gt;"), s)])
        add_row("DESCRIPTION", f.get("description",""))
        if f.get("evidence"):    add_row("EVIDENCE",    f["evidence"],    mono=True)
        add_row("REMEDIATION", f.get("remediation",""), mono=True)
        if f.get("reference"):   add_row("REFERENCE",   f["reference"])
        bt = Table(rows, colWidths=[22*mm, W-22*mm])
        bt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),colors.white),
                                  ("BOX",(0,0),(-1,-1),0.5,colors.HexColor("#dde")),
                                  ("LINEAFTER",(0,0),(0,-1),0.5,RULE_),
                                  ("LINEBELOW",(0,0),(-1,-2),0.3,RULE_),
                                  ("TOPPADDING",(0,0),(-1,-1),5),
                                  ("BOTTOMPADDING",(0,0),(-1,-1),5),
                                  ("LEFTPADDING",(0,0),(-1,-1),8),
                                  ("VALIGN",(0,0),(-1,-1),"TOP")]))
        story.append(KeepTogether([hdr, bt, Spacer(1,5*mm)]))

    # Positive findings
    pf = analysis.get("positive_findings",[])
    if pf:
        story.append(PageBreak())
        story.append(Paragraph("WHAT IS CORRECTLY CONFIGURED", st["section"]))
        story.append(HRFlowable(width=W, thickness=1, color=RULE_))
        for p in pf:
            pt = Table([[
                Paragraph("✓", ParagraphStyle("chk",fontSize=14,textColor=GREEN_,
                                               fontName="Helvetica-Bold",alignment=TA_CENTER)),
                Paragraph(f"<b>{p.get('title','')}</b><br/>"
                          f"<font size='9' color='#555'>{p.get('detail','')}</font>",st["body"])
            ]], colWidths=[12*mm, W-12*mm])
            pt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#f1fff5")),
                                     ("BOX",(0,0),(-1,-1),0.6,GREEN_),
                                     ("ROWPADDING",(0,0),(-1,-1),8),
                                     ("VALIGN",(0,0),(-1,-1),"MIDDLE")]))
            story.extend([Spacer(1,3*mm), pt])

    # Recommendations
    recs = analysis.get("recommendations",[])
    if recs:
        story.extend([Spacer(1,5*mm), Paragraph("PRIORITISED RECOMMENDATIONS", st["section"]),
                      HRFlowable(width=W, thickness=1, color=RULE_), Spacer(1,3*mm)])
        for i, rec in enumerate(recs, 1):
            rt = Table([[
                Paragraph(str(i), ParagraphStyle("rn",fontSize=13,textColor=ACCENT,
                                                   fontName="Helvetica-Bold",alignment=TA_CENTER)),
                Paragraph(rec, st["rec"]),
            ]], colWidths=[12*mm, W-12*mm])
            rt.setStyle(TableStyle([("BACKGROUND",(0,0),(0,0),colors.HexColor("#e8f8fa")),
                                     ("BOX",(0,0),(-1,-1),0.5,RULE_),
                                     ("ROWPADDING",(0,0),(-1,-1),8),
                                     ("VALIGN",(0,0),(-1,-1),"MIDDLE")]))
            story.extend([rt, Spacer(1,2*mm)])

    # Footer
    story.extend([Spacer(1,8*mm), HRFlowable(width=W,thickness=1,color=RULE_), Spacer(1,2*mm),
                  Paragraph("SWARM v1.0 — Powered by Claude Sonnet + Haiku Judge  |  "
                             "For authorised security testing only  |  Black Hat Arsenal India",
                             st["footer"])])
    doc.build(story)
    print(f"  {G}[✓]{RS} PDF → {output_path}")

# ═══════════════════════════════════════════════════════════════════════════════
# DOT / PNG / SVG GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_acl_for_viz(acl_content):
    """Parse mosquitto ACL into per-user read/write topic lists for DOT arrows."""
    perms = {}          # {user: {read:[topics], write:[topics]}}
    current_user = None
    for raw_line in acl_content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"): continue
        parts = line.split()
        if not parts: continue
        if parts[0] == "user" and len(parts) >= 2:
            current_user = parts[1]
            perms.setdefault(current_user, {"read": [], "write": []})
        elif parts[0] == "topic" and current_user:
            if len(parts) == 2:
                perm, topic = "readwrite", parts[1]
            elif len(parts) >= 3:
                perm, topic = parts[1], parts[2]
            else:
                continue
            p = perms[current_user]
            if perm in ("read",      "readwrite"): p["read"].append(topic)
            if perm in ("write",     "readwrite"): p["write"].append(topic)
        # pattern directives apply to all — skip per-user viz
    return perms

SENS_PATTERNS = ["cmd","control","admin","actuator","ota","config","set","write","exec"]

def _topic_color(topic):
    """Return fill/font color for a topic node based on sensitivity."""
    t = topic.lower()
    if any(p in t for p in ["admin","cmd","ota","exec","firmware"]):
        return "#ff3b5c", "white"   # RED — critical control
    if any(p in t for p in ["control","actuator","setpoint","override"]):
        return "#ff7a35", "white"   # ORANGE — control plane
    if "$sys" in t:
        return "#ffaa00", "#1a1a1a" # AMBER — broker internals
    if any(p in t for p in ["audit","reports","logs"]):
        return "#00c853", "white"   # GREEN — audit/safe
    return "#1a3a5a", "white"       # BLUE — data topics

def _tid(topic):
    """Safe DOT node ID from topic string."""
    return "t_" + re.sub(r"[^a-zA-Z0-9]", "_", topic)[:30]

def generate_dot_svg(data, analysis, dot_path):
    print(f"  {C}[→]{RS} Generating topology graph → {dot_path}")
    findings = analysis.get("findings", [])
    score    = analysis.get("overall_score", 50)
    risk     = analysis.get("risk_level",   "MEDIUM")

    if   score < 30: bf, bfont = "#ff3b5c", "white"
    elif score < 55: bf, bfont = "#ff7a35", "white"
    elif score < 75: bf, bfont = "#ffaa00", "#1a1a1a"
    else:            bf, bfont = "#00c853", "white"

    # ── Parse ACL for directional edges ──────────────────────────────
    acl_perms = _parse_acl_for_viz(data.acl_content) if data.acl_content else {}

    # ── Build client nodes from probe + ACL ──────────────────────────
    clients = {}

    if data.anonymous_accepted:
        clients["anon_client"] = dict(
            label="Anonymous\\nClient", fill="#ff3b5c", font="white",
            edge_style='color="#ff3b5c" style=dashed penwidth=2.5',
            edge_label="ANONYMOUS\\n(no auth)")

    for cred in data.default_creds_found[:5]:
        u = cred.split("/")[0].strip()
        nid = "dc_" + re.sub(r"[^a-z0-9]","_",u.lower())
        clients[nid] = dict(
            label=f"Default Cred\\n{cred}", fill="#ff3b5c", font="white",
            edge_style='color="#ff3b5c" style=dashed penwidth=2',
            edge_label=f"DEFAULT\\n{cred}")

    if data.cred_accepted:
        clients["auth_client"] = dict(
            label="Authenticated\\nClient", fill="#00c853", font="white",
            edge_style='color="#00c853" style=solid penwidth=2',
            edge_label="AUTHENTICATED")

    if data.wildcard_messages:
        clients["wildcard_sub"] = dict(
            label="Wildcard\\nSubscriber", fill="#ff7a35", font="white",
            edge_style='color="#ff7a35" style=dashed penwidth=1.5',
            edge_label="SUB: #")

    clients["swarm_tool"] = dict(
        label="SWARM Auditor", fill="#7b7fff", font="white",
        edge_style='color="#7b7fff" style=dotted penwidth=1.5',
        edge_label="PROBE")

    # ── Build topic nodes ─────────────────────────────────────────────
    # From ACL parse (most interesting for directional arrows)
    acl_topics = {}
    for user, perms in acl_perms.items():
        for topic in perms.get("read", []) + perms.get("write", []):
            tid = _tid(topic)
            if tid not in acl_topics:
                fill, font = _topic_color(topic)
                acl_topics[tid] = {"label": topic.replace('"','\\"'),
                                   "fill": fill, "font": font}

    # From live probe (wildcard messages)
    probe_topics = {}
    seen = set()
    for t_name, _ in data.wildcard_messages[:8]:
        if t_name in seen: continue
        seen.add(t_name)
        tid = _tid(t_name)
        fill, font = _topic_color(t_name)
        probe_topics[tid] = {"label": t_name.replace('"','\\"'),
                             "fill": fill, "font": font}
    for st in data.sys_topics_seen[:4]:
        tid = _tid(st)
        probe_topics[tid] = {"label": st.replace('"','\\"'),
                             "fill": "#ffaa00", "font": "#1a1a1a"}

    # Merge — ACL topics take priority since they have permission context
    all_topics = {**probe_topics, **acl_topics}

    # ── Vulnerability boxes ───────────────────────────────────────────
    vuln_nodes = []
    for i, f in enumerate([x for x in findings
                            if x.get("severity") in ("CRITICAL","HIGH")][:6]):
        fill = "#ff3b5c" if f["severity"]=="CRITICAL" else "#ff7a35"
        conf = f.get("haiku_confidence", 50)
        vuln_nodes.append({
            "id":   f"v{i}",
            "fill": fill,
            "label": (f"[{f['severity']}] {f.get('id','')}\\n"
                      f"{f.get('title','')[:35]}\\n"
                      f"Haiku: {conf}%")
        })

    # ── Build DOT ─────────────────────────────────────────────────────
    L = []
    L.append("digraph SWARM_MQTT_Topology {")
    L.append("    graph [")
    L.append(f'        label="SWARM Security Topology  ·  {data.host}:{data.port}  ·  '
             f'Risk: {risk}  ·  Score: {score}/100\\nGenerated: {data.timestamp}"')
    L.append('        labelloc=t fontname="Helvetica" fontsize=15 fontcolor="white"')
    L.append('        bgcolor="#070b10" pad=0.8 splines=spline rankdir=LR')
    L.append('        nodesep=0.9 ranksep=1.6')
    L.append("    ]")
    L.append('    node [fontname="Helvetica" fontsize=11 margin="0.22,0.12"]')
    L.append('    edge [fontname="Helvetica" fontsize=9  fontcolor="#ccddee"]')
    L.append("")

    # Broker
    L.append("    // ── Broker ─────────────────────────────────────────")
    L.append(f'    broker [label="MQTT BROKER\\n{data.host}:{data.port}\\n'
             f'Score: {score}/100\\n{risk}" shape=cylinder style="filled,bold"'
             f' fillcolor="{bf}" fontcolor="{bfont}" penwidth=3 width=2.2 height=1.4]')
    L.append("")

    # TLS status
    tls_fill  = "#00c853" if data.tls_handshake_ok else "#ff3b5c"
    tls_label = f"TLS {'ENABLED' if data.tls_handshake_ok else 'DISABLED'}\\n" \
                f"{'✓ Encrypted' if data.tls_handshake_ok else '✗ Plain-text only'}"
    L.append(f'    tls_node [label="{tls_label}" shape=box3d style=filled'
             f' fillcolor="{tls_fill}" fontcolor="white" fontsize=10]')
    L.append('    broker -> tls_node [color="#555555" style=dotted arrowhead=none]')
    L.append("")

    # Client cluster (connection to broker)
    L.append("    // ── Clients → Broker ────────────────────────────────")
    L.append('    subgraph cluster_clients {')
    L.append('        label="Clients" fontcolor="#8899aa" color="#1a2d47" style=dashed')
    for cid, c in clients.items():
        L.append(f'        {cid} [label="{c["label"]}" shape=ellipse'
                 f' style="filled,bold" fillcolor="{c["fill"]}"'
                 f' fontcolor="{c["font"]}" penwidth=2]')
    L.append("    }")
    L.append("")

    # Topic cluster
    if all_topics:
        L.append("    // ── Topics ─────────────────────────────────────────")
        L.append('    subgraph cluster_topics {')
        L.append('        label="Topics" fontcolor="#8899aa" color="#1a2d47" style=dashed')
        for tid, t in all_topics.items():
            L.append(f'        {tid} [label="{t["label"]}" shape=note style=filled'
                     f' fillcolor="{t["fill"]}" fontcolor="{t["font"]}"]')
        L.append("    }")
        L.append("")

    # ── ACL users cluster (from parsed ACL) ───────────────────────────
    if acl_perms:
        L.append("    // ── ACL Users (from parsed ACL file) ───────────────")
        L.append('    subgraph cluster_acl_users {')
        L.append('        label="ACL Users" fontcolor="#8899aa" color="#2a3d47" style=dashed')
        for user, perms in acl_perms.items():
            is_dangerous = any(
                any(p in t.lower() for p in SENS_PATTERNS)
                for t in perms.get("write", [])
            )
            has_wildcard = "#" in " ".join(perms.get("read",[])+perms.get("write",[]))
            if is_dangerous or has_wildcard:
                fill, font = "#ff3b5c", "white"
            elif perms.get("write") and not any(
                any(p in t.lower() for p in SENS_PATTERNS) for t in perms["write"]):
                fill, font = "#ffaa00", "#1a1a1a"
            else:
                fill, font = "#00c853", "white"
            uid = "u_" + re.sub(r"[^a-z0-9]","_",user.lower())[:20]
            L.append(f'        {uid} [label="{user}" shape=ellipse style="filled"'
                     f' fillcolor="{fill}" fontcolor="{font}" fontsize=10]')
        L.append("    }")
        L.append("")

    # Findings cluster
    if vuln_nodes:
        L.append("    // ── Vulnerability Findings ──────────────────────────")
        L.append('    subgraph cluster_vulns {')
        L.append('        label="Critical / High Findings  (Sonnet + Haiku verified)"'
                 ' fontcolor="#ff6680" color="#ff3b5c44" style=dashed')
        for v in vuln_nodes:
            L.append(f'        {v["id"]} [label="{v["label"]}" shape=box'
                     f' style="filled,rounded" fillcolor="{v["fill"]}"'
                     f' fontcolor="white" penwidth=1.5]')
        L.append("    }")
        L.append("")

    # Retained note
    if data.retained_persists:
        L.append('    ret_note [label="⚠ RETAINED MSG ABUSE\\nPersists on reconnect"'
                 ' shape=note style=filled fillcolor="#ff3b5c" fontcolor="white" fontsize=10]')
        L.append('    broker -> ret_note [color="#ff3b5c" style=bold label="stored"'
                 ' fontcolor="#ff9999"]')
        L.append("")

    # Client → broker connection edges
    L.append("    // ── Client → Broker connection edges ───────────────────")
    for cid, c in clients.items():
        L.append(f'    {cid} -> broker [label="{c["edge_label"]}"'
                 f' {c["edge_style"]}]')
    L.append("")

    # ── Directional READ / WRITE edges (from ACL parse) ───────────────
    if acl_perms:
        L.append("    // ── Directional READ / WRITE edges (from ACL) ─────────")
        L.append("    //   READ  (topic → user): data flows TO the client")
        L.append("    //   WRITE (user → topic): client publishes TO topic")
        L.append("")
        for user, perms in acl_perms.items():
            uid = "u_" + re.sub(r"[^a-z0-9]","_",user.lower())[:20]

            # ACL user → broker (show authentication relationship)
            L.append(f'    {uid} -> broker [color="#444466" style=dotted'
                     f' arrowsize=0.7 label="auth"]')

            # WRITE edges: user → topic (client publishes TO this topic)
            for topic in perms.get("write", [])[:4]:  # cap to avoid clutter
                tid = _tid(topic)
                if tid in all_topics:
                    fill, _ = _topic_color(topic)
                    is_sens  = any(p in topic.lower() for p in SENS_PATTERNS)
                    st       = "bold"  if is_sens else "solid"
                    pw       = "2.5"   if is_sens else "1.5"
                    L.append(f'    {uid} -> {tid} [style={st} penwidth={pw}'
                             f' color="{fill}" label="WRITE" arrowhead=normal]')

            # READ edges: topic → user (data flows TO client)
            for topic in perms.get("read", [])[:4]:
                tid = _tid(topic)
                if tid in all_topics:
                    fill, _ = _topic_color(topic)
                    rc = "#ff7a35" if "#" in topic else fill
                    L.append(f'    {tid} -> {uid} [style=dashed penwidth=1.5'
                             f' color="{rc}" label="READ"'
                             f' arrowhead=open arrowsize=0.8]')
        L.append("")

    # Probe-based topic edges (when no ACL available)
    elif all_topics:
        L.append("    // ── Broker ↔ Topic edges (from live probe) ─────────────")
        for tid, t in all_topics.items():
            fill = t["fill"]
            if   fill == "#ff3b5c": es = 'color="#ff3b5c" style=bold penwidth=2'; el = "SENSITIVE"
            elif fill == "#ffaa00": es = 'color="#ffaa00" style=dashed';           el = "$SYS"
            elif fill == "#00c853": es = 'color="#00c853" style=dashed';           el = "audit"
            else:                   es = 'color="#00d4ff" style=solid';            el = "data"
            L.append(f'    broker -> {tid} [{es} label="{el}" fontcolor="#ccddee"]')
        L.append("")

    # Findings → broker
    if vuln_nodes:
        L.append("    // ── Findings → Broker ──────────────────────────────────")
        for v in vuln_nodes:
            L.append(f'    {v["id"]} -> broker'
                     f' [color="#ff3b5c55" style=dotted arrowhead=none]')
        L.append("")

    # Legend
    L.append("    // ── Legend ─────────────────────────────────────────────")
    L.append('    subgraph cluster_legend {')
    L.append('        label="Legend  (→ WRITE  ⇢ READ)" fontcolor="#8899aa"'
             ' color="#333333" style=dashed fontsize=9')
    L.append('        leg1 [label="CRITICAL / HIGH" shape=box style=filled'
             ' fillcolor="#ff3b5c" fontcolor=white fontsize=9]')
    L.append('        leg2 [label="MEDIUM RISK"     shape=box style=filled'
             ' fillcolor="#ffaa00" fontcolor="#1a1a1a" fontsize=9]')
    L.append('        leg3 [label="SECURE / LOW"    shape=box style=filled'
             ' fillcolor="#00c853" fontcolor=white fontsize=9]')
    L.append('        leg4 [label="Topic: Critical" shape=note style=filled'
             ' fillcolor="#ff3b5c" fontcolor=white fontsize=9]')
    L.append('        leg5 [label="Topic: Data"     shape=note style=filled'
             ' fillcolor="#1a3a5a" fontcolor=white fontsize=9]')
    L.append('        leg1 -> leg2 -> leg3 -> leg4 -> leg5 [style=invis]')
    L.append("    }")
    L.append("}")

    dot_src = "\n".join(L)
    with open(dot_path, "w") as fh: fh.write(dot_src)
    print(f"  {G}[✓]{RS} DOT → {dot_path}")

    base = dot_path.replace(".dot","")
    for fmt in ("png","svg"):
        out = f"{base}.{fmt}"
        try:
            r = subprocess.run(["dot",f"-T{fmt}",dot_path,"-o",out],
                               capture_output=True, timeout=15)
            stderr_msg = r.stderr.decode().strip()
            if r.returncode == 0:
                if stderr_msg:
                    print(f"  {Y}[w]{RS} {fmt.upper()} rendered with warnings: {stderr_msg[:120]}")
                else:
                    print(f"  {G}[✓]{RS} {fmt.upper()} → {out}")
            else:
                print(f"  {R}[✗]{RS} {fmt.upper()} render failed:")
                print(f"       {stderr_msg[:200]}")
        except FileNotFoundError:
            import platform
            if platform.system() == "Darwin":
                hint = "brew install graphviz"
            elif platform.system() == "Linux":
                hint = "sudo apt install graphviz"
            else:
                hint = "Install from https://graphviz.org/download/"
            print(f"  {Y}[!]{RS} graphviz not found — install it first: {C}{hint}{RS}")
            print(f"       Then render manually: dot -T{fmt} {dot_path} -o {out}")
            break   # No point trying SVG if PNG already failed
        except subprocess.TimeoutExpired:
            print(f"  {Y}[!]{RS} {fmt.upper()} render timed out (graph too large?)")

# ═══════════════════════════════════════════════════════════════════════════════
# MODE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _banner():
    OR = "\033[38;2;255;165;0m"   # orange (for accent lines)
    SWARM_ART = r"""
                     .     .
                      \   /
                .------\_/------.
               /   ____/ \____   \
          ____/___/           \___\____
         /    \      .-----.      /    \
        /______\====/  MQTT \====/______\
               /    | BROKER|    \
         _____/     '---+---'     \_____
        /   _ \        /|\        / _   \
       /___/ \_\   PUB  |  SUB   /_/ \___\
             \  \       |       /  /
              \  '------o------'  /
               '----.  / \  .----'
                    \_/   \_/
    """
    SWARM_LETTERS = f"""{B}{G}
   ███████╗██╗    ██╗ █████╗ ██████╗ ███╗   ███╗
   ██╔════╝██║    ██║██╔══██╗██╔══██╗████╗ ████║
   ███████╗██║ █╗ ██║███████║██████╔╝██╔████╔██║
   ╚════██║██║███╗██║██╔══██║██╔══██╗██║╚██╔╝██║
   ███████║╚███╔███╔╝██║  ██║██║  ██║██║ ╚═╝ ██║
   ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝{RS}"""
    SWARM_SUB = f"""{G}
     SECURITY WEAKNESS ANALYSER FOR MQTT
          RECONNAISSANCE AND MAPPING{RS}"""
    SWARM_MODES = f"""
{OR}  Recon | Live Probing | AI Analysis | Chatbot |{RS}
{OR}         | Threat Model | Reporting |{RS}"""
    print(G + SWARM_ART + RS)
    print(SWARM_LETTERS)
    print(SWARM_SUB)
    print(SWARM_MODES)
    print()

def _section(title):
    print(f"\n{C}{'─'*3} {B}{title}{RS}")

def _out_prefix(args, default_name="swarm"):
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = getattr(args, "host", None) or "local"
    out  = getattr(args, "output", None) or f"{default_name}_{host}_{ts}"
    return out

def _check_api(args):
    key = getattr(args, "api_key", None) or os.environ.get("ANTHROPIC_API_KEY","")
    if not key:
        print(f"\n  {R}[✗] No API key.  Use --api-key or set ANTHROPIC_API_KEY env var.{RS}\n")
        sys.exit(1)
    return key

def _make_data(args):
    return RawProbeResult(
        host=getattr(args,"host","unknown"),
        port=getattr(args,"mqtt_port",1883),
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

def _do_ssh(args, data):
    if getattr(args,"ssh_user",None):
        _section("PHASE 2 — SSH AUTO-FETCH")
        ssh_fetch_files(data, args.host,
                        getattr(args,"ssh_port",22),
                        args.ssh_user,
                        getattr(args,"ssh_pass",None),
                        getattr(args,"ssh_key",None))
    else:
        print(f"  {DIM}SSH skipped — add --ssh-user to auto-fetch config/ACL/logs{RS}")

# ─────────────────────────────────────────────────────────────────────────────
# MODE 1: MANUAL
# ─────────────────────────────────────────────────────────────────────────────
def mode_manual(args):
    _banner()
    _section("MANUAL TESTING GUIDE — MQTT")
    print(f"""
  This mode points you to the MQTT manual testing lab.

  {B}Lab repository:{RS}
    {C}{MQTT_UST_URL}{RS}

  {B}What it covers:{RS}
    Scenario 1 — Authentication          (anonymous access, missing password_file)
    Scenario 2 — Authorization           (missing ACLs, any-user-owns-all-topics)
    Scenario 3 — Retained Message Abuse  (persistent payload injection)
    Scenario 4 — Wildcard Abuse          (# and $SYS/# eavesdropping)
    Scenario 5 — Topic/Message Flood     (DoS via publish storms)
    Bonus      — CVE-2021-34432 RCA      (zero-length topic crash)

  {B}Hardware setup:{RS}
    Broker  — Raspberry Pi running Mosquitto
    Client  — ESP32 publishing sensor data / receiving commands

  {B}Quick clone:{RS}
    git clone {MQTT_UST_URL}

  {DIM}After manual testing, run:  python3 swarm.py audit --host <broker-ip>{RS}
""")

# ─────────────────────────────────────────────────────────────────────────────
# MODE 2: FULL AI AUDIT
# ─────────────────────────────────────────────────────────────────────────────
def mode_audit(args):
    _banner()
    api_key = _check_api(args)
    data    = _make_data(args)
    prefix  = _out_prefix(args, "swarm_audit")

    _section("PHASE 1 — LIVE MQTT PROBING")
    ok = run_all_probes(data, getattr(args,"mqtt_user",None),
                             getattr(args,"mqtt_pass",None),
                             getattr(args,"tls",False))
    if not ok: return

    _do_ssh(args, data)

    _section("PHASE 3 — AI ANALYSIS")
    analysis = analyse_with_sonnet(data, api_key)
    evidence = _evidence_summary(data)
    judge    = haiku_judge(analysis.get("findings",[]), evidence, api_key)
    analysis["findings"] = merge_judge(analysis.get("findings",[]), judge)

    _section("PHASE 4 — OUTPUTS")
    score = analysis.get("overall_score","?"); risk = analysis.get("risk_level","?")
    sc    = SEV_COL.get(risk if risk in SEV_COL else "INFO", "")
    print(f"\n  {B}Score:{RS} {sc}{score}/100  [{risk}]{RS}")
    print(f"  {B}Summary:{RS} {analysis.get('executive_summary','')[:120]}...")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        n = sum(1 for f in analysis.get("findings",[]) if f.get("severity")==sev)
        if n: print(f"  {SEV_COL[sev]}{B}{n:>3}x {sev}{RS}")

    pdf_path = f"{prefix}_report.pdf"
    dot_path = f"{prefix}_topology.dot"
    generate_pdf(analysis, data, pdf_path, mode_label="Security Audit")
    generate_dot_svg(data, analysis, dot_path)
    print(f"\n  {G}{B}[✓] Audit complete{RS}")
    print(f"      PDF     → {pdf_path}")
    print(f"      DOT     → {dot_path}")
    print(f"      PNG/SVG → {dot_path.replace('.dot','.png')}  /  {dot_path.replace('.dot','.svg')}\n")

# ─────────────────────────────────────────────────────────────────────────────
# MODE 3: FUME FUZZER
# ─────────────────────────────────────────────────────────────────────────────
def mode_fume(args):
    _banner()
    host     = getattr(args,"host",None)
    port     = getattr(args,"mqtt_port",1883)
    username = getattr(args,"mqtt_user",None)
    password = getattr(args,"mqtt_pass",None)
    fume_dir = getattr(args,"fume_path","./FUME-Fuzzing-MQTT-Brokers")

    _section("FUZZ WITH FUME")

    fume_py = os.path.join(fume_dir, "fuzz.py")
    fume_ok = os.path.exists(fume_py)

    if not fume_ok:
        print(f"""
  {Y}[!]{RS} FUME not found at: {fume_dir}

  {B}Install FUME:{RS}
    git clone {FUME_URL}
    cd FUME-Fuzzing-MQTT-Brokers
    pip install -r requirements.txt

  {B}Then re-run:{RS}
    python3 swarm.py fume --host {host or '<broker-ip>'} --fume-path ./FUME-Fuzzing-MQTT-Brokers
""")
        return

    print(f"\n  {G}[✓]{RS} FUME found at {fume_dir}")
    if not host:
        print(f"  {R}[✗]{RS} --host required for fuzzing\n"); return

    cred_flags = f"--username {username} --password {password}" if username else ""

    print(f"""
  {B}Target:{RS} {host}:{port}
  {B}Credentials:{RS} {username or '(anonymous)'}

  {B}Recommended FUME commands for this target:{RS}

  {C}# 1. Basic CONNECT/PUBLISH fuzzing{RS}
  python3 {fume_py} --broker {host} --port {port} {cred_flags} \\
      --fuzz-connect --fuzz-publish --iterations 1000

  {C}# 2. Topic fuzzing (long topics, special chars, null bytes){RS}
  python3 {fume_py} --broker {host} --port {port} {cred_flags} \\
      --fuzz-topics --topic-len 1000 --iterations 500

  {C}# 3. Payload size fuzzing (test message_size_limit){RS}
  python3 {fume_py} --broker {host} --port {port} {cred_flags} \\
      --fuzz-payload --max-payload 131072 --iterations 500

  {C}# 4. QoS / retain flag fuzzing{RS}
  python3 {fume_py} --broker {host} --port {port} {cred_flags} \\
      --fuzz-qos --fuzz-retain --iterations 300

  {C}# 5. Zero-length topic (CVE-2021-34432 style){RS}
  python3 {fume_py} --broker {host} --port {port} {cred_flags} \\
      --fuzz-topics --min-topic-len 0 --max-topic-len 1 --iterations 100

  {DIM}Monitor broker with:  tail -f /var/log/mosquitto/mosquitto.log{RS}
  {DIM}Or via SSH:           journalctl -u mosquitto -f{RS}

  {B}For a smarter AI-targeted fuzzing strategy, run:{RS}
    python3 swarm.py smartfuzz --host {host} --api-key <key>
""")

# ─────────────────────────────────────────────────────────────────────────────
# MODE 4: SMARTFUZZ (AI-powered fuzzing strategy)
# ─────────────────────────────────────────────────────────────────────────────
def mode_smartfuzz(args):
    _banner()
    api_key = _check_api(args)
    prefix  = _out_prefix(args, "swarm_smartfuzz")

    _section("SMARTFUZZ — AI-POWERED FUZZING STRATEGY")
    print(f"\n  {C}Tell SWARM about your deployment for a targeted fuzzing plan.{RS}\n")

    def ask(prompt, default=""):
        val = input(f"  {B}[?]{RS} {prompt}: ").strip()
        return val or default

    num_clients  = ask("Number of MQTT clients in deployment", "unknown")
    device_types = ask("Device types (ESP32, RPi, PLC, sensor, etc.)", "IoT devices")
    purpose      = ask("Deployment purpose (smart home, industrial, agriculture, etc.)")
    crown_jewel  = ask("Crown jewel — most critical asset to protect")
    concerns     = ask("Specific security concerns (Enter to skip)")
    arch_file    = ask("Path to architecture/context file (Enter to skip)")

    arch_content = ""
    if arch_file and os.path.exists(arch_file):
        try:
            with open(arch_file,"r",errors="replace") as fh:
                arch_content = fh.read(20_000)
            print(f"  {G}[✓]{RS} Loaded: {arch_file}")
        except Exception as e: print(f"  {Y}[!]{RS} Could not read: {e}")

    # Optional: SSH fetch for config context
    data = _make_data(args)
    if getattr(args,"ssh_user",None) and getattr(args,"host",None):
        print("")
        _section("Loading broker config via SSH...")
        ssh_fetch_files(data, args.host,
                        getattr(args,"ssh_port",22),
                        args.ssh_user,
                        getattr(args,"ssh_pass",None),
                        getattr(args,"ssh_key",None))

    context = {
        "broker_host":    getattr(args,"host","not specified"),
        "num_clients":    num_clients,
        "device_types":   device_types,
        "purpose":        purpose,
        "crown_jewel":    crown_jewel,
        "concerns":       concerns,
        "architecture":   arch_content[:8000] if arch_content else "",
        "mosquitto_conf": data.config_content[:5000],
        "acl_file":       data.acl_content[:3000],
        "fume_url":       FUME_URL,
    }

    _section("PHASE — AI ANALYSIS")
    print(f"  {M}[Sonnet]{RS} Generating targeted fuzzing strategy...")
    strategy = smartfuzz_strategy(context, api_key)

    print(f"  {C}[Haiku]{RS}  Validating strategy quality and accuracy...")
    judge    = haiku_judge_strategy(strategy, context, api_key)

    # Display results
    _section("FUZZING STRATEGY")
    print(f"\n  {B}Summary:{RS}     {strategy.get('summary','')}")
    print(f"  {B}Risk profile:{RS} {strategy.get('risk_profile','')}")
    print(f"  {B}Haiku verdict:{RS} {judge.get('overall_quality','?')} — {judge.get('summary','')}\n")

    print(f"  {B}Priority Targets:{RS}")
    for pt in strategy.get("priority_targets",[]):
        print(f"    {R}▶{RS} {pt.get('target','')} — {pt.get('reason','')}")
        print(f"      {DIM}Approach: {pt.get('fuzz_approach','')}{RS}")

    print(f"\n  {B}FUME Commands:{RS}")
    for cmd in strategy.get("fume_commands",[]):
        print(f"    {C}${RS} {cmd.get('command','')}")
        print(f"      {DIM}{cmd.get('purpose','')} → {cmd.get('expected_result','')}{RS}")

    print(f"\n  {B}Crown Jewel Attack Paths:{RS}")
    for ap in strategy.get("crown_jewel_attack_paths",[]):
        sev   = ap.get("severity","HIGH")
        sc_   = SEV_COL.get(sev,Y)
        print(f"    {sc_}{B}[{sev}]{RS} {ap.get('path','')}")
        for i, step in enumerate(ap.get("steps",[]), 1):
            print(f"      {i}. {step}")

    flagged = judge.get("flagged_commands",[])
    if flagged:
        print(f"\n  {Y}[Haiku flags — review before running]{RS}")
        for f in flagged:
            print(f"    {Y}⚠{RS} {f.get('command','')} — {f.get('issue','')}")

    # Save to text report + DOT
    report_path = f"{prefix}_strategy.txt"
    with open(report_path,"w") as fh:
        fh.write(f"SWARM SmartFuzz Strategy\n{'='*60}\n")
        fh.write(f"Generated: {data.timestamp}\n")
        fh.write(f"Target: {getattr(args,'host','unknown')}\n")
        fh.write(f"Haiku quality: {judge.get('overall_quality','?')}\n\n")
        fh.write(json.dumps(strategy, indent=2))
        fh.write(f"\n\n{'='*60}\nHaiku Validation\n{'='*60}\n")
        fh.write(json.dumps(judge, indent=2))
    print(f"\n  {G}[✓]{RS} Strategy saved → {report_path}")

    if data.wildcard_messages or data.anonymous_accepted or data.default_creds_found:
        dummy_analysis = {
            "overall_score": 30, "risk_level": "HIGH",
            "findings": [{"id":"SF-001","severity":"HIGH","title":"Deployment attack surface identified",
                          "description": strategy.get("summary",""),
                          "evidence":"See SmartFuzz strategy","remediation":"See FUME commands",
                          "reference":"","haiku_confidence":85,"haiku_genuine":True,"haiku_note":""}],
            "executive_summary": strategy.get("summary",""),
            "technical_summary": strategy.get("risk_profile",""),
            "positive_findings":[], "recommendations":
                [c.get("command","") for c in strategy.get("fume_commands",[])[:4]],
        }
        dot_path = f"{prefix}_topology.dot"
        generate_dot_svg(data, dummy_analysis, dot_path)

# ─────────────────────────────────────────────────────────────────────────────
# MODE 5: EXPERT CHAT
# ─────────────────────────────────────────────────────────────────────────────
def mode_chat(args):
    _banner()
    api_key = _check_api(args)

    _section("EXPERT CHAT — MQTT Security AI Assistant")

    # Load context
    context_files = {"config":"","acl":"","logs":""}
    if getattr(args,"ssh_user",None) and getattr(args,"host",None):
        print(f"\n  {C}[→]{RS} Loading broker config via SSH for context...")
        data = _make_data(args)
        ssh_fetch_files(data, args.host,
                        getattr(args,"ssh_port",22),
                        args.ssh_user,
                        getattr(args,"ssh_pass",None),
                        getattr(args,"ssh_key",None))
        context_files = {"config":data.config_content,
                         "acl":   data.acl_content,
                         "logs":  data.log_content}

    # Load any extra context file
    extra_ctx = getattr(args,"context_file",None)
    if extra_ctx and os.path.exists(extra_ctx):
        with open(extra_ctx,"r",errors="replace") as fh:
            context_files["extra"] = fh.read(15000)
        print(f"  {G}[✓]{RS} Extra context: {extra_ctx}")

    has_ctx = any(v for v in context_files.values())
    system  = build_chat_system_prompt(context_files)
    history = []

    print(f"""
  {G}SWARM Expert Chat is ready.{RS}
  {DIM}Context loaded: {('mosquitto.conf, ' if context_files.get('config') else '') +
                        ('ACL file, '       if context_files.get('acl')    else '') +
                        ('broker logs'      if context_files.get('logs')   else '') or
                        'none — answers will be general (add --ssh-user for live context)'}
  Commands: 'exit' to quit  |  'clear' to reset history  |  'save' to save transcript{RS}
""")

    transcript = []
    try:
        while True:
            try: user_input = input(f"  {C}{B}You:{RS} ").strip()
            except EOFError: break

            if not user_input: continue
            if user_input.lower() in ("exit","quit","q"):
                print(f"\n  {DIM}Chat ended.{RS}\n"); break
            if user_input.lower() == "clear":
                history.clear(); transcript.clear()
                print(f"  {DIM}History cleared.{RS}"); continue
            if user_input.lower() == "save":
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = f"swarm_chat_{ts}.txt"
                with open(path,"w") as fh:
                    fh.write(f"SWARM Expert Chat — {ts}\n{'='*60}\n\n")
                    fh.write("\n".join(transcript))
                print(f"  {G}[✓]{RS} Saved → {path}"); continue

            history.append({"role":"user","content":user_input})
            try:
                response = _call_claude(SONNET_MODEL, system, history,
                                        api_key, max_tokens=1200)
            except Exception as e:
                print(f"  {R}[✗]{RS} API error: {e}"); history.pop(); continue

            # Strip any residual markdown and render cleanly in terminal
            clean = _strip_md(response)
            print(f"\n  {M}{B}SWARM{RS} {DIM}──────────────────────────────────────────{RS}")
            for para in clean.split("\n\n"):
                para = para.strip()
                if not para:
                    continue
                lines = para.split("\n")
                for line in lines:
                    # List items already have leading spaces — wrap them differently
                    if line.startswith("  -") or line.startswith("  •"):
                        print(textwrap.fill(line, width=74,
                                            initial_indent="  ",
                                            subsequent_indent="    "))
                    else:
                        print(textwrap.fill(line, width=74,
                                            initial_indent="  ",
                                            subsequent_indent="  "))
                print()
            print(f"  {DIM}──────────────────────────────────────────────────────────{RS}\n")
            history.append({"role":"assistant","content":response})
            transcript.extend([f"You: {user_input}", f"SWARM: {response}", ""])
            # Cap history
            if len(history) > 40: history = history[-40:]

    except KeyboardInterrupt:
        print(f"\n\n  {DIM}Chat session ended.{RS}\n")

# ─────────────────────────────────────────────────────────────────────────────
# MODE 6: TOPOLOGY DIAGRAM (standalone)
# ─────────────────────────────────────────────────────────────────────────────
def mode_diagram(args):
    _banner()
    api_key = _check_api(args)
    data    = _make_data(args)
    prefix  = _out_prefix(args, "swarm_diagram")

    _section("TOPOLOGY DIAGRAM")

    if getattr(args,"host",None):
        _section("PHASE 1 — LIVE PROBING")
        ok = run_all_probes(data,
                            getattr(args,"mqtt_user",None),
                            getattr(args,"mqtt_pass",None),
                            getattr(args,"tls",False))
        if not ok: return
        _do_ssh(args, data)

        _section("PHASE 2 — AI ANALYSIS (for diagram labels)")
        analysis = analyse_with_sonnet(data, api_key)
        judge    = haiku_judge(analysis.get("findings",[]), _evidence_summary(data), api_key)
        analysis["findings"] = merge_judge(analysis.get("findings",[]), judge)
    else:
        print(f"  {DIM}No --host provided — generating template diagram{RS}")
        data.host = "mqtt-broker"; data.port = 1883
        analysis  = {"overall_score":50,"risk_level":"UNKNOWN",
                     "findings":[],"executive_summary":"No live data.",
                     "technical_summary":"","positive_findings":[],"recommendations":[]}

    dot_path = f"{prefix}_topology.dot"
    generate_dot_svg(data, analysis, dot_path)
    print(f"\n  {G}{B}[✓] Diagram generated{RS}")
    print(f"      DOT → {dot_path}")
    print(f"      PNG → {dot_path.replace('.dot','.png')}")
    print(f"      SVG → {dot_path.replace('.dot','.svg')}\n")

# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE MENU (no subcommand given)
# ═══════════════════════════════════════════════════════════════════════════════

def _collect_common():
    """Interactively collect common connection args."""
    def ask(prompt, default=None):
        suffix = f" [{default}]" if default else ""
        val = input(f"    {B}{prompt}{suffix}:{RS} ").strip()
        return val or default or ""
    print(f"\n  {B}Connection details{RS} {DIM}(press Enter to skip optional fields){RS}")
    host      = ask("Broker IP / hostname")
    mqtt_port = int(ask("MQTT port","1883") or "1883")
    mqtt_user = ask("MQTT username (optional)")
    mqtt_pass = ask("MQTT password (optional)") if mqtt_user else ""
    tls       = ask("Use TLS? [y/N]","N").lower().startswith("y")
    ssh_user  = ask("SSH username (for auto config-fetch, optional)")
    ssh_pass  = ask("SSH password (optional)") if ssh_user else ""
    ssh_key   = ask("SSH key path (optional)") if ssh_user else ""
    ssh_port  = int(ask("SSH port","22") or "22")
    api_key   = ask("Anthropic API key (or press Enter to use env var)") or \
                os.environ.get("ANTHROPIC_API_KEY","")
    output    = ask("Output file prefix (optional)") or None
    return argparse.Namespace(
        host=host, mqtt_port=mqtt_port, mqtt_user=mqtt_user or None,
        mqtt_pass=mqtt_pass or None, tls=tls,
        ssh_user=ssh_user or None, ssh_pass=ssh_pass or None,
        ssh_key=ssh_key or None, ssh_port=ssh_port,
        api_key=api_key, output=output, context_file=None,
        fume_path="./FUME-Fuzzing-MQTT-Brokers")

def interactive_menu():
    _banner()
    print(f"""
  {B}Select a mode:{RS}

  {C}[1]{RS}  Manual Testing      {DIM}MQTT lab guide + setup instructions{RS}
  {C}[2]{RS}  AI Audit            {DIM}Full audit: live probe + SSH + Sonnet + Haiku judge{RS}
  {C}[3]{RS}  Fuzz with FUME      {DIM}Evolutionary MQTT broker fuzzing commands{RS}
  {C}[4]{RS}  SmartFuzz           {DIM}AI-targeted fuzzing strategy for your deployment{RS}
  {C}[5]{RS}  Expert Chat         {DIM}MQTT security AI assistant (context-aware){RS}
  {C}[6]{RS}  Topology Diagram    {DIM}DOT + PNG + SVG security graph{RS}
  {C}[q]{RS}  Quit
""")
    choice = input(f"  {B}Choice [1-6]:{RS} ").strip().lower()
    if choice == "1":
        mode_manual(argparse.Namespace())
    elif choice in ("2","3","4","5","6"):
        args = _collect_common()
        {"2": mode_audit, "3": mode_fume, "4": mode_smartfuzz,
         "5": mode_chat,  "6": mode_diagram}[choice](args)
    elif choice in ("q","quit","exit"):
        print(f"\n  {DIM}Goodbye.{RS}\n")
    else:
        print(f"\n  {Y}Invalid choice.{RS}\n")

# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser():
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--host",       help="Broker IP or hostname")
    parent.add_argument("--mqtt-port",  type=int, default=1883,   dest="mqtt_port")
    parent.add_argument("--mqtt-user",  default=None,             dest="mqtt_user")
    parent.add_argument("--mqtt-pass",  default=None,             dest="mqtt_pass")
    parent.add_argument("--tls",        action="store_true")
    parent.add_argument("--ssh-user",   default=None,             dest="ssh_user")
    parent.add_argument("--ssh-pass",   default=None,             dest="ssh_pass")
    parent.add_argument("--ssh-key",    default=None,             dest="ssh_key")
    parent.add_argument("--ssh-port",   type=int, default=22,     dest="ssh_port")
    parent.add_argument("--api-key",    default=os.environ.get("ANTHROPIC_API_KEY"), dest="api_key")
    parent.add_argument("--output",     default=None,
                        help="Output file prefix (default: swarm_<host>_<timestamp>)")

    parser = argparse.ArgumentParser(
        prog="swarm",
        description=f"{TOOL_NAME} — {TOOL_DESC}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    sub = parser.add_subparsers(dest="mode")

    sub.add_parser("manual",    parents=[parent], help="Open MQTT manual testing guide")

    p_audit = sub.add_parser("audit", parents=[parent],
                              help="Full AI-powered security audit")
    _ = p_audit  # no extra args needed

    p_fume = sub.add_parser("fume", parents=[parent],
                             help="Fuzz broker with FUME fuzzer")
    p_fume.add_argument("--fume-path", default="./FUME-Fuzzing-MQTT-Brokers", dest="fume_path")

    p_sf = sub.add_parser("smartfuzz", parents=[parent],
                           help="AI-powered targeted fuzzing strategy")
    p_sf.add_argument("--context-file", default=None, dest="context_file",
                      help="Path to architecture/context file")

    p_chat = sub.add_parser("chat", parents=[parent],
                             help="Expert AI chatbot (MQTT security assistant)")
    p_chat.add_argument("--context-file", default=None, dest="context_file",
                        help="Additional context file to load into chat")

    sub.add_parser("diagram", parents=[parent],
                   help="Generate DOT/PNG/SVG security topology graph")

    return parser

def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.mode:
        interactive_menu()
        return

    dispatch = {
        "manual":    mode_manual,
        "audit":     mode_audit,
        "fume":      mode_fume,
        "smartfuzz": mode_smartfuzz,
        "chat":      mode_chat,
        "diagram":   mode_diagram,
    }
    dispatch[args.mode](args)

if __name__ == "__main__":
    main()
