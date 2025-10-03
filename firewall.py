#!/usr/bin/env python3
"""
net_guard.py
- Sniffs all packets on the host (requires admin/root)
- Logs everything to src/system.log
- Detects simple rate-based DDoS and ARP-MITM heuristics
- Maintains src/blacklist.txt and applies OS-level block (netsh on Windows, iptables on Linux)
- When Ctrl+U is HELD, console shows current blacklist as |x.x.x.x|; releasing returns to live logs
Requirements:
  pip install scapy keyboard colorama
Windows: install Npcap
Run as Administrator / root.
"""

import os
import sys
import time
import threading
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

# third-party
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ARP, Ether, conf, get_if_list
except Exception:
    print("scapy not found. Install: pip install scapy")
    raise

try:
    import keyboard
except Exception:
    print("keyboard not found. Install: pip install keyboard")
    raise

try:
    from colorama import init as colorama_init, Fore, Style
except Exception:
    print("colorama not found. Install: pip install colorama")
    raise

colorama_init()

# ---------- CONFIG ----------
BASE_DIR = Path.cwd() / "src"
LOG_FILE = BASE_DIR / "system.log"
BLACKLIST_FILE = BASE_DIR / "blacklist.txt"

WINDOW_SECONDS = 10         # sliding window for rate detection
PACKET_THRESHOLD = 200      # if >= this many packets from same src within WINDOW_SECONDS -> blacklist
CHECK_INTERVAL = 2          # seconds between evaluations
MAX_RECENT_LINES = 200      # in-memory recent log lines for live view
IGNORE_IPS = {"127.0.0.1", "::1", "0.0.0.0"}  # don't block these
CAPTURE_INTERFACE = None    # None = default / all; set to "Ethernet" or similar if needed
# ----------------------------

BASE_DIR.mkdir(parents=True, exist_ok=True)

# runtime state
ip_tracks = defaultdict(lambda: deque())
arp_map = defaultdict(set)
blacklist = set()
recent_logs = deque(maxlen=MAX_RECENT_LINES)
lock = threading.Lock()
show_blacklist_flag = threading.Event()  # set while Ctrl+U is held

def ts_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"

def write_log(s):
    line = f"[{ts_now()}] {s}"
    with lock:
        recent_logs.append(line)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def load_blacklist():
    if BLACKLIST_FILE.exists():
        with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
            for ln in f:
                ip = ln.strip()
                if ip:
                    blacklist.add(ip)
    # try to re-apply blocks
    for ip in list(blacklist):
        os_block_ip(ip, persist=False)
    write_log(f"Loaded blacklist ({len(blacklist)} entries)")

def save_blacklist():
    with lock:
        with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
            for ip in sorted(blacklist):
                f.write(ip + "\n")

def os_block_ip(ip, persist=True):
    if ip in IGNORE_IPS:
        write_log(f"SKIP blocking {ip} (ignored)")
        return False
    try:
        if sys.platform.startswith("win"):
            rule_name = f"net_guard_block_{ip.replace(':','_')}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "enable=yes"
            ]
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # IPv4 iptables block
            cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        write_log(f"OS_BLOCK success for {ip}")
        return True
    except Exception as e:
        write_log(f"OS_BLOCK failed for {ip}: {e}")
        return False

def add_to_blacklist(ip):
    with lock:
        if ip in blacklist:
            return False
        blacklist.add(ip)
        save_blacklist()
    ok = os_block_ip(ip, persist=False)
    write_log(f"ADDED_TO_BLACKLIST {ip} os_blocked={ok}")
    return True

def evaluate_loop():
    while True:
        time.sleep(CHECK_INTERVAL)
        now = time.time()
        to_block = []
        with lock:
            for ip, dq in list(ip_tracks.items()):
                while dq and (now - dq[0] > WINDOW_SECONDS):
                    dq.popleft()
                if len(dq) >= PACKET_THRESHOLD and ip not in blacklist and ip not in IGNORE_IPS:
                    to_block.append((ip, len(dq)))
        for ip, cnt in to_block:
            write_log(f"THRESHOLD_EXCEEDED ip={ip} count={cnt}")
            add_to_blacklist(ip)
            with lock:
                ip_tracks.pop(ip, None)

def mitm_check(ip, mac):
    with lock:
        macs = arp_map[ip]
        if mac not in macs and len(macs) > 0:
            # suspicious: same IP seen with different MAC
            write_log(f"MITM_SUSPECT ip={ip} macs_seen={list(macs)+[mac]}")
            # optional: blacklist automatically - commented out:
            # add_to_blacklist(ip)
        macs.add(mac)

def pkt_handler(pkt):
    now = time.time()
    src_ip = None
    dst_ip = None
    proto = "OTHER"
    info = ""
    try:
        if ARP in pkt:
            psrc = pkt[ARP].psrc
            hwsrc = pkt[ARP].hwsrc
            pdst = pkt[ARP].pdst
            write_log(f"PKT ARP psrc={psrc} pdst={pdst} hwsrc={hwsrc}")
            mitm_check(psrc, hwsrc)
            return
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if TCP in pkt:
                proto = "TCP"
                info = f"{pkt[TCP].sport}->{pkt[TCP].dport} flags={pkt[TCP].flags}"
            elif UDP in pkt:
                proto = "UDP"
                info = f"{pkt[UDP].sport}->{pkt[UDP].dport}"
            else:
                proto = f"IP_PROTO_{pkt[IP].proto}"
                info = pkt.summary()
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            proto = "IPv6"
            info = pkt.summary()
        else:
            info = pkt.summary()
    except Exception as e:
        info = f"PARSE_ERR:{e}"

    if not src_ip:
        src_ip = "unknown"

    write_log(f"PKT src={src_ip} dst={dst_ip} proto={proto} info={info}")

    with lock:
        if src_ip in blacklist or src_ip in IGNORE_IPS:
            return
        dq = ip_tracks[src_ip]
        dq.append(now)
        while dq and (now - dq[0] > WINDOW_SECONDS):
            dq.popleft()

def sniff_thread(iface=None):
    write_log(f"Sniffer starting on iface={iface or 'default (all)'} - may require admin/root")
    # capture all traffic (no BPF) -> heavy; if you want filter, set bpf="port 444" etc.
    sniff(filter=None, prn=pkt_handler, store=0, iface=iface)

def ui_loop():
    clear = lambda: os.system('cls' if os.name == 'nt' else 'clear')
    while True:
        if show_blacklist_flag.is_set():
            clear()
            print(Fore.RED + "=== BLACKLIST (hold Ctrl+U) ===" + Style.RESET_ALL)
            with lock:
                if not blacklist:
                    print("(no banned IPs)")
                else:
                    for ip in sorted(blacklist):
                        print(f"|{ip}|")
            time.sleep(0.2)
            continue
        clear()
        print(Fore.GREEN + "=== LIVE LOG (press and hold Ctrl+U to view blacklist) ===" + Style.RESET_ALL)
        with lock:
            # show last ~30 lines or fewer
            for line in list(recent_logs)[-30:]:
                print(line)
        time.sleep(0.5)

# keyboard handlers: use on_press / on_release + check ctrl held
def _on_press(e):
    try:
        # some platforms provide .name; fallback to .scan_code if needed
        if getattr(e, "name", "") == "u" and keyboard.is_pressed("ctrl"):
            show_blacklist_flag.set()
    except Exception:
        pass

def _on_release(e):
    try:
        if getattr(e, "name", "") == "u":
            show_blacklist_flag.clear()
    except Exception:
        pass

def list_ifaces():
    try:
        ifs = get_if_list()
        write_log(f"Available interfaces: {ifs}")
    except Exception:
        pass

def main():
    load_blacklist()
    list_ifaces()

    # start evaluator
    t_eval = threading.Thread(target=evaluate_loop, daemon=True)
    t_eval.start()

    # start sniffer
    t_sniff = threading.Thread(target=sniff_thread, args=(CAPTURE_INTERFACE,), daemon=True)
    t_sniff.start()

    # keyboard hooks (global). keyboard module needs admin on Windows.
    keyboard.on_press(_on_press)
    keyboard.on_release(_on_release)

    # UI main loop (blocks)
    try:
        ui_loop()
    except KeyboardInterrupt:
        write_log("Exiting (KeyboardInterrupt)")
        sys.exit(0)
    except Exception as e:
        write_log(f"UI error: {e}")
        raise

if __name__ == "__main__":
    main()
