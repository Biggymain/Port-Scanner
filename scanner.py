import socket
import threading
import json
import csv
import os
from queue import Queue
from datetime import datetime

# --- Settings ---
OUTPUT_DIR = "scan_results"
NUM_THREADS = 200
TARGET_IP = input("Enter target IP or hostname: ").strip()

# Ensure results folder exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Files
cve_file = "cve_signatures.json"
results_json = os.path.join(OUTPUT_DIR, "results.json")
results_csv = os.path.join(OUTPUT_DIR, "results.csv")
checkpoint_file = os.path.join(OUTPUT_DIR, "checkpoint.json")
error_log = os.path.join(OUTPUT_DIR, "errors.log")

# Load CVE database
with open(cve_file, "r") as f:
    cve_db = json.load(f)

q = Queue()
seen_ports = set()
lock = threading.Lock()


# --- Load existing results ---
existing_results = []
if os.path.exists(results_json):
    with open(results_json, "r") as f:
        try:
            existing_results = json.load(f)
            for entry in existing_results:
                seen_ports.add(entry["port"])
        except:
            existing_results = []


# --- Save Results ---
def save_result(entry):
    with lock:
        if entry["port"] in seen_ports:
            return
        seen_ports.add(entry["port"])

        # JSON
        data = existing_results + [entry]
        with open(results_json, "w") as f:
            json.dump(data, f, indent=4)

        # CSV
        write_header = not os.path.exists(results_csv)
        with open(results_csv, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "banner", "cve"])
            if write_header:
                writer.writeheader()
            writer.writerow(entry)


# --- Save Errors ---
def log_error(port, error_msg):
    with lock:
        with open(error_log, "a") as f:
            f.write(f"{port}:{error_msg}\n")


# --- Save checkpoint ---
def save_checkpoint(port):
    with lock:
        with open(checkpoint_file, "w") as f:
            json.dump({"last_port": port}, f)


def load_checkpoint():
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, "r") as f:
            try:
                return json.load(f).get("last_port", 1)
            except:
                return 1
    return 1


# --- Protocol-aware Banner Grab ---
def grab_banner(sock, port):
    try:
        sock.settimeout(2)
        if port in [80, 8080, 8000, 8888]:
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        elif port in [443, 8443]:
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        elif port in [25, 587]:
            sock.sendall(b"EHLO example.com\r\n")
        elif port in [143, 993]:
            sock.sendall(b". CAPABILITY\r\n")
        else:
            sock.sendall(b"HELLO\r\n")
        return sock.recv(2048).decode(errors="ignore").strip()
    except:
        return None


# --- Worker Thread ---
def worker(target_ip, total_ports):
    while not q.empty():
        port = q.get()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            conn = sock.connect_ex((target_ip, port))
            if conn == 0:  # Port open
                banner = grab_banner(sock, port)
                entry = {"port": port, "banner": banner or "", "cve": ""}

                if banner:
                    for signature, cve in cve_db.items():
                        if signature.lower() in banner.lower():
                            entry["cve"] = cve
                            break

                save_result(entry)

                msg = f"[OPEN] Port {port}"
                if banner:
                    msg += f" | Banner: {banner}"
                if entry["cve"]:
                    msg += f" | ⚠️ CVE: {entry['cve']}"
                print(msg)
            sock.close()
        except Exception as e:
            log_error(port, str(e))
        finally:
            save_checkpoint(port)
            q.task_done()


# --- Progress Indicator ---
def progress_monitor(total_ports):
    scanned = 0
    start_time = datetime.now()
    while not q.empty():
        with lock:
            scanned = total_ports - q.qsize()
        elapsed = (datetime.now() - start_time).seconds
        rate = scanned / elapsed if elapsed > 0 else 0
        eta = (total_ports - scanned) / rate if rate > 0 else 0
        print(f"[*] Progress: {scanned}/{total_ports} ports scanned | ETA: {int(eta)}s", end="\r")


# --- Main Scan ---
def scan_host(target_ip):
    start_port = 1
    end_port = 65535
    total_ports = end_port - start_port + 1

    for port in range(start_port, end_port + 1):
        if port not in seen_ports:
            q.put(port)

    print(f"[*] Starting scan of {target_ip} on {total_ports} ports...")

    threads = []
    for _ in range(NUM_THREADS):
        t = threading.Thread(target=worker, args=(target_ip, total_ports))
        t.daemon = True
        t.start()
        threads.append(t)

    # Progress monitor runs in background
    pm = threading.Thread(target=progress_monitor, args=(total_ports,))
    pm.daemon = True
    pm.start()

    q.join()
    print("\n[+] Scan complete. Results saved in", OUTPUT_DIR)


if __name__ == "__main__":
    scan_host(TARGET_IP)
