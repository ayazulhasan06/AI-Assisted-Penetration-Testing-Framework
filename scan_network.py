# =========================================
# SecureProbe - Network Scanner
# Optimized, Threaded, Job-Ready
# =========================================

import socket
import threading
from queue import Queue
import logging
import time

# ------------------------------
# Configuration
# ------------------------------
THREAD_COUNT = 100
SOCKET_TIMEOUT = 0.5

COMMON_PORTS = [
    # Core Services
    21, 22, 23, 25, 53, 69, 80, 110, 123,
    137, 138, 139, 143, 161, 389, 443, 445,

    # Remote Access
    3389, 5900, 2222,

    # Databases
    3306, 5432, 6379, 27017, 9200, 1433, 1521,

    # Web / App Servers
    8080, 8081, 8443, 8000, 8888, 9000, 3000, 5000,

    # Cloud / DevOps
    2375, 2376, 6443, 10250, 10255, 9090, 5601,

    # Messaging / Queue
    5672, 15672, 61616, 9092,

    # File Sharing / Misc
    2049, 873, 1900
]

# ------------------------------
# Shared State (Thread-Safe)
# ------------------------------
port_queue = Queue()
open_ports = []
lock = threading.Lock()

# ------------------------------
# Port Scan Function
# ------------------------------
def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        result = sock.connect_ex((target_ip, port))
        sock.close()

        if result == 0:
            with lock:
                open_ports.append(port)
            print(f"[+] Port {port} is open")
            logging.info(f"Port {port} open on {target_ip}")

    except Exception as e:
        logging.debug(f"Port {port} scan error: {e}")

# ------------------------------
# Worker Thread
# ------------------------------
def worker(target_ip):
    while True:
        try:
            port = port_queue.get_nowait()
        except:
            break
        scan_port(target_ip, port)
        port_queue.task_done()

# ------------------------------
# Main Scan Function (USED BY main.py)
# ------------------------------
def scan(target_ip):
    logging.info(f"Network scan started for {target_ip}")
    start_time = time.time()

    # Reset state
    open_ports.clear()
    while not port_queue.empty():
        port_queue.get()

    print("\n[+] Starting Network Scan...")
    print(f"Scanning target: {target_ip} using multi-threaded scanner\n")

    # Load ports
    for port in COMMON_PORTS:
        port_queue.put(port)

    # Start threads
    threads = []
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=worker, args=(target_ip,))
        t.daemon = True
        t.start()
        threads.append(t)

    port_queue.join()

    elapsed = round(time.time() - start_time, 2)

    print("\nScan Complete. Open Ports:")
    print(sorted(open_ports))
    print(f"\nScan Time: {elapsed} seconds")

    logging.info(
        f"Network scan completed for {target_ip} | "
        f"Open ports: {open_ports} | Time: {elapsed}s"
    )

    return sorted(open_ports)
