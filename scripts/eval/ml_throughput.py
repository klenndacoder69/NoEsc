import socket
import time
import json
import sys
import os

# The socket path must match what the ML listener uses
SOCKET_PATH = "/tmp/noesc_ml.sock"
NUM_EVENTS = 10000

# A dummy malicious event that looks exactly like what the C++ daemon sends
dummy_event = json.dumps({
    "pid": 1234,
    "ppid": 1233,
    "uid": 1000,
    "euid": 0,
    "exe": "/usr/bin/sudo",
    "args": ["su", "-"],
    "syscall": "execve",
    "cwd": "/home/user"
}) + "\n"

def test_ml_throughput():
    if os.geteuid() != 0:
        print("[-] Permission denied: the ML socket is owned by root.")
        print("    Run with: sudo .venv/bin/python scripts/eval/ml_throughput.py")
        sys.exit(1)

    if not os.path.exists(SOCKET_PATH):
        print(f"[-] ML socket not found at {SOCKET_PATH}")
        print("Ensure 'noesc-ml-listener' is running (sudo systemctl start noesc-ml-listener)")
        sys.exit(1)

    print(f"[*] Connecting to NoEsc ML Engine at {SOCKET_PATH}...")
    try:
        # The ML listener uses SOCK_DGRAM (connectionless datagram socket)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    except Exception as e:
        print(f"[-] Failed to create socket: {e}")
        sys.exit(1)

    print(f"[*] Sending {NUM_EVENTS} synthetic events to the ML model...")

    start_time = time.time()

    for _ in range(NUM_EVENTS):
        try:
            client.sendto(dummy_event.encode('utf-8'), SOCKET_PATH)
        except Exception as e:
            print(f"[-] Failed to send event: {e}")
            break

    client.close()

    end_time = time.time()
    elapsed = end_time - start_time
    eps = NUM_EVENTS / elapsed

    print("======================================")
    print(" ML Engine Throughput Results")
    print("======================================")
    print(f"  Total Events Sent: {NUM_EVENTS}")
    print(f"  Time Taken:        {elapsed:.3f} seconds")
    print(f"  Throughput (EPS):  {eps:.0f} Events/Second")
    print("======================================")
    print("Note: This measures the raw ingestion and prediction capability of the Python ML process.")

if __name__ == "__main__":
    test_ml_throughput()

