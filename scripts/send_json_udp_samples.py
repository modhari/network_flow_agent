import json
import random
import socket
import time


def main():
    host = "127.0.0.1"
    port = 6343
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for _ in range(200):
        msg = {
            "ts": time.time(),
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "src_port": 51514,
            "dst_port": 443,
            "proto": "TCP",
            "latency_ms": random.choice([20, 30, 40, 180, 220, 300]),
            "bytes": 1200,
            "packets": 10,
        }
        sock.sendto(json.dumps(msg).encode(), (host, port))
        time.sleep(0.02)


if __name__ == "__main__":
    main()
