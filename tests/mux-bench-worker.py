#!/usr/bin/env python3
"""Namespace-local target and load generator for the TLS Mux netem benchmark."""

import argparse
import json
import socket
import struct
import threading
import time


def receive_exact(sock, size):
    received = 0
    while received < size:
        block = sock.recv(min(256 * 1024, size - received))
        if not block:
            raise RuntimeError(f"early EOF after {received} bytes")
        received += len(block)


def target(port):
    listener = socket.create_server(("127.0.0.1", port), reuse_port=False)
    while True:
        conn, _ = listener.accept()

        def serve(stream):
            try:
                request = b""
                while len(request) < 8:
                    block = stream.recv(8 - len(request))
                    if not block:
                        return
                    request += block
                remaining = struct.unpack("!Q", request)[0]
                payload = bytes(256 * 1024)
                while remaining:
                    count = min(remaining, len(payload))
                    stream.sendall(payload[:count])
                    remaining -= count
            finally:
                stream.close()

        threading.Thread(target=serve, args=(conn,), daemon=True).start()


def receive_socks_reply(sock):
    head = sock.recv(4)
    if len(head) != 4 or head[1] != 0:
        raise RuntimeError(f"SOCKS CONNECT failed: {head!r}")
    lengths = {1: 4, 4: 16}
    length = lengths.get(head[3])
    if head[3] == 3:
        length = receive_one(sock)
    if length is None:
        raise RuntimeError("invalid SOCKS address type")
    receive_exact(sock, length + 2)


def receive_one(sock):
    value = sock.recv(1)
    if len(value) != 1:
        raise RuntimeError("early SOCKS EOF")
    return value[0]


def rss_kib(pid, field):
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as status:
            for line in status:
                if line.startswith(field + ":"):
                    return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        pass
    return 0


def client(args):
    barrier = threading.Barrier(args.flows)
    durations = [None] * args.flows
    peak = {"portal": 0, "vector": 0}
    sampling = threading.Event()
    sampling.set()

    def monitor():
        while sampling.is_set():
            peak["portal"] = max(peak["portal"], rss_kib(args.portal_pid, "VmRSS"))
            peak["vector"] = max(peak["vector"], rss_kib(args.vector_pid, "VmRSS"))
            time.sleep(0.01)

    def flow(index):
        try:
            sock = socket.create_connection(("127.0.0.1", args.socks_port), timeout=60)
            sock.sendall(b"\x05\x01\x00")
            if sock.recv(2) != b"\x05\x00":
                raise RuntimeError("SOCKS authentication failed")
            sock.sendall(
                b"\x05\x01\x00\x01\x7f\x00\x00\x01"
                + struct.pack("!H", args.target_port)
            )
            receive_socks_reply(sock)
            barrier.wait(timeout=60)
            started = time.monotonic()
            sock.sendall(struct.pack("!Q", args.bytes))
            receive_exact(sock, args.bytes)
            durations[index] = time.monotonic() - started
            sock.close()
        except Exception as error:
            durations[index] = str(error)
            barrier.abort()

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    threads = [threading.Thread(target=flow, args=(index,)) for index in range(args.flows)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    sampling.clear()
    monitor_thread.join()
    errors = [value for value in durations if not isinstance(value, float)]
    if errors:
        raise RuntimeError(str(errors))
    peak["portal"] = max(peak["portal"], rss_kib(args.portal_pid, "VmHWM"))
    peak["vector"] = max(peak["vector"], rss_kib(args.vector_pid, "VmHWM"))
    elapsed = max(durations)
    total = args.bytes * args.flows
    print(json.dumps({
        "flows": args.flows,
        "mib": total / 1024 / 1024,
        "seconds": round(elapsed, 3),
        "mbps": round(total * 8 / elapsed / 1_000_000, 2),
        "portal_peak_rss_mib": round(peak["portal"] / 1024, 2),
        "vector_peak_rss_mib": round(peak["vector"] / 1024, 2),
    }, sort_keys=True))


def wait_port(port, host):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} did not open")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="role", required=True)
    target_parser = sub.add_parser("target")
    target_parser.add_argument("--port", type=int, required=True)
    wait_parser = sub.add_parser("wait")
    wait_parser.add_argument("--port", type=int, required=True)
    wait_parser.add_argument("--host", default="127.0.0.1")
    client_parser = sub.add_parser("client")
    client_parser.add_argument("--flows", type=int, required=True)
    client_parser.add_argument("--bytes", type=int, required=True)
    client_parser.add_argument("--socks-port", type=int, required=True)
    client_parser.add_argument("--target-port", type=int, required=True)
    client_parser.add_argument("--portal-pid", type=int, required=True)
    client_parser.add_argument("--vector-pid", type=int, required=True)
    args = parser.parse_args()
    if args.role == "target":
        target(args.port)
    elif args.role == "wait":
        wait_port(args.port, args.host)
    else:
        client(args)


if __name__ == "__main__":
    main()
