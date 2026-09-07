#!/usr/bin/env python3
"""Run an end-to-end TLS Mux throughput/RSS sample through Toxiproxy."""

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request


def api(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:8474{path}", data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request) as response:
        return response.read()


def receive_exact(sock, size):
    received = 0
    while received < size:
        block = sock.recv(min(256 * 1024, size - received))
        if not block:
            raise RuntimeError(f"early EOF after {received} bytes")
        received += len(block)
    return received


def target_server(stop, listener):
    listener.settimeout(0.2)

    def serve(conn):
        try:
            request = b""
            while len(request) < 8:
                part = conn.recv(8 - len(request))
                if not part:
                    return
                request += part
            remaining = struct.unpack("!Q", request)[0]
            payload = bytes(256 * 1024)
            while remaining:
                count = min(remaining, len(payload))
                conn.sendall(payload[:count])
                remaining -= count
        finally:
            conn.close()

    try:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            threading.Thread(target=serve, args=(conn,), daemon=True).start()
    finally:
        listener.close()


def run_flow(port, target_port, byte_count, barrier, results, index):
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=60)
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS authentication failed")
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target_port))
        reply = receive_reply(sock)
        if reply != 0:
            raise RuntimeError(f"SOCKS CONNECT failed: {reply}")
        barrier.wait(timeout=60)
        started = time.monotonic()
        sock.sendall(struct.pack("!Q", byte_count))
        receive_exact(sock, byte_count)
        results[index] = time.monotonic() - started
        sock.close()
    except Exception as error:
        results[index] = str(error)
        barrier.abort()


def receive_reply(sock):
    head = receive_bytes(sock, 4)
    if head[3] == 1:
        address_len = 4
    elif head[3] == 3:
        address_len = receive_bytes(sock, 1)[0]
    elif head[3] == 4:
        address_len = 16
    else:
        raise RuntimeError(f"unknown SOCKS address type: {head[3]}")
    receive_bytes(sock, address_len + 2)
    return head[1]


def receive_bytes(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("early EOF")
        chunks.extend(chunk)
    return bytes(chunks)


def rss_kib(pid):
    output = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True)
    return int(output.strip())


def established_tcp(pid):
    try:
        output = subprocess.check_output(
            ["lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-sTCP:ESTABLISHED"],
            text=True, stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return max(0, len(output.splitlines()) - 1)


def wait_port(port, host="127.0.0.1", deadline=10):
    until = time.monotonic() + deadline
    while time.monotonic() < until:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {host}:{port} did not open")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/release/nowhere")
    parser.add_argument("--rtt-ms", type=int, required=True)
    parser.add_argument("--flows", type=int, required=True)
    parser.add_argument("--mib-per-flow", type=int, default=64)
    parser.add_argument("--mux", choices=("0", "1"), default="1")
    parser.add_argument("--profile", default="throughput")
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--external-proxy", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    env = os.environ.copy()
    env.update({"NOW_TRANSPORT_MEMORY_PROFILE": args.profile, "RUST_LOG": "off"})
    log = "debug" if args.debug else "none"
    output = None if args.debug else subprocess.DEVNULL
    portal = subprocess.Popen(
        [args.binary, f"portal://secret@:2000?log={log}"], env=env,
        stdout=output, stderr=output,
    )
    vector = None
    stop = threading.Event()
    target_listener = socket.socket()
    target_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    target_listener.bind(("127.0.0.1", 0))
    target_listener.listen()
    target_port = target_listener.getsockname()[1]
    server = threading.Thread(
        target=target_server, args=(stop, target_listener), daemon=True,
    )
    server.start()
    try:
        wait_port(2000)
        if not args.external_proxy:
            api("DELETE", "/proxies/nowhere")
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    try:
        if not args.external_proxy:
            api("POST", "/proxies", {
                "name": "nowhere", "listen": "0.0.0.0:2001", "upstream": "192.168.64.1:2000",
            })
            latency = args.rtt_ms // 2
            for stream in ("upstream", "downstream"):
                api("POST", f"/proxies/nowhere/toxics", {
                    "name": f"latency-{stream}", "type": "latency", "stream": stream,
                    "toxicity": 1.0, "attributes": {"latency": latency, "jitter": 0},
                })
        wait_port(2001, args.proxy_host)
        # Let a just-updated proxy path complete one RTT before the measured
        # client opens its first carrier. Transfer timing starts later.
        time.sleep(max(args.rtt_ms * 2 / 1000, 1.0))
        vector = subprocess.Popen(
            [args.binary, f"vector://secret@{args.proxy_host}:2001?mux={args.mux}&socks=127.0.0.1:1080&log={log}"],
            env=env, stdout=output, stderr=output,
        )
        wait_port(1080)
        topology = {}

        def capture_topology():
            connections = established_tcp(vector.pid)
            if connections is not None:
                topology["tls_carriers"] = max(0, connections - args.flows)

        barrier = threading.Barrier(args.flows, action=capture_topology)
        durations = [0.0] * args.flows
        byte_count = args.mib_per_flow * 1024 * 1024
        peak = {"portal": rss_kib(portal.pid), "vector": rss_kib(vector.pid)}
        sampling = True

        def sample():
            while sampling:
                peak["portal"] = max(peak["portal"], rss_kib(portal.pid))
                peak["vector"] = max(peak["vector"], rss_kib(vector.pid))
                time.sleep(0.1)

        monitor = threading.Thread(target=sample, daemon=True)
        monitor.start()
        threads = [threading.Thread(
            target=run_flow,
            args=(1080, target_port, byte_count, barrier, durations, index),
            daemon=True,
        ) for index in range(args.flows)]
        wall_start = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        setup_and_transfer = time.monotonic() - wall_start
        sampling = False
        monitor.join()
        errors = [result for result in durations if not isinstance(result, float)]
        if errors:
            raise RuntimeError(f"flow failures: {errors}")
        total = byte_count * args.flows
        transfer = max(durations)
        result = {
            "rtt_ms": args.rtt_ms, "flows": args.flows, "mux": int(args.mux),
            "profile": args.profile, "mib": total / 1024 / 1024,
            "seconds": round(transfer, 3), "mbps": round(total * 8 / transfer / 1_000_000, 2),
            "setup_and_transfer_seconds": round(setup_and_transfer, 3),
            "flow_max_seconds": round(max(durations), 3),
            "portal_peak_rss_mib": round(peak["portal"] / 1024, 2),
            "vector_peak_rss_mib": round(peak["vector"] / 1024, 2),
        }
        result.update(topology)
        print(json.dumps(result, sort_keys=True))
    finally:
        stop.set()
        for process in (vector, portal):
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()


if __name__ == "__main__":
    main()
