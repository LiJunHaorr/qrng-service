#!/usr/bin/env python3
"""v4 服务化集成测试（纯标准库）。

覆盖：
  1. Unix socket 取数（mock_det 全链路，长度/确定性）
  2. 同一服务器两次取数不同（DRBG 状态推进）
  3. TCP 模式取数
  4. fail-closed 跨进程边界：file 后端读穿后，之后所有请求
     都返回同一个错误（服务不退出、拒绝供数）

用法: test_service.py <qrng-server> <qrng-fetch>
"""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time


def wait_socket(path, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(path)
                s.close()
                return True
            except OSError:
                pass
        time.sleep(0.05)
    return False


def start_server(server, backend, config, extra, sock):
    log = sock + ".log"
    proc = subprocess.Popen(
        [server, backend, config, "--foreground", "--socket", sock,
         "--log", log] + extra,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_socket(sock):
        proc.terminate()
        raise SystemExit(f"server did not listen at {sock}")
    return proc


def fetch(fetch_bin, sock, n):
    return subprocess.run(
        [fetch_bin, "-s", sock, "-n", str(n)],
        capture_output=True, timeout=30)


def fetch_tcp(fetch_bin, port, n):
    return subprocess.run(
        [fetch_bin, "-t", f"127.0.0.1:{port}", "-n", str(n)],
        capture_output=True, timeout=30)


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    server, fetch_bin = sys.argv[1], sys.argv[2]
    tmp = tempfile.mkdtemp(prefix="qrng-svc-")

    # --- 1/2: Unix socket，mock_det 全链路（默认 health+cond+drbg） ---
    sock1 = os.path.join(tmp, "one.sock")
    p1 = start_server(server, "mock_det", "42", [], sock1)
    try:
        r = fetch(fetch_bin, sock1, 16)
        assert r.returncode == 0, r.stderr
        out1 = r.stdout.split(b"\n")[0]
        r = fetch(fetch_bin, sock1, 16)
        assert r.returncode == 0, r.stderr
        out2 = r.stdout.split(b"\n")[0]
        # 同一服务器：DRBG 状态推进 => 两次输出不同
        assert out1 != out2, "consecutive fetches must differ"
        print("  unix socket: fetch OK, state advances across requests")

        # 服务器重启：mock_det 种子确定性 => 输出与第一次完全一致
        p1.terminate()
        p1.wait(timeout=5)
        p1b = start_server(server, "mock_det", "42", [], sock1)
        try:
            r = fetch(fetch_bin, sock1, 16)
            assert r.returncode == 0, r.stderr
            out1b = r.stdout.split(b"\n")[0]
            assert out1b == out1, "server restart must reproduce stream"
            print("  unix socket: server restart reproduces stream (det backend)")
        finally:
            p1b.terminate()
            p1b.wait(timeout=5)
    finally:
        if p1.poll() is None:
            p1.terminate()
            p1.wait(timeout=5)

    # --- 3: TCP 模式 ---
    port = 47777
    log2 = os.path.join(tmp, "tcp.log")
    p2 = subprocess.Popen(
        [server, "mock_det", "0", "--foreground", "--tcp", str(port),
         "--log", log2],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 5
        ok = False
        while time.time() < deadline and not ok:
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
                s.close()
                ok = True
            except OSError:
                time.sleep(0.05)
        assert ok, "tcp server did not listen"
        r = fetch_tcp(fetch_bin, port, 100)
        assert r.returncode == 0, r.stderr
        assert b"fetched : 100 bytes" in r.stdout
        print("  tcp: fetch OK")
    finally:
        p2.terminate()
        p2.wait(timeout=5)

    # --- 4: fail-closed 跨进程边界 ---
    raw = os.path.join(tmp, "raw250.bin")
    with open(raw, "wb") as f:
        f.write(bytes(i % 256 for i in range(250)))
    sock4 = os.path.join(tmp, "fail.sock")
    p4 = start_server(server, "file", raw,
                      ["--health", "off", "--condition", "off", "--drbg", "off"],
                      sock4)
    try:
        r1 = fetch(fetch_bin, sock4, 100)
        assert r1.returncode == 0, r1.stderr
        r2 = fetch(fetch_bin, sock4, 100)
        assert r2.returncode == 0, r2.stderr
        r3 = fetch(fetch_bin, sock4, 100)  # 300 字节耗尽
        assert r3.returncode == 1, "exhaustion must fail"
        err3 = r3.stderr.decode()
        assert "exhausted" in err3, err3
        r4 = fetch(fetch_bin, sock4, 100)  # 终态：仍失败、同一错误
        assert r4.returncode == 1, "terminal state must persist"
        err4 = r4.stderr.decode()
        assert err4 == err3, f"terminal error must stay identical:\n{err3}\nvs\n{err4}"
        # 服务进程还活着：fail-closed 是"拒绝供数"而不是"崩溃退出"
        assert p4.poll() is None, "server must stay alive while refusing"
        print("  fail-closed: exhaustion -> persistent refusal, identical error, server alive")
    finally:
        p4.terminate()
        p4.wait(timeout=5)

    print("ALL SERVICE TESTS PASSED")


if __name__ == "__main__":
    main()