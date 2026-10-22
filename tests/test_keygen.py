#!/usr/bin/env python3
"""应用层集成测试：ML-KEM keygen 消费本项目随机链。

覆盖：
  1. 直连模式：keygen 成功、输出指纹与往返结果
  2. 新鲜性：真随机源两次 keygen 密钥不同
  3. 确定性：mock_det 同配置两次 keygen 密钥相同（种子->密钥可复现）
  4. fail-closed：mock_stuck 源 -> keygen REFUSED、exit 1、零密钥产出
  5. 服务模式：-s 从 qrng-server 取种子，两次密钥不同

用法: test_keygen.py <qrng-keygen> <qrng-server>
"""
import os
import re
import subprocess
import sys
import tempfile
import time


def run_keygen(keygen, args):
    return subprocess.run([keygen] + args, capture_output=True, timeout=60)


def wait_socket(path, timeout=5.0):
    import socket
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


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    keygen, server = sys.argv[1], sys.argv[2]
    tmp = tempfile.mkdtemp(prefix="qrng-keygen-")

    def fingerprint(r):
        m = re.search(rb"pubkey\s+SHA-256: ([0-9a-f]{64})", r.stdout)
        assert m, r.stdout + r.stderr
        return m.group(1)

    # 1: 直连 keygen（偏置源 + 如实声明 H，走条件化）
    r = run_keygen(keygen, ["mock_biased", "0.6", "--health", "off",
                            "--min-entropy", "5.5"])
    assert r.returncode == 0, r.stderr
    assert b"roundtrip : encap/decap OK" in r.stdout, r.stdout
    fp1 = fingerprint(r)
    print("  direct: keygen + roundtrip OK")
    # 2+3: 种子敏感性与复现性（mock 是确定性源——"每次运行都新鲜"
    #      只有真硬件能演示，见 README 的 VM 实况命令）：
    #      同一配置两次 => 同密钥（复现）；换起始计数 => 密钥变（敏感）
    ra = run_keygen(keygen, ["mock_det", "7", "--health", "off",
                             "--condition", "off", "--drbg", "off"])
    assert ra.returncode == 0, ra.stderr
    rb = run_keygen(keygen, ["mock_det", "7", "--health", "off",
                             "--condition", "off", "--drbg", "off"])
    assert rb.returncode == 0, rb.stderr
    assert fingerprint(ra) == fingerprint(rb), "same seed must reproduce key"
    print("  same seed -> reproducible key")
    r = run_keygen(keygen, ["mock_det", "8", "--health", "off",
                            "--condition", "off", "--drbg", "off"])
    assert r.returncode == 0, r.stderr
    assert fingerprint(ra) != fingerprint(r), "different seeds must differ"
    print("  different seeds -> different keys")

    # 4: fail-closed（卡死源 -> 拒绝生成密钥）
    r = run_keygen(keygen, ["mock_stuck"])
    assert r.returncode == 1, "keygen must refuse on stuck source"
    assert b"KEYGEN REFUSED" in r.stderr, r.stderr
    assert b"RCT" in r.stderr, r.stderr
    assert b"SHA-256" not in r.stdout, "no key material may be produced"
    print("  fail-closed: stuck source -> keygen REFUSED, no key output")

    # 5: 服务模式（种子来自 qrng-server）
    sock = os.path.join(tmp, "kg.sock")
    log = os.path.join(tmp, "kg.log")
    import socket as sio
    p = subprocess.Popen([server, "mock_biased", "0.6", "--foreground",
                          "--socket", sock, "--log", log, "--health", "off",
                          "--condition", "off", "--drbg", "off"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_socket(sock), "server did not listen"
        r1 = run_keygen(keygen, ["-s", sock])
        assert r1.returncode == 0, r1.stderr
        r2 = run_keygen(keygen, ["-s", sock])
        assert r2.returncode == 0, r2.stderr
        assert fingerprint(r1) != fingerprint(r2), "service seeds must differ"
        assert b"from qrng-server" in r1.stdout, r1.stdout
        print("  service mode: two keygens via qrng-server, different keys")
    finally:
        p.terminate()
        p.wait(timeout=5)

    print("ALL KEYGEN TESTS PASSED")


if __name__ == "__main__":
    main()