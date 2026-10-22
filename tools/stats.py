#!/usr/bin/env python3
"""对随机字节文件做粗统计检验（纯标准库）。

用法: python3 tools/stats.py <file.bin>

输出：
  1) 字节频率卡方（df=255）
  2) most-common-value min-entropy 估计（90B 最入门的估计器：-log2 p_max）
  3) 每个比特位的 1 占比（monobit）

注意：这是 demo 级检验，不是 SP 800-90B 的完整熵评估；
生产用的 min_entropy_mbits 声明需要规范里的正式评估流程。
"""
import argparse
import collections
import math


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    a = ap.parse_args()

    with open(a.file, "rb") as f:
        data = f.read()
    n = len(data)
    if n == 0:
        raise SystemExit("empty file")

    freq = collections.Counter(data)
    top_byte, top_count = freq.most_common(1)[0]
    pmax = top_count / n
    h_mcv = -math.log2(pmax)

    expected = n / 256.0
    chi2 = sum((freq.get(b, 0) - expected) ** 2 for b in range(256)) / expected
    df = 255
    sd = math.sqrt(2 * df)

    print(f"file                    : {a.file}")
    print(f"bytes                   : {n}")
    print(f"most common byte        : 0x{top_byte:02x} ({top_count} times)")
    print(f"min-entropy (MCV est.)  : {h_mcv:.3f} bits/byte   (8.000 = perfect)")
    print(f"chi-square (df=255)     : {chi2:.1f}   (~{df}, sd {sd:.0f})")
    ok = abs(chi2 - df) < 4 * sd
    print(f"byte uniformity         : {'OK' if ok else 'SUSPICIOUS'}")
    print()
    print("monobit per bit position (expect 0.5000):")
    worst = 0.0
    for bit in range(8):
        ones = sum((b >> bit) & 1 for b in data)
        p = ones / n
        worst = max(worst, abs(p - 0.5))
        print(f"  bit {bit}: {p:.4f}")
    z = 2.0 * worst * math.sqrt(n)
    print(f"max bit deviation       : {worst:.4f}  ({z:.1f} sigma; >~4 sigma is a red flag)")

    if not ok or z > 4:
        print()
        print("=> deviation detected: this stream is NOT behaving like uniform bytes")


if __name__ == "__main__":
    main()
