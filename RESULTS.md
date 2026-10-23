# QRNG-demo 全链路整理文档

> 更新日期：2026-10-21（应用层补齐后）
> 代码：本机 `D:\3\Zcode-hg\QRNG-demo\qrng-service` / VM `pqc@pqcvm03:~/Desktop/qrng-service`
> 一句话：从 Quantis 量子熵源到 ML-KEM 密钥，按 NIST 90B/90A/90C 分层搭出完整供给链，fail-closed 贯穿全程。

## 0. 总览：做了什么

| 里程碑 | 内容 | 规范依据 | 主要代码 |
|---|---|---|---|
| v0 | 熵源直连 + 可插拔后端 + fail-closed 状态机 + 熵记账 | — | `src/core.c`、`src/source/*` |
| v1 | 健康测试：RCT + APT + 启动测试 | 90B §4.3/4.4 | `src/health/health.c` |
| v2 | 条件化：hash_df + in/out 熵记账 | 90B §10.3.1 | `src/condition/condition.c`、`sha256.c` |
| v3 | DRBG：AES-256-CTR_DRBG（no-DF） | 90A §10.2.1 | `src/drbg/aes.c`、`ctr_drbg.c` |
| v4 | 服务化：守护进程 + Unix socket/TCP | 90C 衔接 | `apps/qrng_server.c`、`qrng_fetch.c` |
| 应用层 | **ML-KEM-768 keygen 消费端应用** | 复刻生产链用法 | `apps/qrng_keygen.c` |

最终链路（v2 起默认全开，任一环节故障 = 终态 = 拒绝供数）：

```
Quantis USB ── 启动测试(1024B) ── RCT/APT 连续监测 ── hash_df 条件化(记账 in≥8/H·out)
     └── 48B 种子 ── CTR_DRBG(AES-256) ──┬── qrng-cli 直接出数
                                          ├── qrng-server 常驻服务 ── qrng-fetch 取数
                                          └── qrng-keygen ── ML-KEM-768 密钥
```

---

## 1. 做的应用

**`apps/qrng_keygen.c`——ML-KEM-768 密钥生成器**（VM 已构建：
`~/Desktop/qrng-service/build-quantis/qrng-keygen`）。

- **种子注入**：链上取 64 字节（`kem->length_keypair_seed`），交给 liboqs 的
  `OQS_KEM_keypair_derand()` 显式种子 API（选它而不是挂钩全局
  `OQS_randombytes`，是因为后者返回 void 无法传失败——显式注入让
  fail-closed 在应用边界一行 if 就能兑现）
- **两种形态**：
  - 直连：`qrng-keygen quantis 0 [-o mykey]`（进程内整条链）
  - 服务：`qrng-keygen -s /tmp/qrng-demo.sock`（从常驻 qrng-server 取种子，
    生产链 QRNG-Provider + 消费者分进程拓扑的同构形态）
- **产出**：公私钥指纹（SHA-256，用的是本项目自带的 `qrng_sha256`）、
  encap/decap 往返验证、可选 `PREFIX.pub`/`PREFIX.sk` 文件
- **fail-closed 到密钥产出那一刻**：源故障 => `KEYGEN REFUSED`、exit 1、
  **不产出任何密钥**（stdout 连指纹都没有，测试有断言）
- 依赖：liboqs 0.16（用 VM `~/pqc-lab/liboqs` 现成构建）+ OpenSSL

## 2. Demo 
主战场 VM（`ssh pqc@10.20.54.129`，Quantis USB 已插、SDK 已装、免 sudo）。
每个版本一个招牌演示：

```bash
cd ~/Desktop/qrng-service

# v2 ：偏置源 原始 vs 条件化（注意 --drbg off 两边都不能省：
# v3 起 DRBG 默认开，不关的话输出全是 DRBG 的 AES 流，偏置被盖住，
# 两边统计都会"假装 OK"——实测踩过的文档坑）
./build-quantis/qrng-cli mock_biased 0.6 -n 100000 --health off --condition off --drbg off -o raw.bin
./build-quantis/qrng-cli mock_biased 0.6 -n 100000 --health off --condition on --drbg off --min-entropy 5.5 -o cond.bin
python3 tools/stats.py raw.bin    # 卡方 37059 SUSPICIOUS（min-entropy 5.896）
python3 tools/stats.py cond.bin   # 卡方 278 OK（min-entropy 7.806）

# v1 招牌：卡死源触发 RCT 报警 + 进程 fail-closed（exit 1）
./build-quantis/qrng-cli mock_stuck -n 8

# v3 招牌：设备瓶颈 vs DRBG 瞬时速率（10MB）
./build-quantis/qrng-cli quantis 0 -n 10000000 --drbg off -o /dev/null  # ~50s（198KB/s）
./build-quantis/qrng-cli quantis 0 -n 10000000 -o /dev/null            # ~3s（3.7MB/s，设备只给1072B）

# v3：reseed 间隔演示
./build-quantis/qrng-cli mock_det 0 -n 16 --requests 5 --reseed-interval 2 --health off --condition off
#   -> counter: 144B（48 种子 + 2×48 reseed）；drbg: 2 reseeds

# v4：服务化
./build-quantis/qrng-server quantis 0 && ./build-quantis/qrng-fetch -n 10000000 -o a.bin
tail /tmp/qrng-demo.log && pkill -x qrng-server

# 应用层：keygen（真硬件，两次密钥不同=量子新鲜性；卡死源=REFUSED）
./build-quantis/qrng-keygen quantis 0 -o mykey
./build-quantis/qrng-keygen quantis 0            # 密钥与上次不同
./build-quantis/qrng-keygen mock_stuck           # KEYGEN REFUSED + exit 1
./build-quantis/qrng-server quantis 0 && ./build-quantis/qrng-keygen -s /tmp/qrng-demo.sock
```

本机 Windows（MinGW）用于开发：`build6\`（无 Quantis SDK/liboqs，用
`cmake -G "MinGW Makefiles" -DQRNG_WITH_QUANTIS=OFF`，keygen 目标自动跳过）。

## 3. 测试

ctest **5/5**（VM，Ubuntu 24.04 / gcc 13.3 / cmake 3.28；本机 MinGW 除
POSIX 专用目标外同样全过）：

| 测试 | 覆盖 |
|---|---|
| `test_health.c` | **阈值算法对照规范 Table 2 全部数值**（α=2⁻²⁰：H=0.5/1/2/4/8 → 410/311/177/62/13）；RCT 示例 C=11；RCT/APT 故障注入；启动测试门控；核心 fail-closed；非法参数拒绝 |
| `test_condition.c` | SHA-256 四个标准向量（含 100 万 'a'）+ 增量=一次性；hash_df 前缀布局/counter 链接逐字节验证；in/out 记账（H=5.5,n=64→94/64）；>8160 分块（8160+1840）；条件化路径 fail-closed（cond_out=0） |
| `test_drbg.c` | AES-256 两个向量（FIPS 197 + 800-38A，经参考库核验）；**DRBG 首块用 AES 原语手工复算规范算法比对**；确定性/状态推进/种子敏感性；reseed 边界语义；核心记账（只读 48B 种子；interval=2、5 请求→2 次 reseed）；fail-closed |
| `test_service.py` | Unix socket/TCP 取数；服务器重启复现流；**fail-closed 跨进程**（读穿后所有请求同一错误、服务存活拒绝） |
| `test_keygen.py` | keygen+往返；同种子复现/异种子异钥；**KEYGEN REFUSED 零密钥产出**；服务模式两次密钥不同 |

测试纪律：所有规范公式下载 90A/90B 原文核对；关键算法用"手工复算 +
参考库交叉验证"测实现（不是拿实现测实现）——这一纪律先后抓出
阈值向量抄写错误、reseed 边界理解偏差、AES 向量记忆错误 3 个 bug。

真硬件验收（pqcvm03）：原始流卡方 246.2/min-entropy 7.809；DRBG 输出
卡方 253.2/7.982；服务化 10MB+5MB 源字节 1072 不变；keygen 量子新鲜性。

## 4. 怎么调用到 QRNG

**调用路径**（自底向上）：

```
Quantis USB 设备 (0aba:0102, Ellisys Quantis)
  ↑ libusb-1.0
SDK libQuantis（~/idq-quantis，由 ~/Quantis-v18.03.08 源码编译）
  ↑ QuantisCount / QuantisOpen / QuantisReadHandled / QuantisClose
src/source/quantis.c（qrng_backend_t 接口实现）
  ↑ GCC constructor 自注册到 core 的后端表
src/core.c（qrng_core_generate 调度）
```

- `quantis.c` 的实现：`create` 检查 `QuantisCount(QUANTIS_DEVICE_USB)` +
  `QuantisOpen`；`read` 用 `QuantisReadHandled` 按 **4096 字节分块**循环读
  （r<0 报错、r==0 视为故障，都是 fail-closed）；`destroy` 调 `QuantisClose`
- **可插拔**：mock_det/mock_stuck/mock_biased/file 五个后端实现同一
  `qrng_backend_t` 接口，`__attribute__((constructor))` 自注册——加后端
  不改 core。踩过的坑：静态库里未被引用的 constructor 对象不会被链接器
  拉入、自注册静默失效 → CMake 用 **OBJECT 库**
- SDK 本身的三个编译坑（FindUSB1.cmake 路径、CMake 2.6 兼容性、
  `throw(...)` 与 C++17 冲突）及 udev 权限（root:plugdev 0664，免 sudo）
  的解法都记录在 README「Quantis SDK 构建」一节
- 设备物理吞吐 ~198 KB/s（全链处理下），这是 v3 DRBG 存在的理由

## 5. 怎么做的健康测试（90B §4.3/4.4）

**RCT 重复计数测试（4.4.1）**——抓"卡死"级灾难故障：
- cutoff 公式（规范原文核对）：`C = 1 + ceil(−log₂α / H)`
- 算法：同一样本连续出现 C 次 => 报警（状态机就两个变量：上个值 + 连续计数）
- 默认参数 H=8、α=2⁻⁴⁰ => **C=6**（规范原文"six repetitions"一致）

**APT 自适应占比测试（4.4.2）**——抓"熵退化"级慢性故障：
- 字节样本属非二进制 => 窗口 **W=512**；阈值取满足
  `Pr(Binom(W, 2⁻ᴴ) ≥ C) ≤ α` 的最小整数（即规范脚注 10 的
  `C = 1 + CRITBINOM(W, 2⁻ᴴ, 1−α)`），实现用 lgamma 在 log 域算精确分位数
- 算法照规范：每个不相交 512 字节窗口取首样本为 A，数 A 在窗口内出现次数，
  达 C 报警
- 默认参数 => **C=19**；`--alpha-log2 20` => C=13，与规范 Table 2 的 H=8
  行一致（阈值算法已用 Table 2 全部十个数值交叉验证）

**启动测试（4.3）**：首批 1024 字节（= 两个 APT 窗口）先通过 RCT/APT
才允许对外供数；这些样本测试后丢弃，不混进输出。

**fail-closed（4.3 第 2 条）**：持久故障不得再产出任何输出——报警即核心
终态，错误保持第一次的，之后调用一律拒绝。α 取值遵守 4.3 的建议区间
2⁻²⁰~2⁻⁴⁰，全部参数（H、α、startup）命令行可见。

## 6. 怎么做的条件化（90B §10.3.1）

**hash_df（SHA-256 版）**，逐行对齐生产链 `rand_qrng.c` 的 `oqs_hash_df`
（前缀布局、循环结构、255×32 输出上限完全一致）：

```
prefix = counter(1B) || no_output_bits(4B 大端)
while 产出不足:  temp += SHA256(prefix || input);  counter++
取 temp 的前 no_output_bits 位
```

SHA-256 是自包含实现（FIPS 180-4，API 形状照抄 `OQS_SHA2_sha256_inc_*`
便于与生产链对照），四个标准向量锁死正确性。

**熵记账（设计支柱的落地）**：核心按 `in ≥ ceil(8/H × out)` 决定读多少
原始字节——每产出 1 字节至少投入 8/H 字节声明熵，**读不够就不产出**，
比值不是事后统计而是供数的前提；`qrng_core_condition_bytes_in/out`
累计、CLI 打印（H=8 → 1:1；H=5.5 → 1.45:1）。诚实边界写在 README：
条件化不能凭空造熵，in/out 账本就是防"声明虚高"的自欺机制。

## 7. 怎么做的 DRBG（90A §10.2.1）

**AES-256-CTR_DRBG，no-DF 分支**——因为前一层 hash_df 已产出满熵种子，
90A 的 Block_Cipher_df（为不均匀熵输入设计）在这里是重复劳动。
AES-256 自包含（只需加密方向，CTR/DRBG 永不解密），FIPS 197 + 800-38A
向量验证。四个过程都对照 90A Rev.1 原文实现（行内标小节号）：

| 过程 | 算法（AES-256: keylen=32B, blocklen=16B, seedlen=48B） |
|---|---|
| Update (10.2.1.2) | 循环 3 次：V+1 → AES(K,V) 拼 48B → XOR provided_data → 前 32B 新 K、后 16B 新 V |
| Instantiate (10.2.1.3.1) | K=0、V=0 起步 → Update(48B 种子) → reseed_counter=1 |
| Reseed (10.2.1.4.1) | Update(新 48B) → counter=1 |
| Generate (10.2.1.5.1) | 先查 counter>interval（超了拒绝，不许静默生成）→ V+1→AES 拼输出 → **每次 generate 后必调 Update(0⁴⁸)（backtracking 抵抗，规范注释，非可选）** → counter++ |

- 种子/reseed 的 48 字节走 v2 全管线（健康测试+条件化）= 90C 的 ES→DRBG
  衔接；输出按 4096 字节分块（规范单请求上限 2¹⁹ bit）
- reseed_interval 默认 10⁶（规范上限 2⁴⁸），命令行可调
- **模型本质（写在 README 的诚实边界）**：DRBG 输出是计算安全性——
  10MB 每一字节的安全来自那 48B 种子 + AES 强度，不是 10MB 物理熵。
  这正是生产链不做 DRBG 的原因（ML-KEM keygen 只要 64B，条件化直出
  的物理熵更"硬"）；DRBG 的价值在偶发大吞吐（服务化场景），v3 的
  18.8 倍实测就是这个道理

## 8. 可靠性实测：设备掉线自动恢复（生产形态 B）

目标重新定位后（通用随机数服务），补齐了故障恢复闭环并实测：

- `--exit-on-failure` + systemd `Restart=on-failure`（`deploy/qrng-service.service`）
- 实测（sysfs deauthorize 模拟 USB 失联）：掉线 → 客户端收
  `QuantisReadHandled: Input/output error` → 服务退出 → systemd 每 5s
  无限重试 → 设备恢复 → 服务自动 active → 重新过 1024B 启动门禁
  → 恢复供数，全程零人工
- 韧性设计实测：默认 reseed_interval 下设备掉线被 DRBG 吸收
  （100 万请求不碰设备）；`--reseed-interval 1` = 严格模式，掉线即拒绝
- 修复：daemonize 未重定向 stdio（守护进程攥住调用方管道）

## 8.1 v5 可靠性补强实测（监控心跳 + 双阈值 reseed）

- 心跳实测：`--monitor-interval 30`，**无任何客户端请求**时 deauth 设备
  → 30 秒内心跳独立发现（`monitor: SOURCE FAILURE`）→ exit-on-failure
  → systemd 重启 → 设备恢复 → 自动 active、门禁重过、恢复供数
- 修复前同一场景：DRBG 模式下设备掉线**永远不会被发现**（直到百万次
  请求后 reseed 才碰源）——这就是时间盲区
- 双阈值 reseed：字节阈值（32B）触发后核心自动拉新种子（记账
  48+48 可核对）；时间阈值 1s 触发（单测覆盖）
- 新增测试：`test_dual_threshold_reseed`、`test_core_monitor`（含
  记账诚实性：心跳字节计入 bytes_read、不进条件化记账）

## 9. 关键实测数字（pqcvm03，Quantis USB）

| 指标 | 数值 |
|---|---|
| 原始流 10 万字节 | 卡方 246.2（255±92 内）、min-entropy 7.809、monobit 2.5σ |
| 偏置源：原始 → 条件化 | 卡方 37059 SUSPICIOUS → 277.9 OK |
| 设备直出 vs DRBG（10MB） | 50.6s（198KB/s）vs 2.7s（3.7MB/s）= **18.8×**，设备仅出 1072B |
| 服务化 | 10MB+5MB 两请求，源字节全程 1072 |
| ML-KEM keygen | 两次运行密钥不同；卡死源 REFUSED exit 1；服务形态 src=1072 |
| 测试 | ctest 5/5（VM）+ 本机 MinGW C 测试全过 |
