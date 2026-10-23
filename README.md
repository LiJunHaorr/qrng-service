# qrng-service

**按 NIST SP 800-90B / 90A / 90C 分层搭出来的量子随机数供给链**，
从 Quantis USB 熵源一路到 ML-KEM-768 密钥，fail-closed 贯穿全程。

```
Quantis USB ─ 启动测试(1024B) ─ RCT/APT 持续监测 ─ hash_df 条件化 ─ CTR_DRBG
                              │                                    ├── qrng-cli   （一次性取数）
                              │                                    ├── qrng-server（常驻服务）── qrng-fetch
                              │                                    └── qrng-keygen（ML-KEM-768 密钥生成）
                              └── 任一环节故障 = 终态 = 永久拒绝供数（fail-closed）
```

每个环节都有对应的规范依据、可调参数、故障注入测试和能"看见效果"的演示。
接口形状照抄团队 QRNG-Provider（`qrng_core_new/generate/ready/bytes_read/last_error`），
条件化与 pq-liboqs claude 分支的 `oqs_hash_df` 逐行对齐，可直接做对照实验。

**成果数据（实测数字、验收清单、踩坑记录）见 [RESULTS.md](RESULTS.md)。**

## 目录结构

```
qrng-service/
├── include/qrng/
│   ├── qrng_core.h           # 核心 API：后端接口 + 整链配置 + fail-closed 契约
│   ├── qrng_health.h         # 健康测试配置（H / alpha / startup）
│   ├── qrng_condition.h      # 条件化配置 + hash_df 接口
│   ├── qrng_drbg.h           # CTR_DRBG 配置 + 接口
│   ├── qrng_sha256.h         # 自包含 SHA-256
│   └── qrng_aes.h            # 自包含 AES-256（仅加密方向）
├── src/
│   ├── core.c                # 调度 + fail-closed 状态机 + 熵记账
│   ├── source/               # 可插拔熵源后端（GCC constructor 自注册）
│   │   ├── quantis.c         #   Quantis USB（需 SDK）
│   │   ├── mock_det.c        #   确定性计数器（控制流测试）
│   │   ├── mock_stuck.c      #   恒定值（故障注入：RCT 报警）
│   │   ├── mock_biased.c     #   可调偏置（统计演示）
│   │   └── file.c            #   文件回放（离线开发/录流回放）
│   ├── health/health.c       # RCT + APT + 启动测试（90B §4.3/4.4）
│   ├── condition/            # hash_df（90B §10.3.1）+ SHA-256
│   └── drbg/                 # CTR_DRBG（90A §10.2.1）+ AES-256
├── apps/
│   ├── qrng_cli.c            # CLI：一次性取数（层参数全部命令行可见）
│   ├── qrng_server.c         # 守护进程 + Unix socket/TCP 服务
│   ├── qrng_fetch.c          # 取数客户端
│   ├── qrng_keygen.c         # ML-KEM-768 密钥生成（消费端应用）
│   ├── opts.c/h              # 层选项解析（CLI 与 server 共用）
│   ├── proto.h               # 服务协议（4B 请求 -> status+len+payload）
│   └── svc_client.c/h        # 服务的程序化取数（keygen 内嵌用）
├── tests/
│   ├── test_health.c         # 阈值对照规范 Table 2 + 故障注入
│   ├── test_condition.c      # SHA-256 向量 + hash_df 结构 + 熵记账
│   ├── test_drbg.c           # AES 向量 + DRBG 手工复算验证
│   ├── test_service.py       # 服务化集成测试（含 fail-closed 跨进程）
│   └── test_keygen.py        # keygen 应用集成测试
├── tools/stats.py            # 统计检验（卡方 / MCV min-entropy / monobit）
├── deploy/qrng-service.service  # systemd 单元（受监督重启 + 自动恢复）
├── CMakeLists.txt
├── README.md
└── RESULTS.md                # 成果报告：实测数据 / 验收 / 踩坑
```

## 快速开始

### 环境要求

- Linux（推荐 Ubuntu 24.04）：gcc、cmake ≥ 3.16、libusb-1.0-0-dev、python3
- 可选：Quantis USB 设备 + Quantis SDK（编译方法见下）；liboqs（keygen 应用）
- Windows + MinGW（winlibs gcc）也可开发测试（无 Quantis/liboqs 目标）

### 构建

```bash
# 场景 1：无硬件开发（mock 后端够用）
cmake -B build -DQRNG_WITH_QUANTIS=OFF && cmake --build build

# 场景 2：接 Quantis USB（需要先编译 SDK，见下节）
cmake -B build -quantis -DQUANTIS_ROOT=<SDK安装目录> && cmake --build build-quantis

# 场景 3：keygen 应用（需要 liboqs，可选）
#   默认路径 /home/pqc/pqc-lab/liboqs/build，可用 -DOQS_ROOT= 覆盖
cmake -B build && cmake --build build   # 自动探测，找不到就跳过该目标

# 全部测试（5 个套件）
ctest --test-dir build --output-on-failure
```

Windows/MinGW：`cmake -B build -G "MinGW Makefiles" -DQRNG_WITH_QUANTIS=OFF`。

### Quantis SDK 编译（Ubuntu，踩坑实录）

SDK 源码包 `Quantis-v18.03.08`（IDQ 官网下载，**不含在本仓库**）：

```bash
cmake -S ~/Quantis-v18.03.08/Libs-Apps/Quantis -B ~/quantis-sdk-build \
  -DDISABLE_QUANTIS_JAVA=ON -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DCMAKE_MODULE_PATH=~/Quantis-v18.03.08/Libs-Apps/CMake \
  -DCMAKE_INSTALL_PREFIX=~/idq-quantis -DCMAKE_INSTALL_LIB_DIR=lib \
  -DCMAKE_CXX_STANDARD=11 \
  -DCMAKE_C_FLAGS=-I~/Quantis-v18.03.08 -DCMAKE_CXX_FLAGS=-I~/Quantis-v18.03.08
cmake --build ~/quantis-sdk-build -j4 && cmake --install ~/quantis-sdk-build
```

三个坑：FindUSB1.cmake 在 `Libs-Apps/CMake/`；SDK 的 CMake 2.6 兼容性；
`throw(...)` 与 C++17 冲突（固定 C++11）。USB 权限：装
`Drivers/Unix/idq-quantis.rules` 到 `/etc/udev/rules.d/` 并触发，
普通用户即可直连。详见 RESULTS.md。

## 生产部署与故障恢复（通用随机数服务形态）

目标形态：常驻服务、多客户端、**扛得住设备掉线等常见故障**。

### 故障恢复闭环（真硬件实测）

```
设备掉线（实测用 sysfs deauthorize 模拟 USB 失联）
  → 后端读失败 → 核心 fail-closed → 客户端收到错误
  → 服务以非零码退出（--exit-on-failure）
  → systemd 每 5s 无限重试（StartLimitIntervalSec=0）
  → 设备回来 → 重启即"复位"：重新读 1024B 过启动门禁（90B 4.3
    明确允许"由系统复位恢复"）→ 自动恢复供数
```

实测记录（pqcvm03）：设备失联 → 服务 3 次拒绝后退出 → systemd
NRestarts 持续增长 → 设备恢复 → 服务自动 active → 重新过门禁
（src=1072 重置）→ 客户端正常取数。**全程零人工干预。**

### 一个必须理解的韧性设计：DRBG 的"设备闪断吸收窗口"

默认 `reseed_interval=1000000` 时，服务启动后 **100 万次请求内不碰设备**
——设备短暂掉线会被 DRBG 静默吸收（输出仍是计算安全的）。这是特性
不是缺陷：通用随机数服务要的是可用性。两种策略按需选：

| 策略 | 配置 | 语义 |
|---|---|---|
| 高可用（默认） | `--reseed-interval 1000000` | 设备闪断不停服，故障在 reseed 时才暴露 |
| 严格物理熵 | `--reseed-interval 1` | 每次请求都碰设备，掉线立刻 fail-closed |

### 部署

```bash
sudo cp deploy/qrng-service.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now qrng-service
qrng-fetch -s /run/qrng/qrng.sock -n 16      # 验证
systemctl status qrng-service                 # 看状态/重启计数
journalctl -u qrng-service -f                 # 跟日志
```

单元文件里 ExecStart 的二进制路径/设备号按实际改。
注意 fail-closed 语义：**绝不存在"悄悄降级继续供数"**——
恢复的唯一路径是进程重启 + 重新过启动门禁。

## 分层说明

链上的层按 NIST 结构排布，每层 = 规范依据 + 算法 + 可调参数 + 演示：

| 层 | 干什么 | 规范 | 关键点 |
|---|---|---|---|
| 熵源后端 | 从 Quantis/mock/file 读原始字节 | — | 可插拔，constructor 自注册（CMake 用 OBJECT 库，静态库会静默失效） |
| 健康测试 | 抓急性故障（卡死/退化），报警即终态 | 90B §4.3/4.4 | RCT：`C=1+⌈−log₂α/H⌉`（默认 6）；APT：W=512 窗口二项分位数阈值（默认 19）；启动测试 1024B 门禁；100% 全检非抽样 |
| 条件化 | 治慢性偏置：原始字节 -> 均匀字节 | 90B §10.3.1 | hash_df（与生产链 `oqs_hash_df` 逐行对齐）；熵记账强制 `in ≥ 8/H·out` |
| DRBG | 小种子放大吞吐（48B -> MB级） | 90A §10.2.1 | AES-256-CTR_DRBG no-DF；reseed 间隔可调；每次 generate 后强制 Update（backtracking 抵抗） |
| 服务化 | 链常驻进程，多客户端取数 | 90C 衔接 | 守护进程 + Unix socket/TCP；fail-closed 跨进程（单进程持有终态，不 fork-per-connection） |
| keygen 应用 | 真消费端：ML-KEM-768 密钥 | 生产链同构 | 种子显式注入 `keypair_derand`；源故障 = KEYGEN REFUSED，零密钥产出 |

设计纪律：**fail-closed 贯穿全程**（任一环节失败 → 终态 → 永久拒绝）、
**熵记账显式化**（读了多少记多少，比值是供数前提不是事后统计）、
**后端可插拔**（无硬件照样开发测试）。

## 常用命令

```bash
# 一次性取数（全链默认开：健康+条件化+DRBG）
./build-quantis/qrng-cli quantis 0 -n 16
./build-quantis/qrng-cli mock_det 42 -n 16        # 确定性源，输出可复现

# 故障注入：卡死源 -> RCT 报警 + fail-closed（exit 1）
./build-quantis/qrng-cli mock_stuck -n 8

# 偏置源 原始 vs 条件化（注意 --drbg off 两边都带，否则 DRBG 会盖住偏置）
./build-quantis/qrng-cli mock_biased 0.6 -n 100000 --health off --condition off --drbg off -o raw.bin
./build-quantis/qrng-cli mock_biased 0.6 -n 100000 --health off --condition on --drbg off \
    --min-entropy 5.5 -o cond.bin
python3 tools/stats.py raw.bin     # 卡方 ~37000 SUSPICIOUS
python3 tools/stats.py cond.bin    # 卡方 ~278 OK

# 吞吐对照：设备直出 vs DRBG（10MB）
./build-quantis/qrng-cli quantis 0 -n 10000000 --drbg off -o /dev/null   # ~50s
./build-quantis/qrng-cli quantis 0 -n 10000000 -o /dev/null             # ~3s

# reseed 间隔演示
./build-quantis/qrng-cli mock_det 0 -n 16 --requests 5 --reseed-interval 2 \
    --health off --condition off

# 服务化
./build-quantis/qrng-server quantis 0             # 守护进程化
./build-quantis/qrng-fetch -n 10000000 -o a.bin   # 客户端取数
tail /tmp/qrng-demo.log                           # 记账：src 不涨
pkill -x qrng-server

# ML-KEM keygen（消费端应用）
./build-quantis/qrng-keygen quantis 0 -o mykey    # ML-KEM-768 密钥对
./build-quantis/qrng-keygen mock_stuck            # KEYGEN REFUSED + exit 1
./build-quantis/qrng-server quantis 0 && \
    ./build-quantis/qrng-keygen -s /tmp/qrng-demo.sock   # 服务形态
```

层参数：`--health/--condition/--drbg on|off`、`--min-entropy H`、
`--alpha-log2 N`、`--startup N`、`--reseed-interval N`、`--requests K`。

## 诚实边界（先读这个再看数据）

- 健康测试管**急性**故障（卡死/大幅退化），慢性偏置归条件化和统计检验管
- 条件化**不能凭空造熵**：声明 H 虚高时输出统计上"看起来均匀"，
  但 in/out 账本就是防自欺的机制
- DRBG 输出是**计算安全性**（10MB 的安全来自 48B 种子）；
  生产链不做 DRBG 的原因：ML-KEM keygen 只要 64B，条件化直出的物理熵更"硬"
- 看最终输出的统计指标**不能证明熵源没问题**（DRBG 会掩盖一切），
  健康测试必须盯原始字节——这正是它站在源与链之间的原因

## 与生产链的对应关系

| 本项目 | 生产链（QRNG-Provider → pq-liboqs claude 分支） |
|---|---|
| `source/quantis.c` | Quantis SDK 直连 |
| `qrng_core_*` API | `qrng_core_new/generate/ready/bytes_read/last_error` |
| `health/` | Provider 内部 90B 测试 |
| `condition/condition.c` | `rand_qrng.c` 的 `oqs_hash_df`（逐行对齐） |
| `drbg/` | 生产链没有（原因见上） |
| `qrng-server` | Provider 的服务化形态 |
| `qrng-keygen` | 生产链最终用途：QRNG 种子 -> ML-KEM keygen |

## 已知限制 / 后续方向

- 服务端单线程（fail-closed 状态须单进程持有；并发需多 worker + 终态广播架构）
- 无认证/加密（本机 socket + umask；对外 TCP 需补）
- stats.py 是入门级 MCV 估计器，不是 90B 正式熵评估
- 对照实验（同设备 vs 生产链）待做
