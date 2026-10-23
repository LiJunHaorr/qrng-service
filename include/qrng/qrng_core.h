#ifndef QRNG_CORE_H
#define QRNG_CORE_H

#include <stddef.h>
#include <stdint.h>

#include "qrng/qrng_condition.h"
#include "qrng/qrng_drbg.h"
#include "qrng/qrng_health.h"

/* 可插拔熵源后端接口。
 *
 * 接口形状照抄团队 QRNG-Provider 的核心 API
 * （qrng_core_new / generate / ready / bytes_read / last_error），
 * 好处：mock 后端可以在没有硬件的机器上开发测试，
 * 且将来能直接和 pq-liboqs claude 分支的生产链做对照。
 *
 * 与生产版的已知差异（有意为之）：生产版 qrng_core_new 额外接收
 * hash_df 回调，条件化内嵌在核心里；本 demo 把条件化独立成一层
 * （src/condition/），核心负责"健康测试 + 出原始字节"。
 */
typedef struct qrng_backend {
    const char *name;
    /* config 可为 NULL 或空串；返回后端私有状态，NULL 表示初始化失败，
     * 此时向 errbuf 写入人类可读原因 */
    void *(*create)(const char *config, char *errbuf, size_t errbuf_len);
    /* 读 n 字节到 out；返回实际读到的字节数（正常 = n），负值 = 失败。
     * 失败后核心进入终态（见 qrng_core_generate） */
    long (*read)(void *state, uint8_t *out, size_t n,
                 char *errbuf, size_t errbuf_len);
    void (*destroy)(void *state);
} qrng_backend_t;

typedef struct qrng_core qrng_core_t;

/* 整链配置（v2 起汇总各层，v3 的 DRBG 参数将来也加在这里）。
 * 各层 enabled=0 即跳过该层。 */
typedef struct {
    qrng_health_conf_t health;
    qrng_condition_conf_t condition;
    qrng_drbg_conf_t drbg;
} qrng_core_conf_t;

void qrng_core_default_conf(qrng_core_conf_t *conf);

/* 应用只用到下面这几个函数。 */

/* backend: "quantis"/"mock_det"/"mock_stuck"/"mock_biased"/"file"。
 * config 语义由各后端自定（设备号 / 种子 / 偏置值 / 文件路径）。
 * v1 起默认启用健康测试（SP 800-90B RCT/APT + 启动测试）。
 * 失败返回 NULL，原因用 qrng_core_init_error() 取。 */
qrng_core_t *qrng_core_new(const char *backend, const char *config);

/* 带健康测试参数的构造函数（v1）：conf 为 NULL 等价于 qrng_core_new。
 * conf->enabled = 0 退回 v0 裸直通（--health off 用）。 */
qrng_core_t *qrng_core_new_ex(const char *backend, const char *config,
                              const qrng_health_conf_t *conf);

/* v2 构造函数：健康测试 + 条件化（hash_df）全参数版本。
 * conf 为 NULL 时用默认值（两层全开，H=8）。 */
qrng_core_t *qrng_core_new_cfg(const char *backend, const char *config,
                               const qrng_core_conf_t *conf);
const char *qrng_core_init_error(void);

int qrng_core_ready(const qrng_core_t *core);

/* fail-closed 契约：成功返回实际字节数（= n）；任何失败返回负值，
 * 且核心从此进入终态——之后的调用一律失败、错误信息保持不变。
 * 宁可不供数，也不吐可疑数据。
 * 健康测试在返回给调用方之前运行；RCT/APT 触发 = 失败 = 终态。 */
long qrng_core_generate(qrng_core_t *core, uint8_t *out, size_t n);

/* 熵记账：从后端读到的累计原始字节数。健康测试启用时含启动测试
 * 读掉的样本——读了多少就记多少，记账不许撒谎。
 * （v2 的条件化层会在此之上追加 in/out 比值的记录） */
uint64_t qrng_core_bytes_read(const qrng_core_t *core);

/* 条件化熵记账（v2）：喂给 hash_df 的累计原始字节 / 产出的累计
 * 条件化字节。要求 in/out >= 8 / 声明熵（核心按此决定读多少）。
 * 未启用条件化时两者均为 0。 */
uint64_t qrng_core_condition_bytes_in(const qrng_core_t *core);
uint64_t qrng_core_condition_bytes_out(const qrng_core_t *core);

/* DRBG 记账（v3）：从 DRBG 累计产出的字节数与累计 reseed 次数。
 * 种子/reseed 的 48 字节走条件化层，计入 cond_in/out。
 * DRBG 输出不算熵源字节（这是 90A 计算安全性的模型，
 * 与 90B 直出熵的区别，见 README）。 */
uint64_t qrng_core_drbg_bytes_generated(const qrng_core_t *core);
uint64_t qrng_core_drbg_reseeds(const qrng_core_t *core);

/* 监控心跳（v5 可靠性）：从熵源拉 n 字节，仅过健康测试后丢弃。
 * 不进输出、不进条件化，但计入 bytes_read（记账不撒谎）。
 * 目的：DRBG 模式下源字节只在种子时流动，健康状态机存在时间盲区
 * （百万次请求只监测约 1KB 源数据）——心跳让源在时间维度持续受检。
 * 返回 1 = 源仍健康；返回 0 = 源故障（核心进终态，fail-closed，
 * 原因用 qrng_core_last_error 取）。健康测试未启用时返回 1（无监控对象）。 */
int qrng_core_monitor(qrng_core_t *core, size_t n);

/* 健康测试上下文（只读）：NULL = 未启用。
 * 用 qrng_health_* 访问器查阈值/进度，供 CLI 打印与测试断言。 */
const qrng_health_ctx_t *qrng_core_health(const qrng_core_t *core);

const char *qrng_core_last_error(const qrng_core_t *core);
void qrng_core_free(qrng_core_t *core);

/* 后端注册：src/source/ 下的文件用 GCC constructor 自注册，
 * 加新后端不需要改 core.c */
void qrng_register_backend(const qrng_backend_t *backend);
int qrng_backend_count(void);
const char *qrng_backend_name(int index);

#endif /* QRNG_CORE_H */