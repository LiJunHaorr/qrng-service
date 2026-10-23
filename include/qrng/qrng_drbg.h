#ifndef QRNG_DRBG_H
#define QRNG_DRBG_H

#include <stddef.h>
#include <stdint.h>

/* SP 800-90A Rev.1 10.2.1 的 CTR_DRBG（AES-256，不用 derivation
 * function 的分支）。
 *
 * 为什么选 no-DF 分支：我们链路的前一层是 hash_df 条件化（90B），
 * 种子已经是满熵字节——90A 的 df（Block_Cipher_df）是为"熵输入
 * 分布不均"准备的，这里再套一层是重复劳动。90A 10.2.1.3.1 原文：
 * 不用 df 时要求 full-entropy input，正好由条件化层满足。
 *
 * 参数（90A Table 3，AES-256）：
 *   keylen = 256 bit, blocklen = 128 bit, seedlen = 384 bit(48 字节)
 *   reseed_interval 上限 2^48
 *
 * 规范原文核对过的四个过程（见 src/drbg/ctr_drbg.c 行内注释）：
 *   Update(10.2.1.2) / Instantiate(10.2.1.3.1) /
 *   Reseed(10.2.1.4.1) / Generate(10.2.1.5.1)
 * Generate 第 6 步在每次调用后都会用 0^seedlen 调 Update
 * （backtracking 抵抗）——不是可选项，照抄。
 */

#define QRNG_CTR_DRBG_SEEDLEN 48 /* 256 bit Key + 128 bit V */

typedef struct {
	int enabled;                        /* 0 = 输出条件化字节（v2 行为） */
	unsigned long long reseed_interval; /* 请求数阈值，默认 1000000
	                                     * （规范上限 2^48） */
	unsigned long long reseed_bytes;    /* 字节总量阈值，默认 1 GiB。
	                                     * 防大请求失衡：单种子摊的输出
	                                     * 量也必须有上限。0 = 不限 */
	unsigned long long reseed_seconds;  /* 时间阈值，默认 86400（24h）。
	                                     * 防安静服务失衡：低流量时
	                                     * 同一状态也不许用太久。
	                                     * 0 = 不限。惰性触发：下次
	                                     * 请求时检查并 reseed */
} qrng_drbg_conf_t;

void qrng_drbg_default_conf(qrng_drbg_conf_t *conf);

typedef struct qrng_drbg_ctx qrng_drbg_ctx_t;

qrng_drbg_ctx_t *qrng_drbg_new(const qrng_drbg_conf_t *conf);

/* 用 seedlen=48 字节的满熵种子实例化（10.2.1.3.1）：
 * Key=0, V=0 起步，Update(seed)，reseed_counter=1。
 * 本 demo 不用 personalization_string（等价于全零，种子来自
 * 条件化层本身已具备唯一性）。 */
int qrng_drbg_instantiate(qrng_drbg_ctx_t *ctx, const uint8_t seed[QRNG_CTR_DRBG_SEEDLEN]);

/* reseed（10.2.1.4.1）：Update(seed)，reseed_counter=1。 */
int qrng_drbg_reseed(qrng_drbg_ctx_t *ctx, const uint8_t seed[QRNG_CTR_DRBG_SEEDLEN]);

int qrng_drbg_instantiated(const qrng_drbg_ctx_t *ctx);
/* generate(10.2.1.5.1) 第 1 步：reseed_counter > interval 时为真。 */
int qrng_drbg_needs_reseed(const qrng_drbg_ctx_t *ctx);

/* 生成 n 字节（内部按 4096 字节分块，规范单请求上限 2^19 bit）。
 * 返回 1 成功；未实例化或需要 reseed 时返回 0（调用方必须先处理，
 * 这是 90A 的 reseed-required 状态，不许静默跳过）。 */
int qrng_drbg_generate(qrng_drbg_ctx_t *ctx, uint8_t *out, size_t n);

void qrng_drbg_free(qrng_drbg_ctx_t *ctx);

#endif /* QRNG_DRBG_H */