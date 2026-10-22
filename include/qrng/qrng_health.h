#ifndef QRNG_HEALTH_H
#define QRNG_HEALTH_H

#include <stddef.h>
#include <stdint.h>

/* SP 800-90B 第 4 章健康测试的公共配置与接口（v1）。
 *
 * 三个可调参数全部对应用可见（CLI 直达），含义：
 *   - min_entropy_bits：对熵源声明的每样本 min-entropy（H）。
 *     RCT/APT 的阈值都由它推导——把 H 声明高了，阈值就松，
 *     mock_biased 演示的就是"声明 8 bit 却只有 ~5.9 bit"会被抓住。
 *   - alpha_log2：误报率 alpha = 2^-alpha_log2。规范 4.3 节建议
 *     取 2^-20 ~ 2^-40 之间，demo 默认 2^-40（宁紧勿松）。
 *   - startup_samples：启动测试长度。至少要覆盖一个完整 APT 窗口
 *     （W=512），demo 默认 1024 = 两个窗口。
 */
typedef struct {
	int enabled;              /* 0 = 退回 v0 裸直通（demo/对照用） */
	double min_entropy_bits;  /* H，默认 8.0；字节样本合法范围 (0, 8] */
	unsigned alpha_log2;      /* alpha = 2^-alpha_log2，默认 40 */
	unsigned startup_samples; /* 启动测试样本数，默认 1024 */
} qrng_health_conf_t;

void qrng_health_default_conf(qrng_health_conf_t *conf);

typedef struct qrng_health_ctx qrng_health_ctx_t;

/* 创建健康测试上下文。conf 为 NULL 时用默认值。
 * 参数非法（H 越界、startup < 窗口等）返回 NULL 并写 errbuf。 */
qrng_health_ctx_t *qrng_health_start(const qrng_health_conf_t *conf,
                                     char *errbuf, size_t errbuf_len);

/* 喂入 n 个样本（按字节逐个推进 RCT/APT 状态机）。
 * 返回 1 = 全部通过；返回 0 = 触发故障（errbuf 写明是哪个测试、
 * 触发样本序号与计数）。调用方必须让核心进入终态（fail-closed）。
 * 首次凑满 startup_samples 个通过样本之前视为"启动测试未完成"。 */
int qrng_health_check(qrng_health_ctx_t *ctx, const uint8_t *samples, size_t n,
                      char *errbuf, size_t errbuf_len);

int qrng_health_startup_done(const qrng_health_ctx_t *ctx);
unsigned qrng_health_startup_total(const qrng_health_ctx_t *ctx);

/* 阈值查询：CLI 打印、测试对照规范 Table 2 都用它们。 */
unsigned qrng_health_rct_cutoff(const qrng_health_ctx_t *ctx);
unsigned qrng_health_apt_cutoff(const qrng_health_ctx_t *ctx);
unsigned qrng_health_window(const qrng_health_ctx_t *ctx);
uint64_t qrng_health_samples_tested(const qrng_health_ctx_t *ctx);

void qrng_health_free(qrng_health_ctx_t *ctx);

#endif /* QRNG_HEALTH_H */