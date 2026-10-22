#ifndef QRNG_CONDITION_H
#define QRNG_CONDITION_H

#include <stddef.h>
#include <stdint.h>

/* SP 800-90B 条件化层（v2）配置与接口。
 *
 * 生产链对应物：pq-liboqs claude 分支 rand_qrng.c 的 oqs_hash_df
 * （条件化内嵌在 qrng_core 回调里）；本 demo 把它独立成一层，
 * 方便单独演示/测试"原始 vs 条件化"的统计差异。
 *
 * 熵记账纪律（README 设计支柱 2）：
 *   输入:输出字节比必须 >= 8 / min_entropy_bits
 *   —— 每产出 1 字节（8 bit 输出），至少要投入 8/H 字节的原始熵。
 *   声明 H=8 时 1:1；H=5.5 时约 1.45:1。核心按 ceil(8/H * n)
 *   从熵源读原始字节，并累计 in/out 供调用方核对。
 */
typedef struct {
	int enabled;             /* 0 = 不条件化，原始字节直出（v1 行为） */
	double min_entropy_bits; /* 条件化层使用的每字节熵声明，默认 8.0，
	                          * 合法范围 (0, 8]。可以与健康测试的声明
	                          * 不同，但 CLI 默认两者同值 */
} qrng_condition_conf_t;

void qrng_condition_default_conf(qrng_condition_conf_t *conf);

/* hash_df 本体（90B 10.3.1，SHA-256 版）：
 *   while (|temp| < no_output_bits)
 *       temp = temp || SHA256(counter || no_output_bits || input)
 *   返回 temp 的前 no_output_bits 位。
 * 输出上限 255 * 32 字节（counter 是单字节）。成功返回 1。
 * 独立于 core 存在，测试和外部工具可直接调用。 */
int qrng_hash_df(const uint8_t *input, size_t input_len,
                 uint8_t *output, size_t output_len);

#endif /* QRNG_CONDITION_H */