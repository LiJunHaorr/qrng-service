/* SP 800-90B 10.3.1 hash_df 条件化（SHA-256），v2 实现。
 *
 * 逐行对照生产链 pq-liboqs/src/common/rand/rand_qrng.c 的 oqs_hash_df：
 * 前缀布局（counter 单字节 || no_output_bits 4 字节大端）、循环结构、
 * 输出上限（255 * 32 与 UINT32_MAX/8）完全一致；区别只有两点——
 * 1) 生产版走 OQS_SHA2_sha256_inc_*（多后端分发），demo 用自包含
 *    qrng_sha256_inc_*（见 src/condition/sha256.c）；
 * 2) 生产版由 qrng_core_new 的回调参数内嵌进核心，demo 独立成层，
 *    并强制执行 in/out 熵记账（见 core.c 的 generate 流程）。
 */
#include "qrng/qrng_condition.h"
#include "qrng/qrng_sha256.h"

#include <stdint.h>
#include <string.h>

void qrng_condition_default_conf(qrng_condition_conf_t *conf) {
	if (conf == NULL) {
		return;
	}
	conf->enabled = 1;
	conf->min_entropy_bits = 8.0;
}

int qrng_hash_df(const uint8_t *input, size_t input_len,
                 uint8_t *output, size_t output_len) {
	uint8_t digest[QRNG_SHA256_DIGEST_LENGTH];
	uint8_t prefix[5];
	size_t produced = 0;
	uint8_t counter = 1;
	uint32_t output_bits;

	if (input == NULL || input_len == 0 || output == NULL || output_len == 0
	    || output_len > 255U * QRNG_SHA256_DIGEST_LENGTH
	    || output_len > UINT32_MAX / 8U) {
		return 0;
	}
	output_bits = (uint32_t)output_len * 8U;
	prefix[1] = (uint8_t)(output_bits >> 24);
	prefix[2] = (uint8_t)(output_bits >> 16);
	prefix[3] = (uint8_t)(output_bits >> 8);
	prefix[4] = (uint8_t)output_bits;

	while (produced < output_len) {
		qrng_sha256_ctx state;
		size_t take = output_len - produced;

		prefix[0] = counter;
		qrng_sha256_inc_init(&state);
		qrng_sha256_inc(&state, prefix, sizeof prefix);
		qrng_sha256_inc(&state, input, input_len);
		qrng_sha256_inc_finalize(digest, &state);
		if (take > sizeof digest) {
			take = sizeof digest;
		}
		memcpy(output + produced, digest, take);
		produced += take;
		counter++;
	}
	memset(digest, 0, sizeof digest);
	return 1;
}