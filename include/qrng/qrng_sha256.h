#ifndef QRNG_SHA256_H
#define QRNG_SHA256_H

#include <stddef.h>
#include <stdint.h>

/* 紧凑自包含的 SHA-256（FIPS 180-4），demo 无外部依赖。
 *
 * API 形状刻意照抄生产链的 OQS_SHA2_sha256_inc_*：
 *   init -> (inc * n) -> finalize
 * 这样 src/condition/condition.c 的 hash_df 与 pq-liboqs
 * rand_qrng.c 的 oqs_hash_df 可以逐行对照阅读。
 *
 * 正确性由 tests/test_condition.c 用 FIPS/毕测向量锁定
 * （空串、"abc"、55 字节串、100 万个 'a'）。
 */

#define QRNG_SHA256_DIGEST_LENGTH 32

typedef struct {
	uint32_t h[8];
	uint64_t total_len;
	uint8_t buf[64];
	size_t buf_len;
} qrng_sha256_ctx;

void qrng_sha256_inc_init(qrng_sha256_ctx *state);
void qrng_sha256_inc(qrng_sha256_ctx *state, const uint8_t *data, size_t len);
void qrng_sha256_inc_finalize(uint8_t digest[QRNG_SHA256_DIGEST_LENGTH],
                               qrng_sha256_ctx *state);

/* 一次性接口（内部就是 init/inc/finalize）。 */
void qrng_sha256(uint8_t *output, const uint8_t *input, size_t inplen);

#endif /* QRNG_SHA256_H */