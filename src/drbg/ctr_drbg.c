/* SP 800-90A Rev.1 10.2.1 CTR_DRBG 实现（AES-256，no-DF 分支）。
 * 每一步都在行内标了规范小节号，算法文本逐句对照过规范原文。 */
#include "qrng/qrng_drbg.h"

#include "qrng/qrng_aes.h"

#include <stdlib.h>
#include <string.h>

/* 90A 9.3 的单请求上限是 2^19 bit；demo 取 4096 字节（2^15 bit）
 * 一个块串，每个块串之后照规范做一次 Update。 */
#define DRBG_MAX_CHUNK 4096

void qrng_drbg_default_conf(qrng_drbg_conf_t *conf) {
	if (conf == NULL) {
		return;
	}
	conf->enabled = 1;
	conf->reseed_interval = 1000000;
}

struct qrng_drbg_ctx {
	uint32_t rk[QRNG_AES256_ROUND_KEYS]; /* Key 的轮密钥形式 */
	uint8_t key[QRNG_AES256_KEY_BYTES];
	uint8_t V[QRNG_AES_BLOCK_BYTES];
	unsigned long long reseed_interval;
	unsigned long long reseed_counter;
	int instantiated;
};

qrng_drbg_ctx_t *qrng_drbg_new(unsigned long long reseed_interval) {
	if (reseed_interval < 1) {
		return NULL;
	}
	qrng_drbg_ctx_t *ctx = calloc(1, sizeof *ctx);
	if (ctx == NULL) {
		return NULL;
	}
	ctx->reseed_interval = reseed_interval;
	return ctx;
}

/* V = (V + 1) mod 2^128，大端计数器（10.2.1.2 步骤 2 的
 * ctr_len == blocklen 情形，AES 全 128 位都是计数器）。 */
static void v_increment(uint8_t V[QRNG_AES_BLOCK_BYTES]) {
	for (int i = QRNG_AES_BLOCK_BYTES - 1; i >= 0; i--) {
		if (++V[i] != 0) {
			break;
		}
	}
}

static void set_key(qrng_drbg_ctx_t *ctx, const uint8_t key[QRNG_AES256_KEY_BYTES]) {
	memcpy(ctx->key, key, QRNG_AES256_KEY_BYTES);
	qrng_aes256_key_schedule(ctx->rk, key);
}

/* 10.2.1.2 CTR_DRBG_Update（no-DF 分支）：
 * 1. temp = Null
 * 2. while |temp| < 48:  V+1; temp = temp || AES_Encrypt(Key, V)
 *    （48 = 3*16，循环恰好 3 次，无需截断）
 * 4. temp = temp XOR provided_data
 * 5. Key = temp[0:32]   6. V = temp[32:48] */
static void ctr_drbg_update(qrng_drbg_ctx_t *ctx,
                            const uint8_t provided_data[QRNG_CTR_DRBG_SEEDLEN]) {
	uint8_t temp[QRNG_CTR_DRBG_SEEDLEN];
	for (int block = 0; block < 3; block++) {
		v_increment(ctx->V);
		qrng_aes256_encrypt_block(ctx->rk, ctx->V, temp + 16 * block);
	}
	for (size_t i = 0; i < QRNG_CTR_DRBG_SEEDLEN; i++) {
		temp[i] ^= provided_data[i];
	}
	set_key(ctx, temp);
	memcpy(ctx->V, temp + QRNG_AES256_KEY_BYTES, QRNG_AES_BLOCK_BYTES);
	memset(temp, 0, sizeof temp);
}

int qrng_drbg_instantiate(qrng_drbg_ctx_t *ctx, const uint8_t seed[QRNG_CTR_DRBG_SEEDLEN]) {
	if (ctx == NULL || seed == NULL) {
		return 0;
	}
	/* 10.2.1.3.1：Key = 0^256, V = 0^128, Update(seed_material),
	 * reseed_counter = 1。personalization_string 不用 = 全零，
	 * seed_material = entropy_input XOR 0 = entropy_input。 */
	uint8_t zero_key[QRNG_AES256_KEY_BYTES] = {0};
	uint8_t zero_v[QRNG_AES_BLOCK_BYTES] = {0};
	set_key(ctx, zero_key);
	memcpy(ctx->V, zero_v, QRNG_AES_BLOCK_BYTES);
	ctr_drbg_update(ctx, seed);
	ctx->reseed_counter = 1;
	ctx->instantiated = 1;
	return 1;
}

int qrng_drbg_reseed(qrng_drbg_ctx_t *ctx, const uint8_t seed[QRNG_CTR_DRBG_SEEDLEN]) {
	if (ctx == NULL || seed == NULL || !ctx->instantiated) {
		return 0;
	}
	/* 10.2.1.4.1：seed_material = entropy_input XOR 0 = entropy_input；
	 * Update(seed_material); reseed_counter = 1。 */
	ctr_drbg_update(ctx, seed);
	ctx->reseed_counter = 1;
	return 1;
}

int qrng_drbg_instantiated(const qrng_drbg_ctx_t *ctx) {
	return ctx != NULL && ctx->instantiated;
}

int qrng_drbg_needs_reseed(const qrng_drbg_ctx_t *ctx) {
	return ctx == NULL || !ctx->instantiated
	       || ctx->reseed_counter > ctx->reseed_interval;
}

int qrng_drbg_generate(qrng_drbg_ctx_t *ctx, uint8_t *out, size_t n) {
	if (ctx == NULL || out == NULL || n == 0) {
		return 0;
	}
	/* 10.2.1.5.1 步骤 1：reseed required 就拒绝，不许静默生成 */
	if (!ctx->instantiated || ctx->reseed_counter > ctx->reseed_interval) {
		return 0;
	}

	size_t done = 0;
	while (done < n) {
		size_t chunk = n - done;
		if (chunk > DRBG_MAX_CHUNK) {
			chunk = DRBG_MAX_CHUNK;
		}
		/* 步骤 2：不用 additional_input => 等价 0^seedlen */
		uint8_t zeros[QRNG_CTR_DRBG_SEEDLEN] = {0};

		/* 步骤 3-5：V+1; temp = temp || AES_Encrypt(Key, V)；
		 * 取前 requested_bits 位 */
		size_t produced = 0;
		while (produced < chunk) {
			uint8_t block[QRNG_AES_BLOCK_BYTES];
			v_increment(ctx->V);
			qrng_aes256_encrypt_block(ctx->rk, ctx->V, block);
			size_t take = chunk - produced;
			if (take > QRNG_AES_BLOCK_BYTES) {
				take = QRNG_AES_BLOCK_BYTES;
			}
			memcpy(out + done + produced, block, take);
			produced += take;
			memset(block, 0, sizeof block);
		}

		/* 步骤 6（backtracking 抵抗）：每次 generate 后必调
		 * Update(0^seedlen)——不是可选项。 */
		ctr_drbg_update(ctx, zeros);

		/* 步骤 7：reseed_counter+1 */
		ctx->reseed_counter++;
		done += chunk;
	}
	return 1;
}

void qrng_drbg_free(qrng_drbg_ctx_t *ctx) {
	if (ctx != NULL) {
		memset(ctx, 0, sizeof *ctx);
		free(ctx);
	}
}