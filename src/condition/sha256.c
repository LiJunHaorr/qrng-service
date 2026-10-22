/* SHA-256（FIPS 180-4）参考实现：教学 demo 专用，无汇编、无分发层，
 * 换来的是整个文件一眼能读完。 */
#include "qrng/qrng_sha256.h"

#include <string.h>

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(qrng_sha256_ctx *ctx, const uint8_t block[64]) {
	uint32_t w[64];
	for (int i = 0; i < 16; i++) {
		w[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16)
		       | ((uint32_t)block[4 * i + 2] << 8) | (uint32_t)block[4 * i + 3];
	}
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = ROTR32(w[i - 15], 7) ^ ROTR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ROTR32(w[i - 2], 17) ^ ROTR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
	uint32_t e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h = ctx->h[7];

	for (int i = 0; i < 64; i++) {
		uint32_t S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t t1 = h + S1 + ch + K[i] + w[i];
		uint32_t S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = S0 + maj;
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
	ctx->h[5] += f;
	ctx->h[6] += g;
	ctx->h[7] += h;
}

void qrng_sha256_inc_init(qrng_sha256_ctx *state) {
	state->h[0] = 0x6a09e667;
	state->h[1] = 0xbb67ae85;
	state->h[2] = 0x3c6ef372;
	state->h[3] = 0xa54ff53a;
	state->h[4] = 0x510e527f;
	state->h[5] = 0x9b05688c;
	state->h[6] = 0x1f83d9ab;
	state->h[7] = 0x5be0cd19;
	state->total_len = 0;
	state->buf_len = 0;
}

void qrng_sha256_inc(qrng_sha256_ctx *state, const uint8_t *data, size_t len) {
	state->total_len += len;
	if (state->buf_len > 0) {
		size_t take = 64 - state->buf_len;
		if (take > len) {
			take = len;
		}
		memcpy(state->buf + state->buf_len, data, take);
		state->buf_len += take;
		data += take;
		len -= take;
		if (state->buf_len == 64) {
			sha256_block(state, state->buf);
			state->buf_len = 0;
		}
	}
	while (len >= 64) {
		sha256_block(state, data);
		data += 64;
		len -= 64;
	}
	if (len > 0) {
		memcpy(state->buf, data, len);
		state->buf_len = len;
	}
}

void qrng_sha256_inc_finalize(uint8_t digest[QRNG_SHA256_DIGEST_LENGTH],
                              qrng_sha256_ctx *state) {
	uint64_t bits = state->total_len * 8;
	uint8_t pad = 0x80;
	qrng_sha256_inc(state, &pad, 1);
	uint8_t zero = 0;
	while (state->buf_len != 56) {
		qrng_sha256_inc(state, &zero, 1);
	}
	/* 长度域（8 字节大端）。注意此时再 inc 会把 total_len 算进去，
	 * 所以直接手工填块并压缩。 */
	uint8_t len_block[8];
	for (int i = 0; i < 8; i++) {
		len_block[i] = (uint8_t)(bits >> (56 - 8 * i));
	}
	memcpy(state->buf + 56, len_block, 8);
	sha256_block(state, state->buf);
	for (int i = 0; i < 8; i++) {
		digest[4 * i] = (uint8_t)(state->h[i] >> 24);
		digest[4 * i + 1] = (uint8_t)(state->h[i] >> 16);
		digest[4 * i + 2] = (uint8_t)(state->h[i] >> 8);
		digest[4 * i + 3] = (uint8_t)state->h[i];
	}
	memset(state, 0, sizeof *state);
}

void qrng_sha256(uint8_t *output, const uint8_t *input, size_t inplen) {
	qrng_sha256_ctx ctx;
	qrng_sha256_inc_init(&ctx);
	qrng_sha256_inc(&ctx, input, inplen);
	qrng_sha256_inc_finalize(output, &ctx);
}