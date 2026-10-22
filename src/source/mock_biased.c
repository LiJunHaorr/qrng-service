/* 偏置 mock 后端：xorshift32 PRNG + 可调位偏置。
 * 用途：统计演示（真实 Quantis 输出经过板载处理，偏置可能弱到
 * 统计上看不出来；这个后端保证"看着随机但有偏置"在任何机器上
 * 都可复现）。config：P(bit=1)，如 "0.6"（默认 0.6）。 */
#include "qrng/qrng_core.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct {
	uint32_t x;   /* xorshift 状态，必须非零 */
	double p1;    /* P(bit=1) */
} biased_state_t;

static uint32_t xorshift32(uint32_t *x) {
	uint32_t v = *x;
	v ^= v << 13;
	v ^= v >> 17;
	v ^= v << 5;
	*x = v;
	return v;
}

static void *biased_create(const char *config, char *errbuf, size_t el) {
	biased_state_t *s = calloc(1, sizeof *s);
	if (s == NULL) {
		snprintf(errbuf, el, "out of memory");
		return NULL;
	}
	s->x = 0x20261021u;
	s->p1 = 0.6;
	if (config != NULL && config[0] != '\0') {
		s->p1 = strtod(config, NULL);
	}
	if (!(s->p1 > 0.0 && s->p1 < 1.0)) {
		snprintf(errbuf, el, "bias must be in (0,1), got '%s'", config);
		free(s);
		return NULL;
	}
	return s;
}

static long biased_read(void *state, uint8_t *out, size_t n,
                        char *errbuf, size_t el) {
	(void)errbuf;
	(void)el;
	biased_state_t *s = state;
	for (size_t i = 0; i < n; i++) {
		uint8_t byte = 0;
		for (int bit = 0; bit < 8; bit++) {
			/* 取 xorshift 高 24 位映射到 [0,1)，避免低位质量差 */
			double u = (double)(xorshift32(&s->x) >> 8) / 16777216.0;
			if (u < s->p1) {
				byte |= (uint8_t)(1u << bit);
			}
		}
		out[i] = byte;
	}
	return (long)n;
}

static void biased_destroy(void *state) {
	free(state);
}

const qrng_backend_t qrng_backend_mock_biased = {
	"mock_biased", biased_create, biased_read, biased_destroy,
};

__attribute__((constructor)) static void register_mock_biased(void) {
	qrng_register_backend(&qrng_backend_mock_biased);
}
