/* 卡死 mock 后端：恒定输出同一个字节值。
 * 用途：v1 健康测试的故障注入（对应生产链的 mock_stuck——
 * test_qrng_ml_kem 的 --expect-init-failure mock_stuck 170 就是它）。
 * config：卡死的字节值（默认 0xA5）。 */
#include "qrng/qrng_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	uint8_t value;
} stuck_state_t;

static void *stuck_create(const char *config, char *errbuf, size_t el) {
	stuck_state_t *s = calloc(1, sizeof *s);
	if (s == NULL) {
		snprintf(errbuf, el, "out of memory");
		return NULL;
	}
	s->value = 0xA5;
	if (config != NULL && config[0] != '\0') {
		s->value = (uint8_t)strtoul(config, NULL, 0);
	}
	return s;
}

static long stuck_read(void *state, uint8_t *out, size_t n,
                       char *errbuf, size_t el) {
	(void)errbuf;
	(void)el;
	stuck_state_t *s = state;
	memset(out, s->value, n);
	return (long)n;
}

static void stuck_destroy(void *state) {
	free(state);
}

const qrng_backend_t qrng_backend_mock_stuck = {
	"mock_stuck", stuck_create, stuck_read, stuck_destroy,
};

__attribute__((constructor)) static void register_mock_stuck(void) {
	qrng_register_backend(&qrng_backend_mock_stuck);
}
