/* 确定性 mock 后端：输出可预测的递增字节序列。
 * 用途：控制流测试的基线（对应生产链的 mock_det）。
 * config：起始计数（默认 0）。 */
#include "qrng/qrng_core.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct {
	unsigned int counter;
} det_state_t;

static void *det_create(const char *config, char *errbuf, size_t el) {
	det_state_t *s = calloc(1, sizeof *s);
	if (s == NULL) {
		snprintf(errbuf, el, "out of memory");
		return NULL;
	}
	if (config != NULL && config[0] != '\0') {
		s->counter = (unsigned int)strtoul(config, NULL, 0);
	}
	return s;
}

static long det_read(void *state, uint8_t *out, size_t n,
                     char *errbuf, size_t el) {
	(void)errbuf;
	(void)el;
	det_state_t *s = state;
	for (size_t i = 0; i < n; i++) {
		out[i] = (uint8_t)(s->counter + (unsigned int)i);
	}
	s->counter += (unsigned int)n;
	return (long)n;
}

static void det_destroy(void *state) {
	free(state);
}

const qrng_backend_t qrng_backend_mock_det = {
	"mock_det", det_create, det_read, det_destroy,
};

__attribute__((constructor)) static void register_mock_det(void) {
	qrng_register_backend(&qrng_backend_mock_det);
}
