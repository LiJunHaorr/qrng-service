/* 短读 mock 后端：只填请求的一半就返回（另一半故意留垃圾）。
 * 用途：回归测试 v2 修复——条件化/启动门禁绝不能拿未填满的
 * 缓冲当熵（backend 契约允许返回实际读到的字节数）。
 * config：无。 */
#include "qrng/qrng_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	unsigned counter;
} short_state_t;

static void *short_create(const char *config, char *errbuf, size_t el) {
	(void)config;
	short_state_t *s = calloc(1, sizeof *s);
	if (s == NULL) {
		snprintf(errbuf, el, "out of memory");
		return NULL;
	}
	return s;
}

static long short_read(void *state, uint8_t *out, size_t n,
                       char *errbuf, size_t el) {
	(void)errbuf;
	(void)el;
	short_state_t *s = state;
	size_t give = n / 2;
	for (size_t i = 0; i < give; i++) {
		out[i] = (uint8_t)(s->counter + i);
	}
	/* 后半段故意不填：若核心拿整块去 hash_df，就是在用未初始化内存 */
	s->counter += (unsigned)give;
	return (long)give;
}

static void short_destroy(void *state) {
	free(state);
}

const qrng_backend_t qrng_backend_mock_short = {
	"mock_short", short_create, short_read, short_destroy,
};

__attribute__((constructor)) static void register_mock_short(void) {
	qrng_register_backend(&qrng_backend_mock_short);
}