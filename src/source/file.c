/* 文件回放后端：把一个文件当作熵源流顺序读出。
 * 用途：没有设备时离线开发/回放录制的原始流。
 * config：文件路径（必填）。
 * 纪律：文件读尽视为熵源故障（fail-closed）——一个会"断流"的源
 * 不是合格的熵源，这正好用来演示终态行为。 */
#include "qrng/qrng_core.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	FILE *file;
} file_state_t;

static void *file_create(const char *config, char *errbuf, size_t el) {
	if (config == NULL || config[0] == '\0') {
		snprintf(errbuf, el, "file backend requires a path as config");
		return NULL;
	}
	FILE *f = fopen(config, "rb");
	if (f == NULL) {
		snprintf(errbuf, el, "cannot open '%s': %s", config, strerror(errno));
		return NULL;
	}
	file_state_t *s = calloc(1, sizeof *s);
	if (s == NULL) {
		fclose(f);
		snprintf(errbuf, el, "out of memory");
		return NULL;
	}
	s->file = f;
	return s;
}

static long file_read(void *state, uint8_t *out, size_t n,
                      char *errbuf, size_t el) {
	file_state_t *s = state;
	size_t got = fread(out, 1, n, s->file);
	if (got < n) {
		snprintf(errbuf, el,
		         "source exhausted after %zu bytes (a finite stream is a failed source)",
		         got);
		return -1;
	}
	return (long)got;
}

static void file_destroy(void *state) {
	file_state_t *s = state;
	if (s != NULL) {
		fclose(s->file);
		free(s);
	}
}

const qrng_backend_t qrng_backend_file = {
	"file", file_create, file_read, file_destroy,
};

__attribute__((constructor)) static void register_file(void) {
	qrng_register_backend(&qrng_backend_file);
}
