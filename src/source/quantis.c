/* Quantis USB 后端：通过 Quantis SDK 直连设备。
 * 编译条件：QRNG_WITH_QUANTIS（CMake 默认 ON，SDK 路径由 QUANTIS_ROOT 指定）。
 * config：设备号，如 "0"（默认 0）。 */
#include "qrng/qrng_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef QRNG_WITH_QUANTIS
#include <Quantis.h>

#define QUANTIS_CHUNK 4096

typedef struct {
	QuantisDeviceHandle *handle;
} quantis_state_t;

static void *quantis_create(const char *config, char *errbuf, size_t el) {
	unsigned int device = 0;
	if (config != NULL && config[0] != '\0') {
		device = (unsigned int)strtoul(config, NULL, 0);
	}
	quantis_state_t *s = calloc(1, sizeof *s);
	if (s == NULL) {
		snprintf(errbuf, el, "out of memory");
		return NULL;
	}
	if (QuantisCount(QUANTIS_DEVICE_USB) < (int)device + 1) {
		snprintf(errbuf, el, "no Quantis USB device #%u (lsusb | grep 0aba)",
		         device);
		free(s);
		return NULL;
	}
	int rc = QuantisOpen(QUANTIS_DEVICE_USB, device, &s->handle);
	if (rc != QUANTIS_SUCCESS) {
		snprintf(errbuf, el, "QuantisOpen: %s", QuantisStrError(rc));
		free(s);
		return NULL;
	}
	return s;
}

static long quantis_read(void *state, uint8_t *out, size_t n,
                         char *errbuf, size_t el) {
	quantis_state_t *s = state;
	size_t done = 0;
	while (done < n) {
		size_t chunk = n - done;
		if (chunk > QUANTIS_CHUNK) {
			chunk = QUANTIS_CHUNK;
		}
		int r = QuantisReadHandled(s->handle, out + done, chunk);
		if (r < 0) {
			snprintf(errbuf, el, "QuantisReadHandled: %s", QuantisStrError(r));
			return -1;
		}
		if (r == 0) {
			snprintf(errbuf, el, "Quantis returned 0 bytes");
			return -1;
		}
		done += (size_t)r;
	}
	return (long)done;
}

static void quantis_destroy(void *state) {
	quantis_state_t *s = state;
	if (s != NULL) {
		QuantisClose(s->handle);
		free(s);
	}
}

const qrng_backend_t qrng_backend_quantis = {
	"quantis", quantis_create, quantis_read, quantis_destroy,
};

__attribute__((constructor)) static void register_quantis(void) {
	qrng_register_backend(&qrng_backend_quantis);
}
#endif /* QRNG_WITH_QUANTIS */
