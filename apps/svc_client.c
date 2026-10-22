/* qrng-server 的最小内嵌客户端（协议见 proto.h）。 */
#include "svc_client.h"
#include "proto.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int read_full(int fd, void *buf, size_t n) {
	uint8_t *p = buf;
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);
		if (r < 0 && errno == EINTR) {
			continue;
		}
		if (r <= 0) {
			return -1;
		}
		got += (size_t)r;
	}
	return 0;
}

static int write_full(int fd, const void *buf, size_t n) {
	const uint8_t *p = buf;
	size_t sent = 0;
	while (sent < n) {
		ssize_t r = write(fd, p + sent, n - sent);
		if (r < 0 && errno == EINTR) {
			continue;
		}
		if (r < 0) {
			return -1;
		}
		sent += (size_t)r;
	}
	return 0;
}

int qrng_svc_fetch(const char *socket_path, uint8_t *out, size_t n,
                   char *errbuf, size_t el) {
	if (socket_path == NULL || out == NULL || n == 0
	    || n > QRNG_PROTO_MAX_REQUEST) {
		snprintf(errbuf, el, "svc_fetch: invalid arguments");
		return 0;
	}
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		snprintf(errbuf, el, "socket: %s", strerror(errno));
		return 0;
	}
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	if (strlen(socket_path) >= sizeof addr.sun_path) {
		snprintf(errbuf, el, "socket path too long");
		close(fd);
		return 0;
	}
	strcpy(addr.sun_path, socket_path);
	if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		snprintf(errbuf, el, "connect %s: %s (is qrng-server running?)",
		         socket_path, strerror(errno));
		close(fd);
		return 0;
	}

	uint8_t req[4];
	req[0] = (uint8_t)n;
	req[1] = (uint8_t)(n >> 8);
	req[2] = (uint8_t)(n >> 16);
	req[3] = (uint8_t)(n >> 24);
	if (write_full(fd, req, sizeof req) < 0) {
		snprintf(errbuf, el, "write request: %s", strerror(errno));
		close(fd);
		return 0;
	}

	uint8_t hdr[5];
	if (read_full(fd, hdr, sizeof hdr) < 0) {
		snprintf(errbuf, el, "server closed before responding");
		close(fd);
		return 0;
	}
	uint32_t len = (uint32_t)hdr[1] | ((uint32_t)hdr[2] << 8)
	               | ((uint32_t)hdr[3] << 16) | ((uint32_t)hdr[4] << 24);
	if (hdr[0] != QRNG_PROTO_STATUS_OK) {
		/* 服务端 fail-closed：payload 是错误文本，读出来原样透传 */
		size_t take = len;
		if (take > el - 1) {
			take = el - 1;
		}
		if (len > 0 && read_full(fd, errbuf, take) < 0) {
			snprintf(errbuf, el, "truncated error response");
			close(fd);
			return 0;
		}
		if (take < el) {
			errbuf[take] = '\0';
		}
		close(fd);
		return 0;
	}
	if (len != n) {
		snprintf(errbuf, el, "server returned %u bytes, wanted %zu", len, n);
		close(fd);
		return 0;
	}
	if (read_full(fd, out, n) < 0) {
		snprintf(errbuf, el, "truncated response");
		close(fd);
		return 0;
	}
	close(fd);
	return 1;
}