/* v4 客户端：从 qrng-server 取随机字节。
 *
 * 用法：
 *   qrng-fetch [-s SOCKET] [-t HOST:PORT] -n BYTES [-o FILE]
 * 默认连 Unix socket /tmp/qrng-demo.sock。
 * 退出码：0 成功；1 任何失败（含服务端 fail-closed 返回的错误）。
 */
#include "proto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static double now_s(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

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

static void usage(const char *argv0) {
	fprintf(stderr,
	        "usage: %s [-s SOCKET] [-t HOST:PORT] -n BYTES [-o FILE]\n"
	        "  -s  Unix socket path (default %s)\n"
	        "  -t  TCP host:port (e.g. 127.0.0.1:7777)\n",
	        argv0, QRNG_SOCK_DEFAULT);
}

int main(int argc, char **argv) {
	const char *sock_path = QRNG_SOCK_DEFAULT;
	const char *tcp_addr = NULL;
	size_t n = 0;
	const char *out_path = NULL;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
			sock_path = argv[++i];
		} else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
			tcp_addr = argv[++i];
		} else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
			n = (size_t)strtoul(argv[++i], NULL, 0);
		} else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
			out_path = argv[++i];
		} else {
			usage(argv[0]);
			return 1;
		}
	}
	if (n == 0 || n > QRNG_PROTO_MAX_REQUEST) {
		usage(argv[0]);
		return 1;
	}

	int fd;
	if (tcp_addr != NULL) {
		char host[128] = {0};
		int port = 0;
		char *colon = strchr(tcp_addr, ':');
		if (colon == NULL || (size_t)(colon - tcp_addr) >= sizeof host) {
			usage(argv[0]);
			return 1;
		}
		memcpy(host, tcp_addr, (size_t)(colon - tcp_addr));
		port = atoi(colon + 1);
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			perror("socket");
			return 1;
		}
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof addr);
		addr.sin_family = AF_INET;
		addr.sin_port = htons((uint16_t)port);
		if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
			fprintf(stderr, "bad TCP address '%s'\n", tcp_addr);
			close(fd);
			return 1;
		}
		if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
			fprintf(stderr, "connect %s: %s\n", tcp_addr, strerror(errno));
			close(fd);
			return 1;
		}
	} else {
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd < 0) {
			perror("socket");
			return 1;
		}
		struct sockaddr_un addr;
		memset(&addr, 0, sizeof addr);
		addr.sun_family = AF_UNIX;
		if (strlen(sock_path) >= sizeof addr.sun_path) {
			fprintf(stderr, "socket path too long\n");
			close(fd);
			return 1;
		}
		strcpy(addr.sun_path, sock_path);
		if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
			fprintf(stderr, "connect %s: %s (is qrng-server running?)\n",
			        sock_path, strerror(errno));
			close(fd);
			return 1;
		}
	}

	/* 请求：4 字节 LE n */
	uint8_t req[4];
	req[0] = (uint8_t)n;
	req[1] = (uint8_t)(n >> 8);
	req[2] = (uint8_t)(n >> 16);
	req[3] = (uint8_t)(n >> 24);
	if (write_full(fd, req, sizeof req) < 0) {
		perror("write request");
		close(fd);
		return 1;
	}

	/* 响应：status + len + payload */
	uint8_t hdr[5];
	if (read_full(fd, hdr, sizeof hdr) < 0) {
		fprintf(stderr, "server closed before responding\n");
		close(fd);
		return 1;
	}
	uint32_t len = (uint32_t)hdr[1] | ((uint32_t)hdr[2] << 8)
	               | ((uint32_t)hdr[3] << 16) | ((uint32_t)hdr[4] << 24);
	uint8_t *payload = malloc(len ? len : 1);
	if (payload == NULL) {
		fprintf(stderr, "out of memory\n");
		close(fd);
		return 1;
	}
	if (read_full(fd, payload, len) < 0) {
		fprintf(stderr, "truncated response\n");
		free(payload);
		close(fd);
		return 1;
	}
	close(fd);

	if (hdr[0] != QRNG_PROTO_STATUS_OK) {
		fprintf(stderr, "server FAIL (fail-closed): %.*s\n", (int)len, payload);
		free(payload);
		return 1;
	}
	if (len != n) {
		fprintf(stderr, "server returned %u bytes, wanted %zu\n", len, n);
		free(payload);
		return 1;
	}

	double t0 = now_s();
	if (out_path != NULL) {
		FILE *f = fopen(out_path, "wb");
		if (f == NULL) {
			fprintf(stderr, "cannot open %s: %s\n", out_path, strerror(errno));
			free(payload);
			return 1;
		}
		if (fwrite(payload, 1, len, f) != len) {
			fprintf(stderr, "short write to %s\n", out_path);
			fclose(f);
			free(payload);
			return 1;
		}
		fclose(f);
		printf("wrote %u bytes to %s\n", len, out_path);
	} else {
		size_t show = len < 512 ? len : 512;
		for (size_t i = 0; i < show; i++) {
			printf("%02x", payload[i]);
		}
		printf("\n");
		if (len > show) {
			printf("... (%u bytes total, hex output truncated)\n", len);
		}
	}
	(void)t0;
	printf("fetched : %u bytes\n", len);
	free(payload);
	return 0;
}