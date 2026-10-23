/* v4 服务端：把整条链路（健康测试 -> 条件化 -> DRBG）常驻进程化。
 *
 * 用法：
 *   qrng-server <backend> [config] [层选项] [--socket PATH] [--tcp PORT]
 *               [--foreground] [--log FILE]
 *
 * 设计要点：
 * 1. **fail-closed 跨进程边界依然成立**：核心进入终态后服务不退出，
 *    而是对所有后续请求返回同一个错误（90B 4.3：持久故障不得再产出）。
 *    因此核心状态必须留在单个进程里——刻意用单线程 accept 循环，
 *    不做 fork-per-connection（fork 会复制终态、绕过 fail-closed）。
 * 2. 守护进程化：双 fork + setsid + chdir("/") + umask + stdio 重定向
 *    到日志文件（--foreground 留前台，测试/调试用）。
 * 3. 默认 Unix domain socket（生产链 QRNG-Provider 的本地形态）；
 *    --tcp PORT 面向远程消费者（对应 OpenSSL provider 场景）。
 * 4. --exit-on-failure：核心进入终态后服务主动退出（配合 systemd
 *    Restart=on-failure 实现"设备掉线 -> 拒绝 -> 自动重启 -> 重新走
 *    启动门禁"的恢复闭环。90B 4.3 允许"由系统/消费应用复位恢复"；
 *    复位 = 整个进程重来，绝不是悄悄继续供数）。
 */
#include "proto.h"
#include "opts.h"

#include "qrng/qrng_core.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_failed = 0; /* --exit-on-failure 触发 */
static int g_failed_exit = 0;              /* 由 main 从命令行设置 */
static const char *g_socket_path = NULL;

static void on_signal(int sig) {
	(void)sig;
	g_stop = 1;
}

static void log_line(FILE *log, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	time_t now = time(NULL);
	struct tm tmv;
	localtime_r(&now, &tmv);
	char stamp[32];
	strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S", &tmv);
	fprintf(log, "[%s] ", stamp);
	vfprintf(log, fmt, ap);
	fputc('\n', log);
	fflush(log);
	va_end(ap);
}

/* 双 fork 守护进程化（APUE 经典写法） */
static int daemonize(void) {
	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid > 0) {
		_exit(0); /* 父进程退出，shell 不被挂住 */
	}
	if (setsid() < 0) {
		return -1;
	}
	pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid > 0) {
		_exit(0); /* 会话首进程退出，永远不会重获终端 */
	}
	if (chdir("/") < 0) {
		/* 不致命 */
	}
	umask(0077);
	/* stdio 必须脱离调用方：不重定向的话守护进程攥着 ssh 的管道，
	 * 调用方会话被挂住（实测踩过）。日志走 FILE*，不受影响。 */
	int devnull = open("/dev/null", O_RDWR);
	if (devnull >= 0) {
		(void)dup2(devnull, STDIN_FILENO);
		(void)dup2(devnull, STDOUT_FILENO);
		(void)dup2(devnull, STDERR_FILENO);
		if (devnull > 2) {
			close(devnull);
		}
	}
	return 0;
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

static void put_le32(uint8_t *b, uint32_t v) {
	b[0] = (uint8_t)v;
	b[1] = (uint8_t)(v >> 8);
	b[2] = (uint8_t)(v >> 16);
	b[3] = (uint8_t)(v >> 24);
}

/* 服务一个连接：读请求 -> 走核心 -> 写响应。连接由调用方关闭。 */
static void serve_client(int fd, qrng_core_t *core, FILE *log,
                         unsigned long long *served, unsigned long long *failed) {
	for (;;) {
		uint8_t req[4];
		if (read_full(fd, req, sizeof req) < 0) {
			return; /* 客户端关闭/断开：正常结束 */
		}
		uint32_t n = (uint32_t)req[0] | ((uint32_t)req[1] << 8)
		             | ((uint32_t)req[2] << 16) | ((uint32_t)req[3] << 24);
		if (n == 0 || n > QRNG_PROTO_MAX_REQUEST) {
			const char *msg = "invalid request size";
			uint8_t hdr[5] = {QRNG_PROTO_STATUS_FAIL, 0, 0, 0, 0};
			put_le32(hdr + 1, (uint32_t)strlen(msg));
			(void)write_full(fd, hdr, sizeof hdr);
			(void)write_full(fd, msg, strlen(msg));
			return;
		}

		uint8_t *buf = malloc(n);
		if (buf == NULL) {
			const char *msg = "server out of memory";
			uint8_t hdr[5] = {QRNG_PROTO_STATUS_FAIL, 0, 0, 0, 0};
			put_le32(hdr + 1, (uint32_t)strlen(msg));
			(void)write_full(fd, hdr, sizeof hdr);
			(void)write_full(fd, msg, strlen(msg));
			return;
		}

		long r = qrng_core_generate(core, buf, n);
		if (r >= 0) {
			uint8_t hdr[5] = {QRNG_PROTO_STATUS_OK, 0, 0, 0, 0};
			put_le32(hdr + 1, (uint32_t)r);
			if (write_full(fd, hdr, sizeof hdr) == 0
			    && write_full(fd, buf, (size_t)r) == 0) {
				(*served)++;
				log_line(log, "OK %ld bytes (served=%llu, src=%llu)",
				         r, *served,
				         (unsigned long long)qrng_core_bytes_read(core));
			} else {
				log_line(log, "client write error: %s", strerror(errno));
			}
		} else {
			const char *err = qrng_core_last_error(core);
			size_t elen = strlen(err);
			uint8_t hdr[5] = {QRNG_PROTO_STATUS_FAIL, 0, 0, 0, 0};
			put_le32(hdr + 1, (uint32_t)elen);
			(void)write_full(fd, hdr, sizeof hdr);
			(void)write_full(fd, err, elen);
			(*failed)++;
			log_line(log, "FAIL %ld bytes: %s (fail-closed; failures=%llu)",
			         r, err, *failed);
			if (g_failed_exit) {
				/* 终态 + --exit-on-failure：把错误交给本连接后立即退出，
				 * 由 systemd 重启走恢复闭环（重新过启动门禁） */
				log_line(log, "exit-on-failure: terminating for supervised restart");
				g_failed = 1;
				g_stop = 1;
				free(buf);
				return;
			}
		}
		free(buf);
	}
}

static void usage(const char *argv0) {
	fprintf(stderr,
	        "usage: %s <backend> [config] [层选项]\n"
	        "                [--socket PATH] [--tcp PORT] [--foreground]\n"
	        "                [--log FILE] [--exit-on-failure]\n"
	        "层选项同 qrng-cli: --health/--condition/--drbg on|off,\n"
	        "  --reseed-interval N, --min-entropy H, --alpha-log2 N, --startup N\n",
	        argv0);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}
	const char *backend = argv[1];
	const char *config = NULL;
	int argi = 2;
	if (argi < argc && argv[argi][0] != '-') {
		config = argv[argi++];
	}

	qrng_core_conf_t cfg;
	qrng_core_default_conf(&cfg);
	const char *sock_path = QRNG_SOCK_DEFAULT;
	const char *log_path = "/tmp/qrng-demo.log";
	int tcp_port = 0;
	int foreground = 0;
	int exit_on_failure = 0;

	for (; argi < argc; argi++) {
		if (strcmp(argv[argi], "--socket") == 0 && argi + 1 < argc) {
			sock_path = argv[++argi];
		} else if (strcmp(argv[argi], "--tcp") == 0 && argi + 1 < argc) {
			tcp_port = (int)strtoul(argv[++argi], NULL, 0);
		} else if (strcmp(argv[argi], "--foreground") == 0) {
			foreground = 1;
		} else if (strcmp(argv[argi], "--exit-on-failure") == 0) {
			exit_on_failure = 1;
		} else if (strcmp(argv[argi], "--log") == 0 && argi + 1 < argc) {
			log_path = argv[++argi];
		} else {
			int consumed = qrng_opts_try_parse(argc, argv, &argi, &cfg);
			if (consumed < 0) {
				return 1;
			}
			if (consumed == 0) {
				usage(argv[0]);
				return 1;
			}
			argi--; /* qrng_opts_try_parse 已推进到值后，循环再 +1 */
		}
	}

	qrng_core_t *core = qrng_core_new_cfg(backend, config, &cfg);
	if (core == NULL) {
		fprintf(stderr, "init failed: %s\n", qrng_core_init_error());
		return 1;
	}

	/* 日志：后台模式先于守护化打开（fd 跨 fork 存活） */
	FILE *log = fopen(log_path, "a");
	if (log == NULL) {
		fprintf(stderr, "cannot open log %s: %s\n", log_path, strerror(errno));
		qrng_core_free(core);
		return 1;
	}

	int listen_fd = -1;
	if (tcp_port > 0) {
		listen_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (listen_fd < 0) {
			perror("socket");
			qrng_core_free(core);
			return 1;
		}
		int one = 1;
		setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof addr);
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = htons((uint16_t)tcp_port);
		if (bind(listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0
		    || listen(listen_fd, 16) < 0) {
			perror("bind/listen");
			qrng_core_free(core);
			return 1;
		}
	} else {
		listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (listen_fd < 0) {
			perror("socket");
			qrng_core_free(core);
			return 1;
		}
		struct sockaddr_un addr;
		memset(&addr, 0, sizeof addr);
		addr.sun_family = AF_UNIX;
		if (strlen(sock_path) >= sizeof addr.sun_path) {
			fprintf(stderr, "socket path too long\n");
			qrng_core_free(core);
			return 1;
		}
		strcpy(addr.sun_path, sock_path);
		unlink(sock_path); /* 清掉上次没 unlink 的残留 */
		if (bind(listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0
		    || listen(listen_fd, 16) < 0) {
			perror("bind/listen");
			qrng_core_free(core);
			return 1;
		}
		g_socket_path = sock_path;
	}

	if (!foreground && daemonize() != 0) {
		perror("daemonize");
		qrng_core_free(core);
		return 1;
	}

	/* sigaction 且不设 SA_RESTART：signal() 在 glibc 下默认 SA_RESTART，
	 * accept() 被信号打断后会自动重启，主循环永远看不到停止标志
	 * （实测踩过：SIGTERM 后服务杀不掉）。 */
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_signal;
	sa.sa_flags = 0; /* 关键：无 SA_RESTART，accept 返回 EINTR */
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);

	log_line(log, "qrng-server started: backend=%s%s%s tcp=%d foreground=%d",
	         backend, config ? " config=" : "", config ? config : "",
	         tcp_port, foreground);
	log_line(log, "chain: health=%d condition=%d drbg=%d (reseed_interval=%llu)",
	         cfg.health.enabled, cfg.condition.enabled, cfg.drbg.enabled,
	         cfg.drbg.reseed_interval);

	/* serve_client 读的进程级开关 */
	g_failed_exit = exit_on_failure;

	unsigned long long served = 0, failed = 0;
	while (!g_stop) {
		int client = accept(listen_fd, NULL, NULL);
		if (client < 0) {
			if (errno == EINTR) {
				continue;
			}
			log_line(log, "accept: %s", strerror(errno));
			break;
		}
		serve_client(client, core, log, &served, &failed);
		close(client);
	}

	log_line(log, "qrng-server stopping: served=%llu failed=%llu", served, failed);
	if (g_socket_path != NULL) {
		unlink(g_socket_path);
	}
	close(listen_fd);
	fclose(log);
	qrng_core_free(core);
	/* 非零退出码是给 systemd Restart=on-failure 的信号；
	 * 正常 SIGTERM 停止（systemctl stop）返回 0，不会触发重启 */
	return g_failed ? 1 : 0;
}