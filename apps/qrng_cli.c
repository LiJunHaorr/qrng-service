/* v3 CLI：全链路
 * 熵源 -> 启动/连续健康测试（90B 4.3/4.4）-> hash_df 条件化（90B 10.3.1）
 *      -> AES-256-CTR_DRBG（90A 10.2.1，no-DF）-> 输出。
 * 参数全部命令行可见：
 *   --health on|off      健康测试开关（默认 on）
 *   --condition on|off   条件化开关（默认 on；off = v1 行为）
 *   --drbg on|off        DRBG 开关（默认 on；off = v2 行为，条件化直出）
 *   --reseed-interval N  两次 reseed 间最大请求数（默认 1000000）
 *   --requests K         连续 generate 次数（默认 1）——演示 reseed 间隔
 *   --min-entropy H      每字节声明 min-entropy（默认 8.0）
 *   --alpha-log2 N       误报率 alpha = 2^-N（默认 40）
 *   --startup N          启动测试样本数（默认 1024）
 *
 * 用法：
 *   qrng-cli list
 *   qrng-cli <backend> [config] [-n BYTES] [-o FILE] [选项]
 * 示例：
 *   qrng-cli mock_det 42 -n 16
 *   qrng-cli mock_stuck -n 8               # 触发 RCT 报警 + fail-closed
 *   qrng-cli mock_det 0 -n 16 --requests 5 --reseed-interval 2  # reseed 演示
 *   qrng-cli quantis 0 -n 10000000          # DRBG 瞬时速率 vs 设备瓶颈
 *
 * 失败路径故意演示 fail-closed 的终态行为：报错之后立刻再调用一次，
 * 展示终态下调用必失败。 */
#include "qrng/qrng_core.h"

#include "opts.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_s(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void usage(const char *argv0) {
	fprintf(stderr,
	        "usage: %s list\n"
	        "       %s <backend> [config] [-n BYTES] [-o FILE]\n"
	        "                  [--health on|off] [--condition on|off]\n"
	        "                  [--drbg on|off] [--reseed-interval N]\n"
	        "                  [--requests K] [--min-entropy H]\n"
	        "                  [--alpha-log2 N] [--startup N]\n"
	        "backends: mock_det mock_stuck mock_biased file quantis\n",
	        argv0, argv0);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}
	if (strcmp(argv[1], "list") == 0) {
		for (int i = 0; i < qrng_backend_count(); i++) {
			printf("%s\n", qrng_backend_name(i));
		}
		return 0;
	}

	const char *backend = argv[1];
	const char *config = NULL;
	int argi = 2;
	if (argi < argc && argv[argi][0] != '-') {
		config = argv[argi++];
	}

	size_t n = 64;
	const char *out_path = NULL;
	qrng_core_conf_t cfg;
	qrng_core_default_conf(&cfg);
	unsigned long requests = 1;

	for (; argi < argc; argi++) {
		if (strcmp(argv[argi], "-n") == 0 && argi + 1 < argc) {
			n = (size_t)strtoul(argv[++argi], NULL, 0);
		} else if (strcmp(argv[argi], "-o") == 0 && argi + 1 < argc) {
			out_path = argv[++argi];
		} else if (strcmp(argv[argi], "--requests") == 0 && argi + 1 < argc) {
			requests = strtoul(argv[++argi], NULL, 0);
			if (requests < 1) {
				fprintf(stderr, "--requests must be >= 1\n");
				return 1;
			}
		} else {
			/* 层选项与 qrng-server 共用同一解析器（apps/opts.c） */
			int consumed = qrng_opts_try_parse(argc, argv, &argi, &cfg);
			if (consumed < 0) {
				return 1;
			}
			if (consumed == 0) {
				usage(argv[0]);
			return 1;
		}
			argi--; /* 解析器已推进到值后，循环再 +1 */
		}
	}

	qrng_core_t *core = qrng_core_new_cfg(backend, config, &cfg);
	if (core == NULL) {
		fprintf(stderr, "init failed: %s\n", qrng_core_init_error());
		return 1;
	}

	uint8_t *buf = malloc(n ? n : 1);
	if (buf == NULL) {
		fprintf(stderr, "out of memory\n");
		qrng_core_free(core);
		return 1;
	}

	FILE *out_file = NULL;
	if (out_path != NULL && requests > 0) {
		out_file = fopen(out_path, "wb");
		if (out_file == NULL) {
			fprintf(stderr, "cannot open %s: %s\n", out_path, strerror(errno));
			qrng_core_free(core);
			free(buf);
			return 1;
		}
	}

	double t0 = now_s();
	long r = -1;
	for (unsigned long req = 0; req < requests; req++) {
		r = qrng_core_generate(core, buf, n);
		if (r < 0) {
			break;
		}
		if (out_file != NULL) {
			if (fwrite(buf, 1, (size_t)r, out_file) != (size_t)r) {
				fprintf(stderr, "short write to %s\n", out_path);
				qrng_core_free(core);
				free(buf);
				fclose(out_file);
				return 1;
			}
		}
	}
	double t1 = now_s();
	if (out_file != NULL) {
		fclose(out_file);
		out_file = NULL;
	}

	if (r < 0) {
		fprintf(stderr, "FAIL (fail-closed): %s\n", qrng_core_last_error(core));
		/* 终态演示：失败后的调用一律拒绝，错误保持第一次的 */
		long again = qrng_core_generate(core, buf, 1);
		fprintf(stderr, "terminal-state check: second call returns %ld\n", again);
		qrng_core_free(core);
		free(buf);
		return 1;
	}

	if (out_path != NULL) {
		printf("wrote %llu bytes to %s\n",
		       (unsigned long long)((uint64_t)r * requests), out_path);
	} else {
		size_t show = (size_t)r < 512 ? (size_t)r : 512;
		for (size_t i = 0; i < show; i++) {
			printf("%02x", buf[i]);
		}
		printf("\n");
		if ((size_t)r > show) {
			printf("... (%ld bytes total, hex output truncated)\n", r);
		}
	}

	double dt = t1 - t0;
	uint64_t total_out = (uint64_t)r * requests;
	printf("backend : %s\n", backend);
	printf("requests: %lu x %ld bytes = %llu bytes\n", requests, r,
	       (unsigned long long)total_out);
	printf("elapsed : %.3f s (%.0f bytes/s)\n", dt,
	       dt > 0 ? (double)total_out / dt : 0.0);
	printf("counter : %llu bytes read from source\n",
	       (unsigned long long)qrng_core_bytes_read(core));
	const qrng_health_ctx_t *hctx = qrng_core_health(core);
	if (hctx != NULL) {
		printf("health  : RCT C=%u, APT C=%u (W=%u, H=%.1f, alpha=2^-%u)\n",
		       qrng_health_rct_cutoff(hctx), qrng_health_apt_cutoff(hctx),
		       qrng_health_window(hctx), cfg.health.min_entropy_bits,
		       cfg.health.alpha_log2);
		printf("startup : %u samples %s\n", qrng_health_startup_total(hctx),
		       qrng_health_startup_done(hctx) ? "passed" : "PENDING");
		printf("tested  : %llu samples\n",
		       (unsigned long long)qrng_health_samples_tested(hctx));
	} else {
		printf("health  : off\n");
	}
	uint64_t cin = qrng_core_condition_bytes_in(core);
	uint64_t cout = qrng_core_condition_bytes_out(core);
	if (cfg.condition.enabled) {
		double ratio = cout > 0 ? (double)cin / (double)cout : 0.0;
		double req = 8.0 / cfg.condition.min_entropy_bits;
		printf("cond    : hash_df SHA-256, H=%.1f -> in/out >= %.2f\n",
		       cfg.condition.min_entropy_bits, req);
		printf("account : in %llu / out %llu bytes (ratio %.2f)\n",
		       (unsigned long long)cin, (unsigned long long)cout, ratio);
	} else {
		printf("cond    : off\n");
	}
	if (qrng_core_drbg_bytes_generated(core) > 0 || cfg.drbg.enabled) {
		printf("drbg    : AES-256-CTR_DRBG (90A 10.2.1, no DF), reseed_interval=%llu\n",
		       cfg.drbg.reseed_interval);
		printf("drbg    : %llu bytes generated, %llu reseeds\n",
		       (unsigned long long)qrng_core_drbg_bytes_generated(core),
		       (unsigned long long)qrng_core_drbg_reseeds(core));
	} else {
		printf("drbg    : off\n");
	}

	qrng_core_free(core);
	free(buf);
	return 0;
}