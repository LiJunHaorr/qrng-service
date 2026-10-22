/* v1 单元测试：阈值计算对照规范 + 故障注入 + fail-closed 集成。
 *
 * 关键的 Table 2 交叉验证：SP 800-90B 4.4.2 的示例表
 * （alpha = 2^-20，非二进制 W=512）给出
 *   H = 0.5 / 1 / 2 / 4 / 8  ->  C = 410 / 311 / 177 / 62 / 13
 * 阈值算法如果对得上这张表，说明公式实现没有跑偏。
 * RCT 示例（4.4.1 原文）：alpha = 2^-20、H = 2.0 -> C = 11。
 */
#include "qrng/qrng_core.h"
#include "qrng/qrng_health.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static qrng_health_ctx_t *ctx_for(double H, unsigned alpha_log2) {
	qrng_health_conf_t conf;
	qrng_health_default_conf(&conf);
	conf.min_entropy_bits = H;
	conf.alpha_log2 = alpha_log2;
	char err[128] = {0};
	qrng_health_ctx_t *ctx = qrng_health_start(&conf, err, sizeof err);
	assert(ctx != NULL);
	return ctx;
}

static void test_cutoffs_match_spec_tables(void) {
	/* APT：规范 Table 2（alpha = 2^-20，非二进制 W=512） */
	static const double Hs[] = {0.5, 1.0, 2.0, 4.0, 8.0};
	static const unsigned want[] = {410, 311, 177, 62, 13};
	for (size_t i = 0; i < sizeof Hs / sizeof Hs[0]; i++) {
		qrng_health_ctx_t *ctx = ctx_for(Hs[i], 20);
		unsigned got = qrng_health_apt_cutoff(ctx);
		printf("  APT cutoff H=%.1f: got %u, spec %u\n", Hs[i], got, want[i]);
		assert(got == want[i]);
		qrng_health_free(ctx);
	}
	/* RCT：规范 4.4.1 原文示例 */
	qrng_health_ctx_t *ctx = ctx_for(2.0, 20);
	assert(qrng_health_rct_cutoff(ctx) == 11);
	qrng_health_free(ctx);
	/* 我们的默认参数：H=8, alpha=2^-40 -> RCT C=6, APT C=19 */
	ctx = ctx_for(8.0, 40);
	assert(qrng_health_rct_cutoff(ctx) == 6);
	assert(qrng_health_apt_cutoff(ctx) == 19);
	printf("  defaults H=8 alpha=2^-40: RCT C=6, APT C=19 OK\n");
	qrng_health_free(ctx);
}

static void test_rct_detects_stuck(void) {
	qrng_health_ctx_t *ctx = ctx_for(8.0, 40);
	char err[128] = {0};
	uint8_t five[5] = {0xA5, 0xA5, 0xA5, 0xA5, 0xA5};
	assert(qrng_health_check(ctx, five, sizeof five, err, sizeof err) == 1);
	uint8_t sixth[1] = {0xA5};
	assert(qrng_health_check(ctx, sixth, 1, err, sizeof err) == 0);
	printf("  RCT: 6th consecutive byte alarms: %s\n", err);
	assert(strstr(err, "RCT") != NULL);
	/* 换成正常递增流不报警 */
	qrng_health_free(ctx);
	ctx = ctx_for(8.0, 40);
	uint8_t seq[64];
	for (size_t i = 0; i < sizeof seq; i++) {
		seq[i] = (uint8_t)i;
	}
	assert(qrng_health_check(ctx, seq, sizeof seq, err, sizeof err) == 1);
	qrng_health_free(ctx);
}

static void test_apt_detects_overrepresentation(void) {
	/* 窗口首样本 0x42；奇数位填 1..64 的循环值（不等于 0x42=66，
	 * 且相邻永不相等，RCT 不误触发）。0x42 出现次数 = 触发测试变量。 */
	qrng_health_ctx_t *ctx;
	char err[128] = {0};
	for (unsigned occurrences = 18; occurrences <= 19; occurrences++) {
		ctx = ctx_for(8.0, 40); /* cutoff = 19 */
		uint8_t win[512];
		for (size_t j = 0; j < sizeof win; j++) {
			if (j % 2 == 0 && j / 2 < occurrences) {
				win[j] = 0x42;
			} else {
				win[j] = (uint8_t)(1 + j % 64);
			}
		}
		int rc = qrng_health_check(ctx, win, sizeof win, err, sizeof err);
		if (occurrences == 18) {
			assert(rc == 1);
			printf("  APT: 18 occurrences in window pass (cutoff 19)\n");
		} else {
			assert(rc == 0);
			printf("  APT: 19 occurrences in window alarms: %s\n", err);
			assert(strstr(err, "APT") != NULL);
		}
		qrng_health_free(ctx);
	}
}

static void test_core_startup_gating(void) {
	/* mock_det：启动测试 1024 字节通过后，输出从计数 42+1024 开始 */
	qrng_core_t *core = qrng_core_new("mock_det", "42");
	assert(core != NULL);
	uint8_t buf[16];
	long r = qrng_core_generate(core, buf, sizeof buf);
	assert(r == 16);
	for (size_t i = 0; i < sizeof buf; i++) {
		assert(buf[i] == (uint8_t)(42 + 1024 + i));
	}
	assert(qrng_core_bytes_read(core) == 1024 + 16);
	const qrng_health_ctx_t *hctx = qrng_core_health(core);
	assert(hctx != NULL);
	assert(qrng_health_startup_done(hctx));
	assert(qrng_health_samples_tested(hctx) == 1024 + 16);
	printf("  core: startup consumed 1024 bytes, output starts at %02x\n", buf[0]);
	qrng_core_free(core);
}

static void test_core_fail_closed_on_stuck(void) {
	qrng_core_t *core = qrng_core_new("mock_stuck", NULL);
	assert(core != NULL);
	uint8_t buf[8];
	assert(qrng_core_generate(core, buf, sizeof buf) < 0);
	const char *err = qrng_core_last_error(core);
	printf("  core: mock_stuck fails with: %s\n", err);
	assert(strstr(err, "RCT") != NULL);
	assert(qrng_core_ready(core) == 0);
	/* 终态：再调用直接拒绝 */
	assert(qrng_core_generate(core, buf, 1) < 0);
	qrng_core_free(core);

	/* --health off：v0 裸直通，卡死流照样出（对照用） */
	qrng_health_conf_t hc;
	qrng_health_default_conf(&hc);
	hc.enabled = 0;
	core = qrng_core_new_ex("mock_stuck", NULL, &hc);
	assert(core != NULL);
	assert(qrng_core_generate(core, buf, sizeof buf) == 8);
	assert(buf[0] == 0xA5 && buf[7] == 0xA5);
	qrng_core_free(core);
	printf("  core: health off -> raw passthrough OK\n");
}

static void test_file_backend_fail_closed(void) {
	const char *path = "test_100bytes.bin";
	FILE *f = fopen(path, "wb");
	assert(f != NULL);
	for (int i = 0; i < 100; i++) {
		uint8_t b = (uint8_t)(i * 7);
		fwrite(&b, 1, 1, f);
	}
	fclose(f);

	qrng_core_t *core = qrng_core_new("file", path);
	assert(core != NULL);
	uint8_t buf[200];
	/* 健康测试启动需要 1024 字节，100 字节的文件直接读穿 -> fail-closed */
	assert(qrng_core_generate(core, buf, sizeof buf) < 0);
	printf("  file: %s\n", qrng_core_last_error(core));
	assert(qrng_core_generate(core, buf, 1) < 0);
	qrng_core_free(core);
	remove(path);

	/* health off 时回到 v0 行为：请求 200 但只有 100 -> 失败 + 终态 */
	f = fopen(path, "wb");
	for (int i = 0; i < 100; i++) {
		uint8_t b = (uint8_t)i;
		fwrite(&b, 1, 1, f);
	}
	fclose(f);
	qrng_health_conf_t hc;
	qrng_health_default_conf(&hc);
	hc.enabled = 0;
	core = qrng_core_new_ex("file", path, &hc);
	assert(core != NULL);
	assert(qrng_core_generate(core, buf, sizeof buf) < 0);
	assert(qrng_core_generate(core, buf, 1) < 0);
	qrng_core_free(core);
	remove(path);
	printf("  file: v0 exhaustion + terminal state OK\n");
}

static void test_biased_source_with_honest_entropy_claim(void) {
	/* mock_biased 0.6 的真实 p_max = 0.6^8 ~ 0.0168 -> H ~ 5.9 bit。
	 * 声明 H=8 阈值过紧；如实声明 5.5 bit 则健康测试放行，
	 * 统计偏差留给 stats.py 去抓（分层各管各的）。 */
	qrng_health_conf_t hc;
	qrng_health_default_conf(&hc);
	hc.min_entropy_bits = 5.5;
	qrng_core_t *core = qrng_core_new_ex("mock_biased", "0.6", &hc);
	assert(core != NULL);
	uint8_t buf[2048];
	assert(qrng_core_generate(core, buf, sizeof buf) == 2048);
	const qrng_health_ctx_t *hctx = qrng_core_health(core);
	assert(qrng_health_apt_cutoff(hctx) == 42); /* Table 2 算法外推 */
	printf("  biased: H=5.5 declared, APT C=%u, stream passes health\n",
	       qrng_health_apt_cutoff(hctx));
	qrng_core_free(core);
}

static void test_bad_configs_rejected(void) {
	char err[128] = {0};
	qrng_health_conf_t hc;
	qrng_health_default_conf(&hc);
	hc.min_entropy_bits = 8.5;
	assert(qrng_health_start(&hc, err, sizeof err) == NULL);
	printf("  config: %s\n", err);
	hc.min_entropy_bits = 8.0;
	hc.startup_samples = 100; /* < APT 窗口 512 */
	assert(qrng_health_start(&hc, err, sizeof err) == NULL);
	printf("  config: %s\n", err);
	qrng_core_t *core = qrng_core_new_ex("mock_det", "0", &hc);
	assert(core == NULL);
	assert(strstr(qrng_core_init_error(), "startup_samples") != NULL);
}

int main(void) {
	printf("test_cutoffs_match_spec_tables\n");
	test_cutoffs_match_spec_tables();
	printf("test_rct_detects_stuck\n");
	test_rct_detects_stuck();
	printf("test_apt_detects_overrepresentation\n");
	test_apt_detects_overrepresentation();
	printf("test_core_startup_gating\n");
	test_core_startup_gating();
	printf("test_core_fail_closed_on_stuck\n");
	test_core_fail_closed_on_stuck();
	printf("test_file_backend_fail_closed\n");
	test_file_backend_fail_closed();
	printf("test_biased_source_with_honest_entropy_claim\n");
	test_biased_source_with_honest_entropy_claim();
	printf("test_bad_configs_rejected\n");
	test_bad_configs_rejected();
	printf("ALL TESTS PASSED\n");
	return 0;
}