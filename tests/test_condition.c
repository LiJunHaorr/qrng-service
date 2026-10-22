/* v2 单元测试：SHA-256 向量 + hash_df 结构 + 条件化熵记账。
 *
 * SHA-256 用 FIPS 180-4 / NIST CSOR 的四个标准向量锁定；
 * hash_df 验证前缀布局（counter||no_output_bits）与分块结构；
 * 核心层验证 in/out 记账（ceil(8/H * n)）、>8160 字节分块、
 * fail-closed 在条件化路径下依然成立。
 */
#include "qrng/qrng_condition.h"
#include "qrng/qrng_core.h"
#include "qrng/qrng_health.h"
#include "qrng/qrng_sha256.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void hex_equal(const char *name, const uint8_t *got, const char *want_hex) {
	char got_hex[2 * QRNG_SHA256_DIGEST_LENGTH + 1];
	for (size_t i = 0; i < QRNG_SHA256_DIGEST_LENGTH; i++) {
		snprintf(got_hex + 2 * i, 3, "%02x", got[i]);
	}
	if (strcmp(got_hex, want_hex) != 0) {
		fprintf(stderr, "%s: got %s want %s\n", name, got_hex, want_hex);
		assert(0);
	}
}

static void test_sha256_vectors(void) {
	uint8_t d[32];
	const char *empty = "";
	qrng_sha256(d, (const uint8_t *)empty, 0);
	hex_equal("sha256(empty)", d,
	          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	qrng_sha256(d, (const uint8_t *)"abc", 3);
	hex_equal("sha256(abc)", d,
	          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	const char *msg55 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	qrng_sha256(d, (const uint8_t *)msg55, strlen(msg55));
	hex_equal("sha256(55B)", d,
	          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

	uint8_t *million = malloc(1000000);
	assert(million != NULL);
	memset(million, 'a', 1000000);
	qrng_sha256(d, million, 1000000);
	hex_equal("sha256(1M a)", d,
	          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
	free(million);
	printf("  sha256: 4 standard vectors OK\n");

	/* 增量接口：任意切分 == 一次性 */
	uint8_t d2[32];
	qrng_sha256_ctx ctx;
	qrng_sha256_inc_init(&ctx);
	qrng_sha256_inc(&ctx, (const uint8_t *)"ab", 1);
	qrng_sha256_inc(&ctx, (const uint8_t *)"bc", 2);
	qrng_sha256_inc_finalize(d2, &ctx);
	qrng_sha256(d, (const uint8_t *)"abc", 3);
	assert(memcmp(d, d2, 32) == 0);
	printf("  sha256: incremental == one-shot OK\n");
}

static void test_hash_df_structure(void) {
	const char *input = "seed-string";
	size_t ilen = strlen(input);
	uint8_t out[64];

	assert(qrng_hash_df((const uint8_t *)input, ilen, out, 64) == 1);

	/* 前 32 字节 = SHA256(0x01 || 0x00000200 || input)（64 字节输出
	 * => no_output_bits = 512 = 0x00000200） */
	uint8_t expect[32], msg[5 + 64];
	msg[0] = 1; /* counter */
	msg[1] = 0; msg[2] = 0; msg[3] = 2; msg[4] = 0; /* 512 位大端 */
	memcpy(msg + 5, input, ilen);
	qrng_sha256(expect, msg, 5 + ilen);
	assert(memcmp(out, expect, 32) == 0);

	/* 后 32 字节 = counter=2 的下一块 */
	msg[0] = 2;
	qrng_sha256(expect, msg, 5 + ilen);
	assert(memcmp(out + 32, expect, 32) == 0);
	printf("  hash_df: prefix layout + counter chaining OK\n");

	/* 确定性 */
	uint8_t again[64];
	assert(qrng_hash_df((const uint8_t *)input, ilen, again, 64) == 1);
	assert(memcmp(out, again, 64) == 0);

	/* 边界：空输入 / 空输出 / 超过 255*32 */
	assert(qrng_hash_df(NULL, 0, out, 32) == 0);
	assert(qrng_hash_df((const uint8_t *)input, ilen, out, 0) == 0);
	uint8_t big[8161];
	assert(qrng_hash_df((const uint8_t *)input, ilen, big, sizeof big) == 0);
	printf("  hash_df: determinism + limits OK\n");
}

static void core_setup(const char *backend, const char *config,
                       double H, int health_on, qrng_core_t **core) {
	qrng_core_conf_t cfg;
	qrng_core_default_conf(&cfg);
	cfg.health.enabled = health_on;
	cfg.drbg.enabled = 0; /* 本文件专测条件化层，DRBG 关闭 */
	if (H > 0.0) {
		cfg.health.min_entropy_bits = H;
		cfg.condition.min_entropy_bits = H;
	}
	*core = qrng_core_new_cfg(backend, config, &cfg);
	assert(*core != NULL);
}

static void test_condition_accounting(void) {
	/* H=5.5, n=64：raw = ceil(64*8/5.5) = 94 字节，in/out 记账可核对 */
	qrng_core_t *core;
	core_setup("mock_det", "0", 5.5, 0, &core);
	uint8_t buf[64];
	assert(qrng_core_generate(core, buf, sizeof buf) == 64);
	assert(qrng_core_bytes_read(core) == 94);
	assert(qrng_core_condition_bytes_in(core) == 94);
	assert(qrng_core_condition_bytes_out(core) == 64);

	/* 输出必须等于 hash_df(计数器 0..93 的 94 字节, 64 字节出) */
	uint8_t raw[94], expect[64];
	for (size_t i = 0; i < sizeof raw; i++) {
		raw[i] = (uint8_t)i;
	}
	assert(qrng_hash_df(raw, sizeof raw, expect, sizeof expect) == 1);
	assert(memcmp(buf, expect, sizeof expect) == 0);
	printf("  accounting: H=5.5, n=64 -> in 94 / out 64, output == hash_df OK\n");
	qrng_core_free(core);

	/* H=8：1:1 */
	core_setup("mock_det", "0", 8.0, 0, &core);
	assert(qrng_core_generate(core, buf, sizeof buf) == 64);
	assert(qrng_core_condition_bytes_in(core) == 64);
	assert(qrng_core_condition_bytes_out(core) == 64);
	printf("  accounting: H=8 -> 1:1 OK\n");
	qrng_core_free(core);
}

static void test_condition_chunking(void) {
	/* n=10000 > 8160（counter 单字节上限）：分两块 8160 + 1840 */
	qrng_core_t *core;
	core_setup("mock_det", "0", 8.0, 0, &core);
	uint8_t *buf = malloc(10000);
	assert(buf != NULL);
	assert(qrng_core_generate(core, buf, 10000) == 10000);
	assert(qrng_core_condition_bytes_in(core) == 10000);
	assert(qrng_core_condition_bytes_out(core) == 10000);

	/* 块 1：hash_df(counter 0..8159) 8160 字节出 */
	uint8_t *raw = malloc(8160), *expect = malloc(8160);
	assert(raw != NULL && expect != NULL);
	for (size_t i = 0; i < 8160; i++) {
		raw[i] = (uint8_t)i;
	}
	assert(qrng_hash_df(raw, 8160, expect, 8160) == 1);
	assert(memcmp(buf, expect, 8160) == 0);
	/* 块 2：hash_df(counter 8160..9999) 1840 字节出 */
	uint8_t *raw2 = malloc(1840), *expect2 = malloc(1840);
	assert(raw2 != NULL && expect2 != NULL);
	for (size_t i = 0; i < 1840; i++) {
		raw2[i] = (uint8_t)(8160 + i);
	}
	assert(qrng_hash_df(raw2, 1840, expect2, 1840) == 1);
	assert(memcmp(buf + 8160, expect2, 1840) == 0);
	printf("  chunking: n=10000 -> 8160+1840 blocks verified OK\n");
	free(buf); free(raw); free(expect); free(raw2); free(expect2);
	qrng_core_free(core);
}

static void test_condition_fail_closed(void) {
	/* 健康测试 + 条件化全开：卡死源在 RCT 就 fail-closed，
	 * 且不交付 hash_df 输出（原始字节先过健康测试才进条件化） */
	qrng_core_t *core;
	core_setup("mock_stuck", NULL, 8.0, 1, &core);
	uint8_t buf[8];
	assert(qrng_core_generate(core, buf, sizeof buf) < 0);
	const char *err = qrng_core_last_error(core);
	printf("  fail-closed: %s\n", err);
	assert(strstr(err, "RCT") != NULL);
	assert(qrng_core_generate(core, buf, 1) < 0);
	assert(qrng_core_condition_bytes_out(core) == 0); /* 没产出任何条件化字节 */
	qrng_core_free(core);

	/* 健康测试关、条件化开：卡死流照样条件化（统计上会变均匀，
	 * 但急性故障归健康测试管——分层各管各的） */
	core_setup("mock_stuck", NULL, 8.0, 0, &core);
	assert(qrng_core_generate(core, buf, sizeof buf) == 8);
	assert(qrng_core_condition_bytes_out(core) == 8);
	uint8_t raw[8], expect[8];
	memset(raw, 0xA5, sizeof raw);
	assert(qrng_hash_df(raw, sizeof raw, expect, sizeof expect) == 1);
	assert(memcmp(buf, expect, sizeof expect) == 0);
	printf("  condition-only: stuck stream conditioned deterministically OK\n");
	qrng_core_free(core);
}

static void test_bad_condition_conf(void) {
	qrng_core_conf_t cfg;
	qrng_core_default_conf(&cfg);
	cfg.condition.min_entropy_bits = 9.0;
	qrng_core_t *core = qrng_core_new_cfg("mock_det", "0", &cfg);
	assert(core == NULL);
	printf("  config: %s\n", qrng_core_init_error());
	assert(strstr(qrng_core_init_error(), "conditioning min_entropy") != NULL);

	cfg.condition.min_entropy_bits = 8.0;
	cfg.condition.enabled = 0;
	core = qrng_core_new_cfg("mock_det", "0", &cfg);
	assert(core != NULL);
	uint8_t buf[16];
	assert(qrng_core_generate(core, buf, sizeof buf) == 16);
	assert(qrng_core_condition_bytes_in(core) == 0); /* off = 不记账 */
	qrng_core_free(core);
	printf("  config: condition off -> no accounting OK\n");
}

/* 回归测试：短读后端（mock_short 只填一半）必须 fail-closed，
 * 绝不能把未填满的缓冲喂给 hash_df（v2 修复锁定）。 */
static void test_short_read_fail_closed(void) {
	qrng_core_conf_t cfg;
	qrng_core_default_conf(&cfg);
	cfg.health.enabled = 0;
	cfg.condition.enabled = 1;
	cfg.drbg.enabled = 0;
	qrng_core_t *core = qrng_core_new_cfg("mock_short", NULL, &cfg);
	assert(core != NULL);
	uint8_t buf[64];
	assert(qrng_core_generate(core, buf, sizeof buf) < 0);
	printf("  short-read (conditioning): %s\n", qrng_core_last_error(core));
	assert(strstr(qrng_core_last_error(core), "short read") != NULL);
	assert(qrng_core_condition_bytes_out(core) == 0);
	qrng_core_free(core);

	/* 启动门禁同样：短读 = 故障（测不满声明的 1024 字节） */
	qrng_core_default_conf(&cfg);
	cfg.condition.enabled = 0;
	cfg.drbg.enabled = 0;
	core = qrng_core_new_cfg("mock_short", NULL, &cfg);
	assert(core != NULL);
	assert(qrng_core_generate(core, buf, sizeof buf) < 0);
	printf("  short-read (startup): %s\n", qrng_core_last_error(core));
	assert(strstr(qrng_core_last_error(core), "short read") != NULL);
	qrng_core_free(core);
}

int main(void) {
	printf("test_sha256_vectors\n");
	test_sha256_vectors();
	printf("test_hash_df_structure\n");
	test_hash_df_structure();
	printf("test_condition_accounting\n");
	test_condition_accounting();
	printf("test_condition_chunking\n");
	test_condition_chunking();
	printf("test_condition_fail_closed\n");
	test_condition_fail_closed();
	printf("test_short_read_fail_closed\n");
	test_short_read_fail_closed();
	printf("test_bad_condition_conf\n");
	test_bad_condition_conf();
	printf("ALL TESTS PASSED\n");
	return 0;
}