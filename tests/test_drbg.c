/* v3 单元测试：AES-256 向量 + CTR_DRBG 结构 + 核心集成。
 *
 * AES 用 FIPS 197 C.3 与 SP 800-38A F.5.1 的向量锁定；
 * CTR_DRBG 的结构验证很关键：测试里用 qrng_aes256 手工复算
 * "instantiate 的 Update -> generate 的第一个输出块"，与实现
 * 的输出逐字节比对——这不是拿实现测实现，而是拿规范算法的
 * 手工推演测实现。
 */
#include "qrng/qrng_aes.h"
#include "qrng/qrng_core.h"
#include "qrng/qrng_condition.h"
#include "qrng/qrng_drbg.h"
#include "qrng/qrng_health.h"

#include <assert.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdlib.h>
#include <string.h>

static void hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
	for (size_t i = 0; i < len; i++) {
		unsigned v;
		sscanf(hex + 2 * i, "%2x", &v);
		out[i] = (uint8_t)v;
	}
}

static void test_aes256_vectors(void) {
	/* FIPS 197 Appendix C.3（CBC 首块，IV=0 时等价 ECB 单块） */
	uint8_t key[32], in[16], out[16], want[16];
	hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
	             key, 32);
	hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", in, 16);
	hex_to_bytes("f3eed1bdb5d2a03c064b5a7e3db181f8", want, 16);
	uint32_t rk[QRNG_AES256_ROUND_KEYS];
	qrng_aes256_key_schedule(rk, key);
	qrng_aes256_encrypt_block(rk, in, out);
	assert(memcmp(out, want, 16) == 0);
	printf("  aes: FIPS 197 C.3 block OK\n");

	/* SP 800-38A F.5.1 CTR-AES256：E(counter0)。
	 * 期望值 E(f0f1..feff) = C1 XOR P1，已用参考库独立核验。 */
	uint8_t ctr[16], expect[16];
	hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", ctr, 16);
	hex_to_bytes("0bdf7df1591716335e9a8b15c860c502", expect, 16);
	qrng_aes256_encrypt_block(rk, ctr, out);
	assert(memcmp(out, expect, 16) == 0);
	printf("  aes: SP 800-38A F.5.1 CTR block OK\n");
}

static qrng_drbg_ctx_t *drbg_new_custom(unsigned long long interval,
                                       unsigned long long bytes,
                                       unsigned long long seconds) {
	qrng_drbg_conf_t conf;
	qrng_drbg_default_conf(&conf);
	conf.reseed_interval = interval;
	conf.reseed_bytes = bytes;
	conf.reseed_seconds = seconds;
	qrng_drbg_ctx_t *ctx = qrng_drbg_new(&conf);
	assert(ctx != NULL);
	return ctx;
}

/* v5 可靠性：双阈值 reseed（字节总量 + 时间） */
static void test_dual_threshold_reseed(void) {
	/* 字节阈值 32：两个 16B 请求后第三个触发 reseed required */
	qrng_drbg_ctx_t *drbg = drbg_new_custom(1000000, 32, 0);
	uint8_t seed[48], buf[16];
	memset(seed, 0xAB, sizeof seed);
	assert(qrng_drbg_instantiate(drbg, seed) == 1);
	assert(qrng_drbg_generate(drbg, buf, sizeof buf) == 1);
	assert(!qrng_drbg_needs_reseed(drbg));
	assert(qrng_drbg_generate(drbg, buf, sizeof buf) == 1);
	assert(qrng_drbg_needs_reseed(drbg));   /* 32B >= 32B 阈值 */
	assert(qrng_drbg_generate(drbg, buf, sizeof buf) == 0); /* 拒绝 */
	assert(qrng_drbg_reseed(drbg, seed) == 1);
	assert(!qrng_drbg_needs_reseed(drbg));  /* 记账归零 */
	printf("  reseed-bytes: 32B threshold triggers and resets OK\n");
	qrng_drbg_free(drbg);

	/* 时间阈值 1 秒：睡 1 秒后触发 */
	drbg = drbg_new_custom(1000000, 0, 1);
	assert(qrng_drbg_instantiate(drbg, seed) == 1);
	assert(!qrng_drbg_needs_reseed(drbg));  /* 刚实例化，未超时 */

#ifdef _WIN32
	Sleep(1100); /* WinAPI，ms */
#else
	sleep(1);
#endif
	assert(qrng_drbg_needs_reseed(drbg));   /* 惰性触发：下次请求检查 */
	printf("  reseed-seconds: 1s time threshold OK\n");
	qrng_drbg_free(drbg);

	/* 核心层：字节阈值触发时自动从源拉新种子（记账可核对） */
	qrng_core_conf_t cfg;
	qrng_core_default_conf(&cfg);
	cfg.health.enabled = 0;
	cfg.condition.enabled = 0;
	cfg.drbg.enabled = 1;
	cfg.drbg.reseed_interval = 1000000;
	cfg.drbg.reseed_bytes = 32;   /* 两个 16B 请求就 reseed */
	cfg.drbg.reseed_seconds = 0;
	qrng_core_t *core = qrng_core_new_cfg("mock_det", "0", &cfg);
	assert(core != NULL);
	assert(qrng_core_generate(core, buf, sizeof buf) == 16); /* 种子 48 */
	assert(qrng_core_generate(core, buf, sizeof buf) == 16);
	assert(qrng_core_generate(core, buf, sizeof buf) == 16); /* 触发 reseed */
	assert(qrng_core_drbg_reseeds(core) == 1);
	assert(qrng_core_bytes_read(core) == 48 + 48); /* 种子 + reseed 种子 */
	printf("  core: byte threshold pulls new seed (96B from source) OK\n");
	qrng_core_free(core);
}

static void test_core_monitor(void) {
	/* 监控心跳：过健康测试后丢弃、计入 bytes_read、不进条件化记账 */
	qrng_core_conf_t cfg;
	qrng_core_default_conf(&cfg);   /* 健康开 */
	cfg.condition.enabled = 1;
	cfg.drbg.enabled = 0;
	qrng_core_t *core = qrng_core_new_cfg("mock_det", "0", &cfg);
	assert(core != NULL);
	assert(qrng_core_monitor(core, 1024) == 1);
	assert(qrng_core_bytes_read(core) == 1024);          /* 记账诚实 */
	assert(qrng_core_condition_bytes_in(core) == 0);     /* 未条件化 */
	uint64_t tested = qrng_health_samples_tested(qrng_core_health(core));
	assert(tested == 1024);
	printf("  monitor: 1024B tested+discarded, accounting honest OK\n");

	/* 源坏：监控发现即终态（与供数同判） */
	qrng_core_t *bad = qrng_core_new("mock_stuck", NULL);
	assert(bad != NULL);
	assert(qrng_core_monitor(bad, 64) == 0);
	const char *err = qrng_core_last_error(bad);
	printf("  monitor: stuck source detected: %s\n", err);
	assert(strstr(err, "RCT") != NULL);
	assert(qrng_core_generate(bad, (uint8_t[8]){0}, 8) < 0);
	qrng_core_free(core);
	qrng_core_free(bad);
}

static void test_ctr_drbg_structure(void) {
	uint8_t seed[QRNG_CTR_DRBG_SEEDLEN];
	for (size_t i = 0; i < sizeof seed; i++) {
		seed[i] = (uint8_t)(i * 7 + 1);
	}

	qrng_drbg_ctx_t *drbg = drbg_new_custom(1000, 0, 0);
	assert(drbg != NULL);
	assert(qrng_drbg_generate(drbg, seed, 0) == 0); /* 未实例化先拒绝 */
	assert(qrng_drbg_instantiate(drbg, seed) == 1);

	/* 手工复算（90A 10.2.1，no-DF）：
	 * 1) instantiate: Key=0, V=0; Update(seed):
	 *    temp = AES_0(1) || AES_0(2) || AES_0(3) XOR seed
	 *    K1 = temp[0:32], V1 = temp[32:48]
	 * 2) generate 首块: out = AES_K1(V1+1) */
	uint8_t zero_key[32] = {0};
	uint32_t rk0[QRNG_AES256_ROUND_KEYS], rk1[QRNG_AES256_ROUND_KEYS];
	qrng_aes256_key_schedule(rk0, zero_key);
	uint8_t v[16] = {0}, blocks[48], temp[48];
	for (int b = 0; b < 3; b++) {
		for (int i = 15; i >= 0; i--) { /* V+1 */
			if (++v[i] != 0) {
				break;
			}
		}
		qrng_aes256_encrypt_block(rk0, v, blocks + 16 * b);
	}
	for (int i = 0; i < 48; i++) {
		temp[i] = blocks[i] ^ seed[i];
	}
	uint8_t k1[32], v1[16];
	memcpy(k1, temp, 32);
	memcpy(v1, temp + 32, 16);
	qrng_aes256_key_schedule(rk1, k1);
	uint8_t expect[16];
	for (int i = 15; i >= 0; i--) { /* V1+1 */
		if (++v1[i] != 0) {
			break;
		}
	}
	qrng_aes256_encrypt_block(rk1, v1, expect);

	uint8_t got[16];
	assert(qrng_drbg_generate(drbg, got, sizeof got) == 1);
	assert(memcmp(got, expect, sizeof expect) == 0);
	printf("  drbg: first output block == manual spec derivation OK\n");

	/* 确定性：同种子两个实例，走完相同请求序列后流一致
	 * （drbg 之前已消费一个 16 字节请求，drbg2 先同步消费一个） */
	qrng_drbg_ctx_t *drbg2 = drbg_new_custom(1000, 0, 0);
	assert(qrng_drbg_instantiate(drbg2, seed) == 1);
	uint8_t stream1[64], stream2[64], sync[16];
	assert(qrng_drbg_generate(drbg2, sync, sizeof sync) == 1);
	assert(qrng_drbg_generate(drbg, stream1, sizeof stream1) == 1);
	assert(qrng_drbg_generate(drbg2, stream2, sizeof stream2) == 1);
	assert(memcmp(stream1, stream2, sizeof stream1) == 0);
	/* 状态推进：同一实例两次 generate 输出不同 */
	uint8_t again[64];
	assert(qrng_drbg_generate(drbg2, again, sizeof again) == 1);
	assert(memcmp(stream2, again, sizeof stream2) != 0);
	/* 种子敏感性 */
	uint8_t seed2[48];
	memcpy(seed2, seed, sizeof seed2);
	seed2[0] ^= 1;
	qrng_drbg_ctx_t *drbg3 = drbg_new_custom(1000, 0, 0);
	assert(qrng_drbg_instantiate(drbg3, seed2) == 1);
	uint8_t stream3[64];
	assert(qrng_drbg_generate(drbg3, stream3, sizeof stream3) == 1);
	assert(memcmp(stream2, stream3, sizeof stream2) != 0);
	printf("  drbg: determinism / state advance / seed sensitivity OK\n");
	qrng_drbg_free(drbg);
	qrng_drbg_free(drbg2);
	qrng_drbg_free(drbg3);
}

static void test_ctr_drbg_reseed_semantics(void) {
	uint8_t seed[48];
	memset(seed, 0xAB, sizeof seed);
	qrng_drbg_ctx_t *drbg = drbg_new_custom(2, 0, 0); /* 每 2 个请求 reseed */
	assert(qrng_drbg_instantiate(drbg, seed) == 1);
	uint8_t buf[16];
	/* 90A 10.2.1.5.1 步骤 1：generate 前检查 reseed_counter > interval。
	 * 实例化后 counter=1；第 1 次请求（1<=2）通过，counter=2；
	 * 第 2 次请求（2<=2）通过，counter=3；此后 needs_reseed 为真，
	 * 第 3 次请求被拒绝，直到 reseed 把 counter 归 1。 */
	assert(qrng_drbg_generate(drbg, buf, sizeof buf) == 1);
	assert(!qrng_drbg_needs_reseed(drbg));
	assert(qrng_drbg_generate(drbg, buf, sizeof buf) == 1);
	assert(qrng_drbg_needs_reseed(drbg));
	assert(qrng_drbg_generate(drbg, buf, sizeof buf) == 0); /* 拒绝生成 */
	uint8_t seed2[48];
	memset(seed2, 0xCD, sizeof seed2);
	assert(qrng_drbg_reseed(drbg, seed2) == 1);
	assert(!qrng_drbg_needs_reseed(drbg));
	assert(qrng_drbg_generate(drbg, buf, sizeof buf) == 1);
	printf("  drbg: reseed_required at interval boundary OK\n");
	qrng_drbg_free(drbg);

	assert(qrng_drbg_new(NULL) == NULL); /* interval 必须 >= 1 */
}

static void test_core_drbg_integration(void) {
	/* 全链：mock_det + 健康关 + 条件化关 + DRBG 开
	 * => 只从源读 48 字节种子，输出全部来自 DRBG */
	qrng_core_conf_t cfg;
	qrng_core_default_conf(&cfg);
	cfg.health.enabled = 0;
	cfg.condition.enabled = 0;
	cfg.drbg.enabled = 1;
	qrng_core_t *core = qrng_core_new_cfg("mock_det", "0", &cfg);
	assert(core != NULL);
	uint8_t buf[64];
	assert(qrng_core_generate(core, buf, sizeof buf) == 64);
	assert(qrng_core_bytes_read(core) == 48);       /* 只有种子 */
	assert(qrng_core_drbg_bytes_generated(core) == 64);
	assert(qrng_core_drbg_reseeds(core) == 0);
	assert(qrng_core_condition_bytes_in(core) == 0); /* 条件化关 */
	/* 确定性：DRBG 种子来自确定性源 => 输出可复现 */
	uint8_t buf2[64];
	assert(qrng_core_generate(core, buf2, sizeof buf2) == 64);
	assert(memcmp(buf, buf2, sizeof buf) != 0); /* 状态推进 */
	printf("  core: drbg path reads only 48B seed, accounting OK\n");
	qrng_core_free(core);

	/* 种子经条件化层（H=8 => in/out 48/48） */
	qrng_core_default_conf(&cfg);
	cfg.health.enabled = 0;
	cfg.condition.enabled = 1;
	cfg.drbg.enabled = 1;
	core = qrng_core_new_cfg("mock_det", "0", &cfg);
	assert(core != NULL);
	assert(qrng_core_generate(core, buf, sizeof buf) == 64);
	assert(qrng_core_bytes_read(core) == 48);
	assert(qrng_core_condition_bytes_in(core) == 48);
	assert(qrng_core_condition_bytes_out(core) == 48);
	assert(qrng_core_drbg_bytes_generated(core) == 64);
	printf("  core: seed flows through conditioning (in/out 48/48) OK\n");
	qrng_core_free(core);
}

static void test_core_reseed_interval(void) {
	/* 5 个请求、interval=2：请求 3 和 5 前各 reseed 一次
	 * （counter 1,2 通过；3>2 触发；reseed 后 counter=2，
	 *  下一个请求 3>2 再触发）*/
	qrng_core_conf_t cfg;
	qrng_core_default_conf(&cfg);
	cfg.health.enabled = 0;
	cfg.condition.enabled = 0;
	cfg.drbg.enabled = 1;
	cfg.drbg.reseed_interval = 2;
	qrng_core_t *core = qrng_core_new_cfg("mock_det", "0", &cfg);
	assert(core != NULL);
	uint8_t buf[16];
	for (int req = 1; req <= 5; req++) {
		assert(qrng_core_generate(core, buf, sizeof buf) == 16);
	}
	assert(qrng_core_drbg_reseeds(core) == 2);
	assert(qrng_core_bytes_read(core) == 48 + 2 * 48); /* 种子 + 2 次 reseed */
	printf("  core: interval=2, 5 requests -> 2 reseeds, 144B from source OK\n");
	qrng_core_free(core);
}

static void test_core_drbg_fail_closed(void) {
	/* 源在健康测试就 fail-closed：DRBG 永不实例化、零产出 */
	qrng_core_t *core = qrng_core_new("mock_stuck", NULL); /* v1 API 无 DRBG */
	qrng_core_free(core);

	qrng_core_conf_t cfg;
	qrng_core_default_conf(&cfg); /* 全开 */
	qrng_core_t *c2 = qrng_core_new_cfg("mock_stuck", NULL, &cfg);
	assert(c2 != NULL);
	uint8_t buf[8];
	assert(qrng_core_generate(c2, buf, sizeof buf) < 0);
	const char *err = qrng_core_last_error(c2);
	printf("  fail-closed: %s\n", err);
	assert(strstr(err, "RCT") != NULL);
	assert(qrng_core_drbg_bytes_generated(c2) == 0);
	assert(qrng_core_generate(c2, buf, 1) < 0);
	qrng_core_free(c2);
}

int main(void) {
	printf("test_aes256_vectors\n");
	test_aes256_vectors();
	printf("test_ctr_drbg_structure\n");
	test_ctr_drbg_structure();
	printf("test_ctr_drbg_reseed_semantics\n");
	test_ctr_drbg_reseed_semantics();
	printf("test_core_drbg_integration\n");
	test_core_drbg_integration();
	printf("test_core_reseed_interval\n");
	test_core_reseed_interval();
	printf("test_dual_threshold_reseed\n");
	test_dual_threshold_reseed();
	printf("test_core_monitor\n");
	test_core_monitor();
	printf("test_core_drbg_fail_closed\n");
	test_core_drbg_fail_closed();
	printf("ALL TESTS PASSED\n");
	return 0;
}