/* 消费端应用 demo（应用层）：ML-KEM-768 密钥生成，吃本项目链的随机数。
 *
 * 用法：
 *   qrng-keygen <backend> [config] [层选项] [-o PREFIX] [-s SOCKET]
 *
 * 两种取种子方式：
 *   1. 直连：进程内跑整条链（熵源 -> 健康测试 -> 条件化 -> DRBG）
 *   2. 服务：-s /tmp/qrng-demo.sock，64 字节种子从常驻 qrng-server 拉
 *      （生产链形态：RNG 服务与密钥应用分进程部署）
 *
 * 种子交给 liboqs 的 OQS_KEM_keypair_derand()（显式种子注入 API）。
 *
 * fail-closed 在应用边界的契约：
 *   种子拿不到/健康测试报警 => 拒绝调用 keygen、不产出任何密钥、
 *   退出码 1。宁可没有密钥，不用可疑种子生成弱密钥。
 *   （生产链同款语义：OQS_QRNG_PURE_KEYGEN 模式下 QRNG 不可用
 *   时 keygen 必须失败，绝不静默退回系统 RNG。）
 *
 * 演示要点：
 *   - 同一后端两次运行 => 不同密钥（量子种子的新鲜性）
 *   - mock_det（确定性源）=> 每次同一密钥（种子->密钥可复现）
 *   - mock_stuck => RCT 报警，keygen REFUSED，exit 1
 *   - encap/decap 往返验证密钥可用
 */
#include "opts.h"
#include "svc_client.h"

#include "qrng/qrng_core.h"
#include "qrng/qrng_drbg.h"
#include "qrng/qrng_sha256.h"

#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fingerprint(const char *label, const uint8_t *data, size_t len) {
	uint8_t d[QRNG_SHA256_DIGEST_LENGTH];
	qrng_sha256(d, data, len);
	printf("%-10s SHA-256: ", label);
	for (size_t i = 0; i < sizeof d; i++) {
		printf("%02x", d[i]);
	}
	printf("\n");
}

static void usage(const char *argv0) {
	fprintf(stderr,
	        "usage: %s <backend> [config] [层选项] [-o PREFIX] [-s SOCKET]\n"
	        "  -o PREFIX  写出 PREFIX.pub / PREFIX.sk\n"
	        "  -s SOCKET  种子改从 qrng-server 取（服务化形态）\n"
	        "层选项同 qrng-cli\n",
	        argv0);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}
	const char *backend = NULL;
	const char *config = NULL;
	const char *service_sock = NULL;
	const char *prefix = NULL;
	int argi = 1;
	if (argv[argi][0] != '-') {
		backend = argv[argi++];
		if (argi < argc && argv[argi][0] != '-') {
			config = argv[argi++];
		}
	}

	qrng_core_conf_t cfg;
	qrng_core_default_conf(&cfg);
	for (; argi < argc; argi++) {
		if (strcmp(argv[argi], "-o") == 0 && argi + 1 < argc) {
			prefix = argv[++argi];
		} else if (strcmp(argv[argi], "-s") == 0 && argi + 1 < argc) {
			service_sock = argv[++argi];
		} else {
			int consumed = qrng_opts_try_parse(argc, argv, &argi, &cfg);
			if (consumed < 0) {
				return 1;
			}
			if (consumed == 0) {
				usage(argv[0]);
				return 1;
			}
			argi--;
		}
	}
	if (service_sock == NULL && backend == NULL) {
		usage(argv[0]);
		return 1;
	}

	OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
	if (kem == NULL) {
		fprintf(stderr, "OQS_KEM_new(ML-KEM-768) failed\n");
		return 1;
	}
	const size_t seed_len = kem->length_keypair_seed; /* ML-KEM-768: 64 */
	printf("algorithm : %s (keypair seed %zu bytes)\n", kem->method_name, seed_len);

	/* --- 取种子（应用边界，fail-closed 在这里把关）--- */
	uint8_t seed[128];
	char err[512] = {0};
	if (seed_len > sizeof seed) {
		fprintf(stderr, "seed too long for demo buffer\n");
		OQS_KEM_free(kem);
		return 1;
	}

	if (service_sock != NULL) {
		if (!qrng_svc_fetch(service_sock, seed, seed_len, err, sizeof err)) {
			fprintf(stderr, "KEYGEN REFUSED (fail-closed): %s\n", err);
			OQS_KEM_free(kem);
			return 1;
		}
		printf("seed      : %zu bytes from qrng-server (%s)\n", seed_len,
		       service_sock);
	} else {
		qrng_core_t *core = qrng_core_new_cfg(backend, config, &cfg);
		if (core == NULL) {
			fprintf(stderr, "init failed: %s\n", qrng_core_init_error());
			OQS_KEM_free(kem);
			return 1;
		}
		long r = qrng_core_generate(core, seed, seed_len);
		if (r < 0) {
			/* 种子不可疑地获得 => 绝不调用 keygen */
			fprintf(stderr, "KEYGEN REFUSED (fail-closed): %s\n",
			        qrng_core_last_error(core));
			qrng_core_free(core);
			OQS_KEM_free(kem);
			return 1;
		}
		printf("seed      : %ld bytes from chain (backend=%s, src=%lluB)\n",
		       r, backend, (unsigned long long)qrng_core_bytes_read(core));
		qrng_core_free(core);
	}

	/* --- keygen（显式种子）--- */
	uint8_t *pk = malloc(kem->length_public_key);
	uint8_t *sk = malloc(kem->length_secret_key);
	if (pk == NULL || sk == NULL) {
		fprintf(stderr, "out of memory\n");
		free(pk);
		free(sk);
		OQS_KEM_free(kem);
		return 1;
	}
	OQS_STATUS rc = OQS_KEM_keypair_derand(kem, pk, sk, seed);
	OQS_MEM_cleanse(seed, seed_len);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "keypair_derand failed (%d)\n", rc);
		OQS_MEM_secure_free(pk, kem->length_public_key);
		OQS_MEM_secure_free(sk, kem->length_secret_key);
		OQS_KEM_free(kem);
		return 1;
	}

	fingerprint("pubkey", pk, kem->length_public_key);
	fingerprint("privkey", sk, kem->length_secret_key);

	/* --- encap/decap 往返：证明密钥真的能用 --- */
	uint8_t *ct = malloc(kem->length_ciphertext);
	uint8_t *ss1 = malloc(kem->length_shared_secret);
	uint8_t *ss2 = malloc(kem->length_shared_secret);
	if (ct == NULL || ss1 == NULL || ss2 == NULL) {
		fprintf(stderr, "out of memory\n");
		goto cleanup;
	}
	if (OQS_KEM_encaps(kem, ct, ss1, pk) != OQS_SUCCESS
	    || OQS_KEM_decaps(kem, ss2, ct, sk) != OQS_SUCCESS) {
		fprintf(stderr, "encap/decap failed\n");
		goto cleanup;
	}
	if (memcmp(ss1, ss2, kem->length_shared_secret) != 0) {
		fprintf(stderr, "shared secret mismatch!\n");
		goto cleanup;
	}
	printf("roundtrip : encap/decap OK (%zu-byte shared secret matches)\n",
	       kem->length_shared_secret);

	if (prefix != NULL) {
		char path[512];
		snprintf(path, sizeof path, "%s.pub", prefix);
		FILE *f = fopen(path, "wb");
		if (f == NULL || fwrite(pk, 1, kem->length_public_key, f)
		                 != kem->length_public_key) {
			fprintf(stderr, "cannot write %s\n", path);
			goto cleanup;
		}
		fclose(f);
		snprintf(path, sizeof path, "%s.sk", prefix);
		f = fopen(path, "wb");
		if (f == NULL || fwrite(sk, 1, kem->length_secret_key, f)
		                 != kem->length_secret_key) {
			fprintf(stderr, "cannot write %s\n", path);
			goto cleanup;
		}
		fclose(f);
		printf("files     : %s.pub / %s.sk written\n", prefix, prefix);
	}

cleanup:
	if (ct != NULL) {
		OQS_MEM_secure_free(ct, kem->length_ciphertext);
	}
	if (ss1 != NULL) {
		OQS_MEM_secure_free(ss1, kem->length_shared_secret);
	}
	if (ss2 != NULL) {
		OQS_MEM_secure_free(ss2, kem->length_shared_secret);
	}
	OQS_MEM_secure_free(pk, kem->length_public_key);
	OQS_MEM_secure_free(sk, kem->length_secret_key);
	OQS_KEM_free(kem);
	return 0;
}