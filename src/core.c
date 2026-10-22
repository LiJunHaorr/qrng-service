/* 核心调度层：后端注册 + 健康测试挂载 + fail-closed 状态机。
 * 并发纪律（学 rand_qrng.c）：generate 持互斥锁串行化；
 * bytes_read/ready/last_error 是无锁只读快照（64 位对齐读），
 * 语义上允许读到"刚提交的那次"之前的状态，对记账/监控够用。
 *
 * v1 数据流（健康测试启用时）：
 *   首次 generate 先读 startup_samples 字节做启动测试（90B 4.3：
 *   测试通过之前不许对外供数；这些样本测试后丢弃，不做输出），
 *   然后正常读 n 字节、逐字节过 RCT/APT（90B 4.4），通过才交付。
 *   任何一环失败 -> 终态（90B 4.3 第 2 条：持久故障不得再产出）。
 */
#include "qrng/qrng_core.h"

#include <math.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BACKENDS 16

static const qrng_backend_t *g_backends[MAX_BACKENDS];
static int g_backend_count;
static char g_init_error[256];

void qrng_register_backend(const qrng_backend_t *backend) {
	if (g_backend_count < MAX_BACKENDS) {
		g_backends[g_backend_count++] = backend;
	}
}

int qrng_backend_count(void) {
	return g_backend_count;
}

const char *qrng_backend_name(int index) {
	return (index >= 0 && index < g_backend_count) ? g_backends[index]->name : NULL;
}

const char *qrng_core_init_error(void) {
	return g_init_error;
}

#define QRNG_HASH_DF_MAX_OUT (255u * 32u) /* counter 单字节 => 一次最多 8160 字节 */

struct qrng_core {
	const qrng_backend_t *backend;
	void *state;
	qrng_health_ctx_t *health; /* NULL = v0 裸直通 */
	unsigned startup_samples;
	int condition_enabled;
	double condition_min_entropy; /* 条件化层自己的熵声明 */
	uint64_t cond_in, cond_out;   /* hash_df 熵记账 */
	qrng_drbg_ctx_t *drbg;        /* NULL = 不经过 DRBG（v2 行为） */
	uint64_t drbg_out, drbg_reseeds;
	int failed; /* 终态标志：一旦置位不可恢复（fail-closed） */
	uint64_t bytes_read;
	char error[256];
	pthread_mutex_t mutex;
};

void qrng_core_default_conf(qrng_core_conf_t *conf) {
	if (conf == NULL) {
		return;
	}
	qrng_health_default_conf(&conf->health);
	qrng_condition_default_conf(&conf->condition);
	qrng_drbg_default_conf(&conf->drbg);
}

static qrng_core_t *core_new_common(const char *backend, const char *config,
                                    const qrng_health_conf_t *hconf,
                                    const qrng_condition_conf_t *cconf,
                                    const qrng_drbg_conf_t *dconf) {
	const qrng_backend_t *b = NULL;
	for (int i = 0; i < g_backend_count; i++) {
		if (strcmp(g_backends[i]->name, backend) == 0) {
			b = g_backends[i];
			break;
		}
	}
	if (b == NULL) {
		snprintf(g_init_error, sizeof g_init_error, "unknown backend '%s'", backend);
		return NULL;
	}

	qrng_core_t *core = calloc(1, sizeof *core);
	if (core == NULL) {
		snprintf(g_init_error, sizeof g_init_error, "out of memory");
		return NULL;
	}

	char err[128] = {0};
	core->state = b->create(config, err, sizeof err);
	if (core->state == NULL) {
		snprintf(g_init_error, sizeof g_init_error,
		         "backend '%s' init failed: %s", b->name, err);
		free(core);
		return NULL;
	}

	core->backend = b;
	if (hconf == NULL || hconf->enabled) {
		core->health = qrng_health_start(hconf, err, sizeof err);
		if (core->health == NULL) {
			snprintf(g_init_error, sizeof g_init_error,
			         "health tests init failed: %s", err);
			b->destroy(core->state);
			free(core);
			return NULL;
		}
		core->startup_samples = qrng_health_startup_total(core->health);
	}
	if (cconf != NULL && cconf->enabled) {
		if (!(cconf->min_entropy_bits > 0.0 && cconf->min_entropy_bits <= 8.0)) {
			snprintf(g_init_error, sizeof g_init_error,
			         "conditioning min_entropy must be in (0,8] bits/byte, got %g",
			         cconf->min_entropy_bits);
			b->destroy(core->state);
			qrng_health_free(core->health);
			free(core);
			return NULL;
		}
		core->condition_enabled = 1;
		core->condition_min_entropy = cconf->min_entropy_bits;
	}
	if (dconf != NULL && dconf->enabled) {
		core->drbg = qrng_drbg_new(dconf->reseed_interval);
		if (core->drbg == NULL) {
			snprintf(g_init_error, sizeof g_init_error,
			         "drbg init failed (reseed_interval must be >= 1)");
			b->destroy(core->state);
			qrng_health_free(core->health);
			free(core);
			return NULL;
		}
	}
	pthread_mutex_init(&core->mutex, NULL);
	return core;
}

qrng_core_t *qrng_core_new(const char *backend, const char *config) {
	return qrng_core_new_ex(backend, config, NULL);
}

qrng_core_t *qrng_core_new_ex(const char *backend, const char *config,
                              const qrng_health_conf_t *conf) {
	/* v1 API 兼容：只有健康测试参数，条件化与 DRBG 关闭 */
	qrng_condition_conf_t coff;
	qrng_condition_default_conf(&coff);
	coff.enabled = 0;
	return core_new_common(backend, config, conf, &coff, NULL);
}

qrng_core_t *qrng_core_new_cfg(const char *backend, const char *config,
                               const qrng_core_conf_t *conf) {
	qrng_core_conf_t def;
	const qrng_core_conf_t *c = conf;
	if (c == NULL) {
		qrng_core_default_conf(&def);
		c = &def;
	}
	return core_new_common(backend, config, &c->health, &c->condition, &c->drbg);
}

int qrng_core_ready(const qrng_core_t *core) {
	return core != NULL && !core->failed;
}

/* 启动测试（90B 4.3）：读 startup_samples 字节，全部通过才放行。
 * 失败/后端读失败都返回 -1，且 core 已进入终态。 */
static long run_startup(qrng_core_t *core) {
	const unsigned need = core->startup_samples;
	uint8_t *buf = malloc(need);
	if (buf == NULL) {
		snprintf(core->error, sizeof core->error, "out of memory (startup test)");
		core->failed = 1;
		return -1;
	}
	long r = core->backend->read(core->state, buf, need,
	                             core->error, sizeof core->error);
	if (r >= 0 && (size_t)r != need) {
		/* 短读：后端契约允许"返回实际读到的字节数"，但启动门禁
		 * 必须测满声明的长度——供不上就是故障（fail-closed） */
		snprintf(core->error, sizeof core->error,
		         "backend short read during startup test: %ld of %u bytes",
		         r, need);
		r = -1;
	}
	if (r >= 0) {
		core->bytes_read += (uint64_t)r;
		if (qrng_health_check(core->health, buf, (size_t)r,
		                      core->error, sizeof core->error) != 1) {
			r = -1; /* errbuf 已写明哪个测试触发；!= 1 连误用(-1)也算失败 */
		}
	}
	if (r < 0) {
		core->failed = 1;
	}
	free(buf);
	return r;
}

/* 从熵源拉 n 字节种子级字节：启动测试 + 健康测试 + 条件化。
 * DRBG 的实例化/reseed 种子也走这条路（90C 的 ES -> DRBG 衔接）。
 * 必须持有 core->mutex 调用。失败返回 -1（core 已进终态）。 */
static long pull_entropy_locked(qrng_core_t *core, uint8_t *out, size_t n) {
	long r = -1;
	if (core->failed) {
		/* 终态：错误信息保持第一次的，不覆盖 */
		if (core->error[0] == '\0') {
			snprintf(core->error, sizeof core->error, "backend in terminal failure state");
		}
		return -1;
	}
	if (n == 0) {
		return 0;
	}
	/* 启动测试未完成：先测试，通过前不产出任何字节 */
	if (core->health != NULL && !qrng_health_startup_done(core->health)) {
		if (run_startup(core) < 0) {
			return -1;
		}
	}
	{
		if (!core->condition_enabled) {
			r = core->backend->read(core->state, out, n,
			                        core->error, sizeof core->error);
			if (r >= 0) {
				core->bytes_read += (uint64_t)r;
				if (core->health != NULL
			    && qrng_health_check(core->health, out, (size_t)r,
			                   core->error, sizeof core->error) != 1) {
					core->failed = 1; /* RCT/APT 触发 = 终态，不交付缓冲区 */
					pthread_mutex_unlock(&core->mutex);
					return -1;
				}
			} else {
				/* fail-closed：任何失败都是终态。宁可停机，不供可疑数据。 */
				core->failed = 1;
			}
		} else {
			/* v2 条件化路径：每个输出块按 8/H 的比例读原始字节，
			 * 过健康测试后喂 hash_df，产出条件化字节。
			 * in >= ceil(8/H * out) 由 raw_need 的计算方式直接保证。 */
			size_t done = 0;
			while (done < n) {
				size_t chunk = n - done;
				if (chunk > QRNG_HASH_DF_MAX_OUT) {
					chunk = QRNG_HASH_DF_MAX_OUT;
				}
				size_t raw_need = (size_t)ceil(
				    (double)chunk * 8.0 / core->condition_min_entropy);
				uint8_t *raw = malloc(raw_need);
				if (raw == NULL) {
					snprintf(core->error, sizeof core->error,
					         "out of memory (conditioning buffer %zu bytes)",
					         raw_need);
					core->failed = 1;
					break;
				}
				long got = core->backend->read(core->state, raw, raw_need,
				                                core->error, sizeof core->error);
				if (got < 0) {
					core->failed = 1;
					free(raw);
					break;
				}
				if ((size_t)got != raw_need) {
					/* 短读 = 故障：绝不能拿没填满的缓冲去喂 hash_df
				 * （那等于把未初始化内存当熵），记账也不许虚增 */
					snprintf(core->error, sizeof core->error,
					         "backend short read: %ld of %zu bytes "
					         "(refusing to condition uninitialized memory)",
					         got, raw_need);
					core->failed = 1;
					free(raw);
					break;
				}
				core->bytes_read += (uint64_t)got;
				if (core->health != NULL
			    && qrng_health_check(core->health, raw, (size_t)got,
				                   core->error, sizeof core->error) != 1) {
					core->failed = 1;
					free(raw);
					break;
				}
				if (!qrng_hash_df(raw, raw_need, out + done, chunk)) {
					snprintf(core->error, sizeof core->error,
					         "hash_df failed for %zu-byte chunk", chunk);
					core->failed = 1;
					free(raw);
					break;
				}
				core->cond_in += (uint64_t)raw_need;
				core->cond_out += (uint64_t)chunk;
				done += chunk;
				free(raw);
			}
			if (done == n) {
				r = (long)n;
			}
		}
	}
	return r;
}

long qrng_core_generate(qrng_core_t *core, uint8_t *out, size_t n) {
	if (core == NULL) {
		return -1;
	}
	pthread_mutex_lock(&core->mutex);
	long r;
	if (core->drbg == NULL) {
		/* v2 路径：条件化字节直出 */
		r = pull_entropy_locked(core, out, n);
	} else {
		/* v3 路径：种子从 v2 管线来，输出从 DRBG 来 */
		r = -1;
		uint8_t seed[QRNG_CTR_DRBG_SEEDLEN];
		if (!qrng_drbg_instantiated(core->drbg)) {
			if (pull_entropy_locked(core, seed, sizeof seed) < 0) {
				goto done;
			}
			if (!qrng_drbg_instantiate(core->drbg, seed)) {
				snprintf(core->error, sizeof core->error, "drbg instantiate failed");
				core->failed = 1;
				goto done;
			}
		}
		if (qrng_drbg_needs_reseed(core->drbg)) {
			if (pull_entropy_locked(core, seed, sizeof seed) < 0) {
				goto done;
			}
			if (!qrng_drbg_reseed(core->drbg, seed)) {
				snprintf(core->error, sizeof core->error, "drbg reseed failed");
				core->failed = 1;
				goto done;
			}
			core->drbg_reseeds++;
		}
		memset(seed, 0, sizeof seed);
		size_t done = 0;
		while (done < n && !core->failed) {
			size_t chunk = n - done;
			size_t left = (size_t)-1 - done;
			if (chunk > left) {
				chunk = left;
			}
			if (!qrng_drbg_generate(core->drbg, out + done, chunk)) {
				snprintf(core->error, sizeof core->error,
				         "drbg generate failed (reseed required?)");
				core->failed = 1;
				break;
			}
			done += chunk;
		}
		if (done == n) {
			core->drbg_out += (uint64_t)n;
			r = (long)n;
		} else {
			r = -1;
		}
done:;
	}
	pthread_mutex_unlock(&core->mutex);
	return r;
}

uint64_t qrng_core_bytes_read(const qrng_core_t *core) {
	return core ? core->bytes_read : 0;
}

uint64_t qrng_core_drbg_bytes_generated(const qrng_core_t *core) {
	return core ? core->drbg_out : 0;
}

uint64_t qrng_core_drbg_reseeds(const qrng_core_t *core) {
	return core ? core->drbg_reseeds : 0;
}

uint64_t qrng_core_condition_bytes_in(const qrng_core_t *core) {
	return core ? core->cond_in : 0;
}

uint64_t qrng_core_condition_bytes_out(const qrng_core_t *core) {
	return core ? core->cond_out : 0;
}

const qrng_health_ctx_t *qrng_core_health(const qrng_core_t *core) {
	return core ? core->health : NULL;
}

const char *qrng_core_last_error(const qrng_core_t *core) {
	return core ? core->error : g_init_error;
}

void qrng_core_free(qrng_core_t *core) {
	if (core == NULL) {
		return;
	}
	if (core->state != NULL) {
		core->backend->destroy(core->state);
	}
	qrng_health_free(core->health);
	qrng_drbg_free(core->drbg);
	pthread_mutex_destroy(&core->mutex);
	free(core);
}