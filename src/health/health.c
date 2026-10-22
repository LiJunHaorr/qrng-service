/* SP 800-90B 健康测试实现（v1）。公式全部对着规范原文核对，出处标在行内：
 *
 * RCT（4.4.1）—— cutoff：
 *     C = 1 + ceil(-log2(alpha) / H)
 *   规范原文示例：alpha = 2^-20、H = 2.0 时 C = 1 + ceil(20/2.0) = 11；
 *   H = 8、误报率 ~2^-40 时 cutoff = 6（规范原话 "six repetitions"）。
 *   报警条件：同一样本连续出现 C 次（B >= C）。
 *
 * APT（4.4.2）—— 窗口与 cutoff：
 *   W = 512（非二进制样本；本项目所有后端吐字节）。
 *   cutoff C 取满足  Pr(Binom(W, 2^-H) >= C) <= alpha  的最小整数，
 *   即规范脚注 10 的 Excel 写法 C = 1 + CRITBINOM(W, 2^-H, 1-alpha)。
 *   阈值算法已用规范 Table 2 的全部非二进制数值交叉验证
 *   （alpha = 2^-20：H=0.5/1/2/4/8 -> 410/311/177/62/13），见
 *   tests/test_health.c。
 *   报警条件：窗口首样本值在该 W 窗口内出现 C 次（B >= C）。
 *
 * 启动测试（4.3）：首批 startup_samples 个样本必须先通过两个测试
 * 才允许对外供数。规范未规定最小长度，demo 取 1024（两个 APT 窗口），
 * 并强制 >= W，保证 APT 至少完整跑一轮。
 *
 * 纪律（4.3 第 2 条）：持久故障 -> 熵源不得再产出任何输出。
 * 本实现的失败即终态，由 core.c 的 fail-closed 状态机执行。
 */
#include "qrng/qrng_health.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define APT_WINDOW 512 /* 90B 4.4.2：非二进制源的窗口大小 */

struct qrng_health_ctx {
	double H;
	unsigned alpha_log2;
	unsigned window;
	unsigned rct_cutoff;
	unsigned apt_cutoff;
	uint64_t tested;
	uint64_t startup_total;
	uint64_t startup_remaining;
	/* RCT 状态：A = 上一个样本，B = 连续重复计数 */
	int have_prev;
	uint8_t prev;
	unsigned run;
	/* APT 状态：按规范 4.4.2 算法用不相交窗口——
	 * 每个窗口取首样本为 A（target），数它在窗口内出现的次数 B */
	unsigned wpos;
	uint8_t target;
	unsigned count;
};

void qrng_health_default_conf(qrng_health_conf_t *conf) {
	if (conf == NULL) {
		return;
	}
	conf->enabled = 1;
	conf->min_entropy_bits = 8.0;
	conf->alpha_log2 = 40;
	conf->startup_samples = 1024;
}

static double log_binom_pmf(unsigned n, unsigned k, double log_p, double log_q) {
	return lgamma((double)n + 1.0) - lgamma((double)k + 1.0)
	       - lgamma((double)(n - k) + 1.0)
	       + (double)k * log_p + (double)(n - k) * log_q;
}

/* 最小 C 使 Pr(X >= C) <= alpha，X ~ Binom(w, 2^-H)。
 * 从 c = w 往下累计尾概率（尾概率随 c 减小单调增），
 * 记录最后一个仍 <= alpha 的 c。全程 log 域，避免 1 - alpha 精度问题。 */
static unsigned apt_cutoff_for(unsigned w, double H, unsigned alpha_log2) {
	const double p = pow(2.0, -H);
	const double log_p = log(p);
	const double log_q = log1p(-p);
	const double log_alpha = -((double)alpha_log2) * log(2.0);
	unsigned answer = w + 1;
	double tail = 0.0; /* tail = Pr(X >= c) */
	for (unsigned c = w; c >= 1; c--) {
		tail += exp(log_binom_pmf(w, c, log_p, log_q));
		if (log(tail) <= log_alpha) {
			answer = c;
		} else {
			break;
		}
	}
	return answer;
}

qrng_health_ctx_t *qrng_health_start(const qrng_health_conf_t *conf,
                                     char *errbuf, size_t el) {
	qrng_health_conf_t def;
	if (conf == NULL) {
		qrng_health_default_conf(&def);
		conf = &def;
	}
	if (!(conf->min_entropy_bits > 0.0 && conf->min_entropy_bits <= 8.0)) {
		snprintf(errbuf, el, "min_entropy must be in (0,8] bits/byte, got %g",
		         conf->min_entropy_bits);
		return NULL;
	}
	if (conf->alpha_log2 < 1 || conf->alpha_log2 > 64) {
		snprintf(errbuf, el, "alpha_log2 must be in [1,64], got %u",
		         conf->alpha_log2);
		return NULL;
	}
	unsigned startup = conf->startup_samples;
	if (startup < APT_WINDOW) {
		snprintf(errbuf, el,
		         "startup_samples must cover one APT window (%u), got %u",
		         APT_WINDOW, startup);
		return NULL;
	}

	qrng_health_ctx_t *ctx = calloc(1, sizeof *ctx);
	if (ctx == NULL) {
		snprintf(errbuf, el, "out of memory");
		return NULL;
	}
	ctx->H = conf->min_entropy_bits;
	ctx->alpha_log2 = conf->alpha_log2;
	ctx->window = APT_WINDOW;
	/* RCT cutoff（90B 4.4.1） */
	ctx->rct_cutoff = 1 + (unsigned)ceil((double)conf->alpha_log2 / conf->min_entropy_bits);
	/* APT cutoff（90B 4.4.2 + 脚注 10） */
	ctx->apt_cutoff = apt_cutoff_for(APT_WINDOW, conf->min_entropy_bits, conf->alpha_log2);
	ctx->startup_total = startup;
	ctx->startup_remaining = startup;
	return ctx;
}

/* 逐样本推进两个状态机；返回 0 = 报警（errbuf 已写）。 */
static int check_byte(qrng_health_ctx_t *ctx, uint8_t b, uint64_t index,
                      char *errbuf, size_t el) {
	/* --- RCT --- */
	if (!ctx->have_prev) {
		ctx->have_prev = 1;
		ctx->prev = b;
		ctx->run = 1;
	} else if (b == ctx->prev) {
		ctx->run++;
	} else {
		ctx->prev = b;
		ctx->run = 1;
	}
	if (ctx->run >= ctx->rct_cutoff) {
		snprintf(errbuf, el,
		         "health RCT failure at sample #%llu: byte 0x%02x "
		         "repeated %u times consecutively (cutoff C=%u)",
		         (unsigned long long)index, b, ctx->run, ctx->rct_cutoff);
		return 0;
	}

	/* --- APT --- */
	if (ctx->wpos == 0) {
		ctx->target = b;
		ctx->count = 1;
	} else if (b == ctx->target) {
		ctx->count++;
	}
	if (ctx->count >= ctx->apt_cutoff) {
		snprintf(errbuf, el,
		         "health APT failure at sample #%llu: value 0x%02x occurred "
		         "%u times in a %u-sample window (cutoff C=%u)",
		         (unsigned long long)index, ctx->target, ctx->count,
		         ctx->window, ctx->apt_cutoff);
		return 0;
	}
	ctx->wpos = (ctx->wpos + 1) % ctx->window;
	return 1;
}

int qrng_health_check(qrng_health_ctx_t *ctx, const uint8_t *samples, size_t n,
                      char *errbuf, size_t el) {
	if (ctx == NULL || (n > 0 && samples == NULL)) {
		snprintf(errbuf, el, "health check: invalid arguments");
		return -1;
	}
	for (size_t i = 0; i < n; i++) {
		if (!check_byte(ctx, samples[i], ctx->tested + i, errbuf, el)) {
			return 0;
		}
	}
	ctx->tested += (uint64_t)n;
	if (ctx->startup_remaining > 0) {
		ctx->startup_remaining = ctx->startup_remaining > n
		                         ? ctx->startup_remaining - n : 0;
	}
	return 1;
}

int qrng_health_startup_done(const qrng_health_ctx_t *ctx) {
	return ctx != NULL && ctx->startup_remaining == 0;
}

unsigned qrng_health_startup_total(const qrng_health_ctx_t *ctx) {
	return ctx ? (unsigned)ctx->startup_total : 0;
}

unsigned qrng_health_rct_cutoff(const qrng_health_ctx_t *ctx) {
	return ctx ? ctx->rct_cutoff : 0;
}

unsigned qrng_health_apt_cutoff(const qrng_health_ctx_t *ctx) {
	return ctx ? ctx->apt_cutoff : 0;
}

unsigned qrng_health_window(const qrng_health_ctx_t *ctx) {
	return ctx ? ctx->window : 0;
}

uint64_t qrng_health_samples_tested(const qrng_health_ctx_t *ctx) {
	return ctx ? ctx->tested : 0;
}

void qrng_health_free(qrng_health_ctx_t *ctx) {
	free(ctx);
}