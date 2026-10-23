#ifndef QRNG_OPTS_H
#define QRNG_OPTS_H

#include "qrng/qrng_core.h"

/* qrng-cli 与 qrng-server 共享的"层参数"解析器（v4 抽取）：
 *   --health on|off / --condition on|off / --drbg on|off
 *   --reseed-interval N / --reseed-bytes N / --reseed-seconds N
 *   --min-entropy H / --alpha-log2 N / --startup N
 *
 * 用法：应用主循环里对每个 argv 调用本函数。
 * 返回 1 = 是层选项且已消费（*argi 已推进到值后）；
 * 返回 0 = 不是层选项（调用方自己处理）；
 * 返回 -1 = 参数错误（已打印原因）。
 */
int qrng_opts_try_parse(int argc, char **argv, int *argi,
                        qrng_core_conf_t *cfg);

#endif /* QRNG_OPTS_H */