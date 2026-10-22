#ifndef QRNG_SVC_CLIENT_H
#define QRNG_SVC_CLIENT_H

#include <stddef.h>
#include <stdint.h>

/* v4 服务的程序化取数辅助（qrng-fetch 是 CLI，这里是给应用
 * 内嵌用的最小客户端：连 Unix socket 取 n 字节）。
 *
 * 返回 1 = 成功（out 填好）；返回 0 = 失败，errbuf 写明原因
 * （连接失败 / 服务端 fail-closed 返回的错误原样透传）。
 * fail-closed 契约在应用边界的体现：错误必须传上来，由应用
 * 决定拒绝继续——不许静默吞掉换别的随机源。 */
int qrng_svc_fetch(const char *socket_path, uint8_t *out, size_t n,
                   char *errbuf, size_t errbuf_len);

#endif /* QRNG_SVC_CLIENT_H */