#ifndef QRNG_PROTO_H
#define QRNG_PROTO_H

/* qrng-server / qrng-fetch 之间的极简定长协议（v4）。
 *
 * 请求：  4 字节 LE uint32 n（要取的字节数）
 * 响应：  1 字节 status（0=OK，1=FAIL）+ 4 字节 LE uint32 len + len 字节
 *         OK 时 payload 是随机字节；FAIL 时 payload 是错误文本（终态时
 *         错误保持第一次的——fail-closed 跨进程边界依然成立）。
 *
 * 有意不支持的事：多路并发命令、管道化。demo 的服务化目标就一个：
 * 把"启动成本摊平的常驻链路"跑起来给多个客户端用。
 */
#define QRNG_SOCK_DEFAULT "/tmp/qrng-demo.sock"
#define QRNG_PROTO_MAX_REQUEST (16u * 1024u * 1024u) /* 单请求上限 16 MB */
#define QRNG_PROTO_STATUS_OK 0
#define QRNG_PROTO_STATUS_FAIL 1

#endif /* QRNG_PROTO_H */