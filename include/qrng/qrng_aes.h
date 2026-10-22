#ifndef QRNG_AES_H
#define QRNG_AES_H

#include <stddef.h>
#include <stdint.h>

/* 自包含 AES-256（FIPS 197），只实现加密方向——CTR_DRBG 和 CTR
 * 模式永远不调用解密，砍掉一半实现换可读性。
 *
 * 正确性由 tests/test_drbg.c 用 FIPS 197 Appendix C.3 的向量
 * （K=603deb... / P=6bc1bee2... -> C=f3eed1bd...）和
 * SP 800-38A F.5.1 的 CTR 向量锁定。
 */

#define QRNG_AES256_KEY_BYTES 32
#define QRNG_AES_BLOCK_BYTES 16
#define QRNG_AES256_ROUND_KEYS 60 /* (Nr+1)*4 words, Nr=14 */

/* 密钥扩展。rk 必须能容纳 60 个 32 位字。 */
void qrng_aes256_key_schedule(uint32_t rk[QRNG_AES256_ROUND_KEYS],
                               const uint8_t key[QRNG_AES256_KEY_BYTES]);

/* 加密单个 16 字节块。 */
void qrng_aes256_encrypt_block(const uint32_t rk[QRNG_AES256_ROUND_KEYS],
                               const uint8_t in[QRNG_AES_BLOCK_BYTES],
                               uint8_t out[QRNG_AES_BLOCK_BYTES]);

#endif /* QRNG_AES_H */