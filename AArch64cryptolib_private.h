//Copyright (c) 2018-2019, ARM Limited. All rights reserved.
//
//SPDX-License-Identifier:        BSD-3-Clause

#ifndef AARCH64CRYPTOLIB_PRIVATE_H
#define AARCH64CRYPTOLIB_PRIVATE_H

#include "AArch64cryptolib.h"

int sha1_block(uint8_t *init, const uint8_t *src, uint8_t *dst, uint64_t len);
int sha256_block(uint8_t *init, const uint8_t *src, uint8_t *dst, uint64_t len);
/*
 * Assembly calls for AES-CBC/SHA interface
 */
int asm_aes128cbc_sha1_hmac(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
			AArch64crypto_cipher_digest_t *arg);
int asm_aes128cbc_sha256_hmac(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
			AArch64crypto_cipher_digest_t *arg);
int asm_sha1_hmac_aes128cbc_dec(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
			AArch64crypto_cipher_digest_t *arg);
int asm_sha256_hmac_aes128cbc_dec(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
			AArch64crypto_cipher_digest_t *arg);

#endif