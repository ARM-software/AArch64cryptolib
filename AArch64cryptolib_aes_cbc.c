/*
 *   BSD LICENSE
 *
 *   Copyright (C) Cavium networks Ltd. 2017.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Cavium networks nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "AArch64cryptolib_private.h"

#define likely(x)	__builtin_expect((x),1)
#define unlikely(x)	__builtin_expect((x),0)

int
armv8_enc_aes_cbc_sha1_128(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
	uint8_t *dsrc, uint8_t *ddst, uint64_t dlen, armv8_cipher_digest_t *arg)
{

	/* Digest source length has to be equal to or exceed cipher length */
	if (unlikely(dlen < clen))
		return -1;
	/* Digest length has to be a multiple of 8 bytes */
	if (unlikely((dlen % 8) != 0))
		return -1;
	/* Cipher length for this cipher has to be a multiple of 16 bytes */
	if (unlikely((clen % 16) != 0))
		return -1;

	return (asm_aes128cbc_sha1_hmac(csrc, cdst, clen,
						dsrc, ddst, dlen, arg));
}

int
armv8_enc_aes_cbc_sha256_128(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
	uint8_t *dsrc, uint8_t *ddst, uint64_t dlen, armv8_cipher_digest_t *arg)
{

	/* Digest source length has to be equal to or exceed cipher length */
	if (unlikely(dlen < clen))
		return -1;
	/* Digest length has to be a multiple of 8 bytes */
	if (unlikely((dlen % 8) != 0))
		return -1;
	/* Cipher length for this cipher has to be a multiple of 16 bytes */
	if (unlikely((clen % 16) != 0))
		return -1;

	return (asm_aes128cbc_sha256_hmac(csrc, cdst, clen,
						dsrc, ddst, dlen, arg));
}

int
armv8_dec_aes_cbc_sha1_128(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
	uint8_t *dsrc, uint8_t *ddst, uint64_t dlen, armv8_cipher_digest_t *arg)
{

	/* Digest source length has to be equal to or exceed cipher length */
	if (unlikely(dlen < clen))
		return -1;
	/*
	 * The difference between digest source length and cipher source cannot
	 * exceed 64 bytes, or the digest source may be overwritten if it
	 * overlaps with the cipher destination.
	 */
	if (unlikely((dlen - clen) > 64))
		return -1;
	/* Digest length has to be a multiple of 8 bytes */
	if (unlikely((dlen % 8) != 0))
		return -1;
	/* Cipher length for this cipher has to be a multiple of 16 bytes */
	if (unlikely((clen % 16) != 0))
		return -1;

	return (asm_sha1_hmac_aes128cbc_dec(csrc, cdst, clen,
						dsrc, ddst, dlen, arg));
}

int
armv8_dec_aes_cbc_sha256_128(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
	uint8_t *dsrc, uint8_t *ddst, uint64_t dlen, armv8_cipher_digest_t *arg)
{

	/* Digest source length has to be equal to or exceed cipher length */
	if (unlikely(dlen < clen))
		return -1;
	/*
	 * The difference between digest source length and cipher source cannot
	 * exceed 64 bytes, or the digest source may be overwritten if it
	 * overlaps with the cipher destination.
	 */
	if (unlikely((dlen - clen) > 64))
		return -1;
	/* Digest length has to be a multiple of 8 bytes */
	if (unlikely((dlen % 8) != 0))
		return -1;
	/* Cipher length for this cipher has to be a multiple of 16 bytes */
	if (unlikely((clen % 16) != 0))
		return -1;

	return (asm_sha256_hmac_aes128cbc_dec(csrc, cdst, clen,
						dsrc, ddst, dlen, arg));
}

