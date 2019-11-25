/*
 *   BSD LICENSE
 *
 *   Copyright (C) Cavium networks Ltd. 2016.
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

#ifndef offsetof
/** Return the offset of a field in a structure. */
#define offsetof(TYPE, MEMBER)  __builtin_offsetof (TYPE, MEMBER)
#endif

#include "AArch64cryptolib.h"

#define	ASSYM(name, offset)						\
do {									\
	asm volatile("----------\n");					\
	/* Place pattern, name + value in the assembly code */		\
	asm volatile("\n<genassym> " #name " %0\n" :: "i" (offset));	\
} while (0)


static void __attribute__((__unused__))
generate_as_symbols(void)
{

	ASSYM(CIPHER_KEY, offsetof(AArch64crypto_cipher_digest_t, cipher.key));
	ASSYM(CIPHER_IV, offsetof(AArch64crypto_cipher_digest_t, cipher.iv));

	ASSYM(HMAC_KEY, offsetof(AArch64crypto_cipher_digest_t, digest.hmac.key));
	ASSYM(HMAC_IKEYPAD, offsetof(AArch64crypto_cipher_digest_t, digest.hmac.i_key_pad));
	ASSYM(HMAC_OKEYPAD, offsetof(AArch64crypto_cipher_digest_t, digest.hmac.o_key_pad));
}
