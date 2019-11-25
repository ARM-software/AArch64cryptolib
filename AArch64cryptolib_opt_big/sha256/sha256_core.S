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

#include "assym.s"

/*
 * Description:
 *
 * Core SHA-2 Primitives
 *
 * Operations:
 * AArch64crypto_sha256_block_partial:
 * 	out = partial_sha256(init, in, len)	<- no final block
 *
 * sha256_block:
 * 	out = sha256(init, in, len)
 *
 * Prototype:
 *
 * int AArch64crypto_sha256_block_partial(uint8_t *init,
 *			uint8_t *dsrc, uint8_t *ddst, uint64_t len)
 *
 * int sha256_block(uint8_t *init,
 *			uint8_t *dsrc, uint8_t *ddst, uint64_t len)
 *
 * returns: 0 (success), -1 (failure)
 *
 * Registers used:
 *
 * AArch64crypto_sha256_block_partial(
 *	init,			x0	(hash init state - NULL for default)
 *	dsrc,			x1	(digest src address)
 *	ddst,			x2	(digest dst address)
 *	len,			x3	(length)
 *	)
 *
 * sha256_block(
 *	init,			x0	(hash init state - NULL for default)
 *	dsrc,			x1	(digest src address)
 *	ddst,			x2	(digest dst address)
 *	len,			x3	(length)
 *	)
 *
 * Routine register definitions:
 *
 * v4 - v7 -- round consts for sha
 * v21 -- ABCD tmp
 * v22 -- sha working state ABCD (q22)
 * v23 -- sha working state EFGH (q23)
 * v24 -- reg_sha_stateABCD
 * v25 -- reg_sha_stateEFGH
 * v26 -- sha block 0
 * v27 -- sha block 1
 * v28 -- sha block 2
 * v29 -- sha block 3
 * v30 -- reserved
 * v31 -- reserved
 *
 * Constraints:
 *
 * The variable "len" must be a multiple of 16,
 * otherwise error code is returned.
 *
 */
	.file "sha256_core.S"
	.text
	.cpu generic+fp+simd+crypto+crc
	.align	4
	.global AArch64crypto_sha256_block_partial
	.type	AArch64crypto_sha256_block_partial,%function
	.global sha256_block
	.type	sha256_block,%function

	.align	4
.Lrcon:
	.word		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
	.word		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
	.word		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
	.word		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
	.word		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
	.word		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
	.word		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
	.word		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
	.word		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
	.word		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
	.word		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
	.word		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
	.word		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
	.word		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
	.word		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
	.word		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

	.align	4
.Linit_sha_state:
	.word		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
	.word		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

	.align	4

AArch64crypto_sha256_block_partial:
	mov		x6, #1			/* indicate partial hash */
	ands		x5, x3, #0x3f		/* check size mod 1 SHA block */
	b.ne		.Lsha256_error
	cbnz		x0, 1f
	/* address of sha init state consts */
	adr		x0,.Linit_sha_state
1:
	ld1		{v24.4s, v25.4s},[x0]	/* init ABCD, EFGH */
	/* number of 16B blocks (will be at least 4) */
	lsr		x5, x3, 4
	b		.Lsha256_loop

sha256_block:
	mov		x6, xzr			/* indicate full hash */
	ands		x5, x3, #0xf		/* check size mod 16B block */
	b.ne		.Lsha256_error
	cbnz		x0, 1f
	/* address of sha init state consts */
	adr		x0,.Linit_sha_state
1:
	ld1		{v24.4s, v25.4s},[x0]	/* init ABCD, EFGH. (2 cycs) */
	lsr		x5, x3, 4		/* number of 16B blocks */
	cmp		x5, #4	/* at least 4 16B blocks give 1 SHA block */
	b.lo		.Lsha256_last

	.align	4
.Lsha256_loop:
	sub		x5, x5, #4		/* substract 1 SHA block */
	adr		x4,.Lrcon

	ld1		{v26.16b},[x1],16	/* dsrc[0] */
	ld1		{v27.16b},[x1],16	/* dsrc[1] */
	ld1		{v28.16b},[x1],16	/* dsrc[2] */
	ld1		{v29.16b},[x1],16	/* dsrc[3] */

	rev32		v26.16b,v26.16b		/* fix endian w0 */
	rev32		v27.16b,v27.16b		/* fix endian w1 */
	rev32		v28.16b,v28.16b		/* fix endian w2 */
	rev32		v29.16b,v29.16b		/* fix endian w3 */

	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */

	ld1		{v4.16b},[x4],16	/* key0 */
	ld1		{v5.16b},[x4],16	/* key1 */
	ld1		{v6.16b},[x4],16	/* key2 */
	ld1		{v7.16b},[x4],16	/* key3 */

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	sha256su0	v26.4s,v27.4s
	sha256su1	v26.4s,v28.4s,v29.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	sha256su0	v27.4s,v28.4s
	sha256su1	v27.4s,v29.4s,v26.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	sha256su0	v28.4s,v29.4s
	sha256su1	v28.4s,v26.4s,v27.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	sha256su0	v29.4s,v26.4s
	sha256su1	v29.4s,v27.4s,v28.4s

	ld1		{v4.16b},[x4],16	/* key4 */
	ld1		{v5.16b},[x4],16	/* key5 */
	ld1		{v6.16b},[x4],16	/* key6 */
	ld1		{v7.16b},[x4],16	/* key7 */

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	sha256su0	v26.4s,v27.4s
	sha256su1	v26.4s,v28.4s,v29.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	sha256su0	v27.4s,v28.4s
	sha256su1	v27.4s,v29.4s,v26.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	sha256su0	v28.4s,v29.4s
	sha256su1	v28.4s,v26.4s,v27.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	sha256su0	v29.4s,v26.4s
	sha256su1	v29.4s,v27.4s,v28.4s

	ld1		{v4.16b},[x4],16	/* key8 */
	ld1		{v5.16b},[x4],16	/* key9 */
	ld1		{v6.16b},[x4],16	/* key10 */
	ld1		{v7.16b},[x4],16	/* key11 */

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v4.4s,v4.4s,v26.4s	/* wk = key8+w0 */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	sha256su0	v26.4s,v27.4s
	sha256su1	v26.4s,v28.4s,v29.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v5.4s,v5.4s,v27.4s	/* wk = key9+w1 */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	sha256su0	v27.4s,v28.4s
	sha256su1	v27.4s,v29.4s,v26.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v6.4s,v6.4s,v28.4s	/* wk = key10+w2 */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	sha256su0	v28.4s,v29.4s
	sha256su1	v28.4s,v26.4s,v27.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v7.4s,v7.4s,v29.4s	/* wk = key11+w3 */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	sha256su0	v29.4s,v26.4s
	sha256su1	v29.4s,v27.4s,v28.4s

	ld1		{v4.16b},[x4],16	/* key12 */
	ld1		{v5.16b},[x4],16	/* key13 */
	ld1		{v6.16b},[x4],16	/* key14 */
	ld1		{v7.16b},[x4],16	/* key15 */

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v4.4s,v4.4s,v26.4s	/* wk = key12+w0 */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v5.4s,v5.4s,v27.4s	/* wk = key13+w1 */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v6.4s,v6.4s,v28.4s	/* wk = key14+w2 */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v7.4s,v7.4s,v29.4s	/* wk = key15+w3 */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s

	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */

	cmp		x5, #4
	b.hs		.Lsha256_loop

	/* Store partial hash and return or complete hash */
	cbz		x6, .Lsha256_last

	st1		{v24.16b, v25.16b}, [x2]

	mov		x0, xzr
	ret

	/*
	 * Last block with padding. v24-v25 contain hash state.
	 */
.Lsha256_last:
	eor		v26.16b, v26.16b, v26.16b
	eor		v27.16b, v27.16b, v27.16b
	eor		v28.16b, v28.16b, v28.16b
	eor		v29.16b, v29.16b, v29.16b

	adr		x4,.Lrcon
	lsl		x3, x3, 3

	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */

	/* Fill out the first vector register and the end of the block */

	/* move length to the end of the block */
	mov		v29.s[3], w3
	lsr		x3, x3, 32
	mov		v29.s[2], w3		/* and the higher part */
	/* set padding 1 to the first reg */
	mov		w6, #0x80		/* that's the 1 of the pad */
	mov		v26.b[3], w6
	cbz		x5,.Lsha256_final

	sub		x5, x5, #1
	mov		v27.16b, v26.16b
	ld1		{v26.16b},[x1],16
	rev32		v26.16b,v26.16b		/* fix endian w0 */
	cbz		x5,.Lsha256_final

	sub		x5, x5, #1
	mov		v28.16b, v27.16b
	ld1		{v27.16b},[x1],16
	rev32		v27.16b,v27.16b		/* fix endian w1 */
	cbz		x5,.Lsha256_final

	mov		v29.b[0], w6
	ld1		{v28.16b},[x1],16
	rev32		v28.16b,v28.16b		/* fix endian w2 */

.Lsha256_final:

	ld1		{v4.16b},[x4],16	/* key0 */
	ld1		{v5.16b},[x4],16	/* key1 */
	ld1		{v6.16b},[x4],16	/* key2 */
	ld1		{v7.16b},[x4],16	/* key3 */

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	sha256su0	v26.4s,v27.4s
	sha256su1	v26.4s,v28.4s,v29.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	sha256su0	v27.4s,v28.4s
	sha256su1	v27.4s,v29.4s,v26.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	sha256su0	v28.4s,v29.4s
	sha256su1	v28.4s,v26.4s,v27.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	sha256su0	v29.4s,v26.4s
	sha256su1	v29.4s,v27.4s,v28.4s

	ld1		{v4.16b},[x4],16	/* key4 */
	ld1		{v5.16b},[x4],16	/* key5 */
	ld1		{v6.16b},[x4],16	/* key6 */
	ld1		{v7.16b},[x4],16	/* key7 */

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	sha256su0	v26.4s,v27.4s
	sha256su1	v26.4s,v28.4s,v29.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	sha256su0	v27.4s,v28.4s
	sha256su1	v27.4s,v29.4s,v26.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	sha256su0	v28.4s,v29.4s
	sha256su1	v28.4s,v26.4s,v27.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	sha256su0	v29.4s,v26.4s
	sha256su1	v29.4s,v27.4s,v28.4s

	ld1		{v4.16b},[x4],16	/* key8 */
	ld1		{v5.16b},[x4],16	/* key9 */
	ld1		{v6.16b},[x4],16	/* key10 */
	ld1		{v7.16b},[x4],16	/* key11 */

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v4.4s,v4.4s,v26.4s	/* wk = key8+w0 */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	sha256su0	v26.4s,v27.4s
	sha256su1	v26.4s,v28.4s,v29.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v5.4s,v5.4s,v27.4s	/* wk = key9+w1 */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	sha256su0	v27.4s,v28.4s
	sha256su1	v27.4s,v29.4s,v26.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v6.4s,v6.4s,v28.4s	/* wk = key10+w2 */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	sha256su0	v28.4s,v29.4s
	sha256su1	v28.4s,v26.4s,v27.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v7.4s,v7.4s,v29.4s	/* wk = key11+w3 */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	sha256su0	v29.4s,v26.4s
	sha256su1	v29.4s,v27.4s,v28.4s

	ld1		{v4.16b},[x4],16	/* key12 */
	ld1		{v5.16b},[x4],16	/* key13 */
	ld1		{v6.16b},[x4],16	/* key14 */
	ld1		{v7.16b},[x4],16	/* key15 */

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v4.4s,v4.4s,v26.4s	/* wk = key12+w0 */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v5.4s,v5.4s,v27.4s	/* wk = key13+w1 */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v6.4s,v6.4s,v28.4s	/* wk = key14+w2 */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	add		v7.4s,v7.4s,v29.4s	/* wk = key15+w3 */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s

	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */

	rev32		v24.16b, v24.16b
	rev32		v25.16b, v25.16b
	st1		{v24.4s,v25.4s},[x2]	/* save them both */

	mov		x0, xzr
	ret

.Lsha256_error:
	mov		x0, #-1
	ret

	.size	AArch64crypto_sha256_block_partial, .-AArch64crypto_sha256_block_partial
