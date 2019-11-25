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
 * Core SHA-1 Primitives
 *
 * Operations:
 * AArch64crypto_sha1_block_partial:
 * 	out = partial_sha1(init, in, len)	<- no final block
 *
 * sha1_block:
 * 	out = sha1(init, in, len)
 *
 * Prototype:
 *
 * int AArch64crypto_sha1_block_partial(uint8_t *init,
 *			uint8_t *dsrc, uint8_t *ddst, uint64_t len)
 *
 * int sha1_block(uint8_t *init,
 *			uint8_t *dsrc, uint8_t *ddst, uint64_t len)
 *
 * returns: 0 (success), -1 (failure)
 *
 * Registers used:
 *
 * AArch64crypto_sha1_block_partial(
 *	init,			x0	(hash init state - NULL for default)
 *	dsrc,			x1	(digest src address)
 *	ddst,			x2	(digest dst address)
 *	len,			x3	(length)
 *	)
 *
 * sha1_block(
 *	init,			x0	(hash init state - NULL for default)
 *	dsrc,			x1	(digest src address)
 *	ddst,			x2	(digest dst address)
 *	len,			x3	(length)
 *	)
 *
 * Routine register definitions:
 *
 * v4 - v7 -- round consts for sha
 * v22 -- sha working state ABCD (q22)
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
 * The variable "len" must be a multiple of 16 (+20 for the HMAC),
 * otherwise error code is returned.
 *
 */
	.file "sha1_core.S"
	.text
	.cpu generic+fp+simd+crypto+crc
	.align	4
	.global AArch64crypto_sha1_block_partial
	.type	AArch64crypto_sha1_block_partial,%function
	.global sha1_block
	.type	sha1_block,%function

	.align	4
.Lrcon:
	.word		0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999
	.word		0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
	.word		0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
	.word		0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6

	.align	4
.Linit_sha_state:
	.word		0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
	.word		0xc3d2e1f0, 0x00000000, 0x00000000, 0x00000000

	.align	4

AArch64crypto_sha1_block_partial:
	mov		x6, #1			/* indicate partial hash */
	ands		x5, x3, #0x3f		/* Check size mod 1 SHA block */
	b.ne		.Lsha1_error
	cbnz		x0, 1f
	/* address of sha init state consts */
	adr		x0,.Linit_sha_state
1:
	ld1		{v24.4s},[x0],16	/* init ABCD */
	ld1		{v25.4s},[x0]		/* and E */

	/* Load SHA-1 constants */
	adr		x4,.Lrcon
	ld1		{v4.16b},[x4],16	/* key0 */
	ld1		{v5.16b},[x4],16	/* key1 */
	ld1		{v6.16b},[x4],16	/* key2 */
	ld1		{v7.16b},[x4],16	/* key3 */

	lsr		x5, x3, 2		/* number of 4B blocks */
	b		.Lsha1_loop

sha1_block:
	mov		x6, xzr		/* indicate full hash */
	and		x5, x3, #0xf	/* check size mod 16B block */
	cmp		x5, #4		/* additional word is accepted */
	b.eq		1f
	cbnz		x5, .Lsha1_error
1:
	cbnz		x0, 2f
	/* address of sha init state consts */
	adr		x0,.Linit_sha_state
2:
	ld1		{v24.4s},[x0],16	/* init ABCD */
	ld1		{v25.4s},[x0]		/* and E */

	/* Load SHA-1 constants */
	adr		x4,.Lrcon
	ld1		{v4.16b},[x4],16	/* key0 */
	ld1		{v5.16b},[x4],16	/* key1 */
	ld1		{v6.16b},[x4],16	/* key2 */
	ld1		{v7.16b},[x4],16	/* key3 */

	lsr		x5, x3, 2		/* number of 4B blocks */
	/* at least 16 4B blocks give 1 SHA block */
	cmp		x5, #16
	b.lo		.Lsha1_last

	.align	4

.Lsha1_loop:
	sub		x5, x5, #16		/* substract 1 SHA block */

	ld1		{v26.16b},[x1],16	/* dsrc[0] */
	ld1		{v27.16b},[x1],16	/* dsrc[1] */
	ld1		{v28.16b},[x1],16	/* dsrc[2] */
	ld1		{v29.16b},[x1],16	/* dsrc[3] */

	rev32		v26.16b,v26.16b		/* fix endian w0 */
	rev32		v27.16b,v27.16b		/* fix endian w1 */
	rev32		v28.16b,v28.16b		/* fix endian w2 */
	rev32		v29.16b,v29.16b		/* fix endian w3 */

	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
/* quad 0 */
	add		v16.4s,v4.4s,v26.4s
	sha1h		s19,s24
	sha1c		q24,s25,v16.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1su1		v26.4s,v29.4s

	add		v17.4s,v4.4s,v27.4s
	sha1h		s18,s24
	sha1c		q24,s19,v17.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1su1		v27.4s,v26.4s

	add		v16.4s,v4.4s,v28.4s
	sha1h		s19,s24
	sha1c		q24,s18,v16.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1su1		v28.4s,v27.4s

	add		v17.4s,v4.4s,v29.4s
	sha1h		s18,s24
	sha1c		q24,s19,v17.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1su1		v29.4s,v28.4s

	add		v16.4s,v4.4s,v26.4s
	sha1h		s19,s24
	sha1c		q24,s18,v16.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1su1		v26.4s,v29.4s
/* quad 1 */
	add		v17.4s,v5.4s,v27.4s
	sha1h		s18,s24
	sha1p		q24,s19,v17.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1su1		v27.4s,v26.4s

	add		v16.4s,v5.4s,v28.4s
	sha1h		s19,s24
	sha1p		q24,s18,v16.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1su1		v28.4s,v27.4s

	add		v17.4s,v5.4s,v29.4s
	sha1h		s18,s24
	sha1p		q24,s19,v17.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1su1		v29.4s,v28.4s

	add		v16.4s,v5.4s,v26.4s
	sha1h		s19,s24
	sha1p		q24,s18,v16.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1su1		v26.4s,v29.4s

	add		v17.4s,v5.4s,v27.4s
	sha1h		s18,s24
	sha1p		q24,s19,v17.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1su1		v27.4s,v26.4s
/* quad 2 */
	add		v16.4s,v6.4s,v28.4s
	sha1h		s19,s24
	sha1m		q24,s18,v16.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1su1		v28.4s,v27.4s

	add		v17.4s,v6.4s,v29.4s
	sha1h		s18,s24
	sha1m		q24,s19,v17.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1su1		v29.4s,v28.4s

	add		v16.4s,v6.4s,v26.4s
	sha1h		s19,s24
	sha1m		q24,s18,v16.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1su1		v26.4s,v29.4s

	add		v17.4s,v6.4s,v27.4s
	sha1h		s18,s24
	sha1m		q24,s19,v17.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1su1		v27.4s,v26.4s

	add		v16.4s,v6.4s,v28.4s
	sha1h		s19,s24
	sha1m		q24,s18,v16.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1su1		v28.4s,v27.4s
/* quad 3 */
	add		v17.4s,v7.4s,v29.4s
	sha1h		s18,s24
	sha1p		q24,s19,v17.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1su1		v29.4s,v28.4s

	add		v16.4s,v7.4s,v26.4s
	sha1h		s19,s24
	sha1p		q24,s18,v16.4s

	add		v17.4s,v7.4s,v27.4s
	sha1h		s18,s24
	sha1p		q24,s19,v17.4s

	add		v16.4s,v7.4s,v28.4s
	sha1h		s19,s24
	sha1p		q24,s18,v16.4s

	add		v17.4s,v7.4s,v29.4s
	sha1h		s18,s24
	sha1p		q24,s19,v17.4s

	add		v24.4s,v24.4s,v22.4s
	add		v25.4s,v25.4s,v18.4s

	cmp		x5, #16
	b.hs		.Lsha1_loop

	/* Store partial hash and return or complete hash */
	cbz		x6, .Lsha1_last

	st1		{v24.16b},[x2],16
	st1		{v25.16b},[x2]

	mov		x0, xzr
	ret

	/*
	 * Last block with padding. v24-v25[0] contain hash state.
	 */
.Lsha1_last:

	eor		v26.16b, v26.16b, v26.16b
	eor		v27.16b, v27.16b, v27.16b
	eor		v28.16b, v28.16b, v28.16b
	eor		v29.16b, v29.16b, v29.16b

	adr		x4,.Lrcon
	/* Number of bits in message */
	lsl		x3, x3, 3

	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	/* move length to the end of the block */
	mov		v29.s[3], w3
	lsr		x3, x3, 32
	/* and the higher part */
	mov		v29.s[2], w3

	/* The remaining part is up to 3 16B blocks and up to 1 4B block */
	mov		w6, #0x80		/* that's the 1 of the pad */
	mov		v26.b[3], w6
	cbz		x5,.Lsha1_final
	/* Are there 3 16B blocks? */
	cmp		x5, #12
	b.lo		1f
	ld1		{v26.16b},[x1],16
	ld1		{v27.16b},[x1],16
	ld1		{v28.16b},[x1],16
	rev32		v26.16b, v26.16b
	rev32		v27.16b, v27.16b
	rev32		v28.16b, v28.16b
	sub		x5,x5,#12
	mov		v29.b[7], w6
	cbz		x5,.Lsha1_final
	mov		v29.b[7], wzr
	ld1		{v29.s}[0],[x1],4
	rev32		v29.16b,v29.16b
	mov		v29.b[7], w6
	b		.Lsha1_final
1:
	/* Are there 2 16B blocks? */
	cmp		x5, #8
	b.lo		2f
	ld1		{v26.16b},[x1],16
	ld1		{v27.16b},[x1],16
	rev32		v26.16b,v26.16b
	rev32		v27.16b,v27.16b
	sub		x5,x5,#8
	mov		v28.b[7], w6
	cbz		x5,.Lsha1_final
	mov		v28.b[7], wzr
	ld1		{v28.s}[0],[x1],4
	rev32		v28.16b,v28.16b
	mov		v28.b[7], w6
	b		.Lsha1_final
2:
	/* Is there 1 16B block? */
	cmp		x5, #4
	b.lo		3f
	ld1		{v26.16b},[x1],16
	rev32		v26.16b,v26.16b
	sub		x5,x5,#4
	mov		v27.b[7], w6
	cbz		x5,.Lsha1_final
	mov		v27.b[7], wzr
	ld1		{v27.s}[0],[x1],4
	rev32		v27.16b,v27.16b
	mov		v27.b[7], w6
	b		.Lsha1_final
3:
	ld1		{v26.s}[0],[x1],4
	rev32		v26.16b,v26.16b
	mov		v26.b[7], w6

.Lsha1_final:
	ld1		{v4.16b},[x4],16	/* key0 */
	ld1		{v5.16b},[x4],16	/* key1 */
	ld1		{v6.16b},[x4],16	/* key2 */
	ld1		{v7.16b},[x4],16	/* key3 */
/* quad 0 */
	add		v16.4s,v4.4s,v26.4s
	sha1h		s19,s24
	sha1c		q24,s25,v16.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1su1		v26.4s,v29.4s

	add		v17.4s,v4.4s,v27.4s
	sha1h		s18,s24
	sha1c		q24,s19,v17.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1su1		v27.4s,v26.4s

	add		v16.4s,v4.4s,v28.4s
	sha1h		s19,s24
	sha1c		q24,s18,v16.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1su1		v28.4s,v27.4s

	add		v17.4s,v4.4s,v29.4s
	sha1h		s18,s24
	sha1c		q24,s19,v17.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1su1		v29.4s,v28.4s

	add		v16.4s,v4.4s,v26.4s
	sha1h		s19,s24
	sha1c		q24,s18,v16.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1su1		v26.4s,v29.4s
/* quad 1 */
	add		v17.4s,v5.4s,v27.4s
	sha1h		s18,s24
	sha1p		q24,s19,v17.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1su1		v27.4s,v26.4s

	add		v16.4s,v5.4s,v28.4s
	sha1h		s19,s24
	sha1p		q24,s18,v16.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1su1		v28.4s,v27.4s

	add		v17.4s,v5.4s,v29.4s
	sha1h		s18,s24
	sha1p		q24,s19,v17.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1su1		v29.4s,v28.4s

	add		v16.4s,v5.4s,v26.4s
	sha1h		s19,s24
	sha1p		q24,s18,v16.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1su1		v26.4s,v29.4s

	add		v17.4s,v5.4s,v27.4s
	sha1h		s18,s24
	sha1p		q24,s19,v17.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1su1		v27.4s,v26.4s
/* quad 2 */
	add		v16.4s,v6.4s,v28.4s
	sha1h		s19,s24
	sha1m		q24,s18,v16.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1su1		v28.4s,v27.4s

	add		v17.4s,v6.4s,v29.4s
	sha1h		s18,s24
	sha1m		q24,s19,v17.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1su1		v29.4s,v28.4s

	add		v16.4s,v6.4s,v26.4s
	sha1h		s19,s24
	sha1m		q24,s18,v16.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1su1		v26.4s,v29.4s

	add		v17.4s,v6.4s,v27.4s
	sha1h		s18,s24
	sha1m		q24,s19,v17.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1su1		v27.4s,v26.4s

	add		v16.4s,v6.4s,v28.4s
	sha1h		s19,s24
	sha1m		q24,s18,v16.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1su1		v28.4s,v27.4s
/* quad 3 */
	add		v17.4s,v7.4s,v29.4s
	sha1h		s18,s24
	sha1p		q24,s19,v17.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1su1		v29.4s,v28.4s

	add		v16.4s,v7.4s,v26.4s
	sha1h		s19,s24
	sha1p		q24,s18,v16.4s

	add		v17.4s,v7.4s,v27.4s
	sha1h		s18,s24
	sha1p		q24,s19,v17.4s

	add		v16.4s,v7.4s,v28.4s
	sha1h		s19,s24
	sha1p		q24,s18,v16.4s

	add		v17.4s,v7.4s,v29.4s
	sha1h		s18,s24
	sha1p		q24,s19,v17.4s

	add		v25.4s,v25.4s,v18.4s
	add		v24.4s,v24.4s,v22.4s

	rev32		v24.16b,v24.16b
	rev32		v25.16b,v25.16b

	st1		{v24.16b}, [x2],16
	st1		{v25.s}[0], [x2]

	mov		x0, xzr
	ret

.Lsha1_error:
	mov		x0, #-1
	ret

	.size	AArch64crypto_sha1_block_partial, .-AArch64crypto_sha1_block_partial
	.size	sha1_block, .-sha1_block
