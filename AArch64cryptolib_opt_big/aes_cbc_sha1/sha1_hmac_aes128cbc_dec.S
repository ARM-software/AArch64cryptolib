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
 * Combined Auth/Dec Primitive = sha1_hmac/aes128cbc
 *
 * Operations:
 *
 * out = decrypt-AES128CBC(in)
 * return_ash_ptr = SHA1(o_key_pad | SHA1(i_key_pad | in))
 *
 * Prototype:
 *
 * void asm_sha1_hmac_aes128cbc_dec(uint8_t *csrc, uint8_t *cdst,
 *			uint8_t *dsrc, uint8_t *ddst,
 *			uint64_t len, armv8_cipher_digest_t *arg)
 *
 * Registers used:
 *
 * asm_sha1_hmac_aes128cbc_dec(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
 *			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
 *			armv8_cipher_digest_t *arg)
 *
 * Registers used:
 *
 * armv8_enc_aes_cbc_sha1_128(
 *	csrc,			x0	(cipher src address)
 *	cdst,			x1	(cipher dst address)
 *	clen			x2	(cipher length)
 *	dsrc,			x3	(digest src address)
 *	ddst,			x4	(digest dst address)
 *	dlen,			x5	(digest length)
 *	arg			x6	:
 *		arg->cipher.key		(round keys)
 *		arg->cipher.iv		(initialization vector)
 *		arg->digest.hmac.i_key_pad	(partially hashed i_key_pad)
 *		arg->digest.hmac.o_key_pad	(partially hashed o_key_pad)
 *	)
 *
 * Routine register definitions:
 *
 * v0 - v3 -- aes results
 * v4 - v7 -- round consts for sha
 * v8 - v18 -- round keys
 * v19 -- temp register for SHA1
 * v20 -- ABCD copy (q20)
 * v21 -- sha working state (q21)
 * v22 -- sha working state (q22)
 * v23 -- temp register for SHA1
 * v24 -- sha state ABCD
 * v25 -- sha state E
 * v26 -- sha block 0
 * v27 -- sha block 1
 * v28 -- sha block 2
 * v29 -- sha block 3
 * v30 -- reserved
 * v31 -- reserved
 *
 *
 * Constraints:
 *
 * The variable "clen" must be a multiple of 16, otherwise results are not
 * defined. For AES partial blocks the user is required to pad the input
 * to modulus 16 = 0.
 *
 * The variable "dlen" must be a multiple of 8 and greater or equal
 * to "clen". The maximum difference between "dlen" and "clen" cannot
 * exceed 64 bytes. This constrain is strictly related to the needs of the IPSec
 * ESP packet.
 * Short lengths are less optimized at < 16 AES blocks,
 * however they are somewhat optimized, and more so than the enc/auth versions.
 */
	.file "sha1_hmac_aes128cbc_dec.S"
	.text
	.cpu generic+fp+simd+crypto+crc
	.global asm_sha1_hmac_aes128cbc_dec
	.type	asm_sha1_hmac_aes128cbc_dec,%function


	.align	4
.Lrcon:
	.word		0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999
	.word		0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
	.word		0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
	.word		0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6

asm_sha1_hmac_aes128cbc_dec:
/* protect registers */
	sub		sp,sp,8*16
	mov		x9,sp			/* copy for address mode */
	stp		q8,q9,[x9],32
/* fetch args */
	ldr		x7, [x6, #HMAC_IKEYPAD]
	/* init ABCD, E */
	ldp		q24,q25,[x7]
	/* save pointer to o_key_pad partial hash */
	ldr		x7, [x6, #HMAC_OKEYPAD]

	stp		q10,q11,[x9],32

	prfm		PLDL1KEEP,[x0,0]	/* pref next aes_ptr_in */
	prfm		PLDL1KEEP,[x1,0]	/* pref next aes_ptr_out */
	lsr		x10,x2,4		/* aes_blocks = len/16 */

	stp		q12,q13,[x9],32
	stp		q14,q15,[x9]

	ldr		x9, [x6, #CIPHER_KEY]
	ldr		x6, [x6, #CIPHER_IV]
/*
 * init sha state, prefetch, check for small cases.
 * Note that the output is prefetched as a load, for the in-place case
 */
	cmp		x10,16			/* no main loop if <16 */
	blt		.Lshort_cases		/* branch if < 12 */

	/* base address for sha round consts */
	adr		x8,.Lrcon
	ldp		q4,q5,[x8],32		/* key0,key1 */
	ldp		q6,q7,[x8],32		/* key2,key3 */

	/* get outstanding bytes of the digest */
	sub		x8,x5,x2

	mov		x11,x2			/* len -> x11 needed at end */
	ld1		{v30.16b},[x6]		/* get 1st ivec */
	lsr		x12,x11,6		/* total_blocks (sha) */
	ldp		q26,q27,[x3],32		/* next w0,w1 */
	rev32		v26.16b,v26.16b		/* endian swap w0 */
	rev32		v27.16b,v27.16b		/* endian swap w1 */
	ldp		q28,q29,[x3],32		/* next w1,w2 */
	rev32		v28.16b,v28.16b		/* endian swap w2 */
	rev32		v29.16b,v29.16b		/* endian swap w3 */

	/* substract loaded bytes */
	sub		x5,x5,64
/*
 * now we can do the loop prolog, 1st sha1 block
 */
	prfm		PLDL1KEEP,[x0,64]	/* pref next aes_ptr_in */
	prfm		PLDL1KEEP,[x1,64]	/* pref next aes_ptr_out */
/*
 * do the first sha1 block on the plaintext
 */
	mov		v20.16b,v24.16b		/* init working ABCD */

	add		v19.4s,v4.4s,v26.4s
	add		v23.4s,v4.4s,v27.4s
/* quad 0 */
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	ld1		{v8.16b},[x9],16	/* rk[0] */
	sha1c		q24,s25,v19.4s
	sha1su1		v26.4s,v29.4s
	ld1		{v9.16b},[x9],16	/* rk[1] */
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	add		v19.4s,v4.4s,v28.4s
	ld1		{v10.16b},[x9],16	/* rk[2] */
	sha1c		q24,s22,v23.4s
	sha1su1		v27.4s,v26.4s
	add		v23.4s,v4.4s,v29.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	ld1		{v11.16b},[x9],16	/* rk[3] */
	sha1c		q24,s21,v19.4s
	sha1su1		v28.4s,v27.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v26.4s
	sha1su1		v29.4s,v28.4s
	add		v23.4s,v5.4s,v27.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	ld1		{v12.16b},[x9],16	/* rk[4] */
	sha1c		q24,s21,v19.4s
	add		v19.4s,v5.4s,v28.4s
	sha1su1		v26.4s,v29.4s
	ld1		{v13.16b},[x9],16	/* rk[5] */
/* quad 1 */
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	ld1		{v14.16b},[x9],16	/* rk[6] */
	sha1p		q24,s22,v23.4s
	sha1su1		v27.4s,v26.4s
	add		v23.4s,v5.4s,v29.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	ld1		{v15.16b},[x9],16	/* rk[7] */
	sha1p		q24,s21,v19.4s
	sha1su1		v28.4s,v27.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v5.4s,v26.4s
	sha1su1		v29.4s,v28.4s
	add		v23.4s,v5.4s,v27.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	ld1		{v16.16b},[x9],16	/* rk[8] */
	sha1p		q24,s21,v19.4s
	sha1su1		v26.4s,v29.4s
	ld1		{v17.16b},[x9],16	/* rk[9] */
	add		v19.4s,v6.4s,v28.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	ld1		{v18.16b},[x9],16	/* rk[10] */
	sha1p		q24,s22,v23.4s
	sha1su1		v27.4s,v26.4s
/* quad 2 */
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v6.4s,v29.4s
	sha1su1		v28.4s,v27.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v19.4s,v6.4s,v26.4s
	sha1su1		v29.4s,v28.4s
	add		v23.4s,v6.4s,v27.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v19.4s,v6.4s,v28.4s
	sha1su1		v26.4s,v29.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v23.4s,v7.4s,v29.4s
	sha1su1		v27.4s,v26.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	sha1su1		v28.4s,v27.4s
/* quad 3 */
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v7.4s,v26.4s
	sha1su1		v29.4s,v28.4s
	sha1h		s22,s24
	ld1		{v26.16b},[x3],16	/* next w0 */
	sha1p		q24,s21,v19.4s
	add		v23.4s,v7.4s,v27.4s
	sha1h		s21,s24
	ld1		{v27.16b},[x3],16	/* next w1 */
	sha1p		q24,s22,v23.4s
	add		v19.4s,v7.4s,v28.4s
	sha1h		s22,s24
	ld1		{v28.16b},[x3],16	/* next w2 */
	sha1p		q24,s21,v19.4s
	add		v23.4s,v7.4s,v29.4s
	sha1h		s21,s24
	ld1		{v29.16b},[x3],16	/* next w3 */
	sha1p		q24,s22,v23.4s

	/* substract loaded bytes */
	sub		x5,x5,64
/*
 * aes_blocks_left := number after the main (sha) block is done.
 * can be 0 note we account for the extra unwind in main_blocks
 */
	sub		x15,x12,2		/* main_blocks=total_blocks-5 */
	add		v24.4s,v24.4s,v20.4s
	and		x13,x10,3		/* aes_blocks_left */
	ld1		{v0.16b},[x0]		/* next aes block, no update */
	add		v25.4s,v25.4s,v21.4s
	/* next aes block, update aes_ptr_in */
	ld1		{v31.16b},[x0],16

	/* indicate AES blocks to write back */
	mov		x9,xzr
/*
 * main combined loop CBC, can be used by auth/enc version
 */
.Lmain_loop:
/*
 * Because both mov, rev32 and eor have a busy cycle,
 * this takes longer than it looks.
 */
	rev32		v26.16b,v26.16b		/* fix endian w0 */
	mov		v20.16b,v24.16b		/* working ABCD <- ABCD */
	rev32		v27.16b,v27.16b		/* fix endian w1 */
	/* pref next aes_ptr_out, streaming */
	prfm		PLDL1KEEP,[x1,64]
/* aes xform 0, sha quad 0 */
	aesd		v0.16b,v8.16b
	rev32		v28.16b,v28.16b		/* fix endian w2 */
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v9.16b
	add		v19.4s,v4.4s,v26.4s
	aesimc		v0.16b,v0.16b
	sha1su0		v26.4s,v27.4s,v28.4s
	aesd		v0.16b,v10.16b
	sha1h		s22,s24
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v11.16b
	add		v23.4s,v4.4s,v27.4s
	rev32		v29.16b,v29.16b		/* fix endian w3 */
	/* read next aes block, no update */
	ld1		{v1.16b},[x0]
	aesimc		v0.16b,v0.16b
	sha1c		q24,s25,v19.4s
	aesd		v0.16b,v12.16b
	sha1su1		v26.4s,v29.4s
	aesimc		v0.16b,v0.16b
	sha1su0		v27.4s,v28.4s,v29.4s
	aesd		v0.16b,v13.16b
	sha1h		s21,s24
	add		v19.4s,v4.4s,v28.4s
	aesimc		v0.16b,v0.16b
	sha1c		q24,s22,v23.4s
	aesd		v0.16b,v14.16b
	add		v23.4s,v4.4s,v29.4s
	sha1su1		v27.4s,v26.4s
	aesimc		v0.16b,v0.16b
	sha1su0		v28.4s,v29.4s,v26.4s
	aesd		v0.16b,v15.16b
	sha1h		s22,s24
	aesimc		v0.16b,v0.16b
	sha1c		q24,s21,v19.4s
	aesd		v0.16b,v16.16b
	sha1su1		v28.4s,v27.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	aesimc		v0.16b,v0.16b
	sha1h		s21,s24
	aesd		v0.16b,v17.16b
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v26.4s
	sha1su1		v29.4s,v28.4s
	eor		v0.16b,v0.16b,v18.16b	/* final res 0 */
	eor		v0.16b,v0.16b,v30.16b	/* xor w/ prev value */
	/* get next aes block, with update */
	ld1		{v30.16b},[x0],16
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	add		v23.4s,v5.4s,v27.4s
	sha1su1		v26.4s,v29.4s
/* aes xform 1, sha quad 1 */
	sha1su0		v27.4s,v28.4s,v29.4s
	/* save aes res, bump aes_out_ptr */
	st1		{v0.16b},[x1],16
	aesd		v1.16b,v8.16b
	sha1h		s21,s24
	add		v19.4s,v5.4s,v28.4s
	sha1p		q24,s22,v23.4s
	aesimc		v1.16b,v1.16b
	sha1su1		v27.4s,v26.4s
	aesd		v1.16b,v9.16b
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	aesimc		v1.16b,v1.16b
	sha1p		q24,s21,v19.4s
	aesd		v1.16b,v10.16b
	/* read next aes block, no update */
	ld1		{v2.16b},[x0]
	add		v23.4s,v5.4s,v29.4s
	sha1su1		v28.4s,v27.4s
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v11.16b
	sha1su0		v29.4s,v26.4s,v27.4s
	aesimc		v1.16b,v1.16b
	sha1h		s21,s24
	aesd		v1.16b,v12.16b
	sha1p		q24,s22,v23.4s
	sha1su1		v29.4s,v28.4s
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v13.16b
	sha1h		s22,s24
	add		v19.4s,v5.4s,v26.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	aesimc		v1.16b,v1.16b
	sha1p		q24,s21,v19.4s
	aesd		v1.16b,v14.16b
	sha1su1		v26.4s,v29.4s
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v15.16b
	add		v23.4s,v5.4s,v27.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	aesimc		v1.16b,v1.16b
	sha1p		q24,s22,v23.4s
	aesd		v1.16b,v16.16b
	sha1su1		v27.4s,v26.4s
	add		v19.4s,v6.4s,v28.4s
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v17.16b
	add		v23.4s,v6.4s,v29.4s
	eor		v1.16b,v1.16b,v18.16b	/* res xf 1 */
	eor		v1.16b,v1.16b,v31.16b	/* mode op 1 xor w/prev value */
	/* read next aes block, update aes_ptr_in */
	ld1		{v31.16b},[x0],16
/* aes xform 2, sha quad 2 */
	sha1su0		v28.4s,v29.4s,v26.4s
	aesd		v2.16b,v8.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v1.16b},[x1],16
	sha1h		s22,s24
	aesimc		v2.16b,v2.16b
	sha1m		q24,s21,v19.4s
	aesd		v2.16b,v9.16b
	sha1su1		v28.4s,v27.4s
	aesimc		v2.16b,v2.16b
	sha1su0		v29.4s,v26.4s,v27.4s
	aesd		v2.16b,v10.16b
	sha1h		s21,s24
	aesimc		v2.16b,v2.16b
	sha1m		q24,s22,v23.4s
	aesd		v2.16b,v11.16b
	sha1su1		v29.4s,v28.4s
	add		v19.4s,v6.4s,v26.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v12.16b
	sha1h		s22,s24
	aesimc		v2.16b,v2.16b
	sha1m		q24,s21,v19.4s
	aesd		v2.16b,v13.16b
	sha1su1		v26.4s,v29.4s
	add		v23.4s,v6.4s,v27.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	aesimc		v2.16b,v2.16b
	/* read next aes block, no update */
	ld1		{v3.16b},[x0]
	aesd		v2.16b,v14.16b
	sha1h		s21,s24
	aesimc		v2.16b,v2.16b
	sha1m		q24,s22,v23.4s
	aesd		v2.16b,v15.16b
	sha1su1		v27.4s,v26.4s
	add		v19.4s,v6.4s,v28.4s
	aesimc		v2.16b,v2.16b
	sha1h		s22,s24
	aesd		v2.16b,v16.16b
	sha1su0		v28.4s,v29.4s,v26.4s
	aesimc		v2.16b,v2.16b
	sha1m		q24,s21,v19.4s
	aesd		v2.16b,v17.16b
	sha1su1		v28.4s,v27.4s
	add		v23.4s,v7.4s,v29.4s
	eor		v2.16b,v2.16b,v18.16b	/* res 2 */
	add		v19.4s,v7.4s,v26.4s
	eor		v2.16b,v2.16b,v30.16b	/* mode of 2 xor w/prev value */
	/* read next aes block, update aes_ptr_in */
	ld1		{v30.16b},[x0],16
/* aes xform 3, sha quad 3 */
	aesd		v3.16b,v8.16b
	aesimc		v3.16b,v3.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v2.16b},[x1],16
	aesd		v3.16b,v9.16b
	sha1h		s21,s24
	aesimc		v3.16b,v3.16b
	sha1su0		v29.4s,v26.4s,v27.4s
	aesd		v3.16b,v10.16b
	sha1p		q24,s22,v23.4s
	aesimc		v3.16b,v3.16b
	sha1su1		v29.4s,v28.4s
	aesd		v3.16b,v11.16b
	sha1h		s22,s24
	ld1		{v26.16b},[x3],16	/* next w0 */
	aesimc		v3.16b,v3.16b
	sha1p		q24,s21,v19.4s
	aesd		v3.16b,v12.16b
	aesimc		v3.16b,v3.16b
	add		v23.4s,v7.4s,v27.4s
	aesd		v3.16b,v13.16b
	sha1h		s21,s24
	ld1		{v27.16b},[x3],16	/* next w1 */
	aesimc		v3.16b,v3.16b
	sha1p		q24,s22,v23.4s
	aesd		v3.16b,v14.16b
	sub		x15,x15,1		/* dec block count */
	aesimc		v3.16b,v3.16b
	add		v19.4s,v7.4s,v28.4s
	aesd		v3.16b,v15.16b
	ld1		{v0.16b},[x0]		/* next aes block, no update */
	sha1h		s22,s24
	ld1		{v28.16b},[x3],16	/* next w2 */
	aesimc		v3.16b,v3.16b
	sha1p		q24,s21,v19.4s
	aesd		v3.16b,v16.16b
	aesimc		v3.16b,v3.16b
	add		v23.4s,v7.4s,v29.4s
	aesd		v3.16b,v17.16b
	sha1h		s21,s24
	ld1		{v29.16b},[x3],16	/* next w3 */
	sha1p		q24,s22,v23.4s
	add		v24.4s,v24.4s,v20.4s
	eor		v3.16b,v3.16b,v18.16b	/* aes res 3 */
	eor		v3.16b,v3.16b,v31.16b	/* xor w/ prev value */
	/* next aes block, update aes_ptr_in */
	ld1		{v31.16b},[x0],16
	add		v25.4s,v25.4s,v21.4s
	/* save aes res, bump aes_out_ptr */
	st1		{v3.16b},[x1],16
	/* substract loaded bytes */
	sub		x5,x5,64
	/* loop if more to do */
	cbnz		x15,.Lmain_loop
/*
 * now the loop epilog. Since the reads for sha have already been done
 * in advance, we have to have an extra unwind.
 * This is why the test for the short cases is 16 and not 12.
 *
 * the unwind, which is just the main loop without the tests or final reads.
 */
	rev32		v26.16b,v26.16b		/* fix endian w0 */
	mov		v20.16b,v24.16b		/* working ABCD <- ABCD */
	rev32		v27.16b,v27.16b		/* fix endian w1 */
	/* pref next aes_ptr_out, streaming */
	prfm		PLDL1KEEP,[x1,64]
/* aes xform 0, sha quad 0 */
	aesd		v0.16b,v8.16b
	add		v19.4s,v4.4s,v26.4s
	rev32		v28.16b,v28.16b		/* fix endian w2 */
	aesimc		v0.16b,v0.16b
	sha1su0		v26.4s,v27.4s,v28.4s
	/* read next aes block, no update */
	ld1		{v1.16b},[x0]
	aesd		v0.16b,v9.16b
	sha1h		s22,s24
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v10.16b
	add		v23.4s,v4.4s,v27.4s
	aesimc		v0.16b,v0.16b
	sha1c		q24,s25,v19.4s
	aesd		v0.16b,v11.16b
	rev32		v29.16b,v29.16b		/* fix endian w3 */
	aesimc		v0.16b,v0.16b
	sha1su1		v26.4s,v29.4s
	aesd		v0.16b,v12.16b
	aesimc		v0.16b,v0.16b
	sha1su0		v27.4s,v28.4s,v29.4s
	aesd		v0.16b,v13.16b
	sha1h		s21,s24
	add		v19.4s,v4.4s,v28.4s
	aesimc		v0.16b,v0.16b
	sha1c		q24,s22,v23.4s
	aesd		v0.16b,v14.16b
	add		v23.4s,v4.4s,v29.4s
	sha1su1		v27.4s,v26.4s
	aesimc		v0.16b,v0.16b
	sha1su0		v28.4s,v29.4s,v26.4s
	aesd		v0.16b,v15.16b
	sha1h		s22,s24
	aesimc		v0.16b,v0.16b
	sha1c		q24,s21,v19.4s
	aesd		v0.16b,v16.16b
	sha1su1		v28.4s,v27.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	aesimc		v0.16b,v0.16b
	sha1h		s21,s24
	aesd		v0.16b,v17.16b
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v26.4s
	sha1su1		v29.4s,v28.4s
	eor		v0.16b,v0.16b,v18.16b	/* final res 0 */
	add		v23.4s,v5.4s,v27.4s
	eor		v0.16b,v0.16b,v30.16b	/* xor w/ prev value */
	/* read next aes block, update aes_ptr_in */
	ld1		{v30.16b},[x0],16
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	sha1su1		v26.4s,v29.4s
/* aes xform 1, sha quad 1 */
	/* save aes res, bump aes_out_ptr */
	st1		{v0.16b},[x1],16
	sha1su0		v27.4s,v28.4s,v29.4s
	aesd		v1.16b,v8.16b
	sha1h		s21,s24
	add		v19.4s,v5.4s,v28.4s
	aesimc		v1.16b,v1.16b
	sha1p		q24,s22,v23.4s
	aesd		v1.16b,v9.16b
	aesimc		v1.16b,v1.16b
	add		v23.4s,v5.4s,v29.4s
	sha1su1		v27.4s,v26.4s
	aesd		v1.16b,v10.16b
	sha1su0		v28.4s,v29.4s,v26.4s
	/* read next aes block, no update */
	ld1		{v2.16b},[x0]
	aesimc		v1.16b,v1.16b
	sha1h		s22,s24
	aesd		v1.16b,v11.16b
	sha1p		q24,s21,v19.4s
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v12.16b
	sha1su1		v28.4s,v27.4s
	aesimc		v1.16b,v1.16b
	sha1su0		v29.4s,v26.4s,v27.4s
	aesd		v1.16b,v13.16b
	sha1h		s21,s24
	aesimc		v1.16b,v1.16b
	sha1p		q24,s22,v23.4s
	aesd		v1.16b,v14.16b
	add		v19.4s,v5.4s,v26.4s
	sha1su1		v29.4s,v28.4s
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v15.16b
	add		v23.4s,v5.4s,v27.4s
	aesimc		v1.16b,v1.16b
	sha1su0		v26.4s,v27.4s,v28.4s
	aesd		v1.16b,v16.16b
	sha1h		s22,s24
	aesimc		v1.16b,v1.16b
	sha1p		q24,s21,v19.4s
	aesd		v1.16b,v17.16b
	add		v19.4s,v6.4s,v28.4s
	eor		v1.16b,v1.16b,v18.16b	/* res xf 1 */
	sha1su1		v26.4s,v29.4s
	eor		v1.16b,v1.16b,v31.16b	/* mode op 1 xor w/prev value */
	sha1su0		v27.4s,v28.4s,v29.4s
	/* read next aes block, update aes_ptr_in */
	ld1		{v31.16b},[x0],16
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v23.4s,v6.4s,v29.4s
	sha1su1		v27.4s,v26.4s
/* mode op 2 */
/* aes xform 2, sha quad 2 */
	aesd		v2.16b,v8.16b
	sha1su0		v28.4s,v29.4s,v26.4s
	/* save aes res, bump aes_out_ptr */
	st1		{v1.16b},[x1],16
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v9.16b
	sha1h		s22,s24
	aesimc		v2.16b,v2.16b
	sha1m		q24,s21,v19.4s
	aesd		v2.16b,v10.16b
	sha1su1		v28.4s,v27.4s
	aesimc		v2.16b,v2.16b
	add		v19.4s,v6.4s,v26.4s
	aesd		v2.16b,v11.16b
	sha1su0		v29.4s,v26.4s,v27.4s
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v12.16b
	sha1h		s21,s24
	aesimc		v2.16b,v2.16b
	sha1m		q24,s22,v23.4s
	aesd		v2.16b,v13.16b
	sha1su1		v29.4s,v28.4s
	aesimc		v2.16b,v2.16b
	/* read next aes block, no update */
	ld1		{v3.16b},[x0]
	aesd		v2.16b,v14.16b
	add		v23.4s,v6.4s,v27.4s
	aesimc		v2.16b,v2.16b
	sha1su0		v26.4s,v27.4s,v28.4s
	aesd		v2.16b,v15.16b
	sha1h		s22,s24
	aesimc		v2.16b,v2.16b
	sha1m		q24,s21,v19.4s
	aesd		v2.16b,v16.16b
	add		v19.4s,v6.4s,v28.4s
	aesimc		v2.16b,v2.16b
	sha1su1		v26.4s,v29.4s
	aesd		v2.16b,v17.16b
	eor		v2.16b,v2.16b,v18.16b	/* res 2 */
	eor		v2.16b,v2.16b,v30.16b	/* mode of 2 xor w/prev value */
	/* read next aes block, update aes_ptr_in */
	ld1		{v30.16b},[x0],16
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v23.4s,v7.4s,v29.4s
	sha1su1		v27.4s,v26.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	sha1su1		v28.4s,v27.4s
/* mode op 3 */
/* aes xform 3, sha quad 3 */
	aesd		v3.16b,v8.16b
	sha1su0		v29.4s,v26.4s,v27.4s
	aesimc		v3.16b,v3.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v2.16b},[x1],16
	aesd		v3.16b,v9.16b
	sha1h		s21,s24
	aesimc		v3.16b,v3.16b
	sha1p		q24,s22,v23.4s
	aesd		v3.16b,v10.16b
	sha1su1		v29.4s,v28.4s
	aesimc		v3.16b,v3.16b
	add		v19.4s,v7.4s,v26.4s
	aesd		v3.16b,v11.16b
	sha1h		s22,s24
	aesimc		v3.16b,v3.16b
	sha1p		q24,s21,v19.4s
	aesd		v3.16b,v12.16b
	/* read first aes block, no bump */
	ld1		{v0.16b},[x0]
	aesimc		v3.16b,v3.16b
	add		v23.4s,v7.4s,v27.4s
	aesd		v3.16b,v13.16b
	sha1h		s21,s24
	aesimc		v3.16b,v3.16b
	sha1p		q24,s22,v23.4s
	add		v19.4s,v7.4s,v28.4s
	aesd		v3.16b,v14.16b
	sha1h		s22,s24
	aesimc		v3.16b,v3.16b
	sha1p		q24,s21,v19.4s
	aesd		v3.16b,v15.16b
	add		v23.4s,v7.4s,v29.4s
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v16.16b
	sha1h		s21,s24
	aesimc		v3.16b,v3.16b
	sha1p		q24,s22,v23.4s
	aesd		v3.16b,v17.16b
	eor		v3.16b,v3.16b,v18.16b	/* aes res 3 */
	eor		v3.16b,v3.16b,v31.16b	/* xor w/ prev value */
	/* read first aes block, bump aes_ptr_in */
	ld1		{v31.16b},[x0],16

	add		v25.4s,v25.4s,v21.4s
	add		v24.4s,v24.4s,v20.4s

/*
 * now we have to do the 4 aes blocks (b-2) that catch up to where sha is
 */

/* aes xform 0 */
	aesd		v0.16b,v8.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v3.16b},[x1],16
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v9.16b
	/* read next aes block, no update */
	ld1		{v1.16b},[x0]
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v10.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v11.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v12.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v13.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v14.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v15.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v16.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v17.16b
	eor		v0.16b,v0.16b,v18.16b	/* res 0 */
	eor		v0.16b,v0.16b,v30.16b	/* xor w/ ivec (modeop) */
	/* read next aes block, update aes_ptr_in */
	ld1		{v30.16b},[x0],16

/* aes xform 1 */
	aesd		v1.16b,v8.16b
	/* read next aes block, no update */
	ld1		{v2.16b},[x0]
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v9.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v10.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v11.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v12.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v13.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v14.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v15.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v16.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v17.16b
	eor		v1.16b,v1.16b,v18.16b	/* res 1 */
	eor		v1.16b,v1.16b,v31.16b	/* xor w/ ivec (modeop) */
	/* read next aes block, update aes_ptr_in */
	ld1		{v31.16b},[x0],16

/* aes xform 2 */
	aesd		v2.16b,v8.16b
	/* read next aes block, no update */
	ld1		{v3.16b},[x0]
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v9.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v10.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v11.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v12.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v13.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v14.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v15.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v16.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v17.16b
	eor		v2.16b,v2.16b,v18.16b	/* res 2 */
	eor		v2.16b,v2.16b,v30.16b	/* xor w/ ivec (modeop) */
	/* read next aes block, update aes_ptr_in */
	ld1		{v30.16b},[x0],16

/* aes xform 3 */
	aesd		v3.16b,v8.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v9.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v10.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v11.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v12.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v13.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v14.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v15.16b
	eor		v26.16b,v26.16b,v26.16b		/* zero the rest */
	aesimc		v3.16b,v3.16b
	eor		v27.16b,v27.16b,v27.16b		/* zero the rest */
	aesd		v3.16b,v16.16b
	eor		v28.16b,v28.16b,v28.16b		/* zero the rest */
	aesimc		v3.16b,v3.16b
	eor		v29.16b,v29.16b,v29.16b		/* zero the rest */
	aesd		v3.16b,v17.16b
	eor		v3.16b,v3.16b,v18.16b	/* res 3 */
	eor		v3.16b,v3.16b,v31.16b	/* xor w/ ivec (modeop) */

	add		x9,x9,4

/*
 * Now, there is the final b-1 sha1 padded block.
 * This contains between 0-3 aes blocks. We take some pains to avoid read spill
 * by only reading the blocks that are actually defined.
 * this is also the final sha block code for the short_cases.
 */
.Ljoin_common:
	mov		w15,0x80	/* that's the 1 of the pad */
.Lpost_loop_Q0:
	/* assume this was final block */
	mov		v26.b[0],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	/* overwrite previous v26 value (0x80) */
	mov		v26.d[0],x2
	/* assume this was final block */
	mov		v26.b[8],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	mov		v26.d[1],x2
.Lpost_loop_Q1:
	/* assume this is final block */
	mov		v27.b[0],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	/* overwrite previous v27 value (0x80) */
	mov		v27.d[0],x2
	/* assume this was final block */
	mov		v27.b[8],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	mov		v27.d[1],x2
.Lpost_loop_Q2:
	/* assume this was final block */
	mov		v28.b[0],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	/* overwrite previous v28 value (0x80) */
	mov		v28.d[0],x2
	/* assume this was final block */
	mov		v28.b[8],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	mov		v28.d[1],x2
.Lpost_loop_Q3:
	/* assume this was final block */
	mov		v29.b[0],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	/* overwrite previous v29 value (0x80) */
	mov		v29.d[0],x2
	/* assume this was final block */
	mov		v29.b[8],w15
	/* outstanding 8B blocks left */
	cbz		x5,1f
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	mov		v29.d[1],x2

/*
 * That is enough of blocks, we allow up to 64 bytes in total.
 * Now we have the sha1 to do for these 4 16B blocks
 */
1:
	rev32		v26.16b,v26.16b
	rev32		v27.16b,v27.16b
	rev32		v28.16b,v28.16b
	rev32		v29.16b,v29.16b

	mov		v20.16b,v24.16b		/* working ABCD <- ABCD */

	add		v19.4s,v4.4s,v26.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s25,v19.4s
	add		v23.4s,v4.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	add		v23.4s,v4.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	add		v23.4s,v5.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v5.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s
	add		v23.4s,v5.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v5.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s
	add		v23.4s,v5.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v6.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v6.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v19.4s,v6.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v6.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v19.4s,v6.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v7.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v7.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	add		v23.4s,v7.4s,v27.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s

	add		v19.4s,v7.4s,v28.4s
	sha1h		s21,s24
	eor		v26.16b,v26.16b,v26.16b		/* zero sha src 0 */
	sha1p		q24,s22,v23.4s

	add		v23.4s,v7.4s,v29.4s
	sha1h		s22,s24
	eor		v27.16b,v27.16b,v27.16b		/* zero sha src 1 */
	sha1p		q24,s21,v19.4s

	sha1h		s21,s24
	eor		v28.16b,v28.16b,v28.16b		/* zero sha src 2 */
	sha1p		q24,s22,v23.4s

	add		v25.4s,v25.4s,v21.4s
	eor		v29.16b,v29.16b,v29.16b		/* zero sha src 3 */
	add		v24.4s,v24.4s,v20.4s

	/* this was final block */
	cbz		x5,.Lpost_loop
	subs		x5,x5,8
	/* loop if hash is not finished */
	b.ne		.Lpost_loop_Q0
	/* set "1" of the padding if this was a final block */
	mov		v26.b[0],w15

.Lpost_loop:
	/* Add outstanding bytes of digest source */
	add		x11,x11,x8
	/* Add one SHA-1 block since hash is calculated including i_key_pad */
	add		x11,x11,#64
	lsr		x12,x11,32		/* len_hi */
	and		x14,x11,0xffffffff	/* len_lo */
	lsl		x12,x12,3		/* len_hi in bits */
	lsl		x14,x14,3		/* len_lo in bits */

	rev32		v26.16b,v26.16b		/* fix endian w0 */
	mov		v29.s[3],w14		/* len_lo */
	rev32		v27.16b,v27.16b		/* fix endian w1 */
	mov		v29.s[2],w12		/* len_hi */
	rev32		v28.16b,v28.16b		/* fix endian w2 */

	mov		v20.16b,v24.16b		/* working ABCD <- ABCD */
	/* skip write back if there were less than 4 AES blocks */
	cbz		x9,1f
	/*
	 * At this point all data should be fetched for SHA.
	 * Save remaining blocks without danger of overwriting SHA source.
	 */
	stp		q0,q1,[x1],32
	stp		q2,q3,[x1],32
1:
/*
 * final sha block
 * the strategy is to combine the 0-3 aes blocks, which is faster but
 * a little gourmand on code space.
 */
	cbz		x13,.Lzero_aes_blocks_left	/* none to do */
	/* read first aes block, bump aes_ptr_in */
	ld1		{v0.16b},[x0]
	ld1		{v31.16b},[x0],16

	aesd		v0.16b,v8.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v9.16b
	aesimc		v0.16b,v0.16b
	add		v19.4s,v4.4s,v26.4s
	aesd		v0.16b,v10.16b
	add		v23.4s,v4.4s,v27.4s
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v11.16b
	sha1su0		v26.4s,v27.4s,v28.4s
	aesimc		v0.16b,v0.16b
	sha1h		s22,s24
	aesd		v0.16b,v12.16b
	sha1c		q24,s25,v19.4s
	sha1su1		v26.4s,v29.4s
	aesimc		v0.16b,v0.16b
	sha1su0		v27.4s,v28.4s,v29.4s
	aesd		v0.16b,v13.16b
	sha1h		s21,s24
	aesimc		v0.16b,v0.16b
	sha1c		q24,s22,v23.4s
	aesd		v0.16b,v14.16b
	sha1su1		v27.4s,v26.4s
	add		v19.4s,v4.4s,v28.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	aesimc		v0.16b,v0.16b
	sha1h		s22,s24
	aesd		v0.16b,v15.16b
	sha1c		q24,s21,v19.4s
	aesimc		v0.16b,v0.16b
	sha1su1		v28.4s,v27.4s
	add		v23.4s,v4.4s,v29.4s
	aesd		v0.16b,v16.16b
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	aesimc		v0.16b,v0.16b
	sha1c		q24,s22,v23.4s
	aesd		v0.16b,v17.16b
	sha1su1		v29.4s,v28.4s
	eor		v3.16b,v0.16b,v18.16b	/* res 0 */
	eor		v3.16b,v3.16b,v30.16b	/* xor w/ ivec (modeop) */
	add		v19.4s,v4.4s,v26.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	/* save aes res, bump aes_out_ptr */
	st1		{v3.16b},[x1],16
	sha1su1		v26.4s,v29.4s
	/* dec counter */
	sub		x13,x13,1
	cbz		x13,.Lfrmquad1

/* aes xform 1 */
	/* read first aes block, bump aes_ptr_in */
	ld1		{v0.16b},[x0]
	ld1		{v30.16b},[x0],16
	add		v23.4s,v5.4s,v27.4s
	aesd		v0.16b,v8.16b
	add		v19.4s,v5.4s,v28.4s
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v9.16b
	sha1su0		v27.4s,v28.4s,v29.4s
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v10.16b
	sha1h		s21,s24
	aesimc		v0.16b,v0.16b
	sha1p		q24,s22,v23.4s
	aesd		v0.16b,v11.16b
	sha1su1		v27.4s,v26.4s
	aesimc		v0.16b,v0.16b
	sha1su0		v28.4s,v29.4s,v26.4s
	aesd		v0.16b,v12.16b
	sha1h		s22,s24
	aesimc		v0.16b,v0.16b
	sha1p		q24,s21,v19.4s
	aesd		v0.16b,v13.16b
	sha1su1		v28.4s,v27.4s
	add		v23.4s,v5.4s,v29.4s
	aesimc		v0.16b,v0.16b
	sha1su0		v29.4s,v26.4s,v27.4s
	aesd		v0.16b,v14.16b
	sha1h		s21,s24
	aesimc		v0.16b,v0.16b
	sha1p		q24,s22,v23.4s
	aesd		v0.16b,v15.16b
	sha1su1		v29.4s,v28.4s
	aesimc		v0.16b,v0.16b
	add		v19.4s,v5.4s,v26.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	aesd		v0.16b,v16.16b
	sha1h		s22,s24
	aesimc		v0.16b,v0.16b
	sha1p		q24,s21,v19.4s
	aesd		v0.16b,v17.16b
	sha1su1		v26.4s,v29.4s
	eor		v3.16b,v0.16b,v18.16b	/* res 0 */
	eor		v3.16b,v3.16b,v31.16b	/* xor w/ ivec (modeop) */
	add		v23.4s,v5.4s,v27.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	/* save aes res, bump aes_out_ptr */
	st1		{v3.16b},[x1],16
	sha1su1		v27.4s,v26.4s

	sub		x13,x13,1		/* dec counter */
	cbz		x13,.Lfrmquad2

/* aes xform 2 */
	/* read first aes block, bump aes_ptr_in */
	ld1		{v0.16b},[x0],16
	add		v19.4s,v6.4s,v28.4s
	aesd		v0.16b,v8.16b
	add		v23.4s,v6.4s,v29.4s
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v9.16b
	sha1su0		v28.4s,v29.4s,v26.4s
	aesimc		v0.16b,v0.16b
	sha1h		s22,s24
	aesd		v0.16b,v10.16b
	sha1m		q24,s21,v19.4s
	aesimc		v0.16b,v0.16b
	sha1su1		v28.4s,v27.4s
	aesd		v0.16b,v11.16b
	sha1su0		v29.4s,v26.4s,v27.4s
	aesimc		v0.16b,v0.16b
	sha1h		s21,s24
	aesd		v0.16b,v12.16b
	sha1m		q24,s22,v23.4s
	aesimc		v0.16b,v0.16b
	sha1su1		v29.4s,v28.4s
	aesd		v0.16b,v13.16b
	add		v19.4s,v6.4s,v26.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v14.16b
	sha1h		s22,s24
	aesimc		v0.16b,v0.16b
	sha1m		q24,s21,v19.4s
	aesd		v0.16b,v15.16b
	sha1su1		v26.4s,v29.4s
	aesimc		v0.16b,v0.16b
	add		v23.4s,v6.4s,v27.4s
	aesd		v0.16b,v16.16b
	sha1su0		v27.4s,v28.4s,v29.4s
	aesimc		v0.16b,v0.16b
	sha1h		s21,s24
	aesd		v0.16b,v17.16b
	sha1m		q24,s22,v23.4s
	eor		v3.16b,v0.16b,v18.16b	/* res 0 */
	sha1su1		v27.4s,v26.4s
	eor		v3.16b,v3.16b,v30.16b	/* xor w/ ivec (modeop) */
	add		v19.4s,v6.4s,v28.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	/* save aes res, bump aes_out_ptr */
	st1		{v3.16b},[x1],16
	sha1su1		v28.4s,v27.4s
	b		.Lfrmquad3
/*
 * the final block with no aes component, i.e from here there were zero blocks
 */

.Lzero_aes_blocks_left:

	add		v19.4s,v4.4s,v26.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s25,v19.4s
	add		v23.4s,v4.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	add		v23.4s,v4.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	sha1su1		v26.4s,v29.4s

/* quad 1 */
.Lfrmquad1:
	add		v23.4s,v5.4s,v27.4s
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v5.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s
	add		v23.4s,v5.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v5.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s
	add		v23.4s,v5.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	sha1su1		v27.4s,v26.4s

/* quad 2 */
.Lfrmquad2:
	add		v19.4s,v6.4s,v28.4s
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v6.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v19.4s,v6.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v6.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v19.4s,v6.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	sha1su1		v28.4s,v27.4s

/* quad 3 */
.Lfrmquad3:
	add		v23.4s,v7.4s,v29.4s
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v7.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	add		v23.4s,v7.4s,v27.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s

	add		v19.4s,v7.4s,v28.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s

	add		v23.4s,v7.4s,v29.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s

	sha1h		s21,s24
	sha1p		q24,s22,v23.4s

	add		v26.4s,v24.4s,v20.4s
	add		v27.4s,v25.4s,v21.4s

	/* Calculate final HMAC */
	eor		v28.16b, v28.16b, v28.16b
	eor		v29.16b, v29.16b, v29.16b
	/* load o_key_pad partial hash */
	ld1		{v24.16b,v25.16b}, [x7]
	/* working ABCD <- ABCD */
	mov		v20.16b,v24.16b

	/* Set padding 1 to the first reg */
	mov		w11, #0x80		/* that's the 1 of the pad */
	mov		v27.b[7], w11
	/* size of o_key_pad + inner hash */
	mov		x11, #64+20
	/* move length to the end of the block */
	lsl		x11, x11, 3
	mov		v29.s[3], w11
	lsr		x11, x11, 32
	mov		v29.s[2], w11		/* and the higher part */

	add		v19.4s,v4.4s,v26.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s25,v19.4s
	add		v23.4s,v4.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	add		v23.4s,v4.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	add		v23.4s,v5.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v5.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s
	add		v23.4s,v5.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v5.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s
	add		v23.4s,v5.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v6.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v6.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v19.4s,v6.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v6.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v19.4s,v6.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v7.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v7.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	add		v23.4s,v7.4s,v27.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s

	add		v19.4s,v7.4s,v28.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s

	mov		x9,sp
	add		sp,sp,8*16
	ldp		q8,q9,[x9],32
	ldp		q10,q11,[x9],32

	add		v23.4s,v7.4s,v29.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s

	sha1h		s21,s24
	sha1p		q24,s22,v23.4s

	ldp		q12,q13,[x9],32
	ldp		q14,q15,[x9]

	mov		x0, xzr

	add		v24.4s,v24.4s,v20.4s
	add		v25.4s,v25.4s,v21.4s

	rev32		v24.16b, v24.16b
	rev32		v25.16b, v25.16b

	st1		{v24.16b}, [x4],16
	st1		{v25.s}[0], [x4]

	ret

/*
 * These are the short cases (less efficient), here used for 1-11 aes blocks.
 * x10 = aes_blocks
 */
.Lshort_cases:
	ldp		q8,q9,[x9],32
	adr		x8,.Lrcon			/* rcon */
	ldp		q10,q11,[x9],32
	lsl		x11,x10,4		/* len = aes_blocks*16 */

	ldp		q12,q13,[x9],32
	ldp		q4,q5,[x8],32			/* key0, key1 */
	ldp		q14,q15,[x9],32
	ld1		{v30.16b},[x6]			/* get ivec */
	ldp		q16,q17,[x9],32
	ldp		q6,q7,[x8]			/* key2, key3 */
	ld1		{v18.16b},[x9]

	/* get outstanding bytes of the digest */
	sub		x8,x5,x2

	/* indicate AES blocks to write back */
	mov		x9,xzr

	mov		x2,x0
	/*
	 * Digest source has to be at least of cipher source length
	 * therefore it is safe to use x10 to indicate whether we can
	 * overtake cipher processing by 4 AES block here.
	 */
	cmp		x10,4			/* check if 4 or more */
	/* if less, bail to last block */
	blt		.Llast_sha_block

	ldp		q26,q27,[x3],32
	rev32		v26.16b,v26.16b
	rev32		v27.16b,v27.16b
	ldp		q28,q29,[x3],32
	rev32		v28.16b,v28.16b
	rev32		v29.16b,v29.16b

	sub		x5,x5,64

	mov		v20.16b,v24.16b		/* working ABCD <- ABCD */

/* quad 0 */
	add		v19.4s,v4.4s,v26.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s25,v19.4s
	add		v23.4s,v4.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	add		v23.4s,v4.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	add		v23.4s,v5.4s,v27.4s
	sha1su1		v26.4s,v29.4s

/* quad 1 */
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v5.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s
	add		v23.4s,v5.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v5.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s
	add		v23.4s,v5.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v6.4s,v28.4s
	sha1su1		v27.4s,v26.4s

/* quad 2 */
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v6.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v19.4s,v6.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v6.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v19.4s,v6.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v7.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v7.4s,v26.4s
	sha1su1		v29.4s,v28.4s

/* quad 3 */
	add		v23.4s,v7.4s,v27.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s

	add		v19.4s,v7.4s,v28.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s

	add		v23.4s,v7.4s,v29.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s

	sha1h		s21,s24
	sha1p		q24,s22,v23.4s

	add		v25.4s,v25.4s,v21.4s
	add		v24.4s,v24.4s,v20.4s

	/* there were at least 4 AES blocks to process */
	b		.Lshort_loop_no_store

.Lshort_loop:
	cmp		x10,4			/* check if 4 or more */
	/* if less, bail to last block */
	blt		.Llast_sha_block

	stp		q0,q1,[x1],32
	stp		q2,q3,[x1],32

	sub		x9,x9,4

.Lshort_loop_no_store:

	ld1		{v31.16b},[x2]		/* next w no update */
	/* read next aes block, update aes_ptr_in */
	ld1		{v0.16b},[x2],16

	add		x0,x0,64

/* aes xform 0 */
	aesd		v0.16b,v8.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v9.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v10.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v11.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v12.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v13.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v14.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v15.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v16.16b
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v17.16b
	eor		v0.16b,v0.16b,v18.16b
	eor		v0.16b,v0.16b,v30.16b	/* xor w/ prev value */

	ld1		{v30.16b},[x2]		/* read no update */
	/* read next aes block, update aes_ptr_in */
	ld1		{v1.16b},[x2],16

/* aes xform 1 */
	aesd		v1.16b,v8.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v9.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v10.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v11.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v12.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v13.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v14.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v15.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v16.16b
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v17.16b
	eor		v1.16b,v1.16b,v18.16b
	eor		v1.16b,v1.16b,v31.16b	/* xor w/ prev value */

	ld1		{v31.16b},[x2]		/* read no update */
	/* read next aes block, update aes_ptr_in */
	ld1		{v2.16b},[x2],16

/* aes xform 2 */
	aesd		v2.16b,v8.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v9.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v10.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v11.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v12.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v13.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v14.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v15.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v16.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v17.16b
	eor		v2.16b,v2.16b,v18.16b
	eor		v2.16b,v2.16b,v30.16b	/* xor w/ prev value */

	ld1		{v30.16b},[x2]		/* read no update */
	/* read next aes block, update aes_ptr_in */
	ld1		{v3.16b},[x2],16

/* aes xform 3 */
	aesd		v3.16b,v8.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v9.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v10.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v11.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v12.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v13.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v14.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v15.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v16.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v17.16b
	eor		v3.16b,v3.16b,v18.16b
	eor		v3.16b,v3.16b,v31.16b	/* xor w/ prev value */

	add		x9,x9,4

	sub		x10,x10,4		/* 4 less */
	cmp		x5,64
	b.lt		.Lshort_loop		/* keep looping */

	ldp		q26,q27,[x3],32
	rev32		v26.16b,v26.16b
	rev32		v27.16b,v27.16b
	ldp		q28,q29,[x3],32
	rev32		v28.16b,v28.16b
	rev32		v29.16b,v29.16b

	sub		x5,x5,64

	mov		v20.16b,v24.16b		/* working ABCD <- ABCD */

/* quad 0 */
	add		v19.4s,v4.4s,v26.4s
	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s25,v19.4s
	add		v23.4s,v4.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	add		v23.4s,v4.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1c		q24,s22,v23.4s
	add		v19.4s,v4.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1c		q24,s21,v19.4s
	add		v23.4s,v5.4s,v27.4s
	sha1su1		v26.4s,v29.4s

/* quad 1 */
	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v5.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s
	add		v23.4s,v5.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v5.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s
	add		v23.4s,v5.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v6.4s,v28.4s
	sha1su1		v27.4s,v26.4s

/* quad 2 */
	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v6.4s,v29.4s
	sha1su1		v28.4s,v27.4s

	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v19.4s,v6.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	sha1su0		v26.4s,v27.4s,v28.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v6.4s,v27.4s
	sha1su1		v26.4s,v29.4s

	sha1su0		v27.4s,v28.4s,v29.4s
	sha1h		s21,s24
	sha1m		q24,s22,v23.4s
	add		v19.4s,v6.4s,v28.4s
	sha1su1		v27.4s,v26.4s

	sha1su0		v28.4s,v29.4s,v26.4s
	sha1h		s22,s24
	sha1m		q24,s21,v19.4s
	add		v23.4s,v7.4s,v29.4s
	sha1su1		v28.4s,v27.4s

/* quad 3 */
	sha1su0		v29.4s,v26.4s,v27.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s
	add		v19.4s,v7.4s,v26.4s
	sha1su1		v29.4s,v28.4s

	add		v23.4s,v7.4s,v27.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s

	add		v19.4s,v7.4s,v28.4s
	sha1h		s21,s24
	sha1p		q24,s22,v23.4s

	add		v23.4s,v7.4s,v29.4s
	sha1h		s22,s24
	sha1p		q24,s21,v19.4s

	sha1h		s21,s24
	sha1p		q24,s22,v23.4s

	add		v25.4s,v25.4s,v21.4s
	add		v24.4s,v24.4s,v20.4s

	b		.Lshort_loop		/* keep looping */
/*
 * this is arranged so that we can join the common unwind code
 * that does the last sha block and the final 0-3 aes blocks
 */
.Llast_sha_block:
	eor		v26.16b,v26.16b,v26.16b		/* zero the rest */
	eor		v27.16b,v27.16b,v27.16b		/* zero the rest */
	eor		v28.16b,v28.16b,v28.16b		/* zero the rest */
	eor		v29.16b,v29.16b,v29.16b		/* zero the rest */

	mov		x13,x10			/* copy aes blocks for common */
	b		.Ljoin_common		/* join common code */

	.size	asm_sha1_hmac_aes128cbc_dec, .-asm_sha1_hmac_aes128cbc_dec
