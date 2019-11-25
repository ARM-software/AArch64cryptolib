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
 * Combined Auth/Dec Primitive = sha256_hmac/aes128cbc
 *
 * Operations:
 *
 * out = decrypt-AES128CBC(in)
 * return_ash_ptr = SHA256(o_key_pad | SHA256(i_key_pad | in))
 *
 * Prototype:
 *
 * void asm_sha256_hmac_aes128cbc_dec(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
 *			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
 *			AArch64crypto_cipher_digest_t *arg)
 *
 * Registers used:
 *
 * asm_sha256_hmac_aes128cbc_dec(
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
 * v19 - v20 -- round keys
 * v21 -- ABCD tmp
 * v22 -- sha working state ABCD (q22)
 * v23 -- sha working state EFGH (q23)
 * v24 -- sha state ABCD
 * v25 -- sha state EFGH
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
	.file "sha256_hmac_aes128cbc_dec.S"
	.text
	.cpu generic+fp+simd+crypto+crc
	.global asm_sha256_hmac_aes128cbc_dec
	.type	asm_sha256_hmac_aes128cbc_dec,%function


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

.Linit_sha_state:
	.word		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
	.word		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

asm_sha256_hmac_aes128cbc_dec:
/* protect registers */
	sub		sp,sp,8*16
	sub		sp,sp,2*8
	mov		x9,sp			/* copy for address mode */
	stp		q8,q9,[x9],32

/* fetch args */
	ldr		x7, [x6, #HMAC_IKEYPAD]
	/* init ABCD, EFGH */
	ldp		q24,q25,[x7]
	/* save pointer to o_key_pad partial hash */
	ldr		x7, [x6, #HMAC_OKEYPAD]

	stp		q10,q11,[x9],32

	prfm		PLDL1KEEP,[x0,0]	/* pref next aes_ptr_in */
	stp		q12,q13,[x9],32
	prfm		PLDL1KEEP,[x1,0]	/* pref next aes_ptr_out */
	lsr		x10,x2,4		/* aes_blocks = len/16 */
	stp		q14,q15,[x9],32
	/* address of sha init state consts */
	adr		x12,.Linit_sha_state
	stp		x19,x20,[x9]

	ldr		x9, [x6, #CIPHER_KEY]
	ldr		x6, [x6, #CIPHER_IV]
/*
 * init sha state, prefetch, check for small cases.
 * Note that the output is prefetched as a load, for the in-place case
 */
	cmp		x10,16			/* no main loop if <16 */
	blt		.Lshort_cases		/* branch if < 12 */

	/* get outstanding bytes of the digest */
	sub		x20,x5,x2

	mov		x11,x2			/* len -> x11 needed at end */
	ld1		{v30.16b},[x6]		/* get 1st ivec */
	lsr		x12,x11,6		/* total_blocks (sha) */

	ldp		q26,q27,[x3],32
	rev32		v26.16b,v26.16b		/* endian swap w0 */
	rev32		v27.16b,v27.16b		/* endian swap w1 */
	ldp		q28,q29,[x3],32
	rev32		v28.16b,v28.16b		/* endian swap w2 */
	rev32		v29.16b,v29.16b		/* endian swap w3 */

	/* substract loaded bytes */
	sub		x5,x5,64
/*
 * now we can do the loop prolog, 1st sha256 block
 */
	prfm		PLDL1KEEP,[x0,64]	/* pref next aes_ptr_in */
	prfm		PLDL1KEEP,[x1,64]	/* pref next aes_ptr_out */
	/* base address for sha round consts */
	adr		x8,.Lrcon
/*
 * do the first sha256 block on the plaintext
 */
	mov		v22.16b,v24.16b		/* init working ABCD */
	mov		v23.16b,v25.16b		/* init working EFGH */

/* quad 0 */
	ld1		{v4.16b},[x8],16	/* key0 */
	ld1		{v5.16b},[x8],16	/* key1 */
	ld1		{v6.16b},[x8],16	/* key2 */
	ld1		{v7.16b},[x8],16	/* key3 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v8.16b},[x9],16	/* rk[0] */
	sha256h2	q23, q21, v4.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	sha256su1	v26.4s,v28.4s,v29.4s
	ld1		{v9.16b},[x9],16	/* rk[1] */

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v10.16b},[x9],16	/* rk[2] */
	sha256h2	q23, q21, v5.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	sha256su1	v27.4s,v29.4s,v26.4s

	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256h2	q23, q21, v6.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	sha256su1	v28.4s,v26.4s,v27.4s
	ld1		{v11.16b},[x9],16	/* rk[3] */

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256h2	q23, q21, v7.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 1 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v12.16b},[x9],16	/* rk[4] */
	sha256h2	q23, q21, v4.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	sha256su1	v26.4s,v28.4s,v29.4s
	ld1		{v13.16b},[x9],16	/* rk[5] */

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v14.16b},[x9],16	/* rk[6] */
	sha256h2	q23, q21, v5.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	sha256su1	v27.4s,v29.4s,v26.4s

	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256h2	q23, q21, v6.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	sha256su1	v28.4s,v26.4s,v27.4s
	ld1		{v15.16b},[x9],16	/* rk[7] */

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256h2	q23, q21, v7.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 2 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v16.16b},[x9],16	/* rk[8] */
	sha256h2	q23, q21, v4.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	sha256su1	v26.4s,v28.4s,v29.4s
	ld1		{v17.16b},[x9],16	/* rk[9] */

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v18.16b},[x9],16	/* rk[10] */
	sha256h2	q23, q21, v5.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	sha256su1	v27.4s,v29.4s,v26.4s

	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256h2	q23, q21, v6.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256h2	q23, q21, v7.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 3 */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256h2	q23, q21, v4.4s
	ld1		{v26.16b},[x3],16	/* next w0 */
	ld1		{v27.16b},[x3],16	/* next w1 */

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256h2	q23, q21, v5.4s
	ld1		{v28.16b},[x3],16	/* next w2 */
	ld1		{v29.16b},[x3],16	/* next w3 */

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s

	/* substract loaded bytes */
	sub		x5,x5,64

/*
 * aes_blocks_left := number after the main (sha) block is done.
 * can be 0 note we account for the extra unwind in main_blocks
 */
	sub		x15,x12,2		/* main_blocks=total_blocks-5 */

	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	and		x13,x10,3		/* aes_blocks_left */
	ld1		{v0.16b},[x0]		/* next aes block, no update */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */
	add		x9,x0,128		/* lead_ptr = *in */
	/* next aes block, update aes_ptr_in */
	ld1		{v31.16b},[x0],16

	/* indicate AES blocks to write back */
	mov		x19,xzr
/*
 * main combined loop CBC, can be used by auth/enc version
 */
.Lmain_loop:
/*
 * Because both mov, rev32 and eor have a busy cycle, this takes longer
 * than it looks.
 */
	rev32		v26.16b,v26.16b		/* fix endian w0 */
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	prfm		PLDL1KEEP,[x9,64]	/* pref next lead_ptr */
	rev32		v27.16b,v27.16b		/* fix endian w1 */
	/* pref next aes_ptr_out, streaming */
	prfm		PLDL1KEEP,[x1,64]
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	/* base address for sha round consts */
	adr		x8,.Lrcon

/*
 * aes xform 0, sha quad 0
 */
	aesd		v0.16b,v8.16b
	ld1		{v4.16b},[x8],16	/* key0 */
	rev32		v28.16b,v28.16b		/* fix endian w2 */
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v9.16b
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	ld1		{v5.16b},[x8],16	/* key1 */
	aesimc		v0.16b,v0.16b
	sha256su0	v26.4s,v27.4s
	aesd		v0.16b,v10.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v11.16b
	ld1		{v6.16b},[x8],16	/* key2 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	ld1		{v7.16b},[x8],16	/* key3 */
	rev32		v29.16b,v29.16b		/* fix endian w3 */
	/* read next aes block, no update */
	ld1		{v1.16b},[x0]
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v4.4s
	aesd		v0.16b,v12.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	ld1		{v4.16b},[x8],16	/* key4 */
	aesimc		v0.16b,v0.16b
	sha256su0	v27.4s,v28.4s
	aesd		v0.16b,v13.16b
	sha256h		q22, q23, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v5.4s
	aesd		v0.16b,v14.16b
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v27.4s,v29.4s,v26.4s
	aesimc		v0.16b,v0.16b
	sha256su0	v28.4s,v29.4s
	aesd		v0.16b,v15.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v6.4s
	aesd		v0.16b,v16.16b
	sha256su1	v28.4s,v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256su0	v29.4s,v26.4s
	aesimc		v0.16b,v0.16b
	sha256h		q22, q23, v7.4s
	aesd		v0.16b,v17.16b
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s
	eor		v0.16b,v0.16b,v18.16b	/* final res 0 */
	ld1		{v6.16b},[x8],16	/* key6 */
	eor		v0.16b,v0.16b,v30.16b	/* xor w/ prev value */
	/* get next aes block, with update */
	ld1		{v30.16b},[x0],16
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */

/* aes xform 1, sha quad 1 */
	sha256su0	v26.4s,v27.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	mov		v21.16b, v22.16b	/* copy abcd */
	/* save aes res, bump aes_out_ptr */
	st1		{v0.16b},[x1],16
	aesd		v1.16b,v8.16b
	sha256h		q22, q23, v4.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256h2	q23, q21, v4.4s
	aesimc		v1.16b,v1.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	aesd		v1.16b,v9.16b
	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesimc		v1.16b,v1.16b
	sha256h2	q23, q21, v5.4s
	aesd		v1.16b,v10.16b
	/* read next aes block, no update */
	ld1		{v2.16b},[x0]
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v27.4s,v29.4s,v26.4s
	aesimc		v1.16b,v1.16b
	ld1		{v4.16b},[x8],16	/* key4 */
	aesd		v1.16b,v11.16b
	ld1		{v5.16b},[x8],16	/* key5 */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256su0	v28.4s,v29.4s
	aesimc		v1.16b,v1.16b
	sha256h		q22, q23, v6.4s
	aesd		v1.16b,v12.16b
	sha256h2	q23, q21, v6.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	sha256su1	v28.4s,v26.4s,v27.4s
	aesimc		v1.16b,v1.16b
	sha256su0	v29.4s,v26.4s
	aesd		v1.16b,v13.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesimc		v1.16b,v1.16b
	sha256h2	q23, q21, v7.4s
	aesd		v1.16b,v14.16b
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v15.16b
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v16.16b
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v17.16b
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	eor		v1.16b,v1.16b,v18.16b	/* res xf 1 */
	eor		v1.16b,v1.16b,v31.16b	/* mode op 1 xor w/prev value */
	/* read next aes block, update aes_ptr_in */
	ld1		{v31.16b},[x0],16

/* aes xform 2, sha quad 2 */
	sha256su0	v26.4s,v27.4s
	aesd		v2.16b,v8.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v1.16b},[x1],16
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	aesimc		v2.16b,v2.16b
	sha256h2	q23, q21, v4.4s
	aesd		v2.16b,v9.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	aesimc		v2.16b,v2.16b
	sha256su0	v27.4s,v28.4s
	aesd		v2.16b,v10.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesimc		v2.16b,v2.16b
	sha256h2	q23, q21, v5.4s
	aesd		v2.16b,v11.16b
	sha256su1	v27.4s,v29.4s,v26.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	sha256su0	v28.4s,v29.4s
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v12.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesimc		v2.16b,v2.16b
	sha256h2	q23, q21, v6.4s
	aesd		v2.16b,v13.16b
	sha256su1	v28.4s,v26.4s,v27.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su0	v29.4s,v26.4s
	aesimc		v2.16b,v2.16b
	/* read next aes block, no update */
	ld1		{v3.16b},[x0]
	aesd		v2.16b,v14.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesimc		v2.16b,v2.16b
	sha256h2	q23, q21, v7.4s
	aesd		v2.16b,v15.16b
	sha256su1	v29.4s,v27.4s,v28.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	ld1		{v6.16b},[x8],16	/* key6 */
	aesimc		v2.16b,v2.16b
	ld1		{v7.16b},[x8],16	/* key7 */
	aesd		v2.16b,v16.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v17.16b
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	eor		v2.16b,v2.16b,v18.16b	/* res 2 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	eor		v2.16b,v2.16b,v30.16b	/* mode of 2 xor w/prev value */
	/* read next aes block, update aes_ptr_in */
	ld1		{v30.16b},[x0],16

/* aes xform 3, sha quad 3 (hash only) */
	aesd		v3.16b,v8.16b
	aesimc		v3.16b,v3.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v2.16b},[x1],16
	aesd		v3.16b,v9.16b
	ld1		{v26.16b},[x3],16	/* next w0 */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	aesimc		v3.16b,v3.16b
	sha256h2	q23, q21, v4.4s
	aesd		v3.16b,v10.16b
	ld1		{v27.16b},[x3],16	/* next w1 */
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v11.16b
	ld1		{v28.16b},[x3],16	/* next w2 */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesimc		v3.16b,v3.16b
	sha256h2	q23, q21, v5.4s
	aesd		v3.16b,v12.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v13.16b
	ld1		{v29.16b},[x3],16	/* next w3 */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesimc		v3.16b,v3.16b
	sha256h2	q23, q21, v6.4s
	aesd		v3.16b,v14.16b
	sub		x15,x15,1		/* dec block count */
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v15.16b
	ld1		{v0.16b},[x0]		/* next aes block, no update */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesimc		v3.16b,v3.16b
	sha256h2	q23, q21, v7.4s
	aesd		v3.16b,v16.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v17.16b
	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	eor		v3.16b,v3.16b,v18.16b	/* aes res 3 */
	eor		v3.16b,v3.16b,v31.16b	/* xor w/ prev value */
	/* next aes block, update aes_ptr_in */
	ld1		{v31.16b},[x0],16
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */
	/* save aes res, bump aes_out_ptr */
	st1		{v3.16b},[x1],16
	/* substract loaded bytes */
	sub		x5,x5,64
	cbnz		x15,.Lmain_loop		/* loop if more to do */
/*
 * Now the loop epilog. Since the reads for sha have already been done
 * in advance, we have to have an extra unwind.
 * This is why the test for the short cases is 16 and not 12.
 *
 * the unwind, which is just the main loop without the tests or final reads.
 */

	rev32		v26.16b,v26.16b		/* fix endian w0 */
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	rev32		v27.16b,v27.16b		/* fix endian w1 */
	/* pref next aes_ptr_out, streaming */
	prfm		PLDL1KEEP,[x1,64]
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	/* base address for sha round consts */
	adr		x8,.Lrcon
	ld1		{v4.16b},[x8],16	/* key0 */
	ld1		{v5.16b},[x8],16	/* key1 */

/*
 * aes xform 0, sha quad 0
 */
	aesd		v0.16b,v8.16b
	ld1		{v6.16b},[x8],16	/* key2 */
	rev32		v28.16b,v28.16b		/* fix endian w2 */
	ld1		{v7.16b},[x8],16	/* key3 */
	aesimc		v0.16b,v0.16b
	/* read next aes block, no update */
	ld1		{v1.16b},[x0]
	aesd		v0.16b,v9.16b
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	aesimc		v0.16b,v0.16b
	sha256su0	v26.4s,v27.4s
	aesd		v0.16b,v10.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	aesimc		v0.16b,v0.16b
	aesd		v0.16b,v11.16b
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	rev32		v29.16b,v29.16b		/* fix endian w3 */
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v4.4s
	aesd		v0.16b,v12.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	ld1		{v4.16b},[x8],16	/* key4 */
	aesimc		v0.16b,v0.16b
	sha256su0	v27.4s,v28.4s
	aesd		v0.16b,v13.16b
	sha256h		q22, q23, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v5.4s
	aesd		v0.16b,v14.16b
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v27.4s,v29.4s,v26.4s
	aesimc		v0.16b,v0.16b
	sha256su0	v28.4s,v29.4s
	aesd		v0.16b,v15.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v6.4s
	aesd		v0.16b,v16.16b
	sha256su1	v28.4s,v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256su0	v29.4s,v26.4s
	aesimc		v0.16b,v0.16b
	sha256h		q22, q23, v7.4s
	aesd		v0.16b,v17.16b
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s
	eor		v0.16b,v0.16b,v18.16b	/* final res 0 */
	ld1		{v6.16b},[x8],16	/* key6 */
	eor		v0.16b,v0.16b,v30.16b	/* xor w/ prev value */
	/* read next aes block, update aes_ptr_in */
	ld1		{v30.16b},[x0],16
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */

/* aes xform 1, sha quad 1 */
	sha256su0	v26.4s,v27.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	mov		v21.16b, v22.16b	/* copy abcd */
	/* save aes res, bump aes_out_ptr */
	st1		{v0.16b},[x1],16
	aesd		v1.16b,v8.16b
	sha256h		q22, q23, v4.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256h2	q23, q21, v4.4s
	aesimc		v1.16b,v1.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	aesd		v1.16b,v9.16b
	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesimc		v1.16b,v1.16b
	sha256h2	q23, q21, v5.4s
	aesd		v1.16b,v10.16b
	/* read next aes block, no update */
	ld1		{v2.16b},[x0]
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v27.4s,v29.4s,v26.4s
	aesimc		v1.16b,v1.16b
	ld1		{v4.16b},[x8],16	/* key4 */
	aesd		v1.16b,v11.16b
	ld1		{v5.16b},[x8],16	/* key5 */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256su0	v28.4s,v29.4s
	aesimc		v1.16b,v1.16b
	sha256h		q22, q23, v6.4s
	aesd		v1.16b,v12.16b
	sha256h2	q23, q21, v6.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	sha256su1	v28.4s,v26.4s,v27.4s
	aesimc		v1.16b,v1.16b
	sha256su0	v29.4s,v26.4s
	aesd		v1.16b,v13.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesimc		v1.16b,v1.16b
	sha256h2	q23, q21, v7.4s
	aesd		v1.16b,v14.16b
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v15.16b
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v16.16b
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	aesimc		v1.16b,v1.16b
	aesd		v1.16b,v17.16b
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	eor		v1.16b,v1.16b,v18.16b	/* res xf 1 */
	eor		v1.16b,v1.16b,v31.16b	/* mode op 1 xor w/prev value */
	/* read next aes block, update aes_ptr_in */
	ld1		{v31.16b},[x0],16

/* mode op 2 */

/* aes xform 2, sha quad 2 */
	sha256su0	v26.4s,v27.4s
	aesd		v2.16b,v8.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v1.16b},[x1],16
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	aesimc		v2.16b,v2.16b
	sha256h2	q23, q21, v4.4s
	aesd		v2.16b,v9.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	aesimc		v2.16b,v2.16b
	sha256su0	v27.4s,v28.4s
	aesd		v2.16b,v10.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesimc		v2.16b,v2.16b
	sha256h2	q23, q21, v5.4s
	aesd		v2.16b,v11.16b
	sha256su1	v27.4s,v29.4s,v26.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	sha256su0	v28.4s,v29.4s
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v12.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesimc		v2.16b,v2.16b
	sha256h2	q23, q21, v6.4s
	aesd		v2.16b,v13.16b
	sha256su1	v28.4s,v26.4s,v27.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su0	v29.4s,v26.4s
	aesimc		v2.16b,v2.16b
	/* read next aes block, no update */
	ld1		{v3.16b},[x0]
	aesd		v2.16b,v14.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesimc		v2.16b,v2.16b
	sha256h2	q23, q21, v7.4s
	aesd		v2.16b,v15.16b
	sha256su1	v29.4s,v27.4s,v28.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	ld1		{v6.16b},[x8],16	/* key6 */
	aesimc		v2.16b,v2.16b
	ld1		{v7.16b},[x8],16	/* key7 */
	aesd		v2.16b,v16.16b
	aesimc		v2.16b,v2.16b
	aesd		v2.16b,v17.16b
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	eor		v2.16b,v2.16b,v18.16b	/* res 2 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	eor		v2.16b,v2.16b,v30.16b	/* mode of 2 xor w/prev value */
	/* read next aes block, update aes_ptr_in */
	ld1		{v30.16b},[x0],16

/* mode op 3 */

/* aes xform 3, sha quad 3 (hash only) */
	aesd		v3.16b,v8.16b
	aesimc		v3.16b,v3.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v2.16b},[x1],16
	aesd		v3.16b,v9.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	aesimc		v3.16b,v3.16b
	sha256h2	q23, q21, v4.4s
	aesd		v3.16b,v10.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v11.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesimc		v3.16b,v3.16b
	sha256h2	q23, q21, v5.4s
	aesd		v3.16b,v12.16b
	/* read first aes block, no bump */
	ld1		{v0.16b},[x0]
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v13.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesimc		v3.16b,v3.16b
	sha256h2	q23, q21, v6.4s
	aesd		v3.16b,v14.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v15.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesimc		v3.16b,v3.16b
	sha256h2	q23, q21, v7.4s
	aesd		v3.16b,v16.16b
	aesimc		v3.16b,v3.16b
	aesd		v3.16b,v17.16b
	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	eor		v3.16b,v3.16b,v18.16b	/* aes res 3 */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */
	eor		v3.16b,v3.16b,v31.16b	/* xor w/prev value */
	/* read first aes block, bump aes_ptr_in */
	ld1		{v31.16b},[x0],16


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
	eor		v26.16b,v26.16b,v26.16b
	aesimc		v3.16b,v3.16b
	eor		v27.16b,v27.16b,v27.16b
	aesd		v3.16b,v16.16b
	eor		v28.16b,v28.16b,v28.16b
	aesimc		v3.16b,v3.16b
	eor		v29.16b,v29.16b,v29.16b
	aesd		v3.16b,v17.16b
	eor		v3.16b,v3.16b,v18.16b	/* res 3 */
	eor		v3.16b,v3.16b,v31.16b	/* xor w/ ivec (modeop) */

	add		x19,x19,4
/*
 * Now, there is the final b-1 sha256 padded block.
 * This contains between 0-3 aes blocks. We take some pains to avoid read spill
 * by only reading the blocks that are actually defined.
 * This is also the final sha block code for the shortCases.
 */
.Ljoin_common:
	/* base address for sha round consts */
	adr		x8,.Lrcon
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
 * Now we have the sha256 to do for these 4 16B blocks
 */
1:
	mov		x9,x8
	rev32		v26.16b,v26.16b
	ld1		{v4.16b},[x9],16	/* key0 */
	rev32		v27.16b,v27.16b
	rev32		v28.16b,v28.16b
	ld1		{v5.16b},[x9],16	/* key1 */
	rev32		v29.16b,v29.16b

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x9],16	/* key2 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x9],16	/* key3 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	ld1		{v4.16b},[x9],16	/* key4 */
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	ld1		{v5.16b},[x9],16	/* key5 */
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 1 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x9],16	/* key6 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x9],16	/* key7 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	ld1		{v4.16b},[x9],16	/* key4 */
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x9],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 2 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x9],16	/* key6 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x9],16	/* key7 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	ld1		{v4.16b},[x9],16	/* key4 */
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	ld1		{v5.16b},[x9],16	/* key5 */
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 3 */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x9],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	eor		v26.16b,v26.16b,v26.16b	/* zero sha src 0 */
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x9],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	eor		v27.16b,v27.16b,v27.16b	/* zero sha src 1 */
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	eor		v28.16b,v28.16b,v28.16b	/* zero sha src 2 */
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	eor		v29.16b,v29.16b,v29.16b	/* zero sha src 3 */
	sha256h2	q23, q21, v7.4s

	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */

	/* this was final block */
	cbz		x5,.Lpost_loop
	subs		x5,x5,8
	/* loop if hash is not finished */
	b.ne		.Lpost_loop_Q0
	/* set "1" of the padding if this was a final block */
	mov		v26.b[0],w15

.Lpost_loop:
	/* Add outstanding bytes of digest source */
	add		x11,x11,x20
	/* Add one SHA-2 block since hash is calculated including i_key_pad */
	add		x11,x11,#64
	lsr		x12,x11,32		/* len_hi */
	and		x14,x11,0xffffffff	/* len_lo */
	lsl		x12,x12,3		/* len_hi in bits */
	lsl		x14,x14,3		/* len_lo in bits */

	mov		v29.s[3],w14		/* len_lo */
	mov		v29.s[2],w12		/* len_hi */

	rev32		v26.16b,v26.16b		/* fix endian w0 */
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	rev32		v27.16b,v27.16b		/* fix endian w1 */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	rev32		v28.16b,v28.16b		/* fix endian w2 */

	/* skip write back if there were less than 4 AES blocks */
	cbz		x19,1f
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

	adr		x8,.Lrcon
	ld1		{v4.16b},[x8],16	/* key0 */
	aesd		v0.16b,v8.16b
	ld1		{v5.16b},[x8],16	/* key1 */
	aesimc		v0.16b,v0.16b
	ld1		{v6.16b},[x8],16	/* key2 */
	aesd		v0.16b,v9.16b
	ld1		{v7.16b},[x8],16	/* key3 */
	aesimc		v0.16b,v0.16b

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	aesd		v0.16b,v10.16b
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	aesimc		v0.16b,v0.16b
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */

	aesd		v0.16b,v11.16b
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	aesimc		v0.16b,v0.16b
	sha256h		q22, q23, v4.4s
	aesd		v0.16b,v12.16b
	sha256h2	q23, q21, v4.4s
	sha256su1	v26.4s,v28.4s,v29.4s
	aesimc		v0.16b,v0.16b

	sha256su0	v27.4s,v28.4s
	aesd		v0.16b,v13.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v5.4s
	aesd		v0.16b,v14.16b
	sha256su1	v27.4s,v29.4s,v26.4s

	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	aesimc		v0.16b,v0.16b
	sha256h		q22, q23, v6.4s
	aesd		v0.16b,v15.16b
	sha256h2	q23, q21, v6.4s
	aesimc		v0.16b,v0.16b
	sha256su1	v28.4s,v26.4s,v27.4s

	aesd		v0.16b,v16.16b
	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v7.4s
	aesd		v0.16b,v17.16b
	sha256su1	v29.4s,v27.4s,v28.4s
	eor		v3.16b,v0.16b,v18.16b	/* res 0 */
	eor		v3.16b,v3.16b,v30.16b	/* xor w/ ivec (modeop) */

	sub		x13,x13,1		/* dec counter */
	/* save aes res, bump aes_out_ptr */
	st1		{v3.16b},[x1],16
	cbz		x13,.Lfrmquad1

/* aes xform 1 */

	/* read first aes block, bump aes_ptr_in */
	ld1		{v0.16b},[x0]
	ld1		{v30.16b},[x0],16
	ld1		{v4.16b},[x8],16	/* key4 */
	ld1		{v5.16b},[x8],16	/* key5 */
	ld1		{v6.16b},[x8],16	/* key6 */
	ld1		{v7.16b},[x8],16	/* key7 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	aesd		v0.16b,v8.16b
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	aesimc		v0.16b,v0.16b
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */

	aesd		v0.16b,v9.16b
	sha256su0	v26.4s,v27.4s
	aesimc		v0.16b,v0.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	aesd		v0.16b,v10.16b
	sha256h		q22, q23, v4.4s
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v4.4s
	aesd		v0.16b,v11.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	aesimc		v0.16b,v0.16b

	sha256su0	v27.4s,v28.4s
	aesd		v0.16b,v12.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v5.4s
	aesd		v0.16b,v13.16b
	sha256su1	v27.4s,v29.4s,v26.4s

	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	aesimc		v0.16b,v0.16b
	sha256su0	v28.4s,v29.4s
	aesd		v0.16b,v14.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v6.4s
	aesd		v0.16b,v15.16b
	sha256su1	v28.4s,v26.4s,v27.4s
	aesimc		v0.16b,v0.16b

	sha256su0	v29.4s,v26.4s
	aesd		v0.16b,v16.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v7.4s
	aesd		v0.16b,v17.16b
	sha256su1	v29.4s,v27.4s,v28.4s
	eor		v3.16b,v0.16b,v18.16b	/* res 0 */
	eor		v3.16b,v3.16b,v31.16b	/* xor w/ ivec (modeop) */

	sub		x13,x13,1		/* dec counter */
	/* save aes res, bump aes_out_ptr */
	st1		{v3.16b},[x1],16
	cbz		x13,.Lfrmquad2

/* aes xform 2 */

	/* read first aes block, bump aes_ptr_in */
	ld1		{v0.16b},[x0],16
	ld1		{v4.16b},[x8],16	/* key4 */
	ld1		{v5.16b},[x8],16	/* key5 */
	ld1		{v6.16b},[x8],16	/* key6 */
	ld1		{v7.16b},[x8],16	/* key7 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	aesd		v0.16b,v8.16b
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	aesimc		v0.16b,v0.16b
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */

	aesd		v0.16b,v9.16b
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	aesimc		v0.16b,v0.16b
	sha256h		q22, q23, v4.4s
	aesd		v0.16b,v10.16b
	sha256h2	q23, q21, v4.4s
	aesimc		v0.16b,v0.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	aesd		v0.16b,v11.16b

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	aesimc		v0.16b,v0.16b
	sha256h		q22, q23, v5.4s
	aesd		v0.16b,v12.16b
	sha256h2	q23, q21, v5.4s
	aesimc		v0.16b,v0.16b
	sha256su1	v27.4s,v29.4s,v26.4s
	aesd		v0.16b,v13.16b

	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su0	v28.4s,v29.4s
	aesimc		v0.16b,v0.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	aesd		v0.16b,v14.16b
	sha256h		q22, q23, v6.4s
	aesimc		v0.16b,v0.16b
	sha256h2	q23, q21, v6.4s
	aesd		v0.16b,v15.16b
	sha256su1	v28.4s,v26.4s,v27.4s
	aesimc		v0.16b,v0.16b

	aesd		v0.16b,v16.16b
	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	aesimc		v0.16b,v0.16b
	sha256h		q22, q23, v7.4s
	aesd		v0.16b,v17.16b
	sha256h2	q23, q21, v7.4s
	eor		v3.16b,v0.16b,v18.16b	/* res 0 */
	sha256su1	v29.4s,v27.4s,v28.4s
	eor		v3.16b,v3.16b,v30.16b	/* xor w/ ivec (modeop) */
	/* save aes res, bump aes_out_ptr */
	st1		{v3.16b},[x1],16
	b		.Lfrmquad3
/*
 * the final block with no aes component, i.e from here there were zero blocks
 */

.Lzero_aes_blocks_left:
	/* base address for sha round consts */
	adr		x8,.Lrcon
	ld1		{v4.16b},[x8],16	/* key0 */
	ld1		{v5.16b},[x8],16	/* key1 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x8],16	/* key2 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x8],16	/* key3 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 1 */
.Lfrmquad1:
	ld1		{v4.16b},[x8],16	/* key4 */
	ld1		{v5.16b},[x8],16	/* key5 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 2 */
.Lfrmquad2:
	ld1		{v4.16b},[x8],16	/* key4 */
	ld1		{v5.16b},[x8],16	/* key5 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 3 */
.Lfrmquad3:
	ld1		{v4.16b},[x8],16	/* key4 */
	ld1		{v5.16b},[x8],16	/* key5 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	eor		v26.16b,v26.16b,v26.16b	/* zero reg */
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	eor		v27.16b,v27.16b,v27.16b	/* zero reg */
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	eor		v28.16b,v28.16b,v28.16b	/* zero reg */
	sha256h2	q23, q21, v7.4s

	add		v26.4s,v24.4s,v22.4s	/* ABCD += working copy */
	eor		v29.16b,v29.16b,v29.16b	/* zero reg */
	add		v27.4s,v25.4s,v23.4s	/* EFGH += working copy */

	/*
	 * Calculate final HMAC
	 */
	/* base address for sha round consts */
	adr		x8,.Lrcon
	/* load o_key_pad partial hash */
	ld1		{v24.16b},[x7],16
	ld1		{v25.16b},[x7]

	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */

	/* Set padding 1 to the first reg */
	mov		w11, #0x80		/* that's the 1 of the pad */
	mov		v28.b[3], w11
	/* size of o_key_pad + inner hash */
	mov		x11, #64+32
	lsl		x11, x11, 3
	/* move length to the end of the block */
	mov		v29.s[3], w11
	lsr		x11, x11, 32
	mov		v29.s[2], w11		/* and the higher part */

	ld1		{v4.16b},[x8],16	/* key0 */
	ld1		{v5.16b},[x8],16	/* key1 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x8],16	/* key2 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x8],16	/* key3 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s


	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s


	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s


	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	ld1		{v4.16b},[x8],16	/* key8 */
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	ld1		{v5.16b},[x8],16	/* key9 */
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key8+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x8],16	/* key10 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key9+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s


	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x8],16	/* key11 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key10+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	ld1		{v4.16b},[x8],16	/* key12 */
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key11+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s


	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	ld1		{v5.16b},[x8],16	/* key13 */
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key12+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x8],16	/* key14 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key13+w1 */
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x8],16	/* key15 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key14+w2 */
	mov		x9,sp
	add		sp,sp,8*16
	ldp		q8,q9,[x9],32
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	sha256h		q22, q23, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key15+w3 */
	ldp		q10,q11,[x9],32
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */

	sha256h		q22, q23, v7.4s
	ldp		q12,q13,[x9],32
	sha256h2	q23, q21, v7.4s

	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	ldp		q14,q15,[x9],32
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */

	rev32		v24.16b, v24.16b
	ldp		x19,x20,[x9]
	rev32		v25.16b, v25.16b
	st1		{v24.4s},[x4],16
	add		sp,sp,2*8
	mov		x0, xzr
	st1		{v25.4s},[x4]

	ret

/*
 * These are the short cases (less efficient), here used for 1-11 aes blocks.
 * x10 = aes_blocks
 */
.Lshort_cases:
	ldp		q8,q9,[x9],32
	adr		x8,.Lrcon			/* rcon */
	ldp		q10,q11,[x9],32
	lsl		x11,x10,4			/* len=aes_blocks*16 */

	ldp		q12,q13,[x9],32
	ldp		q14,q15,[x9],32
	ld1		{v30.16b},[x6]			/* get ivec */
	ldp		q16,q17,[x9],32
	ld1		{v18.16b},[x9]

	/* get outstanding bytes of the digest */
	sub		x20,x5,x2
 
	/* indicate AES blocks to write back */
	mov		x19,xzr

	mov		x2,x0

	/*
	 * Digest source has to be at least of cipher source length
	 * therefore it is safe to use x10 to indicate whether we can
	 * overtake cipher processing by 4 AES block here.
	 */
	cmp		x10,4			/* check if 4 or more */
	/* if less, bail to last block */
	blt		.Llast_sha_block

	sub		x5,x5,64

	mov		x9,x8			/* top of rcon */

/* quad 0 */
	ld1		{v26.16b},[x3],16
	ld1		{v4.16b},[x9],16	/* key0 */
	ld1		{v27.16b},[x3],16
	rev32		v26.16b,v26.16b
	ld1		{v28.16b},[x3],16
	rev32		v27.16b,v27.16b
	ld1		{v29.16b},[x3],16
	rev32		v28.16b,v28.16b
	ld1		{v5.16b},[x9],16	/* key1 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	rev32		v29.16b,v29.16b

	sha256su0	v26.4s,v27.4s
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x9],16	/* key2 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x9],16	/* key3 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	ld1		{v4.16b},[x9],16	/* key4 */
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	ld1		{v5.16b},[x9],16	/* key5 */
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 1 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x9],16	/* key6 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x9],16	/* key7 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	ld1		{v4.16b},[x9],16	/* key4 */
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	ld1		{v5.16b},[x9],16	/* key5 */
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 2 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x9],16	/* key6 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x9],16	/* key7 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	ld1		{v4.16b},[x9],16	/* key4 */
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	ld1		{v5.16b},[x9],16	/* key5 */
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 3 */
	mov		v21.16b, v22.16b	/* copy abcd */

	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x9],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x9],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s

	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */

	/* there were at least 4 AES blocks to process */
	b		.Lshort_loop_no_store

.Lshort_loop:
	cmp		x10,4			/* check if 4 or more */
	/* if less, bail to last block */
	blt		.Llast_sha_block
	stp		q0,q1,[x1],32
	stp		q2,q3,[x1],32

	sub		x19,x19,4

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
	eor		v0.16b,v0.16b,v30.16b	/* xor w/prev value */

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
	eor		v1.16b,v1.16b,v31.16b	/* xor w/prev value */

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
	eor		v2.16b,v2.16b,v30.16b	/* xor w/prev value */

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
	eor		v3.16b,v3.16b,v31.16b		/* xor w/prev value */

	add		x19,x19,4

	sub		x10,x10,4		/* 4 less */
	cmp		x5,64
	b.lt		.Lshort_loop		/* keep looping */

	sub		x5,x5,64

	mov		x9,x8			/* top of rcon */

/* quad 0 */
	ld1		{v26.16b},[x3],16
	ld1		{v4.16b},[x9],16	/* key0 */
	ld1		{v27.16b},[x3],16
	rev32		v26.16b,v26.16b
	ld1		{v28.16b},[x3],16
	rev32		v27.16b,v27.16b
	ld1		{v29.16b},[x3],16
	rev32		v28.16b,v28.16b
	ld1		{v5.16b},[x9],16	/* key1 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	rev32		v29.16b,v29.16b

	sha256su0	v26.4s,v27.4s
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x9],16	/* key2 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x9],16	/* key3 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	ld1		{v4.16b},[x9],16	/* key4 */
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	ld1		{v5.16b},[x9],16	/* key5 */
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 1 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x9],16	/* key6 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x9],16	/* key7 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	ld1		{v4.16b},[x9],16	/* key4 */
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x9],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 2 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x9],16	/* key6 */
	sha256h2	q23, q21, v4.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x9],16	/* key7 */
	sha256h2	q23, q21, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	ld1		{v4.16b},[x9],16	/* key4 */
	sha256h2	q23, q21, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	ld1		{v5.16b},[x9],16	/* key5 */
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 3 */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	ld1		{v6.16b},[x9],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	ld1		{v7.16b},[x9],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s

	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */

	b		.Lshort_loop		/* keep looping */
/*
 * This is arranged so that we can join the common unwind code that does
 * the last sha block and the final 0-3 aes blocks.
 */
.Llast_sha_block:
	eor		v26.16b,v26.16b,v26.16b		/* zero the rest */
	eor		v27.16b,v27.16b,v27.16b		/* zero the rest */
	eor		v28.16b,v28.16b,v28.16b		/* zero the rest */
	eor		v29.16b,v29.16b,v29.16b		/* zero the rest */

	mov		x13,x10			/* copy aes blocks for common */
	b		.Ljoin_common		/* join common code */

	.size	asm_sha256_hmac_aes128cbc_dec, .-asm_sha256_hmac_aes128cbc_dec
