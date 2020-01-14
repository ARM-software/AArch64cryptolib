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
 * Combined Enc/Auth Primitive = aes128cbc/sha256_hmac
 *
 * Operations:
 *
 * out = encrypt-AES128CBC(in)
 * return_hash_ptr = SHA256(o_key_pad | SHA256(i_key_pad | out))
 *
 * Prototype:
 * void asm_aes128cbc_sha256_hmac(uint8_t *csrc, uint8_t *cdst, uint64_t clen,
 *			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
 *			armv8_cipher_digest_t *arg)
 *
 * Registers used:
 *
 * asm_aes128cbc_sha256_hmac(
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
 * Constraints:
 *
 * The variable "clen" must be a multiple of 16, otherwise results
 * are not defined. For AES partial blocks the user is required
 * to pad the input to modulus 16 = 0.
 * The variable "dlen" must be a multiple of 8 and greater or equal
 * to "clen". This constrain is strictly related to the needs of the IPSec
 * ESP packet. Encrypted payload is hashed along with the 8 byte ESP header,
 * forming ICV. Speed gain is achieved by doing both things at the same time,
 * hence lengths are required to match at least at the cipher level.
 *
 * Short lengths are not optimized at < 12 AES blocks
 */

	.file "aes128cbc_sha256_hmac.S"
	.text
	.cpu generic+fp+simd+crypto+crc
	.global asm_aes128cbc_sha256_hmac
	.type	asm_aes128cbc_sha256_hmac,%function

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

asm_aes128cbc_sha256_hmac:
/* protect registers */
	sub		sp,sp,8*16
	mov		x9,sp			/* copy for address mode */
	stp		q8,q9,[x9],32
/* fetch args */
	ldr		x7, [x6, #HMAC_IKEYPAD]
	/* init ABCD, EFGH. */
	ldp		q24,q25,[x7]
	/* save pointer to o_key_pad partial hash */
	ldr		x7, [x6, #HMAC_OKEYPAD]

	stp		q10,q11,[x9],32

	/* address of sha init state consts */
	adr		x12,.Linit_sha_state
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
	prfm		PLDL1KEEP,[x0,0]	/* pref next aes_ptr_in */
	cmp		x10,12			/* no main loop if <12 */
	b.lt		.Lshort_cases		/* branch if < 12 */

/* proceed */
	ld1		{v3.16b},[x6]		/* get 1st ivec */
	/* read first aes block, bump aes_ptr_in */
	ld1		{v0.16b},[x0],16
	mov		x11,x2			/* len -> x11 needed at end */
	lsr		x12,x11,6		/* total_blocks */
/*
 * now we can do the loop prolog, 1st aes sequence of 4 blocks
 */
	ld1		{v8.16b},[x9],16	/* rk[0] */
	ld1		{v9.16b},[x9],16	/* rk[1] */
	eor		v0.16b,v0.16b,v3.16b	/* xor w/ ivec (modeop) */
	ld1		{v10.16b},[x9],16	/* rk[2] */

/* aes xform 0 */
	aese		v0.16b,v8.16b
	prfm		PLDL1KEEP,[x0,64]	/* pref next aes_ptr_in */
	aesmc		v0.16b,v0.16b
	ld1		{v11.16b},[x9],16	/* rk[3] */
	aese		v0.16b,v9.16b
	prfm		PLDL1KEEP,[x1,64]	/* pref next aes_ptr_out  */
	/* base address for sha round consts */
	adr		x8,.Lrcon
	aesmc		v0.16b,v0.16b
	ld1		{v12.16b},[x9],16	/* rk[4] */
	aese		v0.16b,v10.16b
	/* read next aes block, update aes_ptr_in */
	ld1		{v1.16b},[x0],16
	aesmc		v0.16b,v0.16b
	ld1		{v13.16b},[x9],16	/* rk[5] */
	aese		v0.16b,v11.16b
	aesmc		v0.16b,v0.16b
	ld1		{v14.16b},[x9],16	/* rk[6] */
	aese		v0.16b,v12.16b
	aesmc		v0.16b,v0.16b
	ld1		{v15.16b},[x9],16	/* rk[7] */
	aese		v0.16b,v13.16b
	aesmc		v0.16b,v0.16b
	ld1		{v16.16b},[x9],16	/* rk[8] */
	aese		v0.16b,v14.16b
	aesmc		v0.16b,v0.16b
	ld1		{v17.16b},[x9],16	/* rk[9] */
	aese		v0.16b,v15.16b
	aesmc		v0.16b,v0.16b
	ld1		{v18.16b},[x9],16	/* rk[10] */
	aese		v0.16b,v16.16b
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v17.16b
	eor		v0.16b,v0.16b,v18.16b	/* res 0 */

	eor		v1.16b,v1.16b,v0.16b	/* xor w/ ivec (modeop) */

/* aes xform 1 */
	aese		v1.16b,v8.16b
	/* read next aes block, update aes_ptr_in */
	ld1		{v2.16b},[x0],16
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v9.16b
	prfm		PLDL1KEEP,[x8,0*64]	/* rcon */
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v10.16b
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v11.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v0.16b},[x1],16
	ld1		{v26.16b},[x3],16
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v12.16b
	prfm		PLDL1KEEP,[x8,2*64]	/* rcon */
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v13.16b
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v14.16b
	prfm		PLDL1KEEP,[x8,4*64]	/* rcon */
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v15.16b
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v16.16b
	prfm		PLDL1KEEP,[x8,6*64]	/* rcon */
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v17.16b
	prfm		PLDL1KEEP,[x8,8*64]	/* rcon */
	eor		v1.16b,v1.16b,v18.16b	/* res 1 */

	eor		v2.16b,v2.16b,v1.16b	/* xor w/ ivec (modeop) */

/* aes xform 2 */
	aese		v2.16b,v8.16b
	/* read next aes block, update aes_ptr_in */
	ld1		{v3.16b},[x0],16
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v9.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v10.16b
	prfm		PLDL1KEEP,[x8,10*64]	/* rcon */
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v11.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v1.16b},[x1],16
	ld1		{v27.16b},[x3],16
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v12.16b
	prfm		PLDL1KEEP,[x8,12*64]	/* rcon */
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v13.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v14.16b
	prfm		PLDL1KEEP,[x8,14*64]	/* rcon */
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v15.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v16.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v17.16b
	eor		v2.16b,v2.16b,v18.16b	/* res 2 */

	eor		v3.16b,v3.16b,v2.16b	/* xor w/ivec (modeop) */

/* aes xform 3 */
	aese		v3.16b,v8.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v9.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v10.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v11.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v2.16b},[x1],16
	ld1		{v28.16b},[x3],16
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v12.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v13.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v14.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v15.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v16.16b
	sub		x15,x12,1	/* main_blocks = total_blocks - 1 */
	and		x13,x10,3	/* aes_blocks_left */
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v17.16b
	eor		v3.16b,v3.16b,v18.16b	/* res 3 */

/*
 * Note, aes_blocks_left := number after the main (sha)
 * block is done. Can be 0
 */
	/* save aes res, bump aes_out_ptr */
	st1		{v3.16b},[x1],16
	ld1		{v29.16b},[x3],16

	/* get outstanding bytes of the digest */
	sub		x12,x5,x2
	/* substract loaded bytes */
	sub		x5,x5,64

/*
 * main combined loop CBC
 */
.Lmain_loop:
	/* base address for sha round consts */
	adr		x8,.Lrcon
/*
 * because both mov, rev32 and eor have a busy cycle,
 * this takes longer than it looks. Thats OK since there are 6 cycles
 * before we can use the load anyway; so this goes as fast as it can without
 * SW pipelining (too complicated given the code size)
 */
	rev32		v26.16b,v26.16b
	/* next aes block, update aes_ptr_in */
	ld1		{v0.16b},[x0],16
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	prfm		PLDL1KEEP,[x9,64]	/* pref next lead_ptr */
	rev32		v27.16b,v27.16b
	/* pref next aes_ptr_out, streaming  */
	prfm		PLDL1KEEP,[x1,64]
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	ld1		{v4.16b},[x8],16	/* key0 */
	eor		v0.16b,v0.16b,v3.16b	/* xor w/ prev value */
	ld1		{v5.16b},[x8],16	/* key1 */
/*
 * aes xform 0, sha quad 0
 */
	aese		v0.16b,v8.16b
	ld1		{v6.16b},[x8],16	/* key2 */
	rev32		v28.16b,v28.16b
	ld1		{v7.16b},[x8],16	/* key3  */
	aesmc		v0.16b,v0.16b
	/* read next aes block, update aes_ptr_in */
	ld1		{v1.16b},[x0],16
	aese		v0.16b,v9.16b
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	aesmc		v0.16b,v0.16b
	sha256su0	v26.4s,v27.4s
	aese		v0.16b,v10.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v11.16b
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	/* no place to get rid of this stall */
	rev32		v29.16b,v29.16b
	aesmc		v0.16b,v0.16b
	sha256h2	q23, q21, v4.4s
	aese		v0.16b,v12.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	ld1		{v4.16b},[x8],16	/* key4 */
	aesmc		v0.16b,v0.16b
	sha256su0	v27.4s,v28.4s
	aese		v0.16b,v13.16b
	sha256h		q22, q23, v5.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	aesmc		v0.16b,v0.16b
	sha256h2	q23, q21, v5.4s
	aese		v0.16b,v14.16b
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v27.4s,v29.4s,v26.4s
	aesmc		v0.16b,v0.16b
	sha256su0	v28.4s,v29.4s
	aese		v0.16b,v15.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesmc		v0.16b,v0.16b
	sha256h2	q23, q21, v6.4s
	aese		v0.16b,v16.16b
	sha256su1	v28.4s,v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256su0	v29.4s,v26.4s
	aesmc		v0.16b,v0.16b
	sha256h		q22, q23, v7.4s
	aese		v0.16b,v17.16b
	sha256h2	q23, q21, v7.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s
	eor		v0.16b,v0.16b,v18.16b	/* final res 0 */
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */

/* aes xform 1, sha quad 1 */
	sha256su0	v26.4s,v27.4s
	eor		v1.16b,v1.16b,v0.16b	/* mode op 1 xor w/prev value */
	ld1		{v7.16b},[x8],16	/* key7  */
	mov		v21.16b, v22.16b	/* copy abcd */
	/* save aes res, bump aes_out_ptr */
	st1		{v0.16b},[x1],16
	aese		v1.16b,v8.16b
	sha256h		q22, q23, v4.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256h2	q23, q21, v4.4s
	aesmc		v1.16b,v1.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	aese		v1.16b,v9.16b
	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesmc		v1.16b,v1.16b
	sha256h2	q23, q21, v5.4s
	aese		v1.16b,v10.16b
	/* read next aes block, update aes_ptr_in */
	ld1		{v2.16b},[x0],16
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v27.4s,v29.4s,v26.4s
	aesmc		v1.16b,v1.16b
	ld1		{v4.16b},[x8],16	/* key4 */
	aese		v1.16b,v11.16b
	ld1		{v5.16b},[x8],16	/* key5 */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256su0	v28.4s,v29.4s
	aesmc		v1.16b,v1.16b
	sha256h		q22, q23, v6.4s
	aese		v1.16b,v12.16b
	sha256h2	q23, q21, v6.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	sha256su1	v28.4s,v26.4s,v27.4s
	aesmc		v1.16b,v1.16b
	sha256su0	v29.4s,v26.4s
	aese		v1.16b,v13.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesmc		v1.16b,v1.16b
	sha256h2	q23, q21, v7.4s
	aese		v1.16b,v14.16b
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v15.16b
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v16.16b
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v17.16b
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	eor		v1.16b,v1.16b,v18.16b	/* res xf 1 */


/* mode op 2 */
	eor		v2.16b,v2.16b,v1.16b	/* mode of 2 xor w/prev value */

/* aes xform 2, sha quad 2 */

	sha256su0	v26.4s,v27.4s
	aese		v2.16b,v8.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v1.16b},[x1],16
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	aesmc		v2.16b,v2.16b
	sha256h2	q23, q21, v4.4s
	aese		v2.16b,v9.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	aesmc		v2.16b,v2.16b
	sha256su0	v27.4s,v28.4s
	aese		v2.16b,v10.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesmc		v2.16b,v2.16b
	sha256h2	q23, q21, v5.4s
	aese		v2.16b,v11.16b
	sha256su1	v27.4s,v29.4s,v26.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	sha256su0	v28.4s,v29.4s
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v12.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesmc		v2.16b,v2.16b
	sha256h2	q23, q21, v6.4s
	aese		v2.16b,v13.16b
	sha256su1	v28.4s,v26.4s,v27.4s
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su0	v29.4s,v26.4s
	aesmc		v2.16b,v2.16b
	/* read next aes block, update aes_ptr_in */
	ld1		{v3.16b},[x0],16
	aese		v2.16b,v14.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesmc		v2.16b,v2.16b
	sha256h2	q23, q21, v7.4s
	aese		v2.16b,v15.16b
	sha256su1	v29.4s,v27.4s,v28.4s
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	ld1		{v6.16b},[x8],16	/* key6 */
	aesmc		v2.16b,v2.16b
	ld1		{v7.16b},[x8],16	/* key7 */
	aese		v2.16b,v16.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v17.16b
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	eor		v2.16b,v2.16b,v18.16b	/* res 2 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */

/* mode op 3 */
	eor		v3.16b,v3.16b,v2.16b	/* xor w/prev value */

/* aes xform 3, sha quad 3 (hash only) */
	aese		v3.16b,v8.16b
	aesmc		v3.16b,v3.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v2.16b},[x1],16
	aese		v3.16b,v9.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	aesmc		v3.16b,v3.16b
	sha256h2	q23, q21, v4.4s
	aese		v3.16b,v10.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v11.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesmc		v3.16b,v3.16b
	sha256h2	q23, q21, v5.4s
	aese		v3.16b,v12.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v13.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesmc		v3.16b,v3.16b
	sha256h2	q23, q21, v6.4s
	aese		v3.16b,v14.16b
	sub		x15,x15,1		/* dec block count */
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v15.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesmc		v3.16b,v3.16b
	sha256h2	q23, q21, v7.4s
	aese		v3.16b,v16.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v17.16b
	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	eor		v3.16b,v3.16b,v18.16b	/* aes res 3 */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */
	/* save aes res, bump aes_out_ptr */
	st1		{v3.16b},[x1],16

	ldp		q26,q27,[x3],32
	ldp		q28,q29,[x3],32
	sub		x5,x5,64

	cbnz		x15,.Lmain_loop		/* loop if more to do */

	mov		w15,0x80		/* that's the 1 of the pad */
/*
 * epilog, process remaining aes blocks and b-2 sha block
 * do this inline (no loop) to overlap with the sha part
 * note there are 0-3 aes blocks left.
 */
	rev32		v26.16b,v26.16b		/* fix endian w0 */
	rev32		v27.16b,v27.16b		/* fix endian w1 */
	rev32		v28.16b,v28.16b		/* fix endian w2 */
	rev32		v29.16b,v29.16b		/* fix endian w3 */
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	cbz		x13, .Lbm2fromQ0	/* skip if none left */
	subs		x14,x13,1	/* local copy of aes_blocks_left */
/*
 * mode op 0
 * read next aes block, update aes_ptr_in
 */
	ld1		{v0.16b},[x0],16
	/* base address for sha round consts */
	adr		x8,.Lrcon
	ld1		{v4.16b},[x8],16	/* key0 */
	ld1		{v5.16b},[x8],16	/* key1 */
	ld1		{v6.16b},[x8],16	/* key2 */
	ld1		{v7.16b},[x8],16	/* key3  */
	eor		v0.16b,v0.16b,v3.16b	/* xor w/ prev value */

/* aes xform 0, sha quad 0 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	aese		v0.16b,v8.16b
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	aesmc		v0.16b,v0.16b
	sha256su0	v26.4s,v27.4s
	aese		v0.16b,v9.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	aesmc		v0.16b,v0.16b
	sha256h2	q23, q21, v4.4s
	aese		v0.16b,v10.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su0	v27.4s,v28.4s
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v11.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesmc		v0.16b,v0.16b
	sha256h2	q23, q21, v5.4s
	aese		v0.16b,v12.16b
	sha256su1	v27.4s,v29.4s,v26.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su0	v28.4s,v29.4s
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v13.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesmc		v0.16b,v0.16b
	sha256h2	q23, q21, v6.4s
	aese		v0.16b,v14.16b
	sha256su1	v28.4s,v26.4s,v27.4s
	sha256su0	v29.4s,v26.4s
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v15.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v16.16b
	sha256h2	q23, q21, v7.4s
	sha256su1	v29.4s,v27.4s,v28.4s
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v17.16b
	eor		v0.16b,v0.16b,v18.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v0.16b},[x1],16
	/* if aes_blocks_left_count == 0 */
	beq		.Lbm2fromQ1
/*
 * mode op 1
 * read next aes block, update aes_ptr_in
 */
	ld1		{v1.16b},[x0],16
	ld1		{v4.16b},[x8],16	/* key4 */
	ld1		{v5.16b},[x8],16	/* key5 */
	ld1		{v6.16b},[x8],16	/* key6 */
	ld1		{v7.16b},[x8],16	/* key7 */

	eor		v1.16b,v1.16b,v0.16b	/* xor w/prev value */

/* aes xform 1, sha quad 1 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	aese		v1.16b,v8.16b
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	aesmc		v1.16b,v1.16b
	sha256su0	v26.4s,v27.4s
	aese		v1.16b,v9.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	aesmc		v1.16b,v1.16b
	sha256h2	q23, q21, v4.4s
	aese		v1.16b,v10.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su0	v27.4s,v28.4s
	aesmc		v1.16b,v1.16b
	subs		x14,x14,1		/* dec counter */
	aese		v1.16b,v11.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesmc		v1.16b,v1.16b
	sha256h2	q23, q21, v5.4s
	aese		v1.16b,v12.16b
	sha256su1	v27.4s,v29.4s,v26.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su0	v28.4s,v29.4s
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v13.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesmc		v1.16b,v1.16b
	sha256h2	q23, q21, v6.4s
	aese		v1.16b,v14.16b
	sha256su1	v28.4s,v26.4s,v27.4s
	sha256su0	v29.4s,v26.4s
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v15.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesmc		v1.16b,v1.16b
	sha256h2	q23, q21, v7.4s
	aese		v1.16b,v16.16b
	sha256su1	v29.4s,v27.4s,v28.4s
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v17.16b
	eor		v1.16b,v1.16b,v18.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v1.16b},[x1],16
	/* if aes_blocks_left_count == 0 */
	beq		.Lbm2fromQ2
/*
 * mode op 2
 * read next aes block, update aes_ptr_in
 */
	ld1		{v2.16b},[x0],16
	ld1		{v4.16b},[x8],16	/* key4 */
	ld1		{v5.16b},[x8],16	/* key5 */
	ld1		{v6.16b},[x8],16	/* key6 */
	ld1		{v7.16b},[x8],16	/* key7 */
	eor		v2.16b,v2.16b,v1.16b	/* xor w/prev value */

/* aes xform 2, sha quad 2 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	aese		v2.16b,v8.16b
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	aesmc		v2.16b,v2.16b
	sha256su0	v26.4s,v27.4s
	aese		v2.16b,v9.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	aesmc		v2.16b,v2.16b
	sha256h2	q23, q21, v4.4s
	aese		v2.16b,v10.16b
	sha256su1	v26.4s,v28.4s,v29.4s
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su0	v27.4s,v28.4s
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v11.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	aesmc		v2.16b,v2.16b
	sha256h2	q23, q21, v5.4s
	aese		v2.16b,v12.16b
	sha256su1	v27.4s,v29.4s,v26.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su0	v28.4s,v29.4s
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v13.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	aesmc		v2.16b,v2.16b
	sha256h2	q23, q21, v6.4s
	aese		v2.16b,v14.16b
	sha256su1	v28.4s,v26.4s,v27.4s
	sha256su0	v29.4s,v26.4s
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v15.16b
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v16.16b
	sha256h2	q23, q21, v7.4s
	sha256su1	v29.4s,v27.4s,v28.4s
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v17.16b
	eor		v2.16b,v2.16b,v18.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v2.16b},[x1],16
	/* join common code at Quad 3 */
	b		.Lbm2fromQ3
/*
 * now there is the b-2 sha block before the final one.  Execution takes over
 * in the appropriate part of this depending on how many aes blocks were left.
 * If there were none, the whole thing is executed.
 */
/* quad 0 */
.Lbm2fromQ0:
	/* base address for sha round consts */
	adr		x8,.Lrcon

	ld1		{v4.16b},[x8],16	/* key0 */
	ld1		{v5.16b},[x8],16	/* key1 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key2 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key3 */
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
.Lbm2fromQ1:
	ld1		{v4.16b},[x8],16	/* key4 */
	ld1		{v5.16b},[x8],16	/* key5 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
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
.Lbm2fromQ2:
	ld1		{v4.16b},[x8],16	/* key4 */
	ld1		{v5.16b},[x8],16	/* key5 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
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
.Lbm2fromQ3:
	ld1		{v4.16b},[x8],16	/* key4 */
	ld1		{v5.16b},[x8],16	/* key5 */
	ld1		{v6.16b},[x8],16	/* key6 */
	ld1		{v7.16b},[x8],16	/* key7 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	eor		v26.16b,v26.16b,v26.16b	/* zero reg */
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	eor		v27.16b,v27.16b,v27.16b	/* zero reg */
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	eor		v28.16b,v28.16b,v28.16b	/* zero reg */
	sha256h2	q23, q21, v7.4s

	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */

/* Process remaining 0-3 AES blocks here */
	eor		v29.16b,v29.16b,v29.16b		/* zero sha src 3 */

	cbz		x13,.Lpost_long_Q0

	/* 1st remaining AES block */
	ld1		{v26.16b},[x3],16
	sub		x5,x5,16
	rev32		v26.16b,v26.16b
	subs		x14,x13,1
	b.eq		.Lpost_long_Q1

	/* 2nd remaining AES block */
	ld1		{v27.16b},[x3],16
	sub		x5,x5,16
	rev32		v27.16b,v27.16b
	subs		x14,x14,1
	b.eq		.Lpost_long_Q2

	/* 3rd remaining AES block */
	ld1		{v28.16b},[x3],16
	sub		x5,x5,16
	rev32		v28.16b,v28.16b
	/* Allow for filling this sha256 block with the remaining digest src */
	b		.Lpost_long_Q3
/*
 * Process remaining 8B blocks of the digest
 */
.Lpost_long_Q0:
/* blk 0,1 */
	/* assume final block */
	mov		v26.b[3],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_long_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	/* overwrite previous v26 value (0x80) */
	mov		v26.d[0],x2
	/* assume this was final block */
	mov		v26.b[11],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_long_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	mov		v26.d[1],x2

.Lpost_long_Q1:
/* blk 2,3 */
	/* assume this is final block */
	mov		v27.b[3],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_long_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	/* overwrite previous v27 value (0x80) */
	mov		v27.d[0],x2
	/* assume this was final block */
	mov		v27.b[11],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_long_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	mov		v27.d[1],x2

.Lpost_long_Q2:
/* blk 4,5 */
	/* assume this was final block */
	mov		v28.b[3],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_long_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	/* overwrite previous v28 value (0x80) */
	mov		v28.d[0],x2
	/* assume this was final block */
	mov		v28.b[11],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_long_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	mov		v28.d[1],x2

.Lpost_long_Q3:
/* blk 6,7 */
	/* assume this was final block */
	mov		v29.b[3],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_long_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	/* overwrite previous v29 value (0x80) */
	mov		v29.d[0],x2
	/* assume this was final block */
	mov		v29.b[11],w15
	/*
	 * Outstanding 8B blocks left.
	 * Since there has to be another sha block with padding,
	 * we need to calculate hash without padding here.
	 */
	cbz		x5,1f
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	rev32		x2,x2
	/*
	 * Don't decrease x5 here.
	 * Use it to indicate necessity of constructing "1" padding at the end.
	 */
	mov		v29.d[1],x2

/*
 * That is enough of blocks, we allow up to 64 bytes in total.
 * Now we have the sha256 to do for these 4 16B blocks
 */
1:
	/* base address for sha round consts */
	adr		x8,.Lrcon

	ld1		{v4.16b},[x8],16	/* key0 */
	ld1		{v5.16b},[x8],16	/* key1 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key2 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key3 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	mov		v21.16b, v22.16b	/* copy abcd */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */

	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s

	eor		v26.16b,v26.16b,v26.16b		/* zero sha src 0 */
	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	eor		v27.16b,v27.16b,v27.16b		/* zero sha src 1 */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */
	eor		v28.16b,v28.16b,v28.16b		/* zero sha src 2 */
	eor		v29.16b,v29.16b,v29.16b		/* zero sha src 3 */

	/* this was final block */
	cbz		x5,.Lpost_long_loop
	subs		x5,x5,8
	/* loop if hash is not finished */
	b.ne		.Lpost_long_Q0
	/* set "1" of the padding if this was a final block */
	mov		v26.b[3],w15

.Lpost_long_loop:
	/* Add outstanding bytes of digest source */
	add	x11,x11,x12
	/* Add one SHA-256 block since hash is calculated including i_key_pad */
	add	x11,x11, #64
	lsr	x12,x11,32			/* len_hi */
	and	x13,x11,0xffffffff		/* len_lo */
	lsl	x12,x12,3			/* len_hi in bits */
	lsl	x13,x13,3			/* len_lo in bits */

	mov	v29.s[3],w13			/* len_lo */
	mov	v29.s[2],w12			/* len_hi */

/*
 * do last sha of pad block
 */
	/* base address for sha round consts */
	adr		x8,.Lrcon

/* quad 0 */
	ld1		{v4.16b},[x8],16	/* key0 */
	ld1		{v5.16b},[x8],16	/* key1 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key2 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key3 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 1 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 2 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 3 */
	ldp		q6,q7,[x8],32		/* key6,key7 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	mov		v21.16b, v22.16b	/* copy abcd */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */

	sha256h		q22, q23, v4.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s

	add		v26.4s,v24.4s,v22.4s	/* ABCD += working copy */
	add		v27.4s,v25.4s,v23.4s	/* EFGH += working copy */

	/* Calculate final HMAC */
	eor		v28.16b, v28.16b, v28.16b
	eor		v29.16b, v29.16b, v29.16b
	/* base address for sha round consts */
	adr		x8,.Lrcon
	/* load o_key_pad partial hash */
	ldp		q24,q25,[x7]

	/* Set padding 1 to the first reg */
	mov		w11, #0x80		/* that's the 1 of the pad */
	mov		v28.b[3], w11
	/* size of o_key_pad + inner hash */
	mov		x11, #64+32
	lsl		x11, x11, 3
	/* move length to the end of the block */
	mov		v29.s[3], w11
	ldp		q4,q5,[x8],32		/* key0,key1 */
	lsr		x11, x11, 32
	mov		v29.s[2], w11		/* and the higher part */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key2 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key3 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	ldp		q6,q7,[x8],32		/* key6,key7 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	mov		v21.16b, v22.16b	/* copy abcd */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */

	sha256h		q22, q23, v4.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s

	mov		x9,sp
	add		sp,sp,8*16
	ldp		q8,q9,[x9],32
	ldp		q10,q11,[x9],32

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s

	ldp		q12,q13,[x9],32
	ldp		q14,q15,[x9]

	mov		x0, xzr

	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */

	rev32		v24.16b, v24.16b
	rev32		v25.16b, v25.16b

	stp		q24,q25,[x4]		/* save them both */

	ret

/*
 * These are the short cases (less efficient), here used for 1-11 aes blocks.
 * x10 = aes_blocks
 */
.Lshort_cases:
	ld1		{v3.16b},[x6]			/* get ivec */
	ldp		q8,q9,[x9],32			/* rk[0-1] */
	eor		v26.16b,v26.16b,v26.16b		/* zero sha src 0 */
	ldp		q10,q11,[x9],32			/* rk[2-3] */
	eor		v27.16b,v27.16b,v27.16b		/* zero sha src 1 */
	ldp		q12,q13,[x9],32			/* rk[3-4] */
	eor		v28.16b,v28.16b,v28.16b		/* zero sha src 2 */
	ldp		q14,q15,[x9],32			/* rk[5-6] */
	eor		v29.16b,v29.16b,v29.16b		/* zero sha src 3 */
	ldp		q16,q17,[x9],32			/* rk[7-8] */
	mov		w15,0x80			/* sha padding word */
	lsl		x11,x10,4		/* len = aes_blocks*16 */
	ld1		{v18.16b},[x9]			/* rk[9] */

	/* get outstanding bytes of the digest */
	sub		x12,x5,x2
/*
 * the idea in the short loop (at least 1) is to break out with the padding
 * already in place excepting the final word.
 */
.Lshort_loop:
	adr		x8,.Lrcon			/* rcon */
	/* read next aes block, update aes_ptr_in */
	ld1		{v0.16b},[x0],16
	eor		v0.16b,v0.16b,v3.16b		/* xor w/prev value */

/* aes xform 0 */
	aese		v0.16b,v8.16b
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v9.16b
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v10.16b
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v11.16b
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v12.16b
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v13.16b
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v14.16b
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v15.16b
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v16.16b
	aesmc		v0.16b,v0.16b
	aese		v0.16b,v17.16b
	eor		v0.16b,v0.16b,v18.16b

	/* save aes res, bump aes_out_ptr */
	st1		{v0.16b},[x1],16
	/* load next 16 bytes for SHA-256 */
	ld1		{v26.16b},[x3],16
	/* dec number of bytes of the hash input */
	sub		x5,x5,16
	rev32		v26.16b,v26.16b	/* load res to sha 0, endian swap */
	sub		x10,x10,1		/* dec num_blocks */
	cbz		x10,.Lpost_short_Q1	/* break if no more */
	/* read next aes block, update aes_ptr_in */
	ld1		{v1.16b},[x0],16
	eor		v1.16b,v1.16b,v0.16b	/* xor w/prev value */

/* aes xform 1 */
	aese		v1.16b,v8.16b
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v9.16b
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v10.16b
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v11.16b
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v12.16b
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v13.16b
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v14.16b
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v15.16b
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v16.16b
	aesmc		v1.16b,v1.16b
	aese		v1.16b,v17.16b
	eor		v1.16b,v1.16b,v18.16b

	/* save aes res, bump aes_out_ptr */
	st1		{v1.16b},[x1],16
	/* load next 16 bytes for SHA-256 */
	ld1		{v27.16b},[x3],16
	/* dec number of bytes of the hash input */
	sub		x5,x5,16
	rev32		v27.16b,v27.16b	/* load res to sha 0, endian swap */
	sub		x10,x10,1		/* dec num_blocks */
	cbz		x10,.Lpost_short_Q2	/* break if no more */
	/* read next aes block, update aes_ptr_in */
	ld1		{v2.16b},[x0],16
	eor		v2.16b,v2.16b,v1.16b	/* xor w/prev value */

/* aes xform 2 */
	aese		v2.16b,v8.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v9.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v10.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v11.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v12.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v13.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v14.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v15.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v16.16b
	aesmc		v2.16b,v2.16b
	aese		v2.16b,v17.16b
	eor		v2.16b,v2.16b,v18.16b

	/* save aes res, bump aes_out_ptr */
	st1		{v2.16b},[x1],16
	/* load next 16 bytes for SHA-256 */
	ld1		{v28.16b},[x3],16
	/* dec number of bytes of the hash input */
	sub		x5,x5,16
	rev32		v28.16b,v28.16b	/* load res to sha 0, endian swap */
	sub		x10,x10,1		/* dec num_blocks */
	cbz		x10,.Lpost_short_Q3	/* break if no more */
	/* read next aes block, update aes_ptr_in */
	ld1		{v3.16b},[x0],16
	eor		v3.16b,v3.16b,v2.16b	/* xor w/ prev value */

/* aes xform 3 */
	aese		v3.16b,v8.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v9.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v10.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v11.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v12.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v13.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v14.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v15.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v16.16b
	aesmc		v3.16b,v3.16b
	aese		v3.16b,v17.16b
	eor		v3.16b,v3.16b,v18.16b
	/* save aes res, bump aes_out_ptr */
	st1		{v3.16b},[x1],16
	/* load next 16 bytes for SHA-256 */
	ld1		{v29.16b},[x3],16
	/* dec number of bytes of the hash input */
	sub		x5,x5,16
	/* load res to sha 0, endian swap */
	rev32		v29.16b,v29.16b
/*
 * now we have the sha256 to do for these 4 aes blocks
 */

/* quad 0 */
	ld1		{v4.16b},[x8],16	/* key0 */
	ld1		{v5.16b},[x8],16	/* key1 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key2 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key3 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 1 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 2 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 3 */
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	mov		v21.16b, v22.16b	/* copy abcd */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */

	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s

	eor		v26.16b,v26.16b,v26.16b		/* zero sha src 0 */
	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	eor		v27.16b,v27.16b,v27.16b		/* zero sha src 1 */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */
	eor		v28.16b,v28.16b,v28.16b		/* zero sha src 2 */
	sub		x10,x10,1		/* dec num_blocks */
	eor		v29.16b,v29.16b,v29.16b		/* zero sha src 3 */

	cbnz		x10,.Lshort_loop	/* keep looping if more */

.Lpost_short_Q0:
	/* assume this was final block */
	mov		v26.b[3],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_short_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	/* overwrite previous v26 value (0x80) */
	mov		v26.d[0],x2
	/* assume this was final block */
	mov		v26.b[11],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_short_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	mov		v26.d[1],x2
.Lpost_short_Q1:
	/* zero out vectors */
	eor		v27.16b,v27.16b,v27.16b
	eor		v28.16b,v28.16b,v28.16b
	eor		v29.16b,v29.16b,v29.16b
	/* assume this is final block */
	mov		v27.b[3],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_short_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	/* overwrite previous v27 value (0x80) */
	mov		v27.d[0],x2
	/* assume this was final block */
	mov		v27.b[11],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_short_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	mov		v27.d[1],x2
.Lpost_short_Q2:
	/* zero out vectors (repeated if came from Q0) */
	eor		v28.16b,v28.16b,v28.16b
	eor		v29.16b,v29.16b,v29.16b
	/* assume this was final block */
	mov		v28.b[3],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_short_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	/* overwrite previous v28 value (0x80) */
	mov		v28.d[0],x2
	/* assume this was final block */
	mov		v28.b[11],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_short_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	mov		v28.d[1],x2
.Lpost_short_Q3:
	/* zero out vector (repeated if came from Q1) */
	eor		v29.16b,v29.16b,v29.16b
	/* assume this was final block */
	mov		v29.b[3],w15
	/* outstanding 8B blocks left */
	cbz		x5,.Lpost_short_loop
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	sub		x5,x5,8
	rev32		x2,x2
	/* overwrite previous v29 value (0x80) */
	mov		v29.d[0],x2
	/* assume this was final block */
	mov		v29.b[11],w15
	/* outstanding 8B blocks left */
	cbz		x5,1f
	/* at least 8B left to go, it is safe to fetch this data */
	ldr		x2,[x3],8
	rev32		x2,x2
	mov		v29.d[1],x2

/*
 * That is enough of blocks, we allow up to 64 bytes in total.
 * Now we have the sha256 to do for these 4 16B blocks
 */
1:
	/* base address for sha round consts */
	adr		x8,.Lrcon

	ld1		{v4.16b},[x8],16	/* key0 */
	ld1		{v5.16b},[x8],16	/* key1 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key2 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key3 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	mov		v21.16b, v22.16b	/* copy abcd */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */

	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s

	eor		v26.16b,v26.16b,v26.16b		/* zero sha src 0 */
	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	eor		v27.16b,v27.16b,v27.16b		/* zero sha src 1 */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */
	eor		v28.16b,v28.16b,v28.16b		/* zero sha src 2 */
	eor		v29.16b,v29.16b,v29.16b		/* zero sha src 3 */

	/* this was final block */
	cbz		x5,.Lpost_short_loop
	subs		x5,x5,8
	/* loop if hash is not finished */
	b.ne		.Lpost_short_Q0
	/* set "1" of the padding if this was a final block */
	mov		v26.b[3],w15

/*
 * there are between 0 and 3 aes blocks in the final sha256 blocks
 */
.Lpost_short_loop:
	/* Add outstanding bytes of digest source */
	add	x11,x11,x12
	/* Add one SHA-256 block since hash is calculated including i_key_pad */
	add	x11,x11, #64
	lsr	x12,x11,32			/* len_hi */
	and	x13,x11,0xffffffff		/* len_lo */
	lsl	x12,x12,3			/* len_hi in bits */
	lsl	x13,x13,3			/* len_lo in bits */

	mov	v29.s[3],w13			/* len_lo */
	mov	v29.s[2],w12			/* len_hi */

/* do final block */

	/* base address for sha round consts */
	adr		x8,.Lrcon		/* top of rcon */

/* quad 0 */
	ld1		{v4.16b},[x8],16	/* key0 */
	ld1		{v5.16b},[x8],16	/* key1 */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key2 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key3 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 1 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 2 */
	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

/* quad 3 */
	ldp		q6,q7,[x8],32		/* key6,key7 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	mov		v21.16b, v22.16b	/* copy abcd */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */

	sha256h		q22, q23, v4.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s

	add		v26.4s,v24.4s,v22.4s	/* ABCD += working copy */
	add		v27.4s,v25.4s,v23.4s	/* EFGH += working copy */

	/* Calculate final HMAC */
	eor		v28.16b, v28.16b, v28.16b
	eor		v29.16b, v29.16b, v29.16b
	/* base address for sha round consts */
	adr		x8,.Lrcon
	/* load o_key_pad partial hash */
	ldp		q24,q25,[x7]

	/* Set padding 1 to the first reg */
	mov		w11, #0x80		/* that's the 1 of the pad */
	mov		v28.b[3], w11
	/* size of o_key_pad + inner hash */
	mov		x11, #64+32
	lsl		x11, x11, 3
	/* move length to the end of the block */
	mov		v29.s[3], w11
	ldp		q4,q5,[x8],32		/* key0,key1 */
	lsr		x11, x11, 32
	mov		v29.s[2], w11		/* and the higher part */

	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */

	sha256su0	v26.4s,v27.4s
	mov		v22.16b,v24.16b		/* working ABCD <- ABCD */
	mov		v23.16b,v25.16b		/* working EFGH <- EFGH */
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key2 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key3 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key4+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	sha256su0	v26.4s,v27.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v4.4s
	sha256h2	q23, q21, v4.4s
	ld1		{v6.16b},[x8],16	/* key6 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key5+w1 */
	sha256su1	v26.4s,v28.4s,v29.4s

	sha256su0	v27.4s,v28.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s
	ld1		{v7.16b},[x8],16	/* key7 */
	add		v6.4s,v6.4s,v28.4s	/* wk = key6+w2 */
	sha256su1	v27.4s,v29.4s,v26.4s

	sha256su0	v28.4s,v29.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s
	ld1		{v4.16b},[x8],16	/* key4 */
	add		v7.4s,v7.4s,v29.4s	/* wk = key7+w3 */
	sha256su1	v28.4s,v26.4s,v27.4s

	sha256su0	v29.4s,v26.4s
	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s
	ld1		{v5.16b},[x8],16	/* key5 */
	add		v4.4s,v4.4s,v26.4s	/* wk = key0+w0 */
	sha256su1	v29.4s,v27.4s,v28.4s

	ldp		q6,q7,[x8],32		/* key6,key7 */
	add		v5.4s,v5.4s,v27.4s	/* wk = key1+w1 */
	mov		v21.16b, v22.16b	/* copy abcd */
	add		v6.4s,v6.4s,v28.4s	/* wk = key2+w2 */

	sha256h		q22, q23, v4.4s
	add		v7.4s,v7.4s,v29.4s	/* wk = key3+w3 */
	sha256h2	q23, q21, v4.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v5.4s
	sha256h2	q23, q21, v5.4s

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v6.4s
	sha256h2	q23, q21, v6.4s

	mov		x9,sp
	add		sp,sp,8*16
	ldp		q8,q9,[x9],32
	ldp		q10,q11,[x9],32

	mov		v21.16b, v22.16b	/* copy abcd */
	sha256h		q22, q23, v7.4s
	sha256h2	q23, q21, v7.4s

	ldp		q12,q13,[x9],32
	ldp		q14,q15,[x9]

	mov		x0, xzr

	add		v24.4s,v24.4s,v22.4s	/* ABCD += working copy */
	add		v25.4s,v25.4s,v23.4s	/* EFGH += working copy */

	rev32		v24.16b, v24.16b
	rev32		v25.16b, v25.16b

	stp		q24,q25,[x4]		/* save them both */

	ret

	.size	asm_aes128cbc_sha256_hmac, .-asm_aes128cbc_sha256_hmac
