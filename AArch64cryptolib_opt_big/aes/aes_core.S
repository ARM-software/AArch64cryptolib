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

	.file	"aes_core.S"
	.text
	.cpu generic+fp+simd+crypto+crc
	.align	4
	.global	armv8_expandkeys_enc_aes_cbc_128
	.type	armv8_expandkeys_enc_aes_cbc_128, %function
	.global	armv8_expandkeys_dec_aes_cbc_128
	.type	armv8_expandkeys_dec_aes_cbc_128, %function

	/*
	 * AES key expand algorithm for single round.
	 */
	.macro	key_expand res, key, shuffle_mask, rcon, tq0, tq1, td
	/* temp = rotword(key[3]) */
	tbl	\td\().8b,{\key\().16b},\shuffle_mask\().8b
	dup	\tq0\().2d,\td\().d[0]
	/* temp = subbytes(temp) */
	aese	\tq0\().16b,v19\().16b			/* q19 := 0 */
	/* temp = temp + rcon */
	mov	w11,\rcon
	dup	\tq1\().4s,w11
	eor	\tq0\().16b,\tq0\().16b,\tq1\().16b
	/* tq1 = [0, a, b, c] */
	ext	\tq1\().16b,v19\().16b,\key\().16b,12  	/* q19 := 0 */
	eor	\res\().16b,\key\().16b,\tq1\().16b
	/* tq1 = [0, 0, a, b] */
	ext	\tq1\().16b,v19\().16b,\tq1\().16b,12  	/* q19 := 0 */
	eor	\res\().16b,\res\().16b,\tq1\().16b
	/* tq1 = [0, 0, 0, a] */
	ext	\tq1\().16b,v19\().16b,\tq1\().16b,12	/* q19 := 0 */
	eor	\res\().16b,\res\().16b,\tq1\().16b
	/* + temp */
	eor	\res\().16b,\res\().16b,\tq0\().16b
	.endm
/*
 * *expanded_key, *user_key
 */
	.align	4
armv8_expandkeys_enc_aes_cbc_128:
	sub	sp,sp,4*16
	st1	{v8.16b - v11.16b},[sp]
	ld1	{v0.16b},[x1]				/* user_key */
	mov	w10,0x0e0d				/* form shuffle_word */
	mov	w11,0x0c0f
	orr	w10,w10,w11,lsl 16
	dup	v20.4s,w10				/* shuffle_mask */
	eor	v19.16b,v19.16b,v19.16b			/* zero */
	/* Expand key */
	key_expand v1,v0,v20,0x1,v21,v16,v17
	key_expand v2,v1,v20,0x2,v21,v16,v17
	key_expand v3,v2,v20,0x4,v21,v16,v17
	key_expand v4,v3,v20,0x8,v21,v16,v17
	key_expand v5,v4,v20,0x10,v21,v16,v17
	key_expand v6,v5,v20,0x20,v21,v16,v17
	key_expand v7,v6,v20,0x40,v21,v16,v17
	key_expand v8,v7,v20,0x80,v21,v16,v17
	key_expand v9,v8,v20,0x1b,v21,v16,v17
	key_expand v10,v9,v20,0x36,v21,v16,v17
	/* Store round keys in the correct order */
	st1	{v0.16b - v3.16b},[x0],64
	st1	{v4.16b - v7.16b},[x0],64
	st1	{v8.16b - v10.16b},[x0],48

	ld1	{v8.16b - v11.16b},[sp]
	add	sp,sp,4*16
	ret

	.size	armv8_expandkeys_enc_aes_cbc_128, .-armv8_expandkeys_enc_aes_cbc_128

/*
 * *expanded_key, *user_key
 */
	.align	4
armv8_expandkeys_dec_aes_cbc_128:
	sub	sp,sp,4*16
	st1	{v8.16b-v11.16b},[sp]
	ld1	{v0.16b},[x1]				/* user_key */
	mov	w10,0x0e0d				/* form shuffle_word */
	mov	w11,0x0c0f
	orr	w10,w10,w11,lsl 16
	dup	v20.4s,w10				/* shuffle_mask */
	eor	v19.16b,v19.16b,v19.16b			/* zero */
	/*
	 * Expand key.
	 * Intentionally reverse registers order to allow
	 * for multiple store later.
	 * (Store must be performed in the ascending registers' order)
	 */
	key_expand v10,v0,v20,0x1,v21,v16,v17
	key_expand v9,v10,v20,0x2,v21,v16,v17
	key_expand v8,v9,v20,0x4,v21,v16,v17
	key_expand v7,v8,v20,0x8,v21,v16,v17
	key_expand v6,v7,v20,0x10,v21,v16,v17
	key_expand v5,v6,v20,0x20,v21,v16,v17
	key_expand v4,v5,v20,0x40,v21,v16,v17
	key_expand v3,v4,v20,0x80,v21,v16,v17
	key_expand v2,v3,v20,0x1b,v21,v16,v17
	key_expand v1,v2,v20,0x36,v21,v16,v17
	/* Inverse mixcolumns for keys 1-9 (registers v10-v2) */
	aesimc	v10.16b, v10.16b
	aesimc	v9.16b, v9.16b
	aesimc	v8.16b, v8.16b
	aesimc	v7.16b, v7.16b
	aesimc	v6.16b, v6.16b
	aesimc	v5.16b, v5.16b
	aesimc	v4.16b, v4.16b
	aesimc	v3.16b, v3.16b
	aesimc	v2.16b, v2.16b
	/* Store round keys in the correct order */
	st1	{v1.16b - v4.16b},[x0],64
	st1	{v5.16b - v8.16b},[x0],64
	st1	{v9.16b, v10.16b},[x0],32
	st1	{v0.16b},[x0],16

	ld1	{v8.16b - v11.16b},[sp]
	add	sp,sp,4*16
	ret

	.size	armv8_expandkeys_dec_aes_cbc_128, .-armv8_expandkeys_dec_aes_cbc_128
