//Copyright (c) 2018-2019, ARM Limited. All rights reserved.
//
//SPDX-License-Identifier:        BSD-3-Clause

#ifndef AARCH64CRYPTOLIB_H
#define AARCH64CRYPTOLIB_H

#include <stdint.h>
#include <stdlib.h>

typedef enum cipher_mode { AES_GCM_128, AES_GCM_192, AES_GCM_256 } AArch64crypto_cipher_mode_t;

typedef enum operation_result { SUCCESSFUL_OPERATION = 0, AUTHENTICATION_FAILURE=1, INTERNAL_FAILURE } AArch64crypto_operation_result_t;

typedef union doubleword {
    uint8_t  b[8];
    uint16_t h[4];
    uint32_t s[2];
    uint64_t d[1];
} AArch64crypto_doubleword_t;

typedef union quadword {
    uint8_t  b[16];
    uint16_t h[8];
    uint32_t s[4];
    uint64_t d[2];
} AArch64crypto_quadword_t;

#if defined(PERF_GCM_LITTLE) || defined(PERF_GCM_BIG)
    #define IPSEC_ENABLED
    #define MAX_UNROLL_FACTOR 4
#else
    #if defined(PERF_GCM_BIGGER)
        #define MAX_UNROLL_FACTOR 8
    #else
        #define MAX_UNROLL_FACTOR 1
    #endif
#endif

typedef struct cipher_constants {
    AArch64crypto_quadword_t expanded_aes_keys[15];
    AArch64crypto_quadword_t expanded_hash_keys[MAX_UNROLL_FACTOR];
    AArch64crypto_doubleword_t karat_hash_keys[MAX_UNROLL_FACTOR];
    AArch64crypto_cipher_mode_t mode;
    uint8_t tag_byte_length;
} AArch64crypto_cipher_constants_t;

typedef struct cipher_state {
    AArch64crypto_quadword_t counter;
    AArch64crypto_quadword_t current_tag;
    AArch64crypto_cipher_constants_t * constants;
} AArch64crypto_cipher_state_t;

typedef struct {
	struct {
		uint8_t *key;
		uint8_t *iv;
	} cipher;
	struct {
		struct {
			uint8_t *key;
			uint8_t *i_key_pad;
			uint8_t *o_key_pad;
		} hmac;
	} digest;
} AArch64crypto_cipher_digest_t;

/*
 * Auxiliary calls for AES-CBC/SHA
 */
void AArch64crypto_aes_cbc_expandkeys_128_enc(uint8_t *expanded_key, const uint8_t *user_key);
void AArch64crypto_aes_cbc_expandkeys_128_dec(uint8_t *expanded_key, const uint8_t *user_key);
int AArch64crypto_sha1_block_partial(uint8_t *init, const uint8_t *src, uint8_t *dst,
			uint64_t len);
int AArch64crypto_sha256_block_partial(uint8_t *init, const uint8_t *src, uint8_t *dst,
			uint64_t len);
/*
 * Main interface calls for AES-CBC+SHA1/256 encryption and decryption
 */
int AArch64crypto_encrypt_aes128cbc_sha1(
			uint8_t *csrc, uint8_t *cdst, uint64_t clen,
			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
			AArch64crypto_cipher_digest_t *arg);
int AArch64crypto_encrypt_aes128cbc_sha256(
			uint8_t *csrc, uint8_t *cdst, uint64_t clen,
			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
			AArch64crypto_cipher_digest_t *arg);
int AArch64crypto_decrypt_aes128cbc_sha1(
			uint8_t *csrc, uint8_t *cdst, uint64_t clen,
			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
			AArch64crypto_cipher_digest_t *arg);
int AArch64crypto_decrypt_aes128cbc_sha256(
			uint8_t *csrc, uint8_t *cdst, uint64_t clen,
			uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
			AArch64crypto_cipher_digest_t *arg);

// set the cipher_constants
AArch64crypto_operation_result_t AArch64crypto_aes_gcm_set_constants(
    AArch64crypto_cipher_mode_t mode,
    uint8_t tag_byte_length,
    uint8_t * restrict key,
    AArch64crypto_cipher_constants_t * restrict cc);

// set the counter based on a nonce value (will invoke GHASH if nonce_length!=96)
AArch64crypto_operation_result_t AArch64crypto_aes_gcm_set_counter(
    uint8_t * restrict nonce, uint64_t nonce_length,
        //assumed that nonce can be read in 16B blocks - will read (but not use) up to 15B beyond the end of the nonce
    AArch64crypto_cipher_state_t * restrict cs);

// mode indicates which AEAD is being used (currently only planning to support AES-GCM variants)
// key is secret key K as in RFC5116 - length determined by mode
// nonce and aad as in RFC5116
// aad is authenticated but not encrypted
// plaintext is input to be encrypted and authenticated
// ciphertext is the resultant encrypted data with the authentication tag appended to it (should be 16B longer than plaintext)
// expected return value is SUCCESSFUL_OPERATION
// but will return INTERNAL_FAILURE if you hit any functions not yet implemented
AArch64crypto_operation_result_t AArch64crypto_encrypt_full(
    //Inputs
    AArch64crypto_cipher_mode_t mode,
    uint8_t * restrict key,
    uint8_t * restrict nonce, uint64_t nonce_bit_length,
        //assumed that nonce can be read in 16B blocks - will read (but not use) up to 15B beyond the end of the nonce
    uint8_t * restrict aad,   uint64_t aad_bit_length,
        //assumed that aad can be read in 16B blocks - will read (but not use) up to 15B beyond the end of the aad
    uint8_t * plaintext,      uint64_t plaintext_bit_length,
        //assumed that plaintext can be read in 16B blocks - will read (but not use) up to 15B beyond the end of the plaintext
    //Outputs
    uint8_t * ciphertext,
        //assumed that ciphertext can be written in 16B blocks - will write up to 15B of 0s beyond the end of the ciphertext
    uint8_t * tag
        //assumed that bytes up to tag+15 are accessible and 16B tag always written
    );

// Given a set up state, we can do the encrypt operation
//  - plaintext and ciphertext can point to the same place for in place operation
// NOTE - cipher_state set up:
// 1) cipher_constants set up:
//      set mode and tag_length as appropriate
//      call appropriate aes_gcm_expandkeys_*_kernel for your mode (expects master 128/192/256b key as input)
// 2) cipher_state set up:
//      set constants pointer to point to a set up cipher_constants
//      call aes_gcm_set_counter_kernel with your nonce
// NOTE - encrypt_from_state will ignore and overwrite any current value in cs->current_tag
// expected return value is SUCCESSFUL_OPERATION
// but will return INTERNAL_FAILURE if you hit any functions not yet implemented
AArch64crypto_operation_result_t AArch64crypto_encrypt_from_state(
    //Inputs
    AArch64crypto_cipher_state_t * cs,
    uint8_t * restrict aad,   uint64_t aad_bit_length,
        //assumed that aad can be read in 16B blocks - will read (but not use) up to 15B beyond the end of the aad
    uint8_t * plaintext,      uint64_t plaintext_bit_length,
        //assumed that plaintext can be read in 16B blocks - will read (but not use) up to 15B beyond the end of the plaintext
    //Outputs
    uint8_t * ciphertext,
        //assumed that ciphertext can be written in 16B blocks - will write up to 15B of 0s beyond the end of the ciphertext
    uint8_t * tag
        //assumed that bytes up to tag+15 are accessible and 16B tag always written
    );

// Given a set up cipher_constants_t and the IPsec salt and ESPIV, perform encryption in place
AArch64crypto_operation_result_t AArch64crypto_encrypt_from_constants_IPsec(
    //Inputs
    const AArch64crypto_cipher_constants_t * cc,
    uint32_t salt,
    uint64_t ESPIV,
    const uint8_t * restrict aad,   uint32_t aad_byte_length,
        //assumes aad zero padded to 16B and 0 < aad_byte_length <=16
    uint8_t * plaintext,            uint32_t plaintext_byte_length,
        //in place operation - plaintext becomes ciphertext
        //assumed that ciphertext can be written in 16B blocks - will write up to 15B of 0s beyond the end of the plaintext
    //Output
    uint8_t * tag
        //tag written after ciphertext, so tag will be produced correctly if directly after plaintext
        //will always write 16B of tag, regardless of the tag_byte_length specified in cc
        //caller must ensure that this region is accessible and must preserve any important data
    );

// mode indicates which AEAD is being used (currently only planning to support AES-GCM variants)
// key is secret key K as in RFC5116 - length determined by mode
// nonce and aad as in RFC5116
// aad is authenticated but not decrypted
// ciphertext is the input data to be decrypted with the authentication tag appended to it
// plaintext is the resultant decrypted data (should be 16B shorter than ciphertext)
// expected return value is SUCCESSFUL_OPERATION or AUTHENTICATION_FAILURE (if the provided tag does not match the computed tag)
// but will return INTERNAL_FAILURE if you hit any functions not yet implemented
AArch64crypto_operation_result_t AArch64crypto_decrypt_full(
    //Inputs
    AArch64crypto_cipher_mode_t mode,
    uint8_t * restrict key,
    uint8_t * restrict nonce, uint64_t nonce_bit_length,
        //assumed that nonce can be read in 16B blocks - will read (but not use) up to 15B beyond the end of the nonce
    uint8_t * restrict aad,   uint64_t aad_bit_length,
        //assumed that aad can be read in 16B blocks - will read (but not use) up to 15B beyond the end of the aad
    uint8_t * ciphertext,     uint64_t ciphertext_bit_length,
        //assumed that ciphertext can be read in 16B blocks - will read (but not use) up to 15B beyond the end of the ciphertext
    uint8_t * tag,
        //tag_byte_length specified in cipher_constants
        //assumed that bytes up to tag+15 are accessible, though only the number specified in cipher_constants are used
    //Output
    uint8_t * plaintext
        //assumed that plaintext can be written in 16B blocks - will write up to 15B of 0s beyond the end of the plaintext
    );

// Given a set up state, we can do the decrypt operation
//  - ciphertext and plaintext can point to the same place for in place operation
// NOTE - cipher_state set up:
// 1) cipher_constants set up:
//      set mode and tag_length as appropriate
//      call appropriate aes_gcm_expandkeys_*_kernel for your mode (expects master 128/192/256b key as input)
// 2) cipher_state set up:
//      set constants pointer to point to a set up cipher_constants
//      call aes_gcm_set_counter_kernel with your nonce
// NOTE - decrypt_from_state will ignore and overwrite any current value in cs->current_tag
// expected return value is SUCCESSFUL_OPERATION or AUTHENTICATION_FAILURE (if the provided tag does not match the computed tag)
// but will return INTERNAL_FAILURE if you hit any functions not yet implemented
AArch64crypto_operation_result_t AArch64crypto_decrypt_from_state(
    //Inputs
    AArch64crypto_cipher_state_t * cs,
    uint8_t * restrict aad, uint64_t aad_bit_length,
        //assumed that aad can be read in 16B blocks - will read (but not use) up to 15B beyond the end of the aad
    uint8_t * ciphertext,   uint64_t ciphertext_bit_length,
        //assumed that ciphertext can be read in 16B blocks - will read (but not use) up to 15B beyond the end of the ciphertext
    uint8_t * tag,
        //tag_byte_length specified in cipher_constants
        //assumed that bytes up to tag+15 are accessible, though only the number specified in cipher_constants are used
    //Output
    uint8_t * plaintext
        //assumed that plaintext can be written in 16B blocks - will write up to 15B of 0s beyond the end of the ciphertext
    );

// Given a set up cipher_constants_t and the IPsec salt and ESPIV, perform decryption in place
// Compute checksum of the plaintext at the same time
AArch64crypto_operation_result_t AArch64crypto_decrypt_from_constants_IPsec(
    //Inputs
    const AArch64crypto_cipher_constants_t * cc,
    uint32_t salt,
    uint64_t ESPIV,
    const uint8_t * restrict aad, uint32_t aad_byte_length,
        //aad_byte_length 8 or 12
        //assumed that aad can be read with a 16B read - will read (but not use) up to 8B beyond the end of aad
    uint8_t * ciphertext,   uint32_t ciphertext_byte_length,
        //in place operation - ciphertext becomes plaintext
        //assumed that plaintext can be written in 8B blocks - will write up to 7B of 0s beyond the end of the ciphertext
    const uint8_t * tag,
        //tag_byte_length specified in cipher_constants
        //tag is read before last block of plaintext is written and written back afterwards, so tag will be preserved
        //supported tag sizes are 8B, 12B and 16B, and precisely the size specified will be read/written
    //Output
    uint64_t * checksum
        //one's complement sum of all 64b words in the plaintext
    );

#endif
