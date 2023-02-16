//Copyright (c) 2018-2019, ARM Limited. All rights reserved.
//
//SPDX-License-Identifier:        BSD-3-Clause

#include "AArch64cryptolib.h"

#include "arm_neon.h"
#include <string.h> //want to use memcpy in certain corners
#include <stdio.h>

#ifndef vreinterpretq_u64_p64
#define vreinterpretq_u64_p64 (uint64x2_t)
#endif
#ifndef vreinterpretq_u64_p128
#define vreinterpretq_u64_p128 (uint64x2_t)
#endif
#ifndef vreinterpretq_p64_u64
#define vreinterpretq_p64_u64 (poly64x2_t)
#endif
#ifndef vreinterpretq_p64_u8
#define vreinterpretq_p64_u8 (poly64x2_t)
#endif
#ifndef vreinterpretq_u8_p64
#define vreinterpretq_u8_p64 (uint8x16_t)
#endif
#ifndef vreinterpretq_u8_p128
#define vreinterpretq_u8_p128 (uint8x16_t)
#endif

#ifndef vget_low_p64
#define vget_low_p64 (poly64_t) vget_low_u64
#endif
#ifndef vget_high_p64
#define vget_high_p64 vget_high_u64
#endif

#define cipher_mode_t                   armv8_cipher_mode_t
#define operation_result_t              armv8_operation_result_t
#define quadword_t                      armv8_quadword_t
#define cipher_constants_t              armv8_cipher_constants_t
#define cipher_state_t                  armv8_cipher_state_t

#define encrypt_full                    armv8_enc_aes_gcm_full
#define encrypt_from_state              armv8_enc_aes_gcm_from_state
#define encrypt_from_constants_IPsec    armv8_enc_aes_gcm_from_constants_IPsec
#define decrypt_full                    armv8_dec_aes_gcm_full
#define decrypt_from_state              armv8_dec_aes_gcm_from_state
#define decrypt_from_constants_IPsec    armv8_dec_aes_gcm_from_constants_IPsec


// expands the input key to the keys for each AES round and generates the hash key from the AES round keys
// NOTE - this overwrites the expanded_hash_keys and expanded_keys variables in the cipher constants
static operation_result_t aes_gcm_expandkeys_128_kernel(uint8_t * restrict key, cipher_constants_t * restrict cc); //16B key -> 11 round * 16B = 176B expanded keys
static operation_result_t aes_gcm_expandkeys_192_kernel(uint8_t * restrict key, cipher_constants_t * restrict cc); //24B key -> 13 round * 16B = 208B expanded keys
static operation_result_t aes_gcm_expandkeys_256_kernel(uint8_t * restrict key, cipher_constants_t * restrict cc); //32B key -> 15 round * 16B = 240B expanded keys

// used to authenticate the aad before doing the merged authentication and encryption(/decryption) on the plaintext(/ciphertext)
// also used to append the hash with len(A)_64 | len(C)_64 after merged auth and enc/dec
// NOTE - this reads and overwrites the current_tag variable in the cipher state
static operation_result_t ghash_kernel(uint8_t * restrict input, uint64_t input_length, cipher_state_t * restrict cs);

// generate some number of consecutive blocks of aes_ctr values (usually XORed with plaintext or ciphertext) using and updating current counter value
// this is used just with block_count == 1 for "encrypting" our ghash result to form our tag
static operation_result_t aes_ctr_blk_128_kernel(uint64_t block_count, cipher_state_t * restrict cs, uint8_t * restrict blocks);
static operation_result_t aes_ctr_blk_192_kernel(uint64_t block_count, cipher_state_t * restrict cs, uint8_t * restrict blocks);
static operation_result_t aes_ctr_blk_256_kernel(uint64_t block_count, cipher_state_t * restrict cs, uint8_t * restrict blocks);

static operation_result_t aes_gcm_enc_128_kernel(uint8_t * plaintext, uint64_t plaintext_length, cipher_state_t * restrict cs, uint8_t * ciphertext);
static operation_result_t aes_gcm_enc_192_kernel(uint8_t * plaintext, uint64_t plaintext_length, cipher_state_t * restrict cs, uint8_t * ciphertext);
static operation_result_t aes_gcm_enc_256_kernel(uint8_t * plaintext, uint64_t plaintext_length, cipher_state_t * restrict cs, uint8_t * ciphertext);

static operation_result_t aes_gcm_dec_128_kernel(uint8_t * ciphertext, uint64_t ciphertext_length, cipher_state_t * restrict cs, uint8_t * plaintext);
static operation_result_t aes_gcm_dec_192_kernel(uint8_t * ciphertext, uint64_t ciphertext_length, cipher_state_t * restrict cs, uint8_t * plaintext);
static operation_result_t aes_gcm_dec_256_kernel(uint8_t * ciphertext, uint64_t ciphertext_length, cipher_state_t * restrict cs, uint8_t * plaintext);

//reverse the authentication tag and output it
static operation_result_t aes_gcm_finalize(cipher_state_t * restrict cs, quadword_t final_block, uint8_t * restrict output_tag);


uint8_t rcon[16] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0, 0, 0, 0, 0 };

uint8_t rijndael_sbox[256] =
 {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
 };

operation_result_t armv8_aes_gcm_set_constants(
    cipher_mode_t mode,
    uint8_t tag_byte_length,
    uint8_t * restrict key,
    armv8_cipher_constants_t * restrict cc)
{
    cc->tag_byte_length = tag_byte_length;
    cc->mode = mode;
    operation_result_t result;
    switch(mode) {
        case AES_GCM_128:
            result = aes_gcm_expandkeys_128_kernel(key, cc);
            break;
        case AES_GCM_192:
            result = aes_gcm_expandkeys_192_kernel(key, cc);
            break;
        case AES_GCM_256:
            result = aes_gcm_expandkeys_256_kernel(key, cc);
            break;
        default:
            result = INTERNAL_FAILURE;
            break;
    }
    return result;
}

#define expand_hash_keys \
    /* reverse the bytes of the hash key */ \
    \
    hash_key = vrev64q_u8(hash_key); /* b|B(63b)|a|A(63b) */ \
    \
    /* twist hash key w.r.t. 0x87 so we can do reversed polynomial multiplication with it */ \
    /* need to shift hash_key to the left by one and optionally eor in C2...1 depending on the MSB we shifted out */ \
    /* hashkey = b|B(63b)|a|A(63b) */ \
    /* but we want: */ \
    /* low_twisted_bytes | high_twisted_bytes (this order as we will stream aad/ciphertext in big endian byte order) */ \
    /* = */ \
    /* (B(63b)|0|A(63b)|b) ^ (a ? 0(56b)|0x01C2|0(56b) : 0(128b)) */ \
    \
    uint64x2_t hash_shift_left  = vshlq_n_u64(vreinterpretq_u64_u8(hash_key),1);                         /* B(63b)|0|A(63b)|0 */ \
    uint64x2_t hash_shift_right = vreinterpretq_u64_s64(vshrq_n_s64(vreinterpretq_s64_u8(hash_key),63)); /* b(64b)|a(64b) */ \
    uint8x16_t twist_const_mask = vextq_u8(vreinterpretq_u8_u64(hash_shift_right), vreinterpretq_u8_u64(hash_shift_right), 12); /* b(32b)|a(64b)|b(32b) */ \
    \
    uint64x2_t twist_const = { 0, 0 }; \
    twist_const = vsetq_lane_u64(0xC200000000000001ul, twist_const, 0); /* we'll merge in the carry bit from low */ \
    twist_const = vsetq_lane_u64(1, twist_const, 1); \
    \
    twist_const = vandq_u64(vreinterpretq_u64_u8(twist_const_mask), twist_const);          /* 0(56b)|(a ? 0x01C2 : 0x0000)|0(55b)|b */ \
    poly64x2_t twisted_hash = vreinterpretq_p64_u64(veorq_u64(twist_const, hash_shift_left)); /* (B(63b)|0|A(63b)|b) ^ (a ? 0(56b)|0x01C2|0(56b) : 0(128b)) */ \
    poly64_t twisted_hash_karat = (poly64_t) veor_u64(vget_high_u64(vreinterpretq_u64_p64(twisted_hash)), vget_low_u64(twisted_hash)); \
    \
    /* precompute MAX_UNROLL_FACTOR powers of twisted H */ \
    uint8_t * hash_power_ptr = cc->expanded_hash_keys[0].b; \
    poly64x2_t curr_power = twisted_hash; \
    poly64_t modulo_const = (poly64_t) 0xC200000000000000ul; \
    for( int i=0; i<MAX_UNROLL_FACTOR; ++i) \
    { \
        vst1q_u64((uint64_t *) hash_power_ptr, curr_power); \
        hash_power_ptr += 16; \
        \
        poly64_t curr_power_karat = (poly64_t) veor_u64(vget_high_u64(curr_power), vget_low_u64(curr_power)); \
        /*prepare curr_power for next iteration*/ \
        /*multiply*/ \
        poly128_t t_high = vmull_high_p64(curr_power, twisted_hash); \
        poly128_t t_low  = vmull_p64((poly64_t) vget_low_p64(curr_power), (poly64_t) vget_low_p64(twisted_hash)); \
        poly128_t t_mid  = vmull_p64(curr_power_karat, twisted_hash_karat); \
        \
        /*tidy up karatsuba*/ \
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high)); \
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low)); \
        \
        /*modulo reduction*/ \
        poly128_t tmp_mid_0 = vmull_p64((poly64_t) vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const); \
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8); \
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0)); \
        mid_acc = veorq_u64(mid_acc, high_acc); \
        \
        poly128_t tmp_low_0 = vmull_p64((poly64_t) vget_low_p64(mid_acc), modulo_const); \
        mid_acc = vextq_u8(mid_acc, mid_acc, 8); \
        curr_power = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0)); \
        curr_power = veorq_u64(curr_power, mid_acc); \
        \
        curr_power = vextq_u8(curr_power, curr_power, 8); \
    } \
    uint64_t * hash64_ptr  = (uint64_t *) cc->expanded_hash_keys[0].b; \
    uint64_t * karat64_ptr = (uint64_t *) cc->karat_hash_keys[0].b; \
    for( int i=0; i<MAX_UNROLL_FACTOR; ++i) \
    { \
        karat64_ptr[i] = hash64_ptr[2*i] ^ hash64_ptr[2*i + 1]; \
    }

static operation_result_t aes_gcm_expandkeys_128_kernel(uint8_t * restrict key, cipher_constants_t * restrict cc)
{
    //// expand aes key with Rijndael schedule
    // __asm __volatile
    // (
    //     // 1) first round key is simply the provided key
    //     "       ld1     { v0.16b }, [%[key]]            \n" // v0 is initial key
    //     "       ld1     { v1.16b }, [%[rcon]]           \n" // v1 is rcon
    //     "       st1     { v0.16b }, [%[out_ptr]], #16   \n" // store key 0
    //     // 2) generate further 10 round keys
    //     "1:                                             \n"
    //     "       "
    //     :
    //     :
    //     :
    // )

    const uint8_t bpi = 16; //bytes per iteration
    uint8_t * expanded_aes_keys_ptr = (uint8_t *) cc->expanded_aes_keys[0].b;
    // 1) first (1) round key is simply the provided key
    for(int i=0; i<bpi; ++i)
    {
        expanded_aes_keys_ptr[i] = key[i];
    }

    // 2) generate further 10 round keys
    uint8_t t[4] = { 0,0,0,0 };
    for(int i=1; i<11; ++i)
    {
        t[0] = expanded_aes_keys_ptr[(i*bpi)-3]; //load rotated previous 4 bytes
        t[1] = expanded_aes_keys_ptr[(i*bpi)-2];
        t[2] = expanded_aes_keys_ptr[(i*bpi)-1];
        t[3] = expanded_aes_keys_ptr[(i*bpi)-4];

        t[0] = rijndael_sbox[t[0]] ^ rcon[i]; //apply sbox
        t[1] = rijndael_sbox[t[1]];
        t[2] = rijndael_sbox[t[2]];
        t[3] = rijndael_sbox[t[3]];

        expanded_aes_keys_ptr[(i*bpi)+0] = expanded_aes_keys_ptr[((i-1)*bpi)+0] ^ t[0]; //eor with 16 bytes back
        expanded_aes_keys_ptr[(i*bpi)+1] = expanded_aes_keys_ptr[((i-1)*bpi)+1] ^ t[1];
        expanded_aes_keys_ptr[(i*bpi)+2] = expanded_aes_keys_ptr[((i-1)*bpi)+2] ^ t[2];
        expanded_aes_keys_ptr[(i*bpi)+3] = expanded_aes_keys_ptr[((i-1)*bpi)+3] ^ t[3];

        for( int j=4; j<16; ++j) {
            expanded_aes_keys_ptr[(i*bpi)+j] = expanded_aes_keys_ptr[((i-1)*bpi)+j] ^ expanded_aes_keys_ptr[(i*bpi)+j-4];
        }
    }

    //// encrypt quadword 0 with expanded aes key to form hash key
    uint8x16_t hash_key = vdupq_n_u8(0);
    uint8x16_t k0  = vld1q_u8(cc->expanded_aes_keys[0].b);
    uint8x16_t k1  = vld1q_u8(cc->expanded_aes_keys[1].b);
    uint8x16_t k2  = vld1q_u8(cc->expanded_aes_keys[2].b);
    uint8x16_t k3  = vld1q_u8(cc->expanded_aes_keys[3].b);
    uint8x16_t k4  = vld1q_u8(cc->expanded_aes_keys[4].b);
    uint8x16_t k5  = vld1q_u8(cc->expanded_aes_keys[5].b);
    uint8x16_t k6  = vld1q_u8(cc->expanded_aes_keys[6].b);
    uint8x16_t k7  = vld1q_u8(cc->expanded_aes_keys[7].b);
    uint8x16_t k8  = vld1q_u8(cc->expanded_aes_keys[8].b);
    uint8x16_t k9  = vld1q_u8(cc->expanded_aes_keys[9].b);
    uint8x16_t k10 = vld1q_u8(cc->expanded_aes_keys[10].b);

    hash_key = vaeseq_u8(hash_key, k0); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k1); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k2); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k3); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k4); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k5); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k6); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k7); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k8); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k9);
    hash_key = veorq_u8(hash_key, k10); // revB(56b)|b|revB(7b)|revA(56b)|a|revA(7b)

    expand_hash_keys

    return SUCCESSFUL_OPERATION;
}

static operation_result_t aes_gcm_expandkeys_192_kernel(uint8_t * restrict key, cipher_constants_t * restrict cc)
{
    const uint8_t bpi = 24; //bytes per iteration
    uint8_t * expanded_aes_keys_ptr = (uint8_t *) cc->expanded_aes_keys[0].b;
    // 1) first (1.5) round keys are simply the provided key
    for(int i=0; i<bpi; ++i)
    {
        expanded_aes_keys_ptr[i] = key[i];
    }

    // 2) generate further 11.5 round keys
    uint8_t t[4] = { 0,0,0,0 };
    for(int i=1; i<9; ++i)
    {
        t[0] = expanded_aes_keys_ptr[(i*bpi)-3]; //load rotated previous 4 bytes
        t[1] = expanded_aes_keys_ptr[(i*bpi)-2];
        t[2] = expanded_aes_keys_ptr[(i*bpi)-1];
        t[3] = expanded_aes_keys_ptr[(i*bpi)-4];

        t[0] = rijndael_sbox[t[0]] ^ rcon[i]; //apply sbox
        t[1] = rijndael_sbox[t[1]];
        t[2] = rijndael_sbox[t[2]];
        t[3] = rijndael_sbox[t[3]];

        expanded_aes_keys_ptr[(i*bpi)+0] = expanded_aes_keys_ptr[((i-1)*bpi)+0] ^ t[0]; //eor with 24 bytes back
        expanded_aes_keys_ptr[(i*bpi)+1] = expanded_aes_keys_ptr[((i-1)*bpi)+1] ^ t[1];
        expanded_aes_keys_ptr[(i*bpi)+2] = expanded_aes_keys_ptr[((i-1)*bpi)+2] ^ t[2];
        expanded_aes_keys_ptr[(i*bpi)+3] = expanded_aes_keys_ptr[((i-1)*bpi)+3] ^ t[3];

        for( int j=4; j<16; ++j) {
            expanded_aes_keys_ptr[(i*bpi)+j] = expanded_aes_keys_ptr[((i-1)*bpi)+j] ^ expanded_aes_keys_ptr[(i*bpi)+j-4];
        }

        if(i < 8) {
            for( int j=16; j<24; ++j) {
                expanded_aes_keys_ptr[(i*bpi)+j] = expanded_aes_keys_ptr[((i-1)*bpi)+j] ^ expanded_aes_keys_ptr[(i*bpi)+j-4];
            }
        }
    }

    //// encrypt quadword 0 with expanded aes key to form hash key
    uint8x16_t hash_key = vdupq_n_u8(0);
    uint8x16_t k0  = vld1q_u8(cc->expanded_aes_keys[0].b);
    uint8x16_t k1  = vld1q_u8(cc->expanded_aes_keys[1].b);
    uint8x16_t k2  = vld1q_u8(cc->expanded_aes_keys[2].b);
    uint8x16_t k3  = vld1q_u8(cc->expanded_aes_keys[3].b);
    uint8x16_t k4  = vld1q_u8(cc->expanded_aes_keys[4].b);
    uint8x16_t k5  = vld1q_u8(cc->expanded_aes_keys[5].b);
    uint8x16_t k6  = vld1q_u8(cc->expanded_aes_keys[6].b);
    uint8x16_t k7  = vld1q_u8(cc->expanded_aes_keys[7].b);
    uint8x16_t k8  = vld1q_u8(cc->expanded_aes_keys[8].b);
    uint8x16_t k9  = vld1q_u8(cc->expanded_aes_keys[9].b);
    uint8x16_t k10 = vld1q_u8(cc->expanded_aes_keys[10].b);
    uint8x16_t k11 = vld1q_u8(cc->expanded_aes_keys[11].b);
    uint8x16_t k12 = vld1q_u8(cc->expanded_aes_keys[12].b);

    hash_key = vaeseq_u8(hash_key, k0); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k1); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k2); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k3); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k4); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k5); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k6); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k7); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k8); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k9); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k10); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k11);
    hash_key = veorq_u8(hash_key, k12); // revB(56b)|b|revB(7b)|revA(56b)|a|revA(7b)

    expand_hash_keys

    return SUCCESSFUL_OPERATION;
}

static operation_result_t aes_gcm_expandkeys_256_kernel(uint8_t * restrict key, cipher_constants_t * restrict cc)
{
    //// expand aes key with Rijndael schedule
    const uint8_t bpi = 32; //bytes per iteration
    uint8_t * expanded_aes_keys_ptr = (uint8_t *) cc->expanded_aes_keys[0].b;
    // 1) first (2) round keys are simply the provided key
    for(int i=0; i<bpi; ++i)
    {
        expanded_aes_keys_ptr[i] = key[i];
    }

    // 2) generate further 13 round keys
    uint8_t t[4] = { 0,0,0,0 };
    for(int i=1; i<8; ++i)
    {
        t[0] = expanded_aes_keys_ptr[(i*bpi)-3]; //load rotated previous 4 bytes
        t[1] = expanded_aes_keys_ptr[(i*bpi)-2];
        t[2] = expanded_aes_keys_ptr[(i*bpi)-1];
        t[3] = expanded_aes_keys_ptr[(i*bpi)-4];

        t[0] = rijndael_sbox[t[0]] ^ rcon[i]; //apply sbox
        t[1] = rijndael_sbox[t[1]];
        t[2] = rijndael_sbox[t[2]];
        t[3] = rijndael_sbox[t[3]];

        expanded_aes_keys_ptr[(i*bpi)+0] = expanded_aes_keys_ptr[((i-1)*bpi)+0] ^ t[0]; //eor with 32 bytes back
        expanded_aes_keys_ptr[(i*bpi)+1] = expanded_aes_keys_ptr[((i-1)*bpi)+1] ^ t[1];
        expanded_aes_keys_ptr[(i*bpi)+2] = expanded_aes_keys_ptr[((i-1)*bpi)+2] ^ t[2];
        expanded_aes_keys_ptr[(i*bpi)+3] = expanded_aes_keys_ptr[((i-1)*bpi)+3] ^ t[3];

        for( int j=4; j<16; ++j) {
            expanded_aes_keys_ptr[(i*bpi)+j] = expanded_aes_keys_ptr[((i-1)*bpi)+j] ^ expanded_aes_keys_ptr[(i*bpi)+j-4];
        }

        if(i < 7) {
            t[0] = expanded_aes_keys_ptr[(i*bpi)+12]; //load previous 4 bytes
            t[1] = expanded_aes_keys_ptr[(i*bpi)+13];
            t[2] = expanded_aes_keys_ptr[(i*bpi)+14];
            t[3] = expanded_aes_keys_ptr[(i*bpi)+15];

            t[0] = rijndael_sbox[t[0]]; //apply sbox
            t[1] = rijndael_sbox[t[1]];
            t[2] = rijndael_sbox[t[2]];
            t[3] = rijndael_sbox[t[3]];

            expanded_aes_keys_ptr[(i*bpi)+16] = expanded_aes_keys_ptr[((i-1)*bpi)+16] ^ t[0];  //eor with 32 bytes back
            expanded_aes_keys_ptr[(i*bpi)+17] = expanded_aes_keys_ptr[((i-1)*bpi)+17] ^ t[1];
            expanded_aes_keys_ptr[(i*bpi)+18] = expanded_aes_keys_ptr[((i-1)*bpi)+18] ^ t[2];
            expanded_aes_keys_ptr[(i*bpi)+19] = expanded_aes_keys_ptr[((i-1)*bpi)+19] ^ t[3];

            for( int j=20; j<32; ++j) {
                expanded_aes_keys_ptr[(i*bpi)+j] = expanded_aes_keys_ptr[((i-1)*bpi)+j] ^ expanded_aes_keys_ptr[(i*bpi)+j-4];
            }
        }
    }

    //// encrypt quadword 0 with expanded aes key to form hash key
    uint8x16_t hash_key = vdupq_n_u8(0);
    uint8x16_t k0  = vld1q_u8(cc->expanded_aes_keys[0].b);
    uint8x16_t k1  = vld1q_u8(cc->expanded_aes_keys[1].b);
    uint8x16_t k2  = vld1q_u8(cc->expanded_aes_keys[2].b);
    uint8x16_t k3  = vld1q_u8(cc->expanded_aes_keys[3].b);
    uint8x16_t k4  = vld1q_u8(cc->expanded_aes_keys[4].b);
    uint8x16_t k5  = vld1q_u8(cc->expanded_aes_keys[5].b);
    uint8x16_t k6  = vld1q_u8(cc->expanded_aes_keys[6].b);
    uint8x16_t k7  = vld1q_u8(cc->expanded_aes_keys[7].b);
    uint8x16_t k8  = vld1q_u8(cc->expanded_aes_keys[8].b);
    uint8x16_t k9  = vld1q_u8(cc->expanded_aes_keys[9].b);
    uint8x16_t k10 = vld1q_u8(cc->expanded_aes_keys[10].b);
    uint8x16_t k11 = vld1q_u8(cc->expanded_aes_keys[11].b);
    uint8x16_t k12 = vld1q_u8(cc->expanded_aes_keys[12].b);
    uint8x16_t k13 = vld1q_u8(cc->expanded_aes_keys[13].b);
    uint8x16_t k14 = vld1q_u8(cc->expanded_aes_keys[14].b);

    hash_key = vaeseq_u8(hash_key, k0); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k1); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k2); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k3); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k4); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k5); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k6); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k7); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k8); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k9); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k10); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k11); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k12); hash_key = vaesmcq_u8(hash_key);
    hash_key = vaeseq_u8(hash_key, k13);
    hash_key = veorq_u8(hash_key, k14); // revB(56b)|b|revB(7b)|revA(56b)|a|revA(7b)

    expand_hash_keys

    return SUCCESSFUL_OPERATION;
}

operation_result_t armv8_aes_gcm_set_counter(uint8_t * restrict nonce, uint64_t nonce_length, cipher_state_t * restrict cs)
{
    if(nonce_length == 96) { //normal case - only case for IPsec
        #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
            cs->counter.d[0] = ((uint64_t *) nonce)[0];
            cs->counter.s[2] = ((uint32_t *) nonce)[2];
            cs->counter.s[3] = 1;
        #else
            //note we want to get correct byte order when loading contiguous quadword
            cs->counter.s[0] = (((uint32_t *) nonce)[0]);
            cs->counter.s[1] = (((uint32_t *) nonce)[1]);
            cs->counter.s[2] = (((uint32_t *) nonce)[2]);
            cs->counter.s[3] = __builtin_bswap32(1u);
        #endif
        return SUCCESSFUL_OPERATION;
    } else {
        operation_result_t result_status = SUCCESSFUL_OPERATION;
        quadword_t final_block; // [0]_64 | [len(IV)]_64
                                // MSB --> LSB | MSB --> LSB

        cs->current_tag.d[0] = 0;
        cs->current_tag.d[1] = 0;

        #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
            final_block.d[0] = nonce_length;
            final_block.d[1] = 0;
        #else
            final_block.d[0] = 0;
            final_block.d[1] = __builtin_bswap64(nonce_length);
        #endif

        result_status |= ghash_kernel(nonce, nonce_length, cs);
        result_status |= ghash_kernel(final_block.b, 128, cs);

        cs->counter.d[0] = __builtin_bswap64(cs->current_tag.d[1]);
        cs->counter.d[1] = __builtin_bswap64(cs->current_tag.d[0]);
        cs->current_tag.d[0] = 0;
        cs->current_tag.d[1] = 0;
        return result_status;
    }
}

//Assume input_length is a multiple of 8 (bit_length but describing a byte string)
//Assume we can read up to floor(input_length/128)*16 bytes beyond input
static operation_result_t ghash_kernel(uint8_t * restrict input, uint64_t input_length, cipher_state_t * restrict cs)
{
    // Conceptually:
    // For each block of input:
    //   EOR current_tag with block
    //   128b Polynomial multiply result by hash_key
    //   Modulo reduce 256b multiplication result by R (== (1<<128)&0x87) into current_tag

    //if input_length isn't multiple of 16B (multiple of 128), round up to nearest multiple
    uint64_t full_blocks = input_length >> 7;

    uint64_t last_block_bytes = (input_length & 127ul)>>3;
    //Might need to load a mask if last block is not a full block
    const uint8_t tag_mask[32] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t * in_ptr = input;

    poly64x2_t hash_key_0 = (poly64x2_t) vld1q_u64(cs->constants->expanded_hash_keys[0].d);
    poly64_t hash_karat_0 = (poly64_t) veor_u64(vget_high_u64(hash_key_0), vget_low_u64(hash_key_0));
    poly64_t modulo_const = (poly64_t) 0xC200000000000000ul;
    uint8x16_t low_acc = vld1q_u8(cs->current_tag.b);
#if MAX_UNROLL_FACTOR >= 4
#define GHASH_UNROLL_FACTOR 4
    // Actually want to unroll to act on multiple blocks at a time so:
    // For each 4 consecutive blocks:
    //   EOR current_tag with most significant (0th) block
    //   For i in [0, GHASH_UNROLL_FACTOR-1]:
    //     Partial 128b Polynomial multiply block(i) by hash_key**(GHASH_UNROLL_FACTOR-i), accumulating partial results in 3 128b accumulators (h, m and l)
    //   Modulo reduce 384b of accumulators by R into current_tag
    poly64x2_t hash_key_1 = (poly64x2_t) vld1q_u64(cs->constants->expanded_hash_keys[1].d);
    poly64_t hash_karat_1 = (poly64_t) veor_u64(vget_high_u64(hash_key_1), vget_low_u64(hash_key_1));
    poly64x2_t hash_key_2 = (poly64x2_t) vld1q_u64(cs->constants->expanded_hash_keys[2].d);
    poly64_t hash_karat_2 = (poly64_t) veor_u64(vget_high_u64(hash_key_2), vget_low_u64(hash_key_2));
    poly64x2_t hash_key_3 = (poly64x2_t) vld1q_u64(cs->constants->expanded_hash_keys[3].d);
    poly64_t hash_karat_3 = (poly64_t) veor_u64(vget_high_u64(hash_key_3), vget_low_u64(hash_key_3));

    while( full_blocks > GHASH_UNROLL_FACTOR )
    {
        full_blocks -= 4;
        low_acc = vextq_u8(low_acc, low_acc, 8);
        poly64x2_t block_3 = vreinterpretq_p64_u8(vld1q_u8(in_ptr));
        poly64x2_t block_2 = vreinterpretq_p64_u8(vld1q_u8(in_ptr+16));
        poly64x2_t block_1 = vreinterpretq_p64_u8(vld1q_u8(in_ptr+32));
        poly64x2_t block_0 = vreinterpretq_p64_u8(vld1q_u8(in_ptr+48));
        block_3 = vrev64q_u8(block_3);
        block_2 = vrev64q_u8(block_2);
        block_1 = vrev64q_u8(block_1);
        block_0 = vrev64q_u8(block_0);
        block_3 = veorq_u64(block_3, low_acc);
        poly64_t block_karat_3 = (poly64_t) veor_u64(vget_high_u64(block_3),vget_low_u64(block_3));
        poly64_t block_karat_2 = (poly64_t) veor_u64(vget_high_u64(block_2),vget_low_u64(block_2));
        poly64_t block_karat_1 = (poly64_t) veor_u64(vget_high_u64(block_1),vget_low_u64(block_1));
        poly64_t block_karat_0 = (poly64_t) veor_u64(vget_high_u64(block_0),vget_low_u64(block_0));

        //multiply
        poly128_t t_high_3 = vmull_high_p64(block_3, hash_key_3);
        poly128_t t_low_3  = vmull_p64((poly64_t) vget_low_p64(block_3), (poly64_t) vget_low_p64(hash_key_3));
        poly128_t t_mid_3  = vmull_p64(block_karat_3, hash_karat_3);
        poly128_t t_high_2 = vmull_high_p64(block_2, hash_key_2);
        poly128_t t_low_2  = vmull_p64((poly64_t) vget_low_p64(block_2), (poly64_t) vget_low_p64(hash_key_2));
        poly128_t t_mid_2  = vmull_p64(block_karat_2, hash_karat_2);
        poly128_t t_high_1 = vmull_high_p64(block_1, hash_key_1);
        poly128_t t_low_1  = vmull_p64((poly64_t) vget_low_p64(block_1), (poly64_t) vget_low_p64(hash_key_1));
        poly128_t t_mid_1  = vmull_p64(block_karat_1, hash_karat_1);
        poly128_t t_high_0 = vmull_high_p64(block_0, hash_key_0);
        poly128_t t_low_0  = vmull_p64((poly64_t) vget_low_p64(block_0), (poly64_t) vget_low_p64(hash_key_0));
        poly128_t t_mid_0  = vmull_p64(block_karat_0, hash_karat_0);

        //accumulate up temps
        poly64x2_t high_acc_2 = veorq_u64(vreinterpretq_u64_p128(t_high_3), vreinterpretq_u64_p128(t_high_2));
        poly64x2_t mid_acc_2  = veorq_u64(vreinterpretq_u64_p128(t_mid_3) , vreinterpretq_u64_p128(t_mid_2) );
        poly64x2_t low_acc_2  = veorq_u64(vreinterpretq_u64_p128(t_low_3) , vreinterpretq_u64_p128(t_low_2) );
        poly64x2_t high_acc = veorq_u64(vreinterpretq_u64_p128(t_high_1), vreinterpretq_u64_p128(t_high_0));
        poly64x2_t mid_acc  = veorq_u64(vreinterpretq_u64_p128(t_mid_1) , vreinterpretq_u64_p128(t_mid_0) );
        low_acc  = veorq_u64(vreinterpretq_u64_p128(t_low_1) , vreinterpretq_u64_p128(t_low_0) );
        high_acc = veorq_u64(high_acc, high_acc_2);
        mid_acc  = veorq_u64(mid_acc , mid_acc_2 );
        low_acc  = veorq_u64(low_acc , low_acc_2 );
        //tidy up karatsuba
        mid_acc  = veorq_u64(mid_acc, high_acc);
        mid_acc  = veorq_u64(mid_acc, low_acc );

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64((poly64_t) vget_low_p64(vreinterpretq_u64_p128(high_acc)), modulo_const);
        high_acc = vextq_u8(high_acc, high_acc, 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64((poly64_t) vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(low_acc, vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
        in_ptr += 64;
    }
#undef GHASH_UNROLL_FACTOR
#endif
    //deal with tail
    for( uint64_t i=0; i<full_blocks; ++i )
    {
        low_acc = vextq_u8(low_acc, low_acc, 8);
        poly64x2_t block = vreinterpretq_p64_u8(vld1q_u8(in_ptr));
        block = vrev64q_u8(block);
        block = veorq_u64(block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(block),vget_low_u64(block));

        //multiply
        poly128_t t_high = vmull_high_p64(block, hash_key_0);
        poly128_t t_low  = vmull_p64((poly64_t) vget_low_p64(block), (poly64_t) vget_low_p64(hash_key_0));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat_0);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64((poly64_t) vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64((poly64_t) vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
        in_ptr += 16;
    }
    if(last_block_bytes)
    {
        low_acc = vextq_u8(low_acc, low_acc, 8);
        uint64x2_t mask = vld1q_u8(tag_mask+16-last_block_bytes);
        poly64x2_t block = vreinterpretq_p64_u8(vld1q_u8(in_ptr));
        block = vandq_u64(block, mask);
        block = vrev64q_u8(block);
        block = veorq_u64(block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(block),vget_low_u64(block));

        //multiply
        poly128_t t_high = vmull_high_p64(block, hash_key_0);
        poly128_t t_low  = vmull_p64((poly64_t) vget_low_p64(block), (poly64_t) vget_low_p64(hash_key_0));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat_0);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64((poly64_t) vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64((poly64_t) vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }

    vst1q_u8(cs->current_tag.b, low_acc);
    return SUCCESSFUL_OPERATION;
}

static operation_result_t aes_ctr_blk_128_kernel(uint64_t block_count, cipher_state_t * restrict cs, uint8_t * restrict blocks)
{
    uint8x16_t counter = vld1q_u8(cs->counter.b);
    uint32_t counter_word;
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        counter_word = cs->counter.s[3];
    #else
        counter_word = __builtin_bswap32(cs->counter.s[3]);
    #endif
    uint8x16_t k0  = vld1q_u8(cs->constants->expanded_aes_keys[0].b);
    uint8x16_t k1  = vld1q_u8(cs->constants->expanded_aes_keys[1].b);
    uint8x16_t k2  = vld1q_u8(cs->constants->expanded_aes_keys[2].b);
    uint8x16_t k3  = vld1q_u8(cs->constants->expanded_aes_keys[3].b);
    uint8x16_t k4  = vld1q_u8(cs->constants->expanded_aes_keys[4].b);
    uint8x16_t k5  = vld1q_u8(cs->constants->expanded_aes_keys[5].b);
    uint8x16_t k6  = vld1q_u8(cs->constants->expanded_aes_keys[6].b);
    uint8x16_t k7  = vld1q_u8(cs->constants->expanded_aes_keys[7].b);
    uint8x16_t k8  = vld1q_u8(cs->constants->expanded_aes_keys[8].b);
    uint8x16_t k9  = vld1q_u8(cs->constants->expanded_aes_keys[9].b);
    uint8x16_t k10 = vld1q_u8(cs->constants->expanded_aes_keys[10].b);

    uint8_t * block_ptr = blocks;

    // Do aes-ctr on the number of blocks, using and updating the counter in cs
    for( uint64_t i=0; i!=block_count; ++i )
    {
        uint8x16_t block  = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);

        block = vaeseq_u8(block, k0); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k1); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k2); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k3); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k4); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k5); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k6); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k7); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k8); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k9);
        block = veorq_u8(block, k10);

        vst1q_u8(block_ptr, block);
        block_ptr += 16;
        counter_word++;
    }

    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        cs->counter.s[3] = counter_word;
    #else
        cs->counter.s[3] = __builtin_bswap32(counter_word);
    #endif
    return SUCCESSFUL_OPERATION;
}

static operation_result_t aes_ctr_blk_192_kernel(uint64_t block_count, cipher_state_t * restrict cs, uint8_t * restrict blocks)
{
    uint8x16_t counter = vld1q_u8(cs->counter.b);
    uint32_t counter_word;
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        counter_word = cs->counter.s[3];
    #else
        counter_word = __builtin_bswap32(cs->counter.s[3]);
    #endif
    uint8x16_t k0  = vld1q_u8(cs->constants->expanded_aes_keys[0].b);
    uint8x16_t k1  = vld1q_u8(cs->constants->expanded_aes_keys[1].b);
    uint8x16_t k2  = vld1q_u8(cs->constants->expanded_aes_keys[2].b);
    uint8x16_t k3  = vld1q_u8(cs->constants->expanded_aes_keys[3].b);
    uint8x16_t k4  = vld1q_u8(cs->constants->expanded_aes_keys[4].b);
    uint8x16_t k5  = vld1q_u8(cs->constants->expanded_aes_keys[5].b);
    uint8x16_t k6  = vld1q_u8(cs->constants->expanded_aes_keys[6].b);
    uint8x16_t k7  = vld1q_u8(cs->constants->expanded_aes_keys[7].b);
    uint8x16_t k8  = vld1q_u8(cs->constants->expanded_aes_keys[8].b);
    uint8x16_t k9  = vld1q_u8(cs->constants->expanded_aes_keys[9].b);
    uint8x16_t k10 = vld1q_u8(cs->constants->expanded_aes_keys[10].b);
    uint8x16_t k11 = vld1q_u8(cs->constants->expanded_aes_keys[11].b);
    uint8x16_t k12 = vld1q_u8(cs->constants->expanded_aes_keys[12].b);

    uint8_t * block_ptr = blocks;

    // Do aes-ctr on the number of blocks, using and updating the counter in cs
    for( uint64_t i=0; i!=block_count; ++i )
    {
        uint8x16_t block  = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);

        block = vaeseq_u8(block, k0); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k1); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k2); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k3); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k4); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k5); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k6); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k7); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k8); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k9); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k10); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k11);
        block = veorq_u8(block, k12);

        vst1q_u8(block_ptr, block);
        block_ptr += 16;
        counter_word++;
    }

    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        cs->counter.s[3] = counter_word;
    #else
        cs->counter.s[3] = __builtin_bswap32(counter_word);
    #endif
    return SUCCESSFUL_OPERATION;
}

static operation_result_t aes_ctr_blk_256_kernel(uint64_t block_count, cipher_state_t * restrict cs, uint8_t * restrict blocks)
{
    uint8x16_t counter = vld1q_u8(cs->counter.b);
    uint32_t counter_word;
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        counter_word = cs->counter.s[3];
    #else
        counter_word = __builtin_bswap32(cs->counter.s[3]);
    #endif
    uint8x16_t k0  = vld1q_u8(cs->constants->expanded_aes_keys[0].b);
    uint8x16_t k1  = vld1q_u8(cs->constants->expanded_aes_keys[1].b);
    uint8x16_t k2  = vld1q_u8(cs->constants->expanded_aes_keys[2].b);
    uint8x16_t k3  = vld1q_u8(cs->constants->expanded_aes_keys[3].b);
    uint8x16_t k4  = vld1q_u8(cs->constants->expanded_aes_keys[4].b);
    uint8x16_t k5  = vld1q_u8(cs->constants->expanded_aes_keys[5].b);
    uint8x16_t k6  = vld1q_u8(cs->constants->expanded_aes_keys[6].b);
    uint8x16_t k7  = vld1q_u8(cs->constants->expanded_aes_keys[7].b);
    uint8x16_t k8  = vld1q_u8(cs->constants->expanded_aes_keys[8].b);
    uint8x16_t k9  = vld1q_u8(cs->constants->expanded_aes_keys[9].b);
    uint8x16_t k10 = vld1q_u8(cs->constants->expanded_aes_keys[10].b);
    uint8x16_t k11 = vld1q_u8(cs->constants->expanded_aes_keys[11].b);
    uint8x16_t k12 = vld1q_u8(cs->constants->expanded_aes_keys[12].b);
    uint8x16_t k13 = vld1q_u8(cs->constants->expanded_aes_keys[13].b);
    uint8x16_t k14 = vld1q_u8(cs->constants->expanded_aes_keys[14].b);

    uint8_t * block_ptr = blocks;

    // Do aes-ctr on the number of blocks, using and updating the counter in cs
    for( uint64_t i=0; i!=block_count; ++i )
    {
        uint8x16_t block  = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);

        block = vaeseq_u8(block, k0); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k1); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k2); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k3); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k4); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k5); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k6); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k7); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k8); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k9); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k10); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k11); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k12); block = vaesmcq_u8(block);
        block = vaeseq_u8(block, k13);
        block = veorq_u8(block, k14);

        vst1q_u8(block_ptr, block);
        block_ptr += 16;
        counter_word++;
    }

    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        cs->counter.s[3] = counter_word;
    #else
        cs->counter.s[3] = __builtin_bswap32(counter_word);
    #endif
    return SUCCESSFUL_OPERATION;
}

#ifdef PERF_GCM_LITTLE
    #include "AArch64cryptolib_opt_LITTLE/aes_gcm/enc/aes_gcm_enc_128_kernel__interleaved.c"
#else
    #ifdef PERF_GCM_BIG
        #include "AArch64cryptolib_opt_big/aes_gcm/enc/aes_gcm_enc_128_kernel__interleaved.c"
    #else
        #ifdef PERF_GCM_BIGGER
            #ifdef PERF_GCM_BIGGEREOR3
                #include "AArch64cryptolib_opt_bigger/aes_gcm/enc/aes_gcm_enc_128_kernel_EOR3__interleaved.c"
            #else
                #include "AArch64cryptolib_opt_bigger/aes_gcm/enc/aes_gcm_enc_128_kernel__interleaved.c"
            #endif
        #else
static operation_result_t aes_gcm_enc_128_kernel(uint8_t * plaintext, uint64_t plaintext_length, cipher_state_t * restrict cs, uint8_t * ciphertext)
{
    if(plaintext_length == 0) {
        return SUCCESSFUL_OPERATION;
    }

    uint64_t full_blocks = plaintext_length >> 7;

    uint8x16_t counter = vld1q_u8(cs->counter.b);
    uint32_t counter_word;
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        counter_word = cs->counter.s[3];
    #else
        counter_word = __builtin_bswap32(cs->counter.s[3]);
    #endif
    uint8x16_t k0  = vld1q_u8(cs->constants->expanded_aes_keys[0].b);
    uint8x16_t k1  = vld1q_u8(cs->constants->expanded_aes_keys[1].b);
    uint8x16_t k2  = vld1q_u8(cs->constants->expanded_aes_keys[2].b);
    uint8x16_t k3  = vld1q_u8(cs->constants->expanded_aes_keys[3].b);
    uint8x16_t k4  = vld1q_u8(cs->constants->expanded_aes_keys[4].b);
    uint8x16_t k5  = vld1q_u8(cs->constants->expanded_aes_keys[5].b);
    uint8x16_t k6  = vld1q_u8(cs->constants->expanded_aes_keys[6].b);
    uint8x16_t k7  = vld1q_u8(cs->constants->expanded_aes_keys[7].b);
    uint8x16_t k8  = vld1q_u8(cs->constants->expanded_aes_keys[8].b);
    uint8x16_t k9  = vld1q_u8(cs->constants->expanded_aes_keys[9].b);
    uint8x16_t k10 = vld1q_u8(cs->constants->expanded_aes_keys[10].b);

    poly64x2_t hash_key = (poly64x2_t) vld1q_u64(cs->constants->expanded_hash_keys[0].d);
    poly64_t hash_karat = (poly64_t) veor_u64(vget_high_u64(hash_key), vget_low_u64(hash_key));
    poly64_t modulo_const = (poly64_t) 0xC200000000000000ul;
    uint8x16_t low_acc = vld1q_u8(cs->current_tag.b);

    uint8_t * in_ptr  = plaintext;
    uint8_t * out_ptr = ciphertext;

    // Do aes-gcm on the number of blocks, using and updating the counter in cs
    for( uint64_t i=0; i<full_blocks; ++i )
    {
        uint8x16_t enc_block = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);
        uint8x16_t plain_block = vld1q_u8(in_ptr);
        in_ptr  += 16;

        enc_block = vaeseq_u8(enc_block, k0); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k1); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k2); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k3); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k4); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k5); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k6); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k7); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k8); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k9);
        enc_block = veorq_u8(enc_block, k10);

        uint8x16_t cipher_block = veorq_u8(enc_block, plain_block);
        vst1q_u8(out_ptr, cipher_block);
        out_ptr += 16;
        counter_word++;

        low_acc = vextq_u8(low_acc, low_acc, 8);
        cipher_block = vrev64q_u8(cipher_block);
        cipher_block = veorq_u64(cipher_block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(cipher_block),vget_low_u64(cipher_block));

        //multiply
        poly128_t t_high = vmull_high_p64(cipher_block, hash_key);
        poly128_t t_low  = vmull_p64(vget_low_p64(cipher_block), vget_low_p64(hash_key));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64(vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64(vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }
    if(plaintext_length & 127ul) //possibly need to do final non-full block
    {
        //Generate enc_mask to zero out bits of enc_block which are not used
        uint8_t zero_bits = (uint8_t) 128-(plaintext_length & 127ul);
        uint64x2_t enc_mask = { 0, 0 };
        if(zero_bits < 64) {
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul, enc_mask, 0);
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul >> zero_bits, enc_mask, 1);
        } else {
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul >> (zero_bits-64), enc_mask, 0);
            enc_mask = vsetq_lane_u64(0, enc_mask, 1);
        }

        uint8x16_t enc_block = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);
        uint8x16_t plain_block = vld1q_u8(in_ptr);
        in_ptr  += 16;
        uint8x16_t tail_block = vld1q_u8(out_ptr);

        enc_block = vaeseq_u8(enc_block, k0); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k1); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k2); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k3); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k4); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k5); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k6); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k7); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k8); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k9);
        enc_block = veorq_u8(enc_block, k10);

        uint8x16_t cipher_block = veorq_u8(enc_block, plain_block); //encrypt the whole plaintext block
        tail_block = vbicq_u8(tail_block, enc_mask); //clear region where encryption will go
        cipher_block = vandq_u8(cipher_block, enc_mask); //clear invalid region of full ciphertext block
        tail_block = vorrq_u8(tail_block, cipher_block); //block ready to be saved

        vst1q_u8(out_ptr, tail_block); //save tail memory region, preserving beyond ciphertext
        out_ptr += 16;
        counter_word++;

        low_acc = vextq_u8(low_acc, low_acc, 8);
        cipher_block = vrev64q_u8(cipher_block);
        cipher_block = veorq_u64(cipher_block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(cipher_block),vget_low_u64(cipher_block));

        //multiply
        poly128_t t_high = vmull_high_p64(cipher_block, hash_key);
        poly128_t t_low  = vmull_p64(vget_low_p64(cipher_block), vget_low_p64(hash_key));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64(vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64(vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }

    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        cs->counter.s[3] = counter_word;
    #else
        cs->counter.s[3] = __builtin_bswap32(counter_word);
    #endif

    vst1q_u8(cs->current_tag.b, low_acc);

    return SUCCESSFUL_OPERATION;
}
        #endif
    #endif
#endif

#ifdef PERF_GCM_LITTLE
    #include "AArch64cryptolib_opt_LITTLE/aes_gcm/enc/aes_gcm_enc_192_kernel__interleaved.c"
#else
    #ifdef PERF_GCM_BIG
        #include "AArch64cryptolib_opt_big/aes_gcm/enc/aes_gcm_enc_192_kernel__interleaved.c"
    #else
        #ifdef PERF_GCM_BIGGER
            #ifdef PERF_GCM_BIGGEREOR3
                #include "AArch64cryptolib_opt_bigger/aes_gcm/enc/aes_gcm_enc_192_kernel_EOR3__interleaved.c"
            #else
                #include "AArch64cryptolib_opt_bigger/aes_gcm/enc/aes_gcm_enc_192_kernel__interleaved.c"
            #endif
        #else
static operation_result_t aes_gcm_enc_192_kernel(uint8_t * plaintext, uint64_t plaintext_length, cipher_state_t * restrict cs, uint8_t * ciphertext)
{
    if(plaintext_length == 0) {
        return SUCCESSFUL_OPERATION;
    }

    uint64_t full_blocks = plaintext_length >> 7;

    uint8x16_t counter = vld1q_u8(cs->counter.b);
    uint32_t counter_word;
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        counter_word = cs->counter.s[3];
    #else
        counter_word = __builtin_bswap32(cs->counter.s[3]);
    #endif
    uint8x16_t k0  = vld1q_u8(cs->constants->expanded_aes_keys[0].b);
    uint8x16_t k1  = vld1q_u8(cs->constants->expanded_aes_keys[1].b);
    uint8x16_t k2  = vld1q_u8(cs->constants->expanded_aes_keys[2].b);
    uint8x16_t k3  = vld1q_u8(cs->constants->expanded_aes_keys[3].b);
    uint8x16_t k4  = vld1q_u8(cs->constants->expanded_aes_keys[4].b);
    uint8x16_t k5  = vld1q_u8(cs->constants->expanded_aes_keys[5].b);
    uint8x16_t k6  = vld1q_u8(cs->constants->expanded_aes_keys[6].b);
    uint8x16_t k7  = vld1q_u8(cs->constants->expanded_aes_keys[7].b);
    uint8x16_t k8  = vld1q_u8(cs->constants->expanded_aes_keys[8].b);
    uint8x16_t k9  = vld1q_u8(cs->constants->expanded_aes_keys[9].b);
    uint8x16_t k10 = vld1q_u8(cs->constants->expanded_aes_keys[10].b);
    uint8x16_t k11 = vld1q_u8(cs->constants->expanded_aes_keys[11].b);
    uint8x16_t k12 = vld1q_u8(cs->constants->expanded_aes_keys[12].b);

    poly64x2_t hash_key = (poly64x2_t) vld1q_u64(cs->constants->expanded_hash_keys[0].d);
    poly64_t hash_karat = (poly64_t) veor_u64(vget_high_u64(hash_key), vget_low_u64(hash_key));
    poly64_t modulo_const = (poly64_t) 0xC200000000000000ul;
    uint8x16_t low_acc = vld1q_u8(cs->current_tag.b);

    uint8_t * in_ptr  = plaintext;
    uint8_t * out_ptr = ciphertext;

    // Do aes-gcm on the number of blocks, using and updating the counter in cs
    for( uint64_t i=0; i<full_blocks; ++i )
    {
        uint8x16_t enc_block = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);
        uint8x16_t plain_block = vld1q_u8(in_ptr);
        in_ptr  += 16;

        enc_block = vaeseq_u8(enc_block, k0); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k1); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k2); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k3); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k4); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k5); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k6); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k7); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k8); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k9); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k10); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k11);
        enc_block = veorq_u8(enc_block, k12);

        uint8x16_t cipher_block = veorq_u8(enc_block, plain_block);
        vst1q_u8(out_ptr, cipher_block);
        out_ptr += 16;
        counter_word++;

        low_acc = vextq_u8(low_acc, low_acc, 8);
        cipher_block = vrev64q_u8(cipher_block);
        cipher_block = veorq_u64(cipher_block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(cipher_block),vget_low_u64(cipher_block));

        //multiply
        poly128_t t_high = vmull_high_p64(cipher_block, hash_key);
        poly128_t t_low  = vmull_p64(vget_low_p64(cipher_block), vget_low_p64(hash_key));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64(vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64(vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }
    if(plaintext_length & 127ul) //possibly need to do final non-full block
    {
        //Generate enc_mask to zero out bits of enc_block which are not used
        uint8_t zero_bits = (uint8_t) 128-(plaintext_length & 127ul);
        uint64x2_t enc_mask = { 0, 0 };
        if(zero_bits < 64) {
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul, enc_mask, 0);
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul >> zero_bits, enc_mask, 1);
        } else {
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul >> (zero_bits-64), enc_mask, 0);
            enc_mask = vsetq_lane_u64(0, enc_mask, 1);
        }

        uint8x16_t enc_block = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);
        uint8x16_t plain_block = vld1q_u8(in_ptr);
        in_ptr  += 16;
        uint8x16_t tail_block = vld1q_u8(out_ptr);

        enc_block = vaeseq_u8(enc_block, k0); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k1); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k2); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k3); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k4); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k5); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k6); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k7); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k8); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k9); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k10); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k11);
        enc_block = veorq_u8(enc_block, k12);

        uint8x16_t cipher_block = veorq_u8(enc_block, plain_block); //encrypt the whole plaintext block
        tail_block = vbicq_u8(tail_block, enc_mask); //clear region where encryption will go
        cipher_block = vandq_u8(cipher_block, enc_mask); //clear invalid region of full ciphertext block
        tail_block = vorrq_u8(tail_block, cipher_block); //block ready to be saved

        vst1q_u8(out_ptr, tail_block); //save tail memory region, preserving beyond ciphertext
        out_ptr += 16;
        counter_word++;

        low_acc = vextq_u8(low_acc, low_acc, 8);
        cipher_block = vrev64q_u8(cipher_block);
        cipher_block = veorq_u64(cipher_block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(cipher_block),vget_low_u64(cipher_block));

        //multiply
        poly128_t t_high = vmull_high_p64(cipher_block, hash_key);
        poly128_t t_low  = vmull_p64(vget_low_p64(cipher_block), vget_low_p64(hash_key));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64(vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64(vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }

    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        cs->counter.s[3] = counter_word;
    #else
        cs->counter.s[3] = __builtin_bswap32(counter_word);
    #endif

    vst1q_u8(cs->current_tag.b, low_acc);

    return SUCCESSFUL_OPERATION;
}
        #endif
    #endif
#endif

#ifdef PERF_GCM_LITTLE
    #include "AArch64cryptolib_opt_LITTLE/aes_gcm/enc/aes_gcm_enc_256_kernel__interleaved.c"
#else
    #ifdef PERF_GCM_BIG
        #include "AArch64cryptolib_opt_big/aes_gcm/enc/aes_gcm_enc_256_kernel__interleaved.c"
    #else
        #ifdef PERF_GCM_BIGGER
            #ifdef PERF_GCM_BIGGEREOR3
                #include "AArch64cryptolib_opt_bigger/aes_gcm/enc/aes_gcm_enc_256_kernel_EOR3__interleaved.c"
            #else
                #include "AArch64cryptolib_opt_bigger/aes_gcm/enc/aes_gcm_enc_256_kernel__interleaved.c"
            #endif
        #else
static operation_result_t aes_gcm_enc_256_kernel(uint8_t * plaintext, uint64_t plaintext_length, cipher_state_t * restrict cs, uint8_t * ciphertext)
{
    if(plaintext_length == 0) {
        return SUCCESSFUL_OPERATION;
    }

    uint64_t full_blocks = plaintext_length >> 7;

    uint8x16_t counter = vld1q_u8(cs->counter.b);
    uint32_t counter_word;
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        counter_word = cs->counter.s[3];
    #else
        counter_word = __builtin_bswap32(cs->counter.s[3]);
    #endif
    uint8x16_t k0  = vld1q_u8(cs->constants->expanded_aes_keys[0].b);
    uint8x16_t k1  = vld1q_u8(cs->constants->expanded_aes_keys[1].b);
    uint8x16_t k2  = vld1q_u8(cs->constants->expanded_aes_keys[2].b);
    uint8x16_t k3  = vld1q_u8(cs->constants->expanded_aes_keys[3].b);
    uint8x16_t k4  = vld1q_u8(cs->constants->expanded_aes_keys[4].b);
    uint8x16_t k5  = vld1q_u8(cs->constants->expanded_aes_keys[5].b);
    uint8x16_t k6  = vld1q_u8(cs->constants->expanded_aes_keys[6].b);
    uint8x16_t k7  = vld1q_u8(cs->constants->expanded_aes_keys[7].b);
    uint8x16_t k8  = vld1q_u8(cs->constants->expanded_aes_keys[8].b);
    uint8x16_t k9  = vld1q_u8(cs->constants->expanded_aes_keys[9].b);
    uint8x16_t k10 = vld1q_u8(cs->constants->expanded_aes_keys[10].b);
    uint8x16_t k11 = vld1q_u8(cs->constants->expanded_aes_keys[11].b);
    uint8x16_t k12 = vld1q_u8(cs->constants->expanded_aes_keys[12].b);
    uint8x16_t k13 = vld1q_u8(cs->constants->expanded_aes_keys[13].b);
    uint8x16_t k14 = vld1q_u8(cs->constants->expanded_aes_keys[14].b);

    poly64x2_t hash_key = (poly64x2_t) vld1q_u64(cs->constants->expanded_hash_keys[0].d);
    poly64_t hash_karat = (poly64_t) veor_u64(vget_high_u64(hash_key), vget_low_u64(hash_key));
    poly64_t modulo_const = (poly64_t) 0xC200000000000000ul;
    uint8x16_t low_acc = vld1q_u8(cs->current_tag.b);

    uint8_t * in_ptr  = plaintext;
    uint8_t * out_ptr = ciphertext;

    // Do aes-gcm on the number of blocks, using and updating the counter in cs
    for( uint64_t i=0; i<full_blocks; ++i )
    {
        uint8x16_t enc_block = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);
        uint8x16_t plain_block = vld1q_u8(in_ptr);
        in_ptr  += 16;

        enc_block = vaeseq_u8(enc_block, k0); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k1); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k2); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k3); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k4); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k5); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k6); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k7); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k8); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k9); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k10); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k11); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k12); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k13);
        enc_block = veorq_u8(enc_block, k14);

        uint8x16_t cipher_block = veorq_u8(enc_block, plain_block);
        vst1q_u8(out_ptr, cipher_block);
        out_ptr += 16;
        counter_word++;

        low_acc = vextq_u8(low_acc, low_acc, 8);
        cipher_block = vrev64q_u8(cipher_block);
        cipher_block = veorq_u64(cipher_block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(cipher_block),vget_low_u64(cipher_block));

        //multiply
        poly128_t t_high = vmull_high_p64(cipher_block, hash_key);
        poly128_t t_low  = vmull_p64(vget_low_p64(cipher_block), vget_low_p64(hash_key));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64(vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64(vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }
    if(plaintext_length & 127ul) //possibly need to do final non-full block
    {
        //Generate enc_mask to zero out bits of enc_block which are not used
        uint8_t zero_bits = (uint8_t) 128-(plaintext_length & 127ul);
        uint64x2_t enc_mask = { 0, 0 };
        if(zero_bits < 64) {
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul, enc_mask, 0);
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul >> zero_bits, enc_mask, 1);
        } else {
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul >> (zero_bits-64), enc_mask, 0);
            enc_mask = vsetq_lane_u64(0, enc_mask, 1);
        }

        uint8x16_t enc_block = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);
        uint8x16_t plain_block = vld1q_u8(in_ptr);
        in_ptr  += 16;
        uint8x16_t tail_block = vld1q_u8(out_ptr);

        enc_block = vaeseq_u8(enc_block, k0); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k1); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k2); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k3); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k4); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k5); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k6); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k7); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k8); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k9); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k10); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k11); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k12); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k13);
        enc_block = veorq_u8(enc_block, k14);

        uint8x16_t cipher_block = veorq_u8(enc_block, plain_block); //encrypt the whole plaintext block
        tail_block = vbicq_u8(tail_block, enc_mask); //clear region where encryption will go
        cipher_block = vandq_u8(cipher_block, enc_mask); //clear invalid region of full ciphertext block
        tail_block = vorrq_u8(tail_block, cipher_block); //block ready to be saved

        vst1q_u8(out_ptr, tail_block); //save tail memory region, preserving beyond ciphertext
        out_ptr += 16;
        counter_word++;

        low_acc = vextq_u8(low_acc, low_acc, 8);
        cipher_block = vrev64q_u8(cipher_block);
        cipher_block = veorq_u64(cipher_block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(cipher_block),vget_low_u64(cipher_block));

        //multiply
        poly128_t t_high = vmull_high_p64(cipher_block, hash_key);
        poly128_t t_low  = vmull_p64(vget_low_p64(cipher_block), vget_low_p64(hash_key));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64(vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64(vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }

    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        cs->counter.s[3] = counter_word;
    #else
        cs->counter.s[3] = __builtin_bswap32(counter_word);
    #endif

    vst1q_u8(cs->current_tag.b, low_acc);

    return SUCCESSFUL_OPERATION;
}
        #endif
    #endif
#endif

#ifdef PERF_GCM_LITTLE
    #include "AArch64cryptolib_opt_LITTLE/aes_gcm/dec/aes_gcm_dec_128_kernel__interleaved.c"
#else
    #ifdef PERF_GCM_BIG
        #include "AArch64cryptolib_opt_big/aes_gcm/dec/aes_gcm_dec_128_kernel__interleaved.c"
    #else
        #ifdef PERF_GCM_BIGGER
            #ifdef PERF_GCM_BIGGEREOR3
                #include "AArch64cryptolib_opt_bigger/aes_gcm/dec/aes_gcm_dec_128_kernel_EOR3__interleaved.c"
            #else
                #include "AArch64cryptolib_opt_bigger/aes_gcm/dec/aes_gcm_dec_128_kernel__interleaved.c"
            #endif
        #else
static operation_result_t aes_gcm_dec_128_kernel(uint8_t * ciphertext, uint64_t ciphertext_length, cipher_state_t * restrict cs, uint8_t * plaintext)
{
    if(ciphertext_length == 0) {
        return SUCCESSFUL_OPERATION;
    }

    uint64_t full_blocks = ciphertext_length >> 7;

    uint8x16_t counter = vld1q_u8(cs->counter.b);
    uint32_t counter_word;
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        counter_word = cs->counter.s[3];
    #else
        counter_word = __builtin_bswap32(cs->counter.s[3]);
    #endif
    uint8x16_t k0  = vld1q_u8(cs->constants->expanded_aes_keys[0].b);
    uint8x16_t k1  = vld1q_u8(cs->constants->expanded_aes_keys[1].b);
    uint8x16_t k2  = vld1q_u8(cs->constants->expanded_aes_keys[2].b);
    uint8x16_t k3  = vld1q_u8(cs->constants->expanded_aes_keys[3].b);
    uint8x16_t k4  = vld1q_u8(cs->constants->expanded_aes_keys[4].b);
    uint8x16_t k5  = vld1q_u8(cs->constants->expanded_aes_keys[5].b);
    uint8x16_t k6  = vld1q_u8(cs->constants->expanded_aes_keys[6].b);
    uint8x16_t k7  = vld1q_u8(cs->constants->expanded_aes_keys[7].b);
    uint8x16_t k8  = vld1q_u8(cs->constants->expanded_aes_keys[8].b);
    uint8x16_t k9  = vld1q_u8(cs->constants->expanded_aes_keys[9].b);
    uint8x16_t k10 = vld1q_u8(cs->constants->expanded_aes_keys[10].b);

    poly64x2_t hash_key = (poly64x2_t) vld1q_u64(cs->constants->expanded_hash_keys[0].d);
    poly64_t hash_karat = (poly64_t) veor_u64(vget_high_u64(hash_key), vget_low_u64(hash_key));
    poly64_t modulo_const = (poly64_t) 0xC200000000000000ul;
    uint8x16_t low_acc = vld1q_u8(cs->current_tag.b);

    uint8_t * in_ptr  = ciphertext;
    uint8_t * out_ptr = plaintext;

    // Do aes-gcm on the number of blocks, using and updating the counter in cs
    for( uint64_t i=0; i<full_blocks; ++i )
    {
        uint8x16_t enc_block = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);
        uint8x16_t cipher_block = vld1q_u8(in_ptr);
        in_ptr  += 16;

        enc_block = vaeseq_u8(enc_block, k0); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k1); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k2); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k3); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k4); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k5); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k6); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k7); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k8); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k9);
        enc_block = veorq_u8(enc_block, k10);

        uint8x16_t plain_block = veorq_u8(enc_block, cipher_block);
        vst1q_u8(out_ptr, plain_block);
        out_ptr += 16;
        counter_word++;

        low_acc = vextq_u8(low_acc, low_acc, 8);
        cipher_block = vrev64q_u8(cipher_block);
        cipher_block = veorq_u64(cipher_block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(cipher_block),vget_low_u64(cipher_block));

        //multiply
        poly128_t t_high = vmull_high_p64(cipher_block, hash_key);
        poly128_t t_low  = vmull_p64(vget_low_p64(cipher_block), vget_low_p64(hash_key));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64(vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64(vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }
    if(ciphertext_length & 127ul) //possibly need to do final non-full block
    {
        //Generate enc_mask to zero out bits of enc_block which are not used
        uint8_t zero_bits = (uint8_t) 128-(ciphertext_length & 127ul);
        uint64x2_t enc_mask = { 0, 0 };
        if(zero_bits < 64) {
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul, enc_mask, 0);
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul >> zero_bits, enc_mask, 1);
        } else {
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul >> zero_bits, enc_mask, 0);
            enc_mask = vsetq_lane_u64(0, enc_mask, 1);
        }

        uint8x16_t enc_block = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);
        uint8x16_t cipher_block = vld1q_u8(in_ptr);
        cipher_block = vandq_u8(cipher_block, enc_mask);
        in_ptr  += 16;
        uint8x16_t tail_block = vld1q_u8(out_ptr);

        enc_block = vaeseq_u8(enc_block, k0); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k1); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k2); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k3); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k4); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k5); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k6); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k7); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k8); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k9);
        enc_block = veorq_u8(enc_block, k10);

        uint8x16_t plain_block = veorq_u8(enc_block, cipher_block); //decrypt the whole ciphertext block
        tail_block = vbicq_u8(tail_block, enc_mask); //clear region where decryption will go
        plain_block = vandq_u8(plain_block, enc_mask); //clear invalid region of full plaintext block
        cipher_block = vandq_u8(cipher_block, enc_mask); //clear invalid region of full ciphertext block (for tag calculation)
        tail_block = vorrq_u8(tail_block, plain_block); //block ready to be saved

        vst1q_u8(out_ptr, tail_block);
        out_ptr += 16;
        counter_word++;

        low_acc = vextq_u8(low_acc, low_acc, 8);
        cipher_block = vrev64q_u8(cipher_block);
        cipher_block = veorq_u64(cipher_block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(cipher_block),vget_low_u64(cipher_block));

        //multiply
        poly128_t t_high = vmull_high_p64(cipher_block, hash_key);
        poly128_t t_low  = vmull_p64(vget_low_p64(cipher_block), vget_low_p64(hash_key));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64(vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64(vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }

    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        cs->counter.s[3] = counter_word;
    #else
        cs->counter.s[3] = __builtin_bswap32(counter_word);
    #endif

    vst1q_u8(cs->current_tag.b, low_acc);

    return SUCCESSFUL_OPERATION;
}
        #endif
    #endif
#endif

#ifdef PERF_GCM_LITTLE
    #include "AArch64cryptolib_opt_LITTLE/aes_gcm/dec/aes_gcm_dec_192_kernel__interleaved.c"
#else
    #ifdef PERF_GCM_BIG
        #include "AArch64cryptolib_opt_big/aes_gcm/dec/aes_gcm_dec_192_kernel__interleaved.c"
    #else
        #ifdef PERF_GCM_BIGGER
            #ifdef PERF_GCM_BIGGEREOR3
                #include "AArch64cryptolib_opt_bigger/aes_gcm/dec/aes_gcm_dec_192_kernel_EOR3__interleaved.c"
            #else
                #include "AArch64cryptolib_opt_bigger/aes_gcm/dec/aes_gcm_dec_192_kernel__interleaved.c"
            #endif
        #else
static operation_result_t aes_gcm_dec_192_kernel(uint8_t * ciphertext, uint64_t ciphertext_length, cipher_state_t * restrict cs, uint8_t * plaintext)
{
    if(ciphertext_length == 0) {
        return SUCCESSFUL_OPERATION;
    }

    uint64_t full_blocks = ciphertext_length >> 7;

    uint8x16_t counter = vld1q_u8(cs->counter.b);
    uint32_t counter_word;
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        counter_word = cs->counter.s[3];
    #else
        counter_word = __builtin_bswap32(cs->counter.s[3]);
    #endif
    uint8x16_t k0  = vld1q_u8(cs->constants->expanded_aes_keys[0].b);
    uint8x16_t k1  = vld1q_u8(cs->constants->expanded_aes_keys[1].b);
    uint8x16_t k2  = vld1q_u8(cs->constants->expanded_aes_keys[2].b);
    uint8x16_t k3  = vld1q_u8(cs->constants->expanded_aes_keys[3].b);
    uint8x16_t k4  = vld1q_u8(cs->constants->expanded_aes_keys[4].b);
    uint8x16_t k5  = vld1q_u8(cs->constants->expanded_aes_keys[5].b);
    uint8x16_t k6  = vld1q_u8(cs->constants->expanded_aes_keys[6].b);
    uint8x16_t k7  = vld1q_u8(cs->constants->expanded_aes_keys[7].b);
    uint8x16_t k8  = vld1q_u8(cs->constants->expanded_aes_keys[8].b);
    uint8x16_t k9  = vld1q_u8(cs->constants->expanded_aes_keys[9].b);
    uint8x16_t k10 = vld1q_u8(cs->constants->expanded_aes_keys[10].b);
    uint8x16_t k11 = vld1q_u8(cs->constants->expanded_aes_keys[11].b);
    uint8x16_t k12 = vld1q_u8(cs->constants->expanded_aes_keys[12].b);

    poly64x2_t hash_key = (poly64x2_t) vld1q_u64(cs->constants->expanded_hash_keys[0].d);
    poly64_t hash_karat = (poly64_t) veor_u64(vget_high_u64(hash_key), vget_low_u64(hash_key));
    poly64_t modulo_const = (poly64_t) 0xC200000000000000ul;
    uint8x16_t low_acc = vld1q_u8(cs->current_tag.b);

    uint8_t * in_ptr  = ciphertext;
    uint8_t * out_ptr = plaintext;

    // Do aes-gcm on the number of blocks, using and updating the counter in cs
    for( uint64_t i=0; i<full_blocks; ++i )
    {
        uint8x16_t enc_block = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);
        uint8x16_t cipher_block = vld1q_u8(in_ptr);
        in_ptr  += 16;

        enc_block = vaeseq_u8(enc_block, k0); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k1); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k2); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k3); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k4); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k5); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k6); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k7); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k8); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k9); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k10); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k11);
        enc_block = veorq_u8(enc_block, k12);

        uint8x16_t plain_block = veorq_u8(enc_block, cipher_block);
        vst1q_u8(out_ptr, plain_block);
        out_ptr += 16;
        counter_word++;

        low_acc = vextq_u8(low_acc, low_acc, 8);
        cipher_block = vrev64q_u8(cipher_block);
        cipher_block = veorq_u64(cipher_block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(cipher_block),vget_low_u64(cipher_block));

        //multiply
        poly128_t t_high = vmull_high_p64(cipher_block, hash_key);
        poly128_t t_low  = vmull_p64(vget_low_p64(cipher_block), vget_low_p64(hash_key));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64(vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64(vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }
    if(ciphertext_length & 127ul) //possibly need to do final non-full block
    {
        //Generate enc_mask to zero out bits of enc_block which are not used
        uint8_t zero_bits = (uint8_t) 128-(ciphertext_length & 127ul);
        uint64x2_t enc_mask = { 0, 0 };
        if(zero_bits < 64) {
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul, enc_mask, 0);
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul >> zero_bits, enc_mask, 1);
        } else {
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul >> zero_bits, enc_mask, 0);
            enc_mask = vsetq_lane_u64(0, enc_mask, 1);
        }

        uint8x16_t enc_block = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);
        uint8x16_t cipher_block = vld1q_u8(in_ptr);
        cipher_block = vandq_u8(cipher_block, enc_mask);
        in_ptr  += 16;
        uint8x16_t tail_block = vld1q_u8(out_ptr);

        enc_block = vaeseq_u8(enc_block, k0); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k1); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k2); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k3); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k4); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k5); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k6); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k7); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k8); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k9); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k10); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k11);
        enc_block = veorq_u8(enc_block, k12);

        uint8x16_t plain_block = veorq_u8(enc_block, cipher_block); //decrypt the whole ciphertext block
        tail_block = vbicq_u8(tail_block, enc_mask); //clear region where decryption will go
        plain_block = vandq_u8(plain_block, enc_mask); //clear invalid region of full plaintext block
        cipher_block = vandq_u8(cipher_block, enc_mask); //clear invalid region of full ciphertext block (for tag calculation)
        tail_block = vorrq_u8(tail_block, plain_block); //block ready to be saved

        vst1q_u8(out_ptr, tail_block);;
        out_ptr += 16;
        counter_word++;

        low_acc = vextq_u8(low_acc, low_acc, 8);
        cipher_block = vrev64q_u8(cipher_block);
        cipher_block = veorq_u64(cipher_block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(cipher_block),vget_low_u64(cipher_block));

        //multiply
        poly128_t t_high = vmull_high_p64(cipher_block, hash_key);
        poly128_t t_low  = vmull_p64(vget_low_p64(cipher_block), vget_low_p64(hash_key));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64(vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64(vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }

    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        cs->counter.s[3] = counter_word;
    #else
        cs->counter.s[3] = __builtin_bswap32(counter_word);
    #endif

    vst1q_u8(cs->current_tag.b, low_acc);

    return SUCCESSFUL_OPERATION;
}
        #endif
    #endif
#endif

#ifdef PERF_GCM_LITTLE
    #include "AArch64cryptolib_opt_LITTLE/aes_gcm/dec/aes_gcm_dec_256_kernel__interleaved.c"
#else
    #ifdef PERF_GCM_BIG
        #include "AArch64cryptolib_opt_big/aes_gcm/dec/aes_gcm_dec_256_kernel__interleaved.c"
    #else
        #ifdef PERF_GCM_BIGGER
            #ifdef PERF_GCM_BIGGEREOR3
                #include "AArch64cryptolib_opt_bigger/aes_gcm/dec/aes_gcm_dec_256_kernel_EOR3__interleaved.c"
            #else
                #include "AArch64cryptolib_opt_bigger/aes_gcm/dec/aes_gcm_dec_256_kernel__interleaved.c"
            #endif
        #else
static operation_result_t aes_gcm_dec_256_kernel(uint8_t * ciphertext, uint64_t ciphertext_length, cipher_state_t * restrict cs, uint8_t * plaintext)
{
    if(ciphertext_length == 0) {
        return SUCCESSFUL_OPERATION;
    }

    uint64_t full_blocks = ciphertext_length >> 7;

    uint8x16_t counter = vld1q_u8(cs->counter.b);
    uint32_t counter_word;
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        counter_word = cs->counter.s[3];
    #else
        counter_word = __builtin_bswap32(cs->counter.s[3]);
    #endif
    uint8x16_t k0  = vld1q_u8(cs->constants->expanded_aes_keys[0].b);
    uint8x16_t k1  = vld1q_u8(cs->constants->expanded_aes_keys[1].b);
    uint8x16_t k2  = vld1q_u8(cs->constants->expanded_aes_keys[2].b);
    uint8x16_t k3  = vld1q_u8(cs->constants->expanded_aes_keys[3].b);
    uint8x16_t k4  = vld1q_u8(cs->constants->expanded_aes_keys[4].b);
    uint8x16_t k5  = vld1q_u8(cs->constants->expanded_aes_keys[5].b);
    uint8x16_t k6  = vld1q_u8(cs->constants->expanded_aes_keys[6].b);
    uint8x16_t k7  = vld1q_u8(cs->constants->expanded_aes_keys[7].b);
    uint8x16_t k8  = vld1q_u8(cs->constants->expanded_aes_keys[8].b);
    uint8x16_t k9  = vld1q_u8(cs->constants->expanded_aes_keys[9].b);
    uint8x16_t k10 = vld1q_u8(cs->constants->expanded_aes_keys[10].b);
    uint8x16_t k11 = vld1q_u8(cs->constants->expanded_aes_keys[11].b);
    uint8x16_t k12 = vld1q_u8(cs->constants->expanded_aes_keys[12].b);
    uint8x16_t k13 = vld1q_u8(cs->constants->expanded_aes_keys[13].b);
    uint8x16_t k14 = vld1q_u8(cs->constants->expanded_aes_keys[14].b);

    poly64x2_t hash_key = (poly64x2_t) vld1q_u64(cs->constants->expanded_hash_keys[0].d);
    poly64_t hash_karat = (poly64_t) veor_u64(vget_high_u64(hash_key), vget_low_u64(hash_key));
    poly64_t modulo_const = (poly64_t) 0xC200000000000000ul;
    uint8x16_t low_acc = vld1q_u8(cs->current_tag.b);

    uint8_t * in_ptr  = ciphertext;
    uint8_t * out_ptr = plaintext;

    // Do aes-gcm on the number of blocks, using and updating the counter in cs
    for( uint64_t i=0; i<full_blocks; ++i )
    {
        uint8x16_t enc_block = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);
        uint8x16_t cipher_block = vld1q_u8(in_ptr);
        in_ptr  += 16;

        enc_block = vaeseq_u8(enc_block, k0); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k1); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k2); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k3); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k4); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k5); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k6); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k7); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k8); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k9); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k10); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k11); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k12); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k13);
        enc_block = veorq_u8(enc_block, k14);

        uint8x16_t plain_block = veorq_u8(enc_block, cipher_block);
        vst1q_u8(out_ptr, plain_block);
        out_ptr += 16;
        counter_word++;

        low_acc = vextq_u8(low_acc, low_acc, 8);
        cipher_block = vrev64q_u8(cipher_block);
        cipher_block = veorq_u64(cipher_block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(cipher_block),vget_low_u64(cipher_block));

        //multiply
        poly128_t t_high = vmull_high_p64(cipher_block, hash_key);
        poly128_t t_low  = vmull_p64(vget_low_p64(cipher_block), vget_low_p64(hash_key));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64(vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64(vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }
    if(ciphertext_length & 127ul) //possibly need to do final non-full block
    {
        //Generate enc_mask to zero out bits of enc_block which are not used
        uint8_t zero_bits = (uint8_t) 128-(ciphertext_length & 127ul);
        uint64x2_t enc_mask = { 0, 0 };
        if(zero_bits < 64) {
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul, enc_mask, 0);
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul >> zero_bits, enc_mask, 1);
        } else {
            enc_mask = vsetq_lane_u64(0xFFFFFFFFFFFFFFFFul >> zero_bits, enc_mask, 0);
            enc_mask = vsetq_lane_u64(0, enc_mask, 1);
        }

        uint8x16_t enc_block = vsetq_lane_u32(__builtin_bswap32(counter_word), counter, 3);
        uint8x16_t cipher_block = vld1q_u8(in_ptr);
        cipher_block = vandq_u8(cipher_block, enc_mask);
        in_ptr  += 16;
        uint8x16_t tail_block = vld1q_u8(out_ptr);

        enc_block = vaeseq_u8(enc_block, k0); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k1); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k2); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k3); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k4); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k5); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k6); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k7); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k8); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k9); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k10); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k11); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k12); enc_block = vaesmcq_u8(enc_block);
        enc_block = vaeseq_u8(enc_block, k13);
        enc_block = veorq_u8(enc_block, k14);

        uint8x16_t plain_block = veorq_u8(enc_block, cipher_block); //decrypt the whole ciphertext block
        tail_block = vbicq_u8(tail_block, enc_mask); //clear region where decryption will go
        plain_block = vandq_u8(plain_block, enc_mask); //clear invalid region of full plaintext block
        cipher_block = vandq_u8(cipher_block, enc_mask); //clear invalid region of full ciphertext block (for tag calculation)
        tail_block = vorrq_u8(tail_block, plain_block); //block ready to be saved

        vst1q_u8(out_ptr, tail_block);
        out_ptr += 16;
        counter_word++;

        low_acc = vextq_u8(low_acc, low_acc, 8);
        cipher_block = vrev64q_u8(cipher_block);
        cipher_block = veorq_u64(cipher_block, low_acc);
        poly64_t block_karat = (poly64_t) veor_u64(vget_high_u64(cipher_block),vget_low_u64(cipher_block));

        //multiply
        poly128_t t_high = vmull_high_p64(cipher_block, hash_key);
        poly128_t t_low  = vmull_p64(vget_low_p64(cipher_block), vget_low_p64(hash_key));
        poly128_t t_mid  = vmull_p64(block_karat, hash_karat);

        //tidy up karatsuba
        poly64x2_t mid_acc = veorq_u64(vreinterpretq_u64_p128(t_mid), vreinterpretq_u64_p128(t_high));
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(t_low));

        //modulo reduction
        poly128_t tmp_mid_0 = vmull_p64(vget_low_p64(vreinterpretq_u64_p128(t_high)), modulo_const);
        uint8x16_t high_acc = vextq_u8(vreinterpretq_u8_p128(t_high), vreinterpretq_u8_p128(t_high), 8);
        mid_acc = veorq_u64(mid_acc, vreinterpretq_u64_p128(tmp_mid_0));
        mid_acc = veorq_u64(mid_acc, high_acc);

        poly128_t tmp_low_0 = vmull_p64(vget_low_p64(mid_acc), modulo_const);
        mid_acc = vextq_u8(mid_acc, mid_acc, 8);
        low_acc = veorq_u64(vreinterpretq_u64_p128(t_low), vreinterpretq_u64_p128(tmp_low_0));
        low_acc = veorq_u64(low_acc, mid_acc);
    }

    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        cs->counter.s[3] = counter_word;
    #else
        cs->counter.s[3] = __builtin_bswap32(counter_word);
    #endif

    vst1q_u8(cs->current_tag.b, low_acc);

    return SUCCESSFUL_OPERATION;
}
        #endif
    #endif
#endif

static operation_result_t aes_gcm_finalize(cipher_state_t * restrict cs, quadword_t final_block, uint8_t * restrict output_tag)
{
    uint8x16_t tag = vld1q_u8(cs->current_tag.b);
    uint8x16_t fb  = vld1q_u8(final_block.b);
    tag = vrev64q_u8(tag);
    tag = vextq_u8(tag, tag, 8);
    tag = veorq_u8(tag, fb); // "encrypt" current_tag value with final_aes_ctr_block
    vst1q_u8(output_tag, tag);
    return SUCCESSFUL_OPERATION;
}

operation_result_t encrypt_full(
    cipher_mode_t mode,
    uint8_t * key,
    uint8_t * nonce,       uint64_t nonce_length,
    uint8_t * aad,         uint64_t aad_length,
    uint8_t * plaintext,   uint64_t plaintext_length,  //Inputs
    uint8_t * ciphertext,
    uint8_t * tag)                              //Outputs
{
    operation_result_t result_status = SUCCESSFUL_OPERATION;
    cipher_constants_t cc = { .mode = mode };
    cipher_state_t cs = { .counter = { .d = {0,0} } };
    cs.constants = &cc;

    switch(cs.constants->mode) {
        case AES_GCM_128:
            result_status |= aes_gcm_expandkeys_128_kernel(key, &cc); //set expanded keys and hash key in cc
            break;
        case AES_GCM_192:
            result_status |= aes_gcm_expandkeys_192_kernel(key, &cc); //set expanded keys and hash key in cc
            break;
        case AES_GCM_256:
            result_status |= aes_gcm_expandkeys_256_kernel(key, &cc); //set expanded keys and hash key in cc
            break;
    }
    result_status |= armv8_aes_gcm_set_counter(nonce, nonce_length, &cs); //set counter value in cs
    if( result_status != SUCCESSFUL_OPERATION ) return result_status; //if we have failed in setup, don't continue

    return encrypt_from_state(&cs, aad, aad_length, plaintext, plaintext_length, ciphertext, tag);
}

operation_result_t encrypt_from_state(
    cipher_state_t * cs,
    uint8_t * aad,       uint64_t aad_length,
    uint8_t * plaintext, uint64_t plaintext_length,
    uint8_t * ciphertext,
    uint8_t * restrict tag)
{
    operation_result_t result_status = SUCCESSFUL_OPERATION;
    quadword_t final_aes_ctr_block = { .d = {0,0} };
    quadword_t final_block; // [len(A)]_64 | [len(C)]_64
                            // MSB --> LSB | MSB --> LSB
                            // for AES-CTR len(C) == len(P)

    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        final_block.d[0] = plaintext_length;
        final_block.d[1] = aad_length;
    #else
        final_block.d[0] = __builtin_bswap64(aad_length);
        final_block.d[1] = __builtin_bswap64(plaintext_length);
    #endif

    result_status |= ghash_kernel(aad, aad_length, cs); //update current_tag value in cs with aad

    switch(cs->constants->mode)
    {
        case AES_GCM_128:
            result_status |= aes_ctr_blk_128_kernel(1, cs, final_aes_ctr_block.b); //compute first aes-ctr block for "encrypting" tag
            if( result_status != SUCCESSFUL_OPERATION ) return result_status; //if we have failed in authenticating aad or computing first aes-ctr block, don't continue

            result_status |= aes_gcm_enc_128_kernel(plaintext, plaintext_length, cs, ciphertext); //set ciphertext to encrypted plaintext whilst updating current_tag value in cs
            break;
        case AES_GCM_192:
            result_status |= aes_ctr_blk_192_kernel(1, cs, final_aes_ctr_block.b); //compute first aes-ctr block for "encrypting" tag
            if( result_status != SUCCESSFUL_OPERATION ) return result_status; //if we have failed in authenticating aad or computing first aes-ctr block, don't continue

            result_status |= aes_gcm_enc_192_kernel(plaintext, plaintext_length, cs, ciphertext); //set ciphertext to encrypted plaintext whilst updating current_tag value in cs
            break;
        case AES_GCM_256:
            result_status |= aes_ctr_blk_256_kernel(1, cs, final_aes_ctr_block.b); //compute first aes-ctr block for "encrypting" tag
            if( result_status != SUCCESSFUL_OPERATION ) return result_status; //if we have failed in authenticating aad or computing first aes-ctr block, don't continue

            result_status |= aes_gcm_enc_256_kernel(plaintext, plaintext_length, cs, ciphertext); //set ciphertext to encrypted plaintext whilst updating current_tag value in cs
            break;
    }
    result_status |= ghash_kernel(final_block.b, 128, cs); //update current_tag value in cs with final_block
    result_status |= aes_gcm_finalize(cs, final_aes_ctr_block, tag); //finalize current_tag

    return result_status;
}

operation_result_t decrypt_full(
    cipher_mode_t mode,
    uint8_t * key,
    uint8_t * nonce,       uint64_t nonce_length,
    uint8_t * aad,         uint64_t aad_length,
    uint8_t * ciphertext,  uint64_t ciphertext_length,
    uint8_t * tag,                                     //Inputs
    uint8_t * plaintext)                               //Outputs
{
    operation_result_t result_status = SUCCESSFUL_OPERATION;
    cipher_constants_t cc = { .mode = mode };
    cipher_state_t cs = { .counter = { .d = {0,0} } };
    cs.constants = &cc;

    switch(cs.constants->mode) {
        case AES_GCM_128:
            result_status |= aes_gcm_expandkeys_128_kernel(key, &cc); //set expanded keys and hash key in cc
            break;
        case AES_GCM_192:
            result_status |= aes_gcm_expandkeys_192_kernel(key, &cc); //set expanded keys and hash key in cc
            break;
        case AES_GCM_256:
            result_status |= aes_gcm_expandkeys_256_kernel(key, &cc); //set expanded keys and hash key in cc
            break;
    }
    result_status |= armv8_aes_gcm_set_counter(nonce, nonce_length, &cs); //set counter value in cs
    if( result_status != SUCCESSFUL_OPERATION ) return result_status; //if we have failed in setup, don't continue

    return decrypt_from_state(&cs, aad, aad_length, ciphertext, ciphertext_length, tag, plaintext);
}

operation_result_t decrypt_from_state(
    cipher_state_t * restrict cs,
    uint8_t * aad,        uint64_t aad_length,
    uint8_t * ciphertext, uint64_t ciphertext_length,
    uint8_t * restrict tag,
    uint8_t * plaintext)
{
    //Check for invalid tag sizes
    if ((cs->constants->tag_byte_length < 12 || cs->constants->tag_byte_length > 16) &&
	(cs->constants->tag_byte_length != 4 && cs->constants->tag_byte_length != 8))
    {
	return AUTHENTICATION_FAILURE;
    }
    operation_result_t result_status = SUCCESSFUL_OPERATION;
    quadword_t final_aes_ctr_block = { .d = {0,0} };
    quadword_t final_block; // [len(A)]_64 | [len(C)]_64
                            // MSB --> LSB | MSB --> LSB
                            // for AES-CTR len(C) == len(P)

    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        final_block.d[0] = ciphertext_length;
        final_block.d[1] = aad_length;
    #else
        final_block.d[0] = __builtin_bswap64(aad_length);
        final_block.d[1] = __builtin_bswap64(ciphertext_length);
    #endif

    result_status |= ghash_kernel(aad, aad_length, cs); //update current_tag value in cs with aad

    switch(cs->constants->mode)
    {
        case AES_GCM_128:
            result_status |= aes_ctr_blk_128_kernel(1, cs, final_aes_ctr_block.b); //compute first aes-ctr block for "encrypting" tag
            if( result_status != SUCCESSFUL_OPERATION ) return result_status; //if we have failed in authenticating aad or computing first aes-ctr block, don't continue

            result_status |= aes_gcm_dec_128_kernel(ciphertext, ciphertext_length, cs, plaintext); //set plaintext to decrypted ciphertext whilst updating current_tag value in cs
            break;
        case AES_GCM_192:
            result_status |= aes_ctr_blk_192_kernel(1, cs, final_aes_ctr_block.b); //compute first aes-ctr block for "encrypting" tag
            if( result_status != SUCCESSFUL_OPERATION ) return result_status; //if we have failed in authenticating aad or computing first aes-ctr block, don't continue

            result_status |= aes_gcm_dec_192_kernel(ciphertext, ciphertext_length, cs, plaintext); //set plaintext to decrypted ciphertext whilst updating current_tag value in cs
            break;
        case AES_GCM_256:
            result_status |= aes_ctr_blk_256_kernel(1, cs, final_aes_ctr_block.b); //compute first aes-ctr block for "encrypting" tag
            if( result_status != SUCCESSFUL_OPERATION ) return result_status; //if we have failed in authenticating aad or computing first aes-ctr block, don't continue

            result_status |= aes_gcm_dec_256_kernel(ciphertext, ciphertext_length, cs, plaintext); //set plaintext to decrypted ciphertext whilst updating current_tag value in cs
            break;
    }
    result_status |= ghash_kernel(final_block.b, 128, cs); //update current_tag value in cs with final_block
    result_status |= aes_gcm_finalize(cs, final_aes_ctr_block, cs->current_tag.b); //finalize current_tag
    if( result_status != SUCCESSFUL_OPERATION ) return result_status; //if we have failed in aes-gcm decryption or computing doing final ghash, don't continue

    uint64_t mismatch = 0;
    uint32_t len = cs->constants->tag_byte_length;
    uint8_t *cur = cs->current_tag.b;
    if (len >= sizeof(__int128))
    {
	__int128 a, b;
	memcpy(&a, tag, sizeof(__int128)); tag += sizeof(__int128);
	memcpy(&b, cur, sizeof(__int128)); cur += sizeof(__int128);
	mismatch |= (uint64_t)(a >> 64) ^ (uint64_t)(b >> 64);
	mismatch |= (uint64_t)a ^ (uint64_t)b;
	len -= sizeof(__int128);
    }
    if (len >= sizeof(uint64_t))
    {
	uint64_t a, b;
	memcpy(&a, tag, sizeof(uint64_t)); tag += sizeof(uint64_t);
	memcpy(&b, cur, sizeof(uint64_t)); cur += sizeof(uint64_t);
	mismatch |= a ^ b;
	len -= sizeof(uint64_t);
    }
    if (len >= sizeof(uint32_t))
    {
	uint32_t a, b;
	memcpy(&a, tag, sizeof(uint32_t)); tag += sizeof(uint32_t);
	memcpy(&b, cur, sizeof(uint32_t)); cur += sizeof(uint32_t);
	mismatch |= a ^ b;
	len -= sizeof(uint32_t);
    }
    if (len >= sizeof(uint16_t))
    {
	uint16_t a, b;
	memcpy(&a, tag, sizeof(uint16_t)); tag += sizeof(uint16_t);
	memcpy(&b, cur, sizeof(uint16_t)); cur += sizeof(uint16_t);
	mismatch |= a ^ b;
	len -= sizeof(uint16_t);
    }
    if (len >= sizeof(uint8_t))
    {
	uint8_t a, b;
	memcpy(&a, tag, sizeof(uint8_t)); tag += sizeof(uint8_t);
	memcpy(&b, cur, sizeof(uint8_t)); cur += sizeof(uint8_t);
	mismatch |= a ^ b;
	len -= sizeof(uint8_t);
    }
    return mismatch ? AUTHENTICATION_FAILURE : SUCCESSFUL_OPERATION;
}

// IPsec versions enabled when targeting LITTLE or big cores
#ifdef IPSEC_ENABLED
#ifdef PERF_GCM_LITTLE
    #include "AArch64cryptolib_opt_LITTLE/aes_gcm/enc_IPsec/aes_gcm_enc_from_consts_IPsec_128__interleaved.c"
    #include "AArch64cryptolib_opt_LITTLE/aes_gcm/enc_IPsec/aes_gcm_enc_from_consts_IPsec_192__interleaved.c"
    #include "AArch64cryptolib_opt_LITTLE/aes_gcm/enc_IPsec/aes_gcm_enc_from_consts_IPsec_256__interleaved.c"
#else
    #ifdef PERF_GCM_BIG
        #include "AArch64cryptolib_opt_big/aes_gcm/enc_IPsec/aes_gcm_enc_from_consts_IPsec_128__interleaved.c"
        #include "AArch64cryptolib_opt_big/aes_gcm/enc_IPsec/aes_gcm_enc_from_consts_IPsec_192__interleaved.c"
        #include "AArch64cryptolib_opt_big/aes_gcm/enc_IPsec/aes_gcm_enc_from_consts_IPsec_256__interleaved.c"
    #endif
#endif

operation_result_t encrypt_from_constants_IPsec(
    //Inputs
    const cipher_constants_t * cc,
    uint32_t salt,
    uint64_t ESPIV,
    const uint8_t * restrict aad,   uint32_t aad_byte_length,
        //assumes aad zero padded to 16B and 0 < aad_byte_length <=16
    uint8_t * plaintext,            uint32_t plaintext_byte_length,
        //in place operation - plaintext becomes ciphertext
        //assumed that ciphertext can be written in 16B blocks - will write up to 15B of 0s beyond the end of the plaintext
    //Output
    uint8_t * tag
        //tag_byte_length specified in cipher_constants
        //tag written after ciphertext, so tag will be produced correctly if directly after plaintext
    )
{
    operation_result_t result_status = SUCCESSFUL_OPERATION;
    switch(cc->mode)
    {
        case AES_GCM_128:
            result_status |= encrypt_from_constants_IPsec_128(
                    cc,
                    salt,
                    ESPIV,
                    aad, aad_byte_length, //aad_byte_length 8 or 12
                    plaintext, plaintext_byte_length, //Inputs
                    tag);
            break;
        case AES_GCM_192:
            result_status |= encrypt_from_constants_IPsec_192(
                    cc,
                    salt,
                    ESPIV,
                    aad, aad_byte_length, //aad_byte_length 8 or 12
                    plaintext, plaintext_byte_length, //Inputs
                    tag);
            break;
        case AES_GCM_256:
            result_status |= encrypt_from_constants_IPsec_256(
                    cc,
                    salt,
                    ESPIV,
                    aad, aad_byte_length, //aad_byte_length 8 or 12
                    plaintext, plaintext_byte_length, //Inputs
                    tag);
            break;
    }
    return result_status;
}

#ifdef PERF_GCM_LITTLE
    #include "AArch64cryptolib_opt_LITTLE/aes_gcm/dec_IPsec/aes_gcm_dec_from_consts_IPsec_128__interleaved.c"
    #include "AArch64cryptolib_opt_LITTLE/aes_gcm/dec_IPsec/aes_gcm_dec_from_consts_IPsec_192__interleaved.c"
    #include "AArch64cryptolib_opt_LITTLE/aes_gcm/dec_IPsec/aes_gcm_dec_from_consts_IPsec_256__interleaved.c"
#else
    #ifdef PERF_GCM_BIG
        #include "AArch64cryptolib_opt_big/aes_gcm/dec_IPsec/aes_gcm_dec_from_consts_IPsec_128__interleaved.c"
        #include "AArch64cryptolib_opt_big/aes_gcm/dec_IPsec/aes_gcm_dec_from_consts_IPsec_192__interleaved.c"
        #include "AArch64cryptolib_opt_big/aes_gcm/dec_IPsec/aes_gcm_dec_from_consts_IPsec_256__interleaved.c"
    #endif
#endif

operation_result_t decrypt_from_constants_IPsec(
    //Inputs
    const armv8_cipher_constants_t * cc,
    uint32_t salt,
    uint64_t ESPIV,
    const uint8_t * restrict aad, uint32_t aad_byte_length,
        //aad zero padded to 16B, aad_byte_length 8 or 12
    uint8_t * ciphertext,   uint32_t ciphertext_byte_length,
        //in place operation - ciphertext becomes plaintext
        //assumed that plaintext can be written in 8B blocks - will write up to 7B of 0s beyond the end of the ciphertext
    const uint8_t * tag,
        //tag_byte_length specified in cipher_constants
        //tag is read before last block of plaintext is written and written back afterwards, so tag will be preserved
        //supported tag sizes are 8B, 12B and 16B, and precisely the size specified will be read
    //Output
    uint64_t * checksum
        //one's complement sum of all 64b words in the plaintext
    )
{
    operation_result_t result_status = SUCCESSFUL_OPERATION;
    switch(cc->mode)
    {
        case AES_GCM_128:
            result_status |= decrypt_from_constants_IPsec_128(
                    cc,
                    salt,
                    ESPIV,
                    aad, aad_byte_length, //aad_byte_length 8 or 12
                    ciphertext, ciphertext_byte_length, //Inputs
                    tag,
                    checksum);
            break;
        case AES_GCM_192:
            result_status |= decrypt_from_constants_IPsec_192(
                    cc,
                    salt,
                    ESPIV,
                    aad, aad_byte_length, //aad_byte_length 8 or 12
                    ciphertext, ciphertext_byte_length, //Inputs
                    tag,
                    checksum);
            break;
        case AES_GCM_256:
            result_status |= decrypt_from_constants_IPsec_256(
                    cc,
                    salt,
                    ESPIV,
                    aad, aad_byte_length, //aad_byte_length 8 or 12
                    ciphertext, ciphertext_byte_length, //Inputs
                    tag,
                    checksum);
            break;
    }
    return result_status;
}
#endif

#undef cipher_mode_t
#undef operation_result_t
#undef quadword_t
#undef cipher_constants_t
#undef cipher_state_t

#undef encrypt_full
#undef encrypt_from_state
#undef encrypt_from_constants_IPsec
#undef decrypt_full
#undef decrypt_from_state
#undef decrypt_from_constants_IPsec

#undef expand_hash_keys

#undef aes_gcm_expandkeys_128_kernel
#undef aes_gcm_expandkeys_192_kernel
#undef aes_gcm_expandkeys_256_kernel

#undef ghash_kernel

#undef aes_ctr_blk_128_kernel
#undef aes_ctr_blk_192_kernel
#undef aes_ctr_blk_256_kernel

#undef aes_gcm_enc_128_kernel
#undef aes_gcm_enc_192_kernel
#undef aes_gcm_enc_256_kernel

#undef aes_gcm_dec_128_kernel
#undef aes_gcm_dec_192_kernel
#undef aes_gcm_dec_256_kernel

#undef aes_gcm_finalize

#undef rcon

#undef rijndael_sbox
