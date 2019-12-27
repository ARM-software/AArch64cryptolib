//Copyright (c) 2018-2019, ARM Limited. All rights reserved.
//
//SPDX-License-Identifier:        BSD-3-Clause

#define NDEBUG
#include <assert.h>

#include <stdbool.h>
#include <stdio.h>
#include <math.h>
#include <string.h>

#include "AArch64cryptolib.h"

#define MAX_LINE_LEN 128

#ifndef TEST_DEBUG
#define TEST_DEBUG_PRINTF 0
#else
#define TEST_DEBUG_PRINTF 1
#endif

#define cipher_mode_t       AArch64crypto_cipher_mode_t
#define operation_result_t  AArch64crypto_operation_result_t
#define doubleword_t        AArch64crypto_doubleword_t
#define quadword_t          AArch64crypto_quadword_t
#define cipher_constants_t  AArch64crypto_cipher_constants_t
#define cipher_state_t      AArch64crypto_cipher_state_t

#define aes_gcm_set_counter             AArch64crypto_aes_gcm_set_counter
#define encrypt_full                    AArch64crypto_encrypt_full
#define encrypt_from_state              AArch64crypto_encrypt_from_state
#define encrypt_from_constants_IPsec    AArch64crypto_encrypt_from_constants_IPsec
#define decrypt_full                    AArch64crypto_decrypt_full
#define decrypt_from_state              AArch64crypto_decrypt_from_state
#define decrypt_from_constants_IPsec    AArch64crypto_decrypt_from_constants_IPsec

#define aesgcm_debug_printf(...) \
    do { if (TEST_DEBUG_PRINTF) printf(__VA_ARGS__); } while (0)

inline uint8_t hextobyte(uint8_t top, uint8_t bot) {
    assert(('0' <= top && top <= '9') || ('A' <= top && top <= 'F') || ('a' <= top && top <= 'f'));
    assert(('0' <= bot && bot <= '9') || ('A' <= bot && bot <= 'F') || ('a' <= bot && bot <= 'f'));
    uint8_t t = top & 0xf;
    uint8_t b = bot & 0xf;
    t += top & 0x40 ? 9 : 0;
    b += bot & 0x40 ? 9 : 0;
    return (t<<4) + b;
}

//// Called once a reference state is set up, runs encrypt/decrypt
//// and checks the outputs match the expected outputs
bool __attribute__ ((noinline)) test_reference(cipher_state_t cs,
                    uint8_t * aad, uint64_t aad_length,
                    uint8_t * reference_plaintext,
                    uint64_t plaintext_length,
                    uint64_t plaintext_byte_length,
                    uint8_t * reference_tag,
                    uint8_t * reference_ciphertext,
                    uint64_t reference_checksum, bool check_checksum,
                    bool verbose)
{
    bool success = true;
    quadword_t temp_counter = cs.counter;
    quadword_t reference_counter = temp_counter;
    reference_counter.s[3] = __builtin_bswap32(__builtin_bswap32(reference_counter.s[3]) + (((uint32_t) plaintext_length + 127)>>7) + 1);
    if(verbose)
    {
        printf("Reference counter: 0x%016lx_%016lx\n",
                    reference_counter.d[1], reference_counter.d[0]);
    }
    uint8_t * tag;

    uint8_t * output = (uint8_t *)malloc(plaintext_byte_length+16);
    #ifdef IPSEC_ENABLED
    //// ENCRYPT IPsec TEST
    cs.current_tag.d[0] = 0;
    cs.current_tag.d[1] = 0;
    if((aad_length > 0) && (aad_length <= 128) && (cs.counter.s[3] == __builtin_bswap32(1u)))
    {
        if(verbose) printf("\n\nENCRYPTION IPsec TEST\n");
        memcpy(output, reference_plaintext, plaintext_byte_length); // Encryption done in place, need to copy reference to output

        uint8_t zero_padded_aad[16] = { 0 }; // IPsec encrypt requires aad to be zero padded
        memcpy(zero_padded_aad, aad, aad_length>>3);

        tag = output+plaintext_byte_length; // tag will go after end of ciphertext

        operation_result_t encrypt_result = encrypt_from_constants_IPsec(
                cs.constants,
                cs.counter.s[0],
                (((uint64_t) cs.counter.s[2])<<32) | cs.counter.s[1],
                zero_padded_aad, aad_length>>3,
                output, plaintext_length>>3,
                tag);

        if(verbose)
        {
            if(output != NULL) {
                printf("Computed ciphertext: 0x");
                for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                    printf("%02x", output[i]);
                }
                printf("\n");
            } else {
                printf("Computed ciphertext: NULL\n");
            }
            printf("Computed tag: 0x%016lx_%016lx\n",
                    __builtin_bswap64(((uint64_t*)tag)[0]),
                    __builtin_bswap64(((uint64_t*)tag)[1]));
        }

        bool ref_ciphertext_match = true;
        for(int i=0; i<(plaintext_length>>3); ++i) {
            if( output[i] != reference_ciphertext[i] ) ref_ciphertext_match = false;
        }
        bool reference_tag_match = true;
        for(int i=0; i<(cs.constants->tag_byte_length); ++i) {
            if( tag[i] != reference_tag[i] ) reference_tag_match = false;
        }
        if(verbose) printf("Reference ciphertext match %s!\nReference tag match %s!\n", ref_ciphertext_match ? "success" : "failure", reference_tag_match ? "success" : "failure");

        cs.counter = temp_counter; //reset counter early so we can retest without recomputing the counter
        if(!ref_ciphertext_match || !reference_tag_match || (encrypt_result != SUCCESSFUL_OPERATION)) {
            if(verbose) printf("Encryption failure!\n");
            success = false;
        }
    }
    else
    {
        if(verbose) printf("\n\nENCRYPTION IPsec TEST skipped\n");
    }

    //// DECRYPT IPsec TEST
    cs.current_tag.d[0] = 0;
    cs.current_tag.d[1] = 0;
    if((aad_length > 0) && (aad_length <= 128) && (cs.counter.s[3] == __builtin_bswap32(1u)))
    {
        if(verbose) printf("\n\nDECRYPTION IPsec TEST\n");
        memcpy(output, reference_ciphertext, plaintext_byte_length); // Decryption done in place, need to copy reference to output

        tag = output+plaintext_byte_length; // tag will go after end of plaintext
        memcpy(tag, reference_tag, cs.constants->tag_byte_length); // copy the reference tag
        uint64_t checksum = 0;

        operation_result_t decrypt_result = decrypt_from_constants_IPsec(
                cs.constants,
                cs.counter.s[0],
                (((uint64_t) cs.counter.s[2])<<32) | cs.counter.s[1],
                aad, aad_length>>3,
                output, plaintext_length>>3,
                tag,
                &checksum);

        if(verbose)
        {
            if(output != NULL) {
                printf("Computed plaintext: 0x");
                for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                    printf("%02x", output[i]);
                }
                printf("\n");
            } else {
                printf("Computed plaintext: NULL\n");
            }
            printf("Computed tag: 0x%016lx_%016lx\n",
                    __builtin_bswap64(((uint64_t*)tag)[0]),
                    __builtin_bswap64(((uint64_t*)tag)[1]));
            printf("Computed checksum: 0x%016lx\n",
                    __builtin_bswap64(checksum));
        }

        bool ref_plaintext_match = true;
        for(int i=0; i<(plaintext_length>>3); ++i) {
            if( output[i] != reference_plaintext[i] ) ref_plaintext_match = false;
        }
        if(verbose) printf("Reference plaintext match %s!\nReference checksum match %s!\n",
                ref_plaintext_match ? "success" : "failure", (checksum == reference_checksum) ? "success" : "failure");

        cs.counter = temp_counter;
        if(!ref_plaintext_match || (decrypt_result != SUCCESSFUL_OPERATION) || (check_checksum && (checksum != reference_checksum))) {
            if(verbose) printf("Decryption failure!\n");
            success = false;
        }
        else
        {
            if(verbose) printf("Decryption authenticated\n");
        }
    }
    else
    {
        if(verbose) printf("\n\nENCRYPTION IPsec TEST skipped\n");
    }
    #endif

    tag = (uint8_t *)malloc(cs.constants->tag_byte_length);

    //// ENCRYPTION TEST
    //// Encrypt reference plaintext and check output with reference ciphertext and tag
    cs.current_tag.d[0] = 0;
    cs.current_tag.d[1] = 0;
    if(verbose) printf("\n\nENCRYPTION TEST\n");

    operation_result_t encrypt_result = encrypt_from_state(
            &cs,
            aad, aad_length,
            reference_plaintext, plaintext_length,     //Inputs
            output,
            tag); //Outputs

    if(verbose)
    {
        if(output != NULL) {
            printf("Computed ciphertext: 0x");
            for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                printf("%02x", output[i]);
            }
            printf("\n");
        } else {
            printf("Computed ciphertext: NULL\n");
        }
        printf("Computed tag: 0x%016lx_%016lx\n",
                __builtin_bswap64(((uint64_t*)tag)[0]),
                __builtin_bswap64(((uint64_t*)tag)[1]));
        printf("Computed counter: 0x%016lx_%016lx\n",
                    cs.counter.d[1], cs.counter.d[0]);
    }

    bool ref_ciphertext_match = true;
    for(int i=0; i<(plaintext_length>>3); ++i) {
        if( output[i] != reference_ciphertext[i] ) ref_ciphertext_match = false;
    }
    bool reference_tag_match = true;
    for(int i=0; i<(cs.constants->tag_byte_length); ++i) {
        if( tag[i] != reference_tag[i] ) reference_tag_match = false;
    }
    bool reference_counter_match = true;
    for(int i=0; i<4; ++i) {
        if( cs.counter.s[i] != reference_counter.s[i] ) reference_counter_match = false;
    }
    if(verbose) printf("Reference ciphertext match %s!\nReference tag match %s!\nReference counter match %s!\n", ref_ciphertext_match ? "success" : "failure", reference_tag_match ? "success" : "failure", reference_counter_match ? "success" : "failure");

    cs.counter = temp_counter; //reset counter early so we can retest without recomputing the counter
    if(!ref_ciphertext_match || !reference_tag_match || !reference_counter_match || (encrypt_result != SUCCESSFUL_OPERATION)) {
        if(verbose) printf("Encryption failure!\n");
        success = false;
    }

    //// DECRYPTION TEST
    //// Decrypt reference ciphertext and check output with reference plaintext and tag
    //reset counter and tag
    cs.current_tag.d[0] = 0;
    cs.current_tag.d[1] = 0;

    if(verbose) printf("\n\nDECRYPTION TEST\n");

    operation_result_t decrypt_result = decrypt_from_state(
            &cs,
            aad, aad_length,
            reference_ciphertext, plaintext_length,
            reference_tag,
            output); //Outputs

    if(verbose)
    {
        if(output != NULL) {
            printf("Computed plaintext: 0x");
            for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                printf("%02x", output[i]);
            }
            printf("\n");
        } else {
            printf("Computed plaintext: NULL\n");
        }
        printf("Computed tag: 0x%016lx_%016lx\n",
                __builtin_bswap64(cs.current_tag.d[0]),
                __builtin_bswap64(cs.current_tag.d[1]));
        printf("Computed counter: 0x%016lx_%016lx\n",
                    cs.counter.d[1], cs.counter.d[0]);
    }

    bool ref_plaintext_match = true;
    for(int i=0; i<(plaintext_length>>3); ++i) {
        if( output[i] != reference_plaintext[i] ) ref_plaintext_match = false;
    }
    reference_tag_match = true;
    for(int i=0; i<(cs.constants->tag_byte_length); ++i) {
        if( cs.current_tag.b[i] != reference_tag[i] ) reference_tag_match = false;
    }
    reference_counter_match = true;
    for(int i=0; i<4; ++i) {
        if( cs.counter.s[i] != reference_counter.s[i] ) reference_counter_match = false;
    }
    if(verbose) printf("Reference plaintext match %s!\nReference tag match %s!\nReference counter match %s!\n", ref_plaintext_match ? "success" : "failure", reference_tag_match ? "success" : "failure", reference_counter_match ? "success" : "failure");

    free(output);
    free(tag);
    cs.counter = temp_counter;
    if(!ref_plaintext_match || !reference_tag_match || !reference_counter_match || (decrypt_result != SUCCESSFUL_OPERATION)) {
        if(verbose) printf("Decryption failure!\n");
        success = false;
    }
    else
    {
        if(verbose) printf("Decryption authenticated\n");
    }

    return success;
}

//// Called once a reference state is set up and we expect it to fail authentication runs decryption
//// and checks the result is an authentication failure
bool test_reference_invalid_auth(cipher_state_t cs,
                    uint8_t * aad, uint64_t aad_length,
                    uint8_t * reference_plaintext,
                    uint64_t plaintext_length,
                    uint64_t plaintext_byte_length,
                    uint8_t * reference_tag,
                    uint8_t * reference_ciphertext,
                    bool verbose)
{
    bool success = true;
    quadword_t temp_counter = cs.counter;
    uint8_t * tag;

    uint8_t * output = (uint8_t *)malloc(plaintext_byte_length+16);

    #ifdef IPSEC_ENABLED
    //// DECRYPT IPsec TEST
    cs.current_tag.d[0] = 0;
    cs.current_tag.d[1] = 0;
    if((aad_length > 0) && (aad_length <= 128) && (cs.counter.s[3] == __builtin_bswap32(1u)))
    {
        if(verbose) printf("\n\nDECRYPTION IPsec TEST\n");
        memcpy(output, reference_ciphertext, plaintext_byte_length); // Decryption done in place, need to copy reference to output

        tag = output+plaintext_byte_length; // tag will go after end of plaintext
        memcpy(tag, reference_tag, cs.constants->tag_byte_length); // copy the reference tag
        uint64_t checksum = 0;

        operation_result_t decrypt_result = decrypt_from_constants_IPsec(
                cs.constants,
                cs.counter.s[0],
                (((uint64_t) cs.counter.s[2])<<32) | cs.counter.s[1],
                aad, aad_length>>3,
                output, plaintext_length>>3,
                tag,
                &checksum);

        if(verbose)
        {
            if(output != NULL) {
                printf("Computed plaintext: 0x");
                for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                    printf("%02x", output[i]);
                }
                printf("\n");
            } else {
                printf("Computed plaintext: NULL\n");
            }
            printf("Computed tag: 0x%016lx_%016lx\n",
                    __builtin_bswap64(((uint64_t*)tag)[0]),
                    __builtin_bswap64(((uint64_t*)tag)[1]));
            printf("Computed checksum: 0x%016lx\n",
                    __builtin_bswap64(checksum));
        }

        bool ref_plaintext_match = true;
        for(int i=0; i<(plaintext_length>>3); ++i) {
            if( output[i] != reference_plaintext[i] ) ref_plaintext_match = false;
        }
        if(verbose) printf("Reference plaintext match %s!\n", ref_plaintext_match ? "success" : "failure");

        cs.counter = temp_counter;
        if(decrypt_result != AUTHENTICATION_FAILURE) {
            if(verbose) printf("Decryption didn't cause authentication failure!\n");
            success = false;
        }
        else
        {
            if(verbose) printf("Decryption failed authentication correctly\n");
        }
    }
    else
    {
        if(verbose) printf("\n\nENCRYPTION IPsec TEST skipped\n");
    }
    #endif

    tag = (uint8_t *)malloc(cs.constants->tag_byte_length);

    //// DECRYPTION TEST
    //// Decrypt reference ciphertext and check output with reference plaintext and tag
    cs.current_tag.d[0] = 0;
    cs.current_tag.d[1] = 0;
    if(verbose) printf("\n\nDECRYPTION TEST\n");

    operation_result_t decrypt_result = decrypt_from_state(
            &cs,
            aad, aad_length,
            reference_ciphertext, plaintext_length,
            reference_tag,
            output); //Outputs

    if(verbose)
    {
        if(output != NULL) {
            printf("Computed plaintext: 0x");
            for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                printf("%02x", output[i]);
            }
            printf("\n");
        } else {
            printf("Computed plaintext: NULL\n");
        }
        printf("Computed tag: 0x%016lx_%016lx\n",
                __builtin_bswap64(cs.current_tag.d[0]),
                __builtin_bswap64(cs.current_tag.d[1]));
    }

    bool ref_plaintext_match = true;
    for(int i=0; i<(plaintext_length>>3); ++i) {
        if( output[i] != reference_plaintext[i] ) ref_plaintext_match = false;
    }
    bool reference_tag_match = true;
    for(int i=0; i<(cs.constants->tag_byte_length); ++i) {
        if( tag[i] != reference_tag[i] ) reference_tag_match = false;
    }
    if(verbose) printf("Reference plaintext match %s!\nReference tag match %s!\n", ref_plaintext_match ? "success" : "failure", reference_tag_match ? "success" : "failure");

    free(output);
    free(tag);
    cs.counter = temp_counter;
    if(decrypt_result != AUTHENTICATION_FAILURE) {
        if(verbose) printf("Decryption didn't cause authentication failure!\n");
        success = false;
    }
    else
    {
        if(verbose) printf("Decryption failed authentication correctly\n");
    }

    return success;
}

//// Read a reference file and check that encrypt/decrypt operations are
//// producing the correct outputs without errors
void process_test_file(FILE * fin)
{
    //// Initialise/Default values
    cipher_constants_t cc = { .mode = 0 };
    cipher_state_t cs = { .counter = { .d = {0,0} } };
    cs.constants = &cc;
    uint8_t * aad = NULL;
    uint64_t aad_length = 0;
    uint64_t aad_byte_length = 0;

    uint8_t * reference_plaintext = NULL;
    uint64_t plaintext_length = 0;
    uint64_t plaintext_byte_length = 0;

    uint8_t reference_checksum[8] = { 0 };
    bool checksum_set = false;

    uint8_t reference_tag[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

    uint8_t * reference_ciphertext = NULL;

    uint8_t * nonce = NULL;
    uint64_t nonce_length = 96;
    uint64_t nonce_byte_length = 16;

    char * input_buff = (char *)malloc(MAX_LINE_LEN);
    fpos_t last_line;
    uint8_t key_length = 16;

    bool acceptable = true;
    bool new_reference = false;
    bool expect_valid_auth = true;
    uint64_t passes = 0;
    uint64_t skips = 0;

    while(!feof(fin)) {
        fgetpos(fin, &last_line);
        if(fgets(input_buff, MAX_LINE_LEN, fin)) {
            if (input_buff[0]!='#' && input_buff[0]!='\0') {
                if(input_buff[0] == '\n' || (input_buff[0] == '\r' && input_buff[1] == '\n')) {
                    if(new_reference)
                    {
                        if(acceptable)
                        {
                            bool pass;
                            if(expect_valid_auth) {
                                pass = test_reference( cs,
                                            aad, aad_length,
                                            reference_plaintext,
                                            plaintext_length,
                                            plaintext_byte_length,
                                            reference_tag,
                                            reference_ciphertext,
                                            *((uint64_t *) reference_checksum), checksum_set,
                                            false);
                            } else {
                                pass = test_reference_invalid_auth( cs,
                                            aad, aad_length,
                                            reference_plaintext,
                                            plaintext_length,
                                            plaintext_byte_length,
                                            reference_tag,
                                            reference_ciphertext,
                                            false);
                            }

                            if (!pass)
                            {
                                for(uint64_t i=0; i<15; ++i) {
                                    quadword_t tmp = cs.constants->expanded_aes_keys[i];
                                    printf("expanded_aes_keys[%lu] %016lx %016lx\n",
                                        i,
                                        (tmp.d[1]), (tmp.d[0]));
                                }

                                for(uint64_t i=0; i<MAX_UNROLL_FACTOR; ++i) {
                                    quadword_t tmp = cs.constants->expanded_hash_keys[i];
                                    printf("expanded_hash_keys[%lu] %016lx %016lx\n",
                                        i,
                                        (tmp.d[1]), (tmp.d[0]));
                                }
                                for(uint64_t i=0; i<MAX_UNROLL_FACTOR; ++i) {
                                    doubleword_t tmp = cs.constants->karat_hash_keys[i];
                                    printf("karat_hash_keys[%lu] %016lx\n",
                                        i,
                                        (tmp.d[0]));
                                }

                                printf("Keylen = %u\nIVlen = %lu\nPTlen = %lu\nAADlen = %lu\nTaglen = %u\n",
                                        key_length<<3,nonce_length, plaintext_length, aad_length, (cs.constants->tag_byte_length)<<3);
                                printf("Key 0x");
                                for(uint64_t i=0; i<key_length; ++i) {
                                    printf("%02x", cs.constants->expanded_aes_keys[0].b[i]);
                                }
                                printf("\n");
                                printf("IV  0x");
                                for(uint64_t i=0; i<((nonce_length+7)>>3); ++i) {
                                    printf("%02x", nonce[i]);
                                }
                                printf("\n");
                                printf("IVp 0x");
                                for(uint64_t i=0; i<nonce_byte_length; ++i) {
                                    printf("%02x", cs.counter.b[i]);
                                }
                                printf("\n");
                                printf("PT  0x");
                                for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                                    printf("%02x", reference_plaintext[i]);
                                }
                                printf("\n");
                                printf("CS  0x");
                                for(uint64_t i=0; i<8; ++i) {
                                    printf("%02x", reference_checksum[i]);
                                }
                                printf("\n");
                                printf("AAD 0x");
                                for(uint64_t i=0; i<aad_byte_length; ++i) {
                                    printf("%02x", aad[i]);
                                }
                                printf("\n");
                                printf("CT  0x");
                                for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                                    printf("%02x", reference_ciphertext[i]);
                                }
                                printf("\n");
                                printf("Tag 0x");
                                for(uint64_t i=0; i<(cs.constants->tag_byte_length); ++i) {
                                    printf("%02x", reference_tag[i]);
                                }
                                printf("\n");

                                if(expect_valid_auth) {
                                    pass = test_reference( cs,
                                                aad, aad_length,
                                                reference_plaintext,
                                                plaintext_length,
                                                plaintext_byte_length,
                                                reference_tag,
                                                reference_ciphertext,
                                                *((uint64_t *) reference_checksum), checksum_set,
                                                true);
                                } else {
                                    pass = test_reference_invalid_auth( cs,
                                                aad, aad_length,
                                                reference_plaintext,
                                                plaintext_length,
                                                plaintext_byte_length,
                                                reference_tag,
                                                reference_ciphertext,
                                                true);
                                }
                                exit(1);
                            }
                            passes++;
                        }
                        else
                        {
                            skips++;
                        }
                    }
                    new_reference = false;
                    checksum_set = false;
                    expect_valid_auth = true;
                }
                else if(strncmp(input_buff, "[Keylen", 7) == 0) {
                    //set the cipher mode
                    if(strncmp (input_buff+10, "128", 3) == 0) {
                        cs.constants->mode = AES_GCM_128;
                        key_length = 16;
                        aesgcm_debug_printf("Cipher mode set to AES_GCM_128\n");
                    } else if(strncmp (input_buff+10, "192", 3) == 0) {
                        cs.constants->mode = AES_GCM_192;
                        key_length = 24;
                        aesgcm_debug_printf("Cipher mode set to AES_GCM_192\n");
                    } else if(strncmp (input_buff+10, "256", 3) == 0) {
                        cs.constants->mode = AES_GCM_256;
                        key_length = 32;
                        aesgcm_debug_printf("Cipher mode set to AES_GCM_256\n");
                    } else {
                        aesgcm_debug_printf("Cipher mode not recognised - keeping previous value\n");
                    }
                }
                else if(strncmp(input_buff, "[IVlen", 6) == 0) {
                    //set the nonce length
                    nonce_length = strtoul(input_buff+9, NULL, 10);
                    nonce_byte_length = ((nonce_length+127)&~127ul)>>3; //pad to block size
                    free(nonce);
                    nonce = (uint8_t *)malloc(nonce_byte_length);
                    aesgcm_debug_printf("Nonce length set to %lu\n", nonce_length);
                }
                else if(strncmp(input_buff, "[PTlen", 6) == 0) {
                    //set the plaintext length
                    plaintext_length = strtoul(input_buff+9, NULL, 10);
                    plaintext_byte_length = ((plaintext_length+127)&~127ul)>>3; //pad to block size
                    aesgcm_debug_printf("1 addr %lx len %lu bitlen %lu\n", (uint64_t) reference_plaintext, plaintext_length, plaintext_byte_length);
                    free(reference_plaintext);
                    free(reference_ciphertext);
                    if( plaintext_byte_length ) {
                        reference_plaintext = (uint8_t *)malloc(plaintext_byte_length);
                        reference_ciphertext = (uint8_t *)malloc(plaintext_byte_length);
                    } else {
                        reference_plaintext = NULL;
                        reference_ciphertext = NULL;
                    }
                    aesgcm_debug_printf("Plaintext length set to %lu\n", plaintext_length);
                }
                else if(strncmp(input_buff, "[AADlen", 7) == 0) {
                    //set the aad length
                    aad_length = strtoul(input_buff+10, NULL, 10);
                    aad_byte_length = ((aad_length+127)&~127ul)>>3; //pad to block size
                    free(aad);
                    aad = (uint8_t *)malloc(aad_byte_length);
                    aesgcm_debug_printf("AAD length set to %lu\n", aad_length);
                }
                else if(strncmp(input_buff, "[Taglen", 7) == 0) {
                    //set the tag length
                    cs.constants->tag_byte_length = (uint8_t) strtoul(input_buff+10, NULL, 10)>>3;
                    aesgcm_debug_printf("Tag length set to %u\n\n", (cs.constants->tag_byte_length)<<3);
                }
                else if(strncmp(input_buff, "Count", 5) == 0) {
                    //start of new reference
                    aesgcm_debug_printf("New reference: %s\n", input_buff);
                    new_reference = true;
                }
                else if(strncmp(input_buff, "Key", 3) == 0) {
                    //set the AES key and associated precomputation
                    //needs the cipher mode to be set already
                    uint8_t temp_key[32];
                    fsetpos(fin, &last_line);
                    fseek(fin, 6, SEEK_CUR);
                    for(uint64_t i=0; i<key_length; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        temp_key[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                    operation_result_t result;
                    result = AArch64crypto_aes_gcm_set_constants(cs.constants->mode, cs.constants->tag_byte_length, temp_key, &cc);
                    aesgcm_debug_printf("Key start\n");
                    if(result != SUCCESSFUL_OPERATION) {
                        printf("Failure in key expansion!\n");
                        exit(1);
                    } else {
                        //FIXME: I think this makes sense on BE systems, need to check
                        aesgcm_debug_printf("Key set to %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                temp_key[0], temp_key[1], temp_key[2],  temp_key[3],  temp_key[4],  temp_key[5],  temp_key[6],  temp_key[7],
                                temp_key[8], temp_key[9], temp_key[10], temp_key[11], temp_key[12], temp_key[13], temp_key[14], temp_key[15]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "IV", 2) == 0) {
                    //set the nonce
                    fsetpos(fin, &last_line);
                    fseek(fin, 5, SEEK_CUR);
                    for(uint64_t i=0; i<((nonce_length+7)>>3); ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        nonce[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                    for(uint64_t i=(nonce_length+7)>>3; i<nonce_byte_length; ++i) {
                        nonce[i] = 0xde; //ensure that reading beyond end will be caught
                    }
                    operation_result_t result = aes_gcm_set_counter(nonce, nonce_length, &cs);
                    if(result != SUCCESSFUL_OPERATION) {
                        printf("Failure while setting nonce!\n");
                        exit(1);
                    }
                    aesgcm_debug_printf("Set nonce - length %lu (%lu) 0x", nonce_length, nonce_byte_length);
                    for(uint64_t i=0; i<nonce_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", nonce[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "PT", 2) == 0) {
                    //set the reference plaintext
                    fsetpos(fin, &last_line);
                    fseek(fin, 5, SEEK_CUR);
                    for(uint64_t i=0; i<((plaintext_length+7)>>3); ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        reference_plaintext[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                    for(uint64_t i=(plaintext_length+7)>>3; i<plaintext_byte_length; ++i) {
                        reference_plaintext[i] = 0xde; //ensure that reading beyond end will be caught
                    }
                    aesgcm_debug_printf("Set reference plaintext - length %lu (%lu) 0x", plaintext_length, plaintext_byte_length);
                    for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", reference_plaintext[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "CS", 2) == 0) {
                    //set the reference plaintext
                    fsetpos(fin, &last_line);
                    fseek(fin, 5, SEEK_CUR);
                    for(uint64_t i=0; i<8; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        reference_checksum[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                    checksum_set = true;
                    aesgcm_debug_printf("Set reference checksum - length %lu (%lu) 0x", 8ul, 8ul);
                    for(uint64_t i=0; i<8; ++i) {
                        aesgcm_debug_printf("%02x", reference_checksum[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "AAD", 3) == 0) {
                    //set the additional authentication data
                    fsetpos(fin, &last_line);
                    fseek(fin, 6, SEEK_CUR);
                    for(uint64_t i=0; i<((aad_length+7)>>3); ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        aad[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                    for(uint64_t i=(aad_length+7)>>3; i<aad_byte_length; ++i) {
                        aad[i] = 0xde; //ensure that reading beyond end will be caught
                    }
                    aesgcm_debug_printf("Set aad - length %lu (%lu) 0x", aad_length, aad_byte_length);
                    for(uint64_t i=0; i<aad_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", aad[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "CT", 2) == 0) {
                    //set the reference ciphertext
                    fsetpos(fin, &last_line);
                    fseek(fin, 5, SEEK_CUR);
                    for(uint64_t i=0; i<((plaintext_length+7)>>3); ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        reference_ciphertext[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                    for(uint64_t i=(plaintext_length+7)>>3; i<plaintext_byte_length; ++i) {
                        reference_ciphertext[i] = 0xde; //ensure that reading beyond end will be caught
                    }
                    aesgcm_debug_printf("Set reference ciphertext - length %lu (%lu) 0x", plaintext_length, plaintext_byte_length);
                    for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", reference_ciphertext[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "Tag", 3) == 0) {
                    //set the authentication tag
                    for(int i=0; i<16; ++i) {
                        reference_tag[i] = hextobyte(input_buff[6+(2*i)], input_buff[7+(2*i)]);
                    }
                    aesgcm_debug_printf("Set reference tag - length %u (%u) 0x", (cs.constants->tag_byte_length)<<3, cs.constants->tag_byte_length);
                    for (uint64_t i=0; i<cs.constants->tag_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", reference_tag[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "FAIL", 4) == 0) {
                    //Expect this reference to fail
                    expect_valid_auth = false;
                    aesgcm_debug_printf("Expect this reference to fail\n");
                }
            }
        }
    }
    free(input_buff);

    printf("Successfully processed %lu inputs:\nPASS:\t%lu\nSKIP:\t%lu\n\n", passes+skips, passes, skips);

    free(aad);
    free(reference_plaintext);
    free(reference_ciphertext);
}

int main(int argc, char* argv[]) {
    //// Get reference input file name
    char reference_filename[100];
    if(argc==2) {
        strcpy(reference_filename, argv[1]);
    } else {
        strcpy(reference_filename, "ref_default");
    }
    printf("Using reference file %s\n", reference_filename);
    FILE * fin = fopen(reference_filename,"rb");
    if(fin == NULL) {
        printf("Could not open reference file\n");
        exit(1);
    }

    process_test_file(fin);
    fclose(fin);

    return 0;
}
