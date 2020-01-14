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

#define cipher_mode_t       armv8_cipher_mode_t
#define operation_result_t  armv8_operation_result_t
#define quadword_t          armv8_quadword_t
#define cipher_constants_t  armv8_cipher_constants_t
#define cipher_state_t      armv8_cipher_state_t

#define aes_gcm_set_counter             armv8_aes_gcm_set_counter
#define encrypt_full                    armv8_enc_aes_gcm_full
#define encrypt_from_state              armv8_enc_aes_gcm_from_state
#define encrypt_from_constants_IPsec    armv8_enc_aes_gcm_from_constants_IPsec
#define decrypt_full                    armv8_dec_aes_gcm_full
#define decrypt_from_state              armv8_dec_aes_gcm_from_state
#define decrypt_from_constants_IPsec    armv8_dec_aes_gcm_from_constants_IPsec

#ifndef TEST_DEBUG
#define TEST_DEBUG_PRINTF 0
#else
#define TEST_DEBUG_PRINTF 1
#endif

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

//// Read a reference file and check that encrypt/decrypt operations are
//// producing the correct outputs without errors
void process_test_file(FILE * fin, uint64_t test_count, bool encrypt, bool IPsec,
                       bool overwrite_buffer_length, uint64_t overwritten_buffer_length)
{
    //// Initialise/Default values
    cipher_constants_t cc = { .mode = 0 };
    cipher_state_t cs = { .counter = { .d = {0,0} } };
    cs.constants = &cc;
    uint8_t * aad = NULL;
    uint64_t aad_length = 0;
    uint64_t aad_byte_length = 0;

    uint8_t * reference_plaintext = NULL;
    uint8_t * plaintext = NULL;
    uint64_t plaintext_length = 0;
    uint64_t plaintext_byte_length = 0;

    uint8_t reference_tag[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    uint8_t tag[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

    uint8_t * reference_ciphertext = NULL;
    uint8_t * ciphertext = NULL;

    uint8_t * nonce = NULL;
    uint64_t nonce_length = 96;
    uint64_t nonce_byte_length = 16;

    char * input_buff = (char *)malloc(MAX_LINE_LEN);
    fpos_t last_line;
    uint8_t key_length = 16;

    bool new_reference = false;

    //set up PT/CT variables if we're overwriting the buffer length
    if(overwrite_buffer_length) {
        plaintext_length = overwritten_buffer_length<<3;
        plaintext_byte_length = (overwritten_buffer_length+15)&~15;
        free(reference_plaintext);
        reference_plaintext = (uint8_t *)malloc(plaintext_byte_length);
        free(plaintext);
        plaintext = (uint8_t *)malloc(plaintext_byte_length);
        free(reference_ciphertext);
        reference_ciphertext = (uint8_t *)malloc(plaintext_byte_length);
        free(ciphertext);
        ciphertext = (uint8_t *)malloc(plaintext_byte_length);
    }

    while(!feof(fin)) {
        fgetpos(fin, &last_line);
        if(fgets(input_buff, MAX_LINE_LEN, fin)) {
            if (input_buff[0]!='#' && input_buff[0]!='\0') {
                if(input_buff[0] == '\n' || (input_buff[0] == '\r' && input_buff[1] == '\n')) {
                    if(new_reference)
                    {
                        operation_result_t result = SUCCESSFUL_OPERATION;
                        if(encrypt)
                        {
                            if(IPsec)
                            {
                                #ifdef IPSEC_ENABLED
                                uint32_t salt = cs.counter.s[0];
                                uint64_t ESPIV = (((uint64_t) cs.counter.s[2])<<32) | cs.counter.s[1];
                                for(uint64_t i=0; i<test_count; ++i) {
                                    result = encrypt_from_constants_IPsec(
                                                    cs.constants,
                                                    salt,
                                                    ESPIV,
                                                    aad, aad_length>>3,
                                                    reference_plaintext, plaintext_length>>3,
                                                    tag);
                                }
                                #else
                                printf("IPsec not supported on this target\n");
                                #endif
                            } else {
                                for(uint64_t i=0; i<test_count; ++i) {
                                    result |= encrypt_from_state(
                                                &cs,
                                                aad, aad_length,
                                                reference_plaintext, plaintext_length,     //Inputs
                                                ciphertext,
                                                tag); //Outputs
                                }
                            }
                        } else {
                            if(IPsec)
                            {
                                #ifdef IPSEC_ENABLED
                                uint32_t salt = cs.counter.s[0];
                                uint64_t ESPIV = (((uint64_t) cs.counter.s[2])<<32) | cs.counter.s[1];
                                uint64_t checksum;
                                for(uint64_t i=0; i<test_count; ++i) {
                                    result = decrypt_from_constants_IPsec(
                                                    cs.constants,
                                                    salt,
                                                    ESPIV,
                                                    aad, aad_length>>3,
                                                    reference_ciphertext, plaintext_length>>3,
                                                    tag,
                                                    &checksum);
                                }
                                #else
                                printf("IPsec not supported on this target\n");
                                #endif
                            } else {
                                for(uint64_t i=0; i<test_count; ++i) {
                                    result |= decrypt_from_state(
                                                &cs,
                                                aad, aad_length,
                                                reference_ciphertext, plaintext_length,
                                                reference_tag,                              //Inputs
                                                plaintext); //Output
                                }
                            }
                        }
                        printf("%s - %s\n%lu runs\n%lu bytes\nResult is %s\n%s",
                        encrypt ? "Encrypt" : "Decrypt", IPsec ? "IPsec" : "Generic",
                        test_count, plaintext_byte_length, (result == SUCCESSFUL_OPERATION) ? "Success" : "Failure",
                        encrypt ? "" : "(only should be Success with 1 run - need to reset counter and tag between each call)\n");
                    }
                    new_reference = false;
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
                else if(strncmp(input_buff, "[PTlen", 6) == 0 && !overwrite_buffer_length) {
                    //set the plaintext length
                    plaintext_length = strtoul(input_buff+9, NULL, 10);
                    plaintext_byte_length = ((plaintext_length+127)&~127ul)>>3; //pad to block size
                    free(reference_plaintext);
                    reference_plaintext = (uint8_t *)malloc(plaintext_byte_length);
                    free(plaintext);
                    plaintext = (uint8_t *)malloc(plaintext_byte_length);
                    free(reference_ciphertext);
                    reference_ciphertext = (uint8_t *)malloc(plaintext_byte_length);
                    free(ciphertext);
                    ciphertext = (uint8_t *)malloc(plaintext_byte_length);
                    aesgcm_debug_printf("Plaintext length set to %lu\n", plaintext_length);
                }
                else if(strncmp(input_buff, "[AADlen", 7) == 0) {
                    //set the aad length
                    aad_length = strtoul(input_buff+10, NULL, 10);
                    aad_byte_length = ((aad_length+127)&~127ul)>>3; //pad to block size
                    free(aad);
                    aad = (uint8_t *)malloc(aad_byte_length);
                    aesgcm_debug_printf("AAD length set to %lu\n", aad_byte_length);
                }
                else if(strncmp(input_buff, "[Taglen", 7) == 0) {
                    //set the tag length
                    cs.constants->tag_byte_length = (uint8_t) strtoul(input_buff+10, NULL, 10)>>3;
                    aesgcm_debug_printf("Tag length set to %u\n\n", (cs.constants->tag_byte_length)<<3);
                }
                else if(strncmp(input_buff, "Count", 5) == 0) {
                    //start of new reference
                    if( test_count == 0) {
                        test_count = strtoul(input_buff+8, NULL, 10);
                    }
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
                    result = armv8_aes_gcm_set_constants(cs.constants->mode, cs.constants->tag_byte_length, temp_key, &cc);
                    if(result != SUCCESSFUL_OPERATION) {
                        printf("Failure in key expansion!\n");
                        exit(1);
                    } else {
                        //FIXME: I think this makes sense on BE systems, need to check
                        aesgcm_debug_printf("Key set to %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                temp_key[0], temp_key[1], temp_key[2],  temp_key[3],  temp_key[4],  temp_key[5],  temp_key[6],  temp_key[7],
                                temp_key[8], temp_key[9], temp_key[10], temp_key[11], temp_key[12], temp_key[13], temp_key[14], temp_key[15]);
                    }
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
                        nonce[i] = 0;
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
                        reference_plaintext[i] = 0;
                    }
                    aesgcm_debug_printf("Set reference plaintext - length %lu (%lu) 0x", plaintext_length, plaintext_byte_length);
                    for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", reference_plaintext[i]);
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
                        aad[i] = 0;
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
                        reference_ciphertext[i] = 0;
                    }
                    aesgcm_debug_printf("Set reference ciphertext - length %lu (%lu) 0x", plaintext_length, plaintext_byte_length);
                    for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", reference_ciphertext[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "Tag", 3) == 0) {
                    //set the authentication tag
                    // quadword_t temp_tag;
                    for(int i=0; i<16; ++i) {
                        reference_tag[i] = hextobyte(input_buff[6+(2*i)], input_buff[7+(2*i)]);
                    }
                    aesgcm_debug_printf("Reference tag set to %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                            reference_tag[0], reference_tag[1], reference_tag[2], reference_tag[3], reference_tag[4], reference_tag[5], reference_tag[6], reference_tag[7],
                            reference_tag[8], reference_tag[9], reference_tag[10], reference_tag[11], reference_tag[12], reference_tag[13], reference_tag[14], reference_tag[15] );
                }
            }
        }
    }
    free(input_buff);

    free(aad);
    free(reference_plaintext);
    free(reference_ciphertext);
}

int main(int argc, char* argv[]) {
    //// Get input cipher size
    char reference_filename[100];
    uint64_t test_count = 0;
    bool encrypt = true;
    bool IPsec = true;
    bool overwrite_buffer_length = false;
    uint64_t overwritten_buffer_length = 0;
    if(argc>=2) {
        strcpy(reference_filename, argv[1]);
    } else {
        strcpy(reference_filename, "ref_default");
    }
    if(argc>=3) {
        test_count = strtoul(argv[2], NULL, 10);
    }
    if(argc>=4) {
        encrypt = (bool) strtoul(argv[3], NULL, 10);
    }
    if(argc>=5) {
        IPsec = (bool) strtoul(argv[4], NULL, 10);
    }
    if(argc>=6) {
        overwrite_buffer_length = true;
        overwritten_buffer_length = strtoul(argv[5], NULL, 10);
    }
    printf("Using reference file %s\n", reference_filename);
    FILE * fin = fopen(reference_filename,"rb");
    if(fin == NULL) {
        printf("Could not open reference file\n");
        exit(1);
    }

    process_test_file(fin, test_count, encrypt, IPsec, overwrite_buffer_length, overwritten_buffer_length);
    fclose(fin);

    return 0;
}
