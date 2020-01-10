//Copyright (c) 2018-2019, ARM Limited. All rights reserved.
//
//SPDX-License-Identifier:        BSD-3-Clause

#define NDEBUG
#include <assert.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "AArch64cryptolib.h"

#define MAX_LINE_LEN 128

#define operation_result_t  AArch64crypto_operation_result_t

#ifndef TEST_DEBUG
#define TEST_DEBUG_PRINTF 0
#else
#define TEST_DEBUG_PRINTF 1
#endif

#define aescbc_debug_printf(...) \
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
void process_test_file(FILE * fin, uint64_t test_count, bool encrypt,
                       bool overwrite_buffer_length, uint64_t overwritten_buffer_length)
{
    //// Initialise/Default values
    uint64_t block_byte_length = 16;

    uint64_t plaintext_byte_length = 0;

    char * input_buff = (char *)malloc(MAX_LINE_LEN);
    fpos_t last_line;

    uint8_t *key = NULL;
    uint8_t *iv = NULL;
    uint8_t *pt = NULL;
    uint8_t *ct = NULL;
    bool new_reference = false;

    //set up PT/CT variables if we're overwriting the buffer length
    if(overwrite_buffer_length) {
        plaintext_byte_length = (overwritten_buffer_length+15)&~15;
    }

    key = malloc(block_byte_length);
    iv = malloc(block_byte_length);

    while(!feof(fin)) {
        fgetpos(fin, &last_line);
        if(fgets(input_buff, MAX_LINE_LEN, fin)) {
            if (input_buff[0]!='#' && input_buff[0]!='\0') {
                if(input_buff[0] == '\n' || (input_buff[0] == '\r' && input_buff[1] == '\n')) {
                    if(new_reference)
                    {
                        operation_result_t result = SUCCESSFUL_OPERATION;
                        AArch64crypto_cipher_digest_t arg;
                        uint8_t key_expanded[256] = {0};
                        uint8_t *output;
                        uint8_t *auth;

                        output = (uint8_t *)malloc(plaintext_byte_length);
                        //// Dummy auth data to feed cipher function.
                        auth = (uint8_t *)malloc(block_byte_length);
                        //// Dummy auth key
                        arg.digest.hmac.key = key;
                        arg.digest.hmac.i_key_pad = key;
                        arg.digest.hmac.o_key_pad = key;
                        if(encrypt)
                        {
                            AArch64crypto_aes_cbc_expandkeys_128_enc(key_expanded, key);
                            arg.cipher.key = key_expanded;
                            arg.cipher.iv = iv;
                            for(uint64_t i=0; i<test_count; ++i) {
                                result |= AArch64crypto_encrypt_aes128cbc_sha1(
                                            pt, output, plaintext_byte_length,
                                            pt, auth, plaintext_byte_length,
                                            &arg);
#ifdef TEST_DEBUG
                                printf("encrypt output:\n");
                                for(int i=0; i<plaintext_byte_length; ++i) {
                                    printf("%02x", output[i]);
                                }
                                for(int i=0; i<plaintext_byte_length; ++i) {
                                    if( output[i] != ct[i] ) {
                                        printf("encrypt failed. result: %d\n", result);
                                        break;
                                    }
                                }
                                printf("\n");
#endif
                            }
                        } else {
                            AArch64crypto_aes_cbc_expandkeys_128_dec(key_expanded, key);
                            arg.cipher.key = key_expanded;
                            arg.cipher.iv = iv;
                            for(uint64_t i=0; i<test_count; ++i) {
                                result |= AArch64crypto_decrypt_aes128cbc_sha1(
                                            ct, output, plaintext_byte_length,
                                            output, auth, plaintext_byte_length,
                                            &arg);
#ifdef TEST_DEBUG
                                printf("decrypt output:\n");
                                for(int i=0; i<plaintext_byte_length; ++i) {
                                    printf("%02x", output[i]);
                                }
                                for(int i=0; i<plaintext_byte_length; ++i) {
                                    if( output[i] != pt[i] ) {
                                        printf("decrypt failed. result: %d\n", result);
                                        break;
                                    }
                                }
                                printf("\n");
#endif
                            }
                        }
                        printf("%s\n%lu runs\n%lu bytes\nResult is %s\n",
                        encrypt ? "Encrypt" : "Decrypt",
                        test_count, plaintext_byte_length, (result == SUCCESSFUL_OPERATION) ? "Success" : "Failure");

                        free(output);
                        free(auth);
                    }
                    new_reference = false;
                }
                else if(strncmp(input_buff, "COUNT", 5) == 0) {
                    if( test_count == 0) {
                        test_count = strtoul(input_buff+8, NULL, 10);
                    }
                    aescbc_debug_printf("Test count set to: %lu\n", test_count);
                    new_reference = true;
                }
                else if(strncmp(input_buff, "KEY", 3) == 0) {
                    //set the AES key
                    fsetpos(fin, &last_line);
                    fseek(fin, 6, SEEK_CUR);
                    for(uint64_t i=0; i<block_byte_length; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        key[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}

                    aescbc_debug_printf("Key set to %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                            key[0], key[1], key[2],  key[3],  key[4],  key[5],  key[6],  key[7],
                            key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]);
                    aescbc_debug_printf("\n");
                }
                else if(strncmp(input_buff, "IV", 2) == 0) {
                    //set the nonce
                    fsetpos(fin, &last_line);
                    fseek(fin, 5, SEEK_CUR);
                    for(uint64_t i=0; i<block_byte_length; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        iv[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}

                    aescbc_debug_printf("Set nonce - length %lu Bytes 0x", block_byte_length);
                    for(uint64_t i=0; i<block_byte_length; ++i) {
                        aescbc_debug_printf("%02x", iv[i]);
                    }
                    aescbc_debug_printf("\n");
                }
                else if(strncmp(input_buff, "PLAINTEXT", 9) == 0) {
                    //set the reference plaintext
                    uint64_t i=0;
                    fsetpos(fin, &last_line);
                    fseek(fin, 12, SEEK_CUR);
                    while( isxdigit(fgetc(fin)) ) {
                        i++;
                    }
                    if (plaintext_byte_length == 0) {
                        plaintext_byte_length = (i >> 1);
                    }
                    pt = (uint8_t *)malloc(plaintext_byte_length);
                    fsetpos(fin, &last_line);
                    fseek(fin, 12, SEEK_CUR);
                    for (i=0; i<plaintext_byte_length; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        pt[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}

                    aescbc_debug_printf("Set reference plaintext - length %lu Bytes 0x", plaintext_byte_length);
                    for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                        aescbc_debug_printf("%02x", pt[i]);
                    }
                    aescbc_debug_printf("\n");
                }
                else if(strncmp(input_buff, "CIPHERTEXT", 10) == 0) {
                    //set the reference ciphertext
                    uint64_t i=0;
                    fsetpos(fin, &last_line);
                    fseek(fin, 13, SEEK_CUR);
                    while( isxdigit(fgetc(fin)) ) {
                        i++;
                    }
                    if (plaintext_byte_length == 0) {
                        plaintext_byte_length = (i >> 1);
                    }
                    ct = (uint8_t *)malloc(plaintext_byte_length);
                    fsetpos(fin, &last_line);
                    fseek(fin, 13, SEEK_CUR);
                    for(i=0; i<plaintext_byte_length; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        ct[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}

                    aescbc_debug_printf("Set reference ciphertext - length %lu Bytes 0x", plaintext_byte_length);
                    for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                        aescbc_debug_printf("%02x", ct[i]);
                    }
                    aescbc_debug_printf("\n");
                }
            }
            else if(strncmp(input_buff, "# Key Length :", 14) == 0) {
                    //Check key length
                    if(strncmp (input_buff+15, "128", 3) != 0) {
                    printf("ERROR: Currently only key length 128 is supported.\n");
                    exit(1);
                }
            }
        }
    }
    free(key);
    free(iv);
    free(pt);
    free(ct);
    free(input_buff);
}

int main(int argc, char* argv[]) {
    //// Get input cipher size
    char reference_filename[100];
    uint64_t test_count = 0;
    bool encrypt = true;
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
        overwrite_buffer_length = true;
        overwritten_buffer_length = strtoul(argv[4], NULL, 10);
    }

    printf("Using reference file %s\n", reference_filename);
    FILE * fin = fopen(reference_filename,"rb");
    if(fin == NULL) {
        printf("Could not open reference file\n");
        exit(1);
    }

    process_test_file(fin, test_count, encrypt, overwrite_buffer_length, overwritten_buffer_length);
    fclose(fin);

    return 0;
}
