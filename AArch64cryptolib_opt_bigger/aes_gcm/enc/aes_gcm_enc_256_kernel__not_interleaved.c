/*--------------------------------------------------------------------------
* The confidential and proprietary information contained in this file may
* only be used by a person authorised under and to the extent permitted
* by a subsisting licensing agreement from ARM Limited.
*
*            (C) COPYRIGHT 2018 ARM Limited.
*                ALL RIGHTS RESERVED
*
* This entire notice must be reproduced on all copies of this file
* and copies of this file may only be made by a person if such person is
* permitted to do so under the terms of a subsisting license agreement
* from ARM Limited.
*
* AUTHOR : Samuel Lee <samuel.lee@arm.com>
*
* HISTORY :
*
*---------------------------------------------------------------------------*/

/*
Approach - We want to reload constants as we have plenty of spare ASIMD slots around crypto units for loading
Unroll x8 in main loop
*/

#define end_input_ptr       "x4"
#define main_end_input_ptr  "x5"
#define temp0_x     "x6"
#define temp1_x     "x7"
#define temp2_x     "x13"
#define temp3_x     "x14"

#define ctr0b       "v0.16b"
#define ctr0        "v0"
#define ctr0d       "d0"
#define ctr1b       "v1.16b"
#define ctr1        "v1"
#define ctr1d       "d1"
#define ctr2b       "v2.16b"
#define ctr2        "v2"
#define ctr2d       "d2"
#define ctr3b       "v3.16b"
#define ctr3        "v3"
#define ctr3d       "d3"
#define ctr4b       "v4.16b"
#define ctr4        "v4"
#define ctr4d       "d4"
#define ctr5b       "v5.16b"
#define ctr5        "v5"
#define ctr5d       "d5"
#define ctr6b       "v6.16b"
#define ctr6        "v6"
#define ctr6d       "d6"
#define ctr7b       "v7.16b"
#define ctr7        "v7"
#define ctr7d       "d7"

#define res0b       "v8.16b"
#define res0        "v8"
#define res0q       "q8"
#define res1b       "v9.16b"
#define res1        "v9"
#define res1q       "q9"
#define res2b       "v10.16b"
#define res2        "v10"
#define res2q       "q10"
#define res3b       "v11.16b"
#define res3        "v11"
#define res3q       "q11"
#define res4b       "v12.16b"
#define res4        "v12"
#define res4q       "q12"
#define res5b       "v13.16b"
#define res5        "v13"
#define res5q       "q13"
#define res6b       "v14.16b"
#define res6        "v14"
#define res6q       "q14"
#define res7b       "v15.16b"
#define res7        "v15"
#define res7q       "q15"

#define ctr_t0      "v8"
#define ctr_t0b     "v8.16b"
#define ctr_t0q     "q8"
#define ctr_t1      "v9"
#define ctr_t1b     "v9.16b"
#define ctr_t1q     "q9"
#define ctr_t2      "v10"
#define ctr_t2b     "v10.16b"
#define ctr_t2q     "q10"
#define ctr_t3      "v11"
#define ctr_t3b     "v11.16b"
#define ctr_t3q     "q11"
#define ctr_t4      "v12"
#define ctr_t4b     "v12.16b"
#define ctr_t4q     "q12"
#define ctr_t5      "v13"
#define ctr_t5b     "v13.16b"
#define ctr_t5q     "q13"
#define ctr_t6      "v14"
#define ctr_t6b     "v14.16b"
#define ctr_t6q     "q14"
#define ctr_t7      "v15"
#define ctr_t7b     "v15.16b"
#define ctr_t7q     "q15"

#define acc_hb      "v17.16b"
#define acc_h       "v17"
#define acc_mb      "v18.16b"
#define acc_m       "v18"
#define acc_lb      "v19.16b"
#define acc_l       "v19"

#define h1          "v20"
#define h1q         "q20"
#define h12k        "v21"
#define h12kq       "q21"
#define h2          "v22"
#define h2q         "q22"
#define h3          "v23"
#define h3q         "q23"
#define h34k        "v24"
#define h34kq       "q24"
#define h4          "v25"
#define h4q         "q25"
#define h5          "v20"
#define h5q         "q20"
#define h56k        "v21"
#define h56kq       "q21"
#define h6          "v22"
#define h6q         "q22"
#define h7          "v23"
#define h7q         "q23"
#define h78k        "v24"
#define h78kq       "q24"
#define h8          "v25"
#define h8q         "q25"

#define t0          "v16"
#define t0d         "d16"

#define t1          "v29"
#define t2          res1
#define t3          t1

#define t4          res0
#define t5          res2
#define t6          t0

#define t7          res3
#define t8          res4
#define t9          res5

#define t10         res6
#define t11         "v21"
#define t12         t1

#define rtmp_ctr    "v30"
#define rtmp_ctrq   "q30"
#define rctr_inc    "v31"
#define rctr_incd   "d31"

#define mod_constant  t0
#define mod_constantd t0d

#define rk0         "v26.16b"
#define rk0q        "q26"
#define rk1         "v27.16b"
#define rk1q        "q27"
#define rk2         "v28.16b"
#define rk2q        "q28"
#define rk2q1       "v28.1q"
#define rk3         "v26.16b"
#define rk3q        "q26"
#define rk3q1       "v26.1q"
#define rk4         "v27.16b"
#define rk4q        "q27"
#define rk4v        "v27"
#define rk5         "v28.16b"
#define rk5q        "q28"
#define rk6         "v26.16b"
#define rk6q        "q26"
#define rk7         "v27.16b"
#define rk7q        "q27"
#define rk8         "v28.16b"
#define rk8q        "q28"
#define rk9         "v26.16b"
#define rk9q        "q26"
#define rk10        "v27.16b"
#define rk10q       "q27"
#define rk11        "v28.16b"
#define rk11q       "q28"
#define rk12        "v26.16b"
#define rk12q       "q26"
#define rk13        "v27.16b"
#define rk13q       "q27"
#define rk14        "v28.16b"
#define rk14q       "q28"


static operation_result_t aes_gcm_enc_256_kernel(uint8_t * plaintext, uint64_t plaintext_length, cipher_state_t * restrict cs, uint8_t * ciphertext)
{
    if(plaintext_length == 0) {
        return SUCCESSFUL_OPERATION;
    }

    uint8_t * in_ptr = plaintext;
    uint8_t * out_ptr = ciphertext;
    uint64_t bit_length = plaintext_length;

    const uint8_t counter_increment[16] = { 0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 0 };
    const uint8_t modulo_constant[8] = { 0, 0, 0, 0,  0, 0, 0, 0xc2 };

    asm volatile
    (
        // Initial ////
        // load counter and current_tag
        "       ld1     { "ctr0b" }, [%[counter]]                           \n" // CTR block 0
        "       rev32   "rtmp_ctr".16b, "ctr0".16b                          \n" // set up reversed counter
        "       ld1     { "rctr_inc".16b }, [%[counter_increment]]          \n" // set up counter increment

        "       ld1     { "acc_lb" }, [%[current_tag]]                      \n"

        // set up counter for potential second to eighth blocks
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 0

        "       rev32   "ctr1".16b, "rtmp_ctr".16b                          \n" // CTR block 1
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 1

        "       rev32   "ctr2".16b, "rtmp_ctr".16b                          \n" // CTR block 2
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 2

        "       rev32   "ctr3".16b, "rtmp_ctr".16b                          \n" // CTR block 3
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 3

        "       rev32   "ctr4".16b, "rtmp_ctr".16b                          \n" // CTR block 4
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 4

        "       rev32   "ctr5".16b, "rtmp_ctr".16b                          \n" // CTR block 5
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 5

        "       rev32   "ctr6".16b, "rtmp_ctr".16b                          \n" // CTR block 6
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 6

        "       rev32   "ctr7".16b, "rtmp_ctr".16b                          \n" // CTR block 7
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 7


        "       add     "end_input_ptr", %[input_ptr], %[bit_length], LSR #3\n" // end_input_ptr
        "       lsr     "main_end_input_ptr", %[bit_length], #3             \n" // byte_len
        "       sub     "main_end_input_ptr", "main_end_input_ptr", #1      \n" // byte_len - 1
        "       and     "main_end_input_ptr", "main_end_input_ptr", #0xffffffffffffff80\n" // number of bytes to be processed in main loop (at least 1 byte must be handled by tail)
        "       add     "main_end_input_ptr", "main_end_input_ptr", %[input_ptr]\n"
        // load constants
        "       ldp     "rk0q", "rk1q", [%[cc], #0]                         \n" // load rk0, rk1

        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 0
        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 1
        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 0
        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 1
        "       aese    "ctr2b", "rk0"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 0
        "       aese    "ctr2b", "rk1"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 1
        "       aese    "ctr3b", "rk0"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 0
        "       aese    "ctr3b", "rk1"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 1
        "       aese    "ctr4b", "rk0"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 0
        "       aese    "ctr4b", "rk1"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 1
        "       aese    "ctr5b", "rk0"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 0
        "       aese    "ctr5b", "rk1"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 1
        "       aese    "ctr6b", "rk0"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 0
        "       aese    "ctr6b", "rk1"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 1
        "       aese    "ctr7b", "rk0"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 0
        "       aese    "ctr7b", "rk1"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 1

        "       ldp     "rk2q", "rk3q", [%[cc], #32]                        \n" // load rk2, rk3

        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 2
        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 3
        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 2
        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 3
        "       aese    "ctr2b", "rk2"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 2
        "       aese    "ctr2b", "rk3"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 3
        "       aese    "ctr3b", "rk2"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 2
        "       aese    "ctr3b", "rk3"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 3
        "       aese    "ctr4b", "rk2"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 2
        "       aese    "ctr4b", "rk3"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 3
        "       aese    "ctr5b", "rk2"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 2
        "       aese    "ctr5b", "rk3"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 3
        "       aese    "ctr6b", "rk2"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 2
        "       aese    "ctr6b", "rk3"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 3
        "       aese    "ctr7b", "rk2"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 2
        "       aese    "ctr7b", "rk3"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 3

        "       ldp     "rk4q", "rk5q", [%[cc], #64]                        \n" // load rk4, rk5

        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 4
        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 5
        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 4
        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 5
        "       aese    "ctr2b", "rk4"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 4
        "       aese    "ctr2b", "rk5"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 5
        "       aese    "ctr3b", "rk4"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 4
        "       aese    "ctr3b", "rk5"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 5
        "       aese    "ctr4b", "rk4"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 4
        "       aese    "ctr4b", "rk5"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 5
        "       aese    "ctr5b", "rk4"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 4
        "       aese    "ctr5b", "rk5"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 5
        "       aese    "ctr6b", "rk4"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 4
        "       aese    "ctr6b", "rk5"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 5
        "       aese    "ctr7b", "rk4"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 4
        "       aese    "ctr7b", "rk5"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 5

        "       ldp     "rk6q", "rk7q", [%[cc], #96]                        \n" // load rk6, rk7

        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 6
        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 7
        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 6
        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 7
        "       aese    "ctr2b", "rk6"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 6
        "       aese    "ctr2b", "rk7"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 7
        "       aese    "ctr3b", "rk6"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 6
        "       aese    "ctr3b", "rk7"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 7
        "       aese    "ctr4b", "rk6"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 6
        "       aese    "ctr4b", "rk7"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 7
        "       aese    "ctr5b", "rk6"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 6
        "       aese    "ctr5b", "rk7"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 7
        "       aese    "ctr6b", "rk6"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 6
        "       aese    "ctr6b", "rk7"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 7
        "       aese    "ctr7b", "rk6"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 6
        "       aese    "ctr7b", "rk7"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 7

        "       ldp     "rk8q", "rk9q", [%[cc], #128]                       \n" // load rk8, rk9

        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 8
        "       aese    "ctr0b", "rk9"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 9
        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 8
        "       aese    "ctr1b", "rk9"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 9
        "       aese    "ctr2b", "rk8"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 8
        "       aese    "ctr2b", "rk9"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 9
        "       aese    "ctr3b", "rk8"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 8
        "       aese    "ctr3b", "rk9"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 9
        "       aese    "ctr4b", "rk8"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 8
        "       aese    "ctr4b", "rk9"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 9
        "       aese    "ctr5b", "rk8"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 8
        "       aese    "ctr5b", "rk9"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 9
        "       aese    "ctr6b", "rk8"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 8
        "       aese    "ctr6b", "rk9"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 9
        "       aese    "ctr7b", "rk8"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 8
        "       aese    "ctr7b", "rk9"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 9

        "       ldp     "rk10q", "rk11q", [%[cc], #160]                     \n" // load rk10, rk11

        "       aese    "ctr0b", "rk10"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 10
        "       aese    "ctr0b", "rk11"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 11
        "       aese    "ctr1b", "rk10"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 10
        "       aese    "ctr1b", "rk11"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 11
        "       aese    "ctr2b", "rk10"  \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 10
        "       aese    "ctr2b", "rk11"  \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 11
        "       aese    "ctr3b", "rk10"  \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 10
        "       aese    "ctr3b", "rk11"  \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 11
        "       aese    "ctr4b", "rk10"  \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 10
        "       aese    "ctr4b", "rk11"  \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 11
        "       aese    "ctr5b", "rk10"  \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 10
        "       aese    "ctr5b", "rk11"  \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 11
        "       aese    "ctr6b", "rk10"  \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 10
        "       aese    "ctr6b", "rk11"  \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 11
        "       aese    "ctr7b", "rk10"  \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 10
        "       aese    "ctr7b", "rk11"  \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 11

        "       ldp     "rk12q", "rk13q", [%[cc], #192]                     \n" // load rk12, rk13
        "       ldr     "rk14q", [%[cc], #224]                              \n" // load rk14

        "       aese    "ctr0b", "rk12"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 12
        "       aese    "ctr0b", "rk13"                                     \n" // AES block 0 - round 13
        "       eor     "ctr0b", "ctr0b", "rk14"                            \n" // AES block 0 - round 14
        "       aese    "ctr1b", "rk12"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 12
        "       aese    "ctr1b", "rk13"                                     \n" // AES block 1 - round 13
        "       eor     "ctr1b", "ctr1b", "rk14"                            \n" // AES block 1 - round 14
        "       aese    "ctr2b", "rk12"  \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 12
        "       aese    "ctr2b", "rk13"                                     \n" // AES block 2 - round 13
        "       eor     "ctr2b", "ctr2b", "rk14"                            \n" // AES block 2 - round 14
        "       aese    "ctr3b", "rk12"  \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 12
        "       aese    "ctr3b", "rk13"                                     \n" // AES block 3 - round 13
        "       eor     "ctr3b", "ctr3b", "rk14"                            \n" // AES block 3 - round 14
        "       aese    "ctr4b", "rk12"  \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 12
        "       aese    "ctr4b", "rk13"                                     \n" // AES block 4 - round 13
        "       eor     "ctr4b", "ctr4b", "rk14"                            \n" // AES block 4 - round 14
        "       aese    "ctr5b", "rk12"  \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 12
        "       aese    "ctr5b", "rk13"                                     \n" // AES block 5 - round 13
        "       eor     "ctr5b", "ctr5b", "rk14"                            \n" // AES block 5 - round 14
        "       aese    "ctr6b", "rk12"  \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 12
        "       aese    "ctr6b", "rk13"                                     \n" // AES block 6 - round 13
        "       eor     "ctr6b", "ctr6b", "rk14"                            \n" // AES block 6 - round 14
        "       aese    "ctr7b", "rk12"  \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 12
        "       aese    "ctr7b", "rk13"                                     \n" // AES block 7 - round 13
        "       eor     "ctr7b", "ctr7b", "rk14"                            \n" // AES block 7 - round 14

        // possibly jump to end
        // input_ptr vs. end_ptr comparison here
        "       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // check if we have <= 8 blocks
        "       b.ge    2f                                                  \n" // handle tail

        "       ldp     "ctr_t0q", "ctr_t1q", [%[input_ptr]], #32           \n" // AES block 0, 1 - load plaintext
        "       eor     "res0b", "ctr_t0b", "ctr0b"                         \n" // AES block 0 - result
        "       eor     "res1b", "ctr_t1b", "ctr1b"                         \n" // AES block 1 - result
        "       stp     "res0q", "res1q", [%[output_ptr]], #32              \n" // AES block 0, 1 - store result

        "       ldp     "ctr_t2q", "ctr_t3q", [%[input_ptr]], #32           \n" // AES block 2, 3 - load plaintext
        "       eor     "res2b", "ctr_t2b", "ctr2b"                         \n" // AES block 2 - result
        "       eor     "res3b", "ctr_t3b", "ctr3b"                         \n" // AES block 3 - result
        "       stp     "res2q", "res3q", [%[output_ptr]], #32              \n" // AES block 2, 3 - store result

        "       ldp     "ctr_t4q", "ctr_t5q", [%[input_ptr]], #32           \n" // AES block 4, 5 - load plaintext
        "       eor     "res4b", "ctr_t4b", "ctr4b"                         \n" // AES block 4 - result
        "       eor     "res5b", "ctr_t5b", "ctr5b"                         \n" // AES block 5 - result
        "       stp     "res4q", "res5q", [%[output_ptr]], #32              \n" // AES block 4, 5 - store result

        "       ldp     "ctr_t6q", "ctr_t7q", [%[input_ptr]], #32           \n" // AES block 6, 7 - load plaintext
        "       eor     "res6b", "ctr_t6b", "ctr6b"                         \n" // AES block 6 - result
        "       eor     "res7b", "ctr_t7b", "ctr7b"                         \n" // AES block 7 - result
        "       stp     "res6q", "res7q", [%[output_ptr]], #32              \n" // AES block 6, 7 - store result

        "       rev32   "ctr0".16b, "rtmp_ctr".16b                          \n" // CTR block 8
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8

        "       rev32   "ctr1".16b, "rtmp_ctr".16b                          \n" // CTR block 9
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 9

        "       rev32   "ctr2".16b, "rtmp_ctr".16b                          \n" // CTR block 10
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 10

        "       rev32   "ctr3".16b, "rtmp_ctr".16b                          \n" // CTR block 11
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 11

        "       rev32   "ctr4".16b, "rtmp_ctr".16b                          \n" // CTR block 12
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 12

        // !!! POSSIBLY JUMP TO PREPRETAIL - just GHASH these and then TAIL !!!
        "       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // check if we have <= 8 blocks
        "       b.ge    7f                                                  \n" // do prepretail

        //// Main loop ////
        // parts described above
        "1:                                                                 \n" // main loop start
        "       rev32   "ctr5".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+13
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+13

        "       rev32   "ctr6".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+14
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+14

        "       rev32   "ctr7".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+15
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+15

                                                                                // load h8l | h8h
        "       ldp     "h7q", "h8q", [%[cc], #336]                         \n" // load h7l | h7h
                                                                                // load h6l | h6h
        "       ldp     "h5q", "h6q", [%[cc], #304]                         \n" // load h5l | h5h
                                                                                // load h8k | h7k
        "       ldp     "h56kq", "h78kq", [%[cc], #400]                     \n" // load h6k | h5k

        "       ext     "acc_lb", "acc_lb", "acc_lb", #8                    \n" // PRE 0
        "       rev64   "res0b", "res0b"                                    \n" // GHASH block 8k
        "       rev64   "res1b", "res1b"                                    \n" // GHASH block 8k+1
        "       rev64   "res2b", "res2b"                                    \n" // GHASH block 8k+2
        "       rev64   "res3b", "res3b"                                    \n" // GHASH block 8k+3
        "       eor     "res0b", "res0b", "acc_lb"                          \n" // PRE 1
        "       pmull2  "acc_h".1q, "res0".2d, "h8".2d                      \n" // GHASH block 8k - high
        "       pmull   "acc_l".1q, "res0".1d, "h8".1d                      \n" // GHASH block 8k - low

        "       trn1    "acc_m".2d, "res1".2d, "res0".2d                    \n" // GHASH block 8k, 8k+1 - mid
        "       trn2    "res0".2d, "res1".2d, "res0".2d                     \n" // GHASH block 8k, 8k+1 - mid
        "       eor     "res0".16b, "res0".16b, "acc_m".16b                 \n" // GHASH block 8k, 8k+1 - mid
        "       pmull2  "acc_m".1q, "res0".2d, "h78k".2d                    \n" // GHASH block 8k   - mid
        "       pmull   "h78k".1q, "res0".1d, "h78k".1d                     \n" // GHASH block 8k+1 - mid
        "       eor     "acc_mb", "acc_mb", "h78k".16b                      \n" // GHASH block 8k+1 - mid

        "       pmull2  "t0".1q, "res1".2d, "h7".2d                         \n" // GHASH block 8k+1 - high
        "       eor     "acc_hb", "acc_hb", "t0".16b                        \n" // GHASH block 8k+1 - high
        "       pmull   "h7".1q, "res1".1d, "h7".1d                         \n" // GHASH block 8k+1 - low
        "       eor     "acc_lb", "acc_lb", "h7".16b                        \n" // GHASH block 8k+1 - low

        "       pmull2  "t1".1q, "res2".2d, "h6".2d                         \n" // GHASH block 8k+2 - high
        "       pmull2  "t2".1q, "res3".2d, "h5".2d                         \n" // GHASH block 8k+3 - high
        "       eor     "t1".16b, "t1".16b, "t2".16b                        \n" // GHASH block 8k+2 - high
        "       eor     "acc_hb", "acc_hb", "t1".16b                        \n" // GHASH block 8k+3 - high

        "       pmull   "h6".1q, "res2".1d, "h6".1d                         \n" // GHASH block 8k+2 - low
        "       pmull   "h5".1q, "res3".1d, "h5".1d                         \n" // GHASH block 8k+3 - low
        "       eor     "t2".16b, "h6".16b, "h5".16b                        \n" // GHASH block 8k+2 - low
        "       eor     "acc_lb", "acc_lb", "t2".16b                        \n" // GHASH block 8k+3 - low

        "       trn1    "t3".2d, "res3".2d, "res2".2d                       \n" // GHASH block 8k+2, 8k+3 - mid
        "       trn2    "res2".2d, "res3".2d, "res2".2d                     \n" // GHASH block 8k+2, 8k+3 - mid
        "       eor     "res2".16b, "res2".16b, "t3".16b                    \n" // GHASH block 8k+2, 8k+3 - mid
        "       pmull2  "t3".1q, "res2".2d, "h56k".2d                       \n" // GHASH block 8k+2 - mid
        "       pmull   "h56k".1q, "res2".1d, "h56k".1d                     \n" // GHASH block 8k+3 - mid
        "       eor     "h56k".16b, "h56k".16b, "t3".16b                    \n" // GHASH block 8k+2 - mid
        "       eor     "acc_mb", "acc_mb", "h56k".16b                      \n" // GHASH block 8k+3 - mid

                                                                                // load h4l | h4h
        "       ldp     "h3q", "h4q", [%[cc], #272]                         \n" // load h3l | h3h
                                                                                // load h2l | h2h
        "       ldp     "h1q", "h2q", [%[cc], #240]                         \n" // load h1l | h1h
                                                                                // load h4k | h3k
        "       ldp     "h12kq", "h34kq", [%[cc], #368]                     \n" // load h2k | h1k

        "       rev64   "res4b", "res4b"                                    \n" // GHASH block 8k+4 (t0, t1, and t2 free)
        "       rev64   "res5b", "res5b"                                    \n" // GHASH block 8k+5 (t0, t1, t2 and t3 free)
        "       rev64   "res6b", "res6b"                                    \n" // GHASH block 8k+6 (t0, t1, and t2 free)
        "       rev64   "res7b", "res7b"                                    \n" // GHASH block 8k+7 (t0, t1, t2 and t3 free)

        "       pmull2  "t4".1q, "res4".2d, "h4".2d                         \n" // GHASH block 8k+4 - high
        "       pmull2  "t5".1q, "res5".2d, "h3".2d                         \n" // GHASH block 8k+5 - high
        "       eor     "t5".16b, "t4".16b, "t5".16b                        \n" // GHASH block 8k+4 - high
        "       eor     "acc_hb", "acc_hb", "t5".16b                        \n" // GHASH block 8k+5 - high

        "       pmull   "h4".1q, "res4".1d, "h4".1d                         \n" // GHASH block 8k+4 - low
        "       pmull   "h3".1q, "res5".1d, "h3".1d                         \n" // GHASH block 8k+5 - low
        "       eor     "acc_lb", "acc_lb", "h4".16b                        \n" // GHASH block 8k+4 - low
        "       eor     "acc_lb", "acc_lb", "h3".16b                        \n" // GHASH block 8k+5 - low

        "       trn1    "t6".2d, "res5".2d, "res4".2d                       \n" // GHASH block 8k+4, 8k+5 - mid
        "       trn2    "res4".2d, "res5".2d, "res4".2d                     \n" // GHASH block 8k+4, 8k+5 - mid
        "       eor     "res4".16b, "res4".16b, "t6".16b                    \n" // GHASH block 8k+4, 8k+5 - mid
        "       pmull2  "t6".1q, "res4".2d, "h34k".2d                       \n" // GHASH block 8k+4 - mid
        "       pmull   "h34k".1q, "res4".1d, "h34k".1d                     \n" // GHASH block 8k+5 - mid
        "       eor     "h34k".16b, "h34k".16b, "t6".16b                    \n" // GHASH block 8k+4 - mid
        "       eor     "acc_mb", "acc_mb", "h34k".16b                      \n" // GHASH block 8k+5 - mid

        "       pmull2  "t7".1q, "res6".2d, "h2".2d                         \n" // GHASH block 8k+6 - high
        "       pmull2  "t8".1q, "res7".2d, "h1".2d                         \n" // GHASH block 8k+7 - high
        "       eor     "t8".16b, "t7".16b, "t8".16b                        \n" // GHASH block 8k+6 - high
        "       eor     "acc_hb", "acc_hb", "t8".16b                        \n" // GHASH block 8k+7 - high

        "       pmull   "h2".1q, "res6".1d, "h2".1d                         \n" // GHASH block 8k+6 - low
        "       pmull   "h1".1q, "res7".1d, "h1".1d                         \n" // GHASH block 8k+7 - low
        "       eor     "h1".16b, "h2".16b, "h1".16b                        \n" // GHASH block 8k+6 - low
        "       eor     "acc_lb", "acc_lb", "h1".16b                        \n" // GHASH block 8k+7 - low

        "       trn1    "t9".2d, "res7".2d, "res6".2d                       \n" // GHASH block 8k+6, 8k+7 - mid
        "       trn2    "res6".2d, "res7".2d, "res6".2d                     \n" // GHASH block 8k+6, 8k+7 - mid
        "       eor     "res6".16b, "res6".16b, "t9".16b                    \n" // GHASH block 8k+6, 8k+7 - mid
        "       pmull2  "t9".1q, "res6".2d, "h12k".2d                       \n" // GHASH block 8k+6 - mid
        "       pmull   "h12k".1q, "res6".1d, "h12k".1d                     \n" // GHASH block 8k+7 - mid
        "       eor     "h12k".16b, "h12k".16b, "t9".16b                    \n" // GHASH block 8k+6, 8k+7 - mid
        "       eor     "acc_mb", "acc_mb", "h12k".16b                      \n" // GHASH block 8k+6, 8k+7 - mid

        "       ldr     "mod_constantd", [%[modulo_constant]]               \n" // MODULO - load modulo constant
        "       eor     "t10".16b, "acc_hb", "acc_lb"                       \n" // MODULO - karatsuba tidy up
        "       eor     "acc_mb", "acc_mb", "t10".16b                       \n" // MODULO - karatsuba tidy up
        "       pmull   "t11".1q, "acc_h".1d, "mod_constant".1d             \n" // MODULO - top 64b align with mid
        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n" // MODULO - other top alignment
        "       eor     "t11".16b, "acc_hb", "t11".16b                      \n" // MODULO - fold into mid
        "       eor     "acc_mb", "acc_mb", "t11".16b                       \n" // MODULO - fold into mid
        "       pmull   "acc_h".1q, "acc_m".1d, "mod_constant".1d           \n" // MODULO - mid 64b align with low
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n" // MODULO - other mid alignment
        "       eor     "acc_lb", "acc_lb", "acc_hb"                        \n" // MODULO - fold into low
        "       eor     "acc_lb", "acc_lb", "acc_mb"                        \n" // MODULO - fold into low

        "       ldp     "rk0q", "rk1q", [%[cc], #0]                         \n" // load rk0, rk1

        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 0
        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 1
        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 0
        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 1
        "       aese    "ctr2b", "rk0"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 0
        "       aese    "ctr2b", "rk1"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 1
        "       aese    "ctr3b", "rk0"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 0
        "       aese    "ctr3b", "rk1"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 1
        "       aese    "ctr4b", "rk0"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 0
        "       aese    "ctr4b", "rk1"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 1
        "       aese    "ctr5b", "rk0"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 0
        "       aese    "ctr5b", "rk1"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 1
        "       aese    "ctr6b", "rk0"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 0
        "       aese    "ctr6b", "rk1"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 1
        "       aese    "ctr7b", "rk0"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 0
        "       aese    "ctr7b", "rk1"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 1

        "       ldp     "rk2q", "rk3q", [%[cc], #32]                        \n" // load rk2, rk3

        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 2
        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 3
        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 2
        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 3
        "       aese    "ctr2b", "rk2"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 2
        "       aese    "ctr2b", "rk3"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 3
        "       aese    "ctr3b", "rk2"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 2
        "       aese    "ctr3b", "rk3"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 3
        "       aese    "ctr4b", "rk2"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 2
        "       aese    "ctr4b", "rk3"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 3
        "       aese    "ctr5b", "rk2"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 2
        "       aese    "ctr5b", "rk3"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 3
        "       aese    "ctr6b", "rk2"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 2
        "       aese    "ctr6b", "rk3"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 3
        "       aese    "ctr7b", "rk2"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 2
        "       aese    "ctr7b", "rk3"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 3

        "       ldp     "rk4q", "rk5q", [%[cc], #64]                        \n" // load rk4, rk5

        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 4
        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 5
        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 4
        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 5
        "       aese    "ctr2b", "rk4"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 4
        "       aese    "ctr2b", "rk5"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 5
        "       aese    "ctr3b", "rk4"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 4
        "       aese    "ctr3b", "rk5"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 5
        "       aese    "ctr4b", "rk4"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 4
        "       aese    "ctr4b", "rk5"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 5
        "       aese    "ctr5b", "rk4"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 4
        "       aese    "ctr5b", "rk5"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 5
        "       aese    "ctr6b", "rk4"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 4
        "       aese    "ctr6b", "rk5"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 5
        "       aese    "ctr7b", "rk4"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 4
        "       aese    "ctr7b", "rk5"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 5

        "       ldp     "rk6q", "rk7q", [%[cc], #96]                        \n" // load rk6, rk7

        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 6
        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 7
        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 6
        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 7
        "       aese    "ctr2b", "rk6"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 6
        "       aese    "ctr2b", "rk7"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 7
        "       aese    "ctr3b", "rk6"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 6
        "       aese    "ctr3b", "rk7"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 7
        "       aese    "ctr4b", "rk6"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 6
        "       aese    "ctr4b", "rk7"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 7
        "       aese    "ctr5b", "rk6"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 6
        "       aese    "ctr5b", "rk7"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 7
        "       aese    "ctr6b", "rk6"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 6
        "       aese    "ctr6b", "rk7"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 7
        "       aese    "ctr7b", "rk6"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 6
        "       aese    "ctr7b", "rk7"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 7

        "       ldp     "rk8q", "rk9q", [%[cc], #128]                       \n" // load rk8, rk9

        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 8
        "       aese    "ctr0b", "rk9"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 9
        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 8
        "       aese    "ctr1b", "rk9"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 9
        "       aese    "ctr2b", "rk8"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 8
        "       aese    "ctr2b", "rk9"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 9
        "       aese    "ctr3b", "rk8"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 8
        "       aese    "ctr3b", "rk9"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 9
        "       aese    "ctr4b", "rk8"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 8
        "       aese    "ctr4b", "rk9"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 9
        "       aese    "ctr5b", "rk8"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 8
        "       aese    "ctr5b", "rk9"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 9
        "       aese    "ctr6b", "rk8"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 8
        "       aese    "ctr6b", "rk9"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 9
        "       aese    "ctr7b", "rk8"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 8
        "       aese    "ctr7b", "rk9"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 9

        "       ldp     "rk10q", "rk11q", [%[cc], #160]                     \n" // load rk10, rk11

        "       aese    "ctr0b", "rk10"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 10
        "       aese    "ctr0b", "rk11"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 11
        "       aese    "ctr1b", "rk10"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 10
        "       aese    "ctr1b", "rk11"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 11
        "       aese    "ctr2b", "rk10"  \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 10
        "       aese    "ctr2b", "rk11"  \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 11
        "       aese    "ctr3b", "rk10"  \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 10
        "       aese    "ctr3b", "rk11"  \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 11
        "       aese    "ctr4b", "rk10"  \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 10
        "       aese    "ctr4b", "rk11"  \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 11
        "       aese    "ctr5b", "rk10"  \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 10
        "       aese    "ctr5b", "rk11"  \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 11
        "       aese    "ctr6b", "rk10"  \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 10
        "       aese    "ctr6b", "rk11"  \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 11
        "       aese    "ctr7b", "rk10"  \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 10
        "       aese    "ctr7b", "rk11"  \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 11

        "       ldp     "rk12q", "rk13q", [%[cc], #192]                     \n" // load rk12, rk13
        "       ldr     "rk14q", [%[cc], #224]                              \n" // load rk14

        "       aese    "ctr0b", "rk12"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 12
        "       aese    "ctr0b", "rk13"                                     \n" // AES block 8k+8 - round 13
        "       aese    "ctr1b", "rk12"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 12
        "       aese    "ctr1b", "rk13"                                     \n" // AES block 8k+9 - round 13
        "       aese    "ctr2b", "rk12"  \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 12
        "       aese    "ctr2b", "rk13"                                     \n" // AES block 8k+10 - round 13
        "       aese    "ctr3b", "rk12"  \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 12
        "       aese    "ctr3b", "rk13"                                     \n" // AES block 8k+11 - round 13
        "       aese    "ctr4b", "rk12"  \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 12
        "       aese    "ctr4b", "rk13"                                     \n" // AES block 8k+12 - round 13
        "       aese    "ctr5b", "rk12"  \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 12
        "       aese    "ctr5b", "rk13"                                     \n" // AES block 8k+13 - round 13
        "       aese    "ctr6b", "rk12"  \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 12
        "       aese    "ctr6b", "rk13"                                     \n" // AES block 8k+14 - round 13
        "       aese    "ctr7b", "rk12"  \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 12
        "       aese    "ctr7b", "rk13"                                     \n" // AES block 8k+15 - round 13

        "       ldp     "ctr_t0q", "ctr_t1q", [%[input_ptr]], #32           \n" // AES block 8k+8, 8k+9 - load plaintext
        "       eor     "ctr_t0b", "ctr_t0b", "rk14"                        \n" // AES block 8k+8 - round 14
        "       eor     "res0b", "ctr_t0b", "ctr0b"                         \n" // AES block 8k+8 - result
        "       eor     "ctr_t1b", "ctr_t1b", "rk14"                        \n" // AES block 8k+9 - round 14
        "       eor     "res1b", "ctr_t1b", "ctr1b"                         \n" // AES block 8k+9 - result
        "       stp     "res0q", "res1q", [%[output_ptr]], #32              \n" // AES block 8k+8, 8k+9 - store result

        "       ldp     "ctr_t2q", "ctr_t3q", [%[input_ptr]], #32           \n" // AES block 8k+10, 8k+11 - load plaintext
        "       eor     "ctr_t2b", "ctr_t2b", "rk14"                        \n" // AES block 8k+10 - round 14
        "       eor     "res2b", "ctr_t2b", "ctr2b"                         \n" // AES block 8k+10 - result
        "       eor     "ctr_t3b", "ctr_t3b", "rk14"                        \n" // AES block 8k+11 - round 14
        "       eor     "res3b", "ctr_t3b", "ctr3b"                         \n" // AES block 8k+11 - result
        "       stp     "res2q", "res3q", [%[output_ptr]], #32              \n" // AES block 8k+10, 8k+11 - store result

        "       ldp     "ctr_t4q", "ctr_t5q", [%[input_ptr]], #32           \n" // AES block 8k+12, 8k+13 - load plaintext
        "       eor     "ctr_t4b", "ctr_t4b", "rk14"                        \n" // AES block 8k+12 - round 14
        "       eor     "res4b", "ctr_t4b", "ctr4b"                         \n" // AES block 8k+12 - result
        "       eor     "ctr_t5b", "ctr_t5b", "rk14"                        \n" // AES block 8k+13 - round 14
        "       eor     "res5b", "ctr_t5b", "ctr5b"                         \n" // AES block 8k+13 - result
        "       stp     "res4q", "res5q", [%[output_ptr]], #32              \n" // AES block 8k+12, 8k+13 - store result

        "       ldp     "ctr_t6q", "ctr_t7q", [%[input_ptr]], #32           \n" // AES block 8k+14, 8k+15 - load plaintext
        "       eor     "ctr_t6b", "ctr_t6b", "rk14"                        \n" // AES block 8k+14 - round 14
        "       eor     "res6b", "ctr_t6b", "ctr6b"                         \n" // AES block 8k+14 - result
        "       eor     "ctr_t7b", "ctr_t7b", "rk14"                        \n" // AES block 8k+15 - round 14
        "       eor     "res7b", "ctr_t7b", "ctr7b"                         \n" // AES block 8k+15 - result
        "       stp     "res6q", "res7q", [%[output_ptr]], #32              \n" // AES block 8k+14, 8k+15 - store result

        "       rev32   "h1".16b, "rtmp_ctr".16b                            \n" // CTR block 8k+16
        "       mov     "ctr0".16b, "h1".16b                                \n" // CTR block 8k+16
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+16

        "       rev32   "h2".16b, "rtmp_ctr".16b                            \n" // CTR block 8k+17
        "       mov     "ctr1".16b, "h2".16b                                \n" // CTR block 8k+17
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+17

        "       rev32   "h3".16b, "rtmp_ctr".16b                            \n" // CTR block 8k+18
        "       mov     "ctr2".16b, "h3".16b                                \n" // CTR block 8k+18
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+18

        "       rev32   "h4".16b, "rtmp_ctr".16b                            \n" // CTR block 8k+19
        "       mov     "ctr3".16b, "h4".16b                                \n" // CTR block 8k+19
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+19

        "       rev32   "ctr4".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+20
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+20

        "       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // LOOP CONTROL
        "       b.lt    1b                                                  \n"

        "7:                                                                 \n" // PREPRETAIL
        "       rev32   "ctr5".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+13
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+13

        "       rev32   "ctr6".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+14
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+14

        "       rev32   "ctr7".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+15
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+15

                                                                                // load h8l | h8h
        "       ldp     "h7q", "h8q", [%[cc], #336]                         \n" // load h7l | h7h
                                                                                // load h6l | h6h
        "       ldp     "h5q", "h6q", [%[cc], #304]                         \n" // load h5l | h5h
                                                                                // load h8k | h7k
        "       ldp     "h56kq", "h78kq", [%[cc], #400]                     \n" // load h6k | h5k

        "       ext     "acc_lb", "acc_lb", "acc_lb", #8                    \n" // PRE 0
        "       rev64   "res0b", "res0b"                                    \n" // GHASH block 8k
        "       rev64   "res1b", "res1b"                                    \n" // GHASH block 8k+1
        "       rev64   "res2b", "res2b"                                    \n" // GHASH block 8k+2
        "       rev64   "res3b", "res3b"                                    \n" // GHASH block 8k+3
        "       eor     "res0b", "res0b", "acc_lb"                          \n" // PRE 1
        "       pmull2  "acc_h".1q, "res0".2d, "h8".2d                      \n" // GHASH block 8k - high
        "       pmull   "acc_l".1q, "res0".1d, "h8".1d                      \n" // GHASH block 8k - low

        "       trn1    "acc_m".2d, "res1".2d, "res0".2d                    \n" // GHASH block 8k, 8k+1 - mid
        "       trn2    "res0".2d, "res1".2d, "res0".2d                     \n" // GHASH block 8k, 8k+1 - mid
        "       eor     "res0".16b, "res0".16b, "acc_m".16b                 \n" // GHASH block 8k, 8k+1 - mid
        "       pmull2  "acc_m".1q, "res0".2d, "h78k".2d                    \n" // GHASH block 8k   - mid
        "       pmull   "h78k".1q, "res0".1d, "h78k".1d                     \n" // GHASH block 8k+1 - mid
        "       eor     "acc_mb", "acc_mb", "h78k".16b                      \n" // GHASH block 8k+1 - mid

        "       pmull2  "t0".1q, "res1".2d, "h7".2d                         \n" // GHASH block 8k+1 - high
        "       eor     "acc_hb", "acc_hb", "t0".16b                        \n" // GHASH block 8k+1 - high
        "       pmull   "h7".1q, "res1".1d, "h7".1d                         \n" // GHASH block 8k+1 - low
        "       eor     "acc_lb", "acc_lb", "h7".16b                        \n" // GHASH block 8k+1 - low

        "       pmull2  "t1".1q, "res2".2d, "h6".2d                         \n" // GHASH block 8k+2 - high
        "       pmull2  "t2".1q, "res3".2d, "h5".2d                         \n" // GHASH block 8k+3 - high
        "       eor     "t1".16b, "t1".16b, "t2".16b                        \n" // GHASH block 8k+2 - high
        "       eor     "acc_hb", "acc_hb", "t1".16b                        \n" // GHASH block 8k+3 - high

        "       pmull   "h6".1q, "res2".1d, "h6".1d                         \n" // GHASH block 8k+2 - low
        "       pmull   "h5".1q, "res3".1d, "h5".1d                         \n" // GHASH block 8k+3 - low
        "       eor     "t2".16b, "h6".16b, "h5".16b                        \n" // GHASH block 8k+2 - low
        "       eor     "acc_lb", "acc_lb", "t2".16b                        \n" // GHASH block 8k+3 - low

        "       trn1    "t3".2d, "res3".2d, "res2".2d                       \n" // GHASH block 8k+2, 8k+3 - mid
        "       trn2    "res2".2d, "res3".2d, "res2".2d                     \n" // GHASH block 8k+2, 8k+3 - mid
        "       eor     "res2".16b, "res2".16b, "t3".16b                    \n" // GHASH block 8k+2, 8k+3 - mid
        "       pmull2  "t3".1q, "res2".2d, "h56k".2d                       \n" // GHASH block 8k+2 - mid
        "       pmull   "h56k".1q, "res2".1d, "h56k".1d                     \n" // GHASH block 8k+3 - mid
        "       eor     "h56k".16b, "h56k".16b, "t3".16b                    \n" // GHASH block 8k+2 - mid
        "       eor     "acc_mb", "acc_mb", "h56k".16b                      \n" // GHASH block 8k+3 - mid

                                                                                // load h4l | h4h
        "       ldp     "h3q", "h4q", [%[cc], #272]                         \n" // load h3l | h3h
                                                                                // load h2l | h2h
        "       ldp     "h1q", "h2q", [%[cc], #240]                         \n" // load h1l | h1h
                                                                                // load h4k | h3k
        "       ldp     "h12kq", "h34kq", [%[cc], #368]                     \n" // load h2k | h1k

        "       rev64   "res4b", "res4b"                                    \n" // GHASH block 8k+4 (t0, t1, and t2 free)
        "       rev64   "res5b", "res5b"                                    \n" // GHASH block 8k+5 (t0, t1, t2 and t3 free)
        "       rev64   "res6b", "res6b"                                    \n" // GHASH block 8k+6 (t0, t1, and t2 free)
        "       rev64   "res7b", "res7b"                                    \n" // GHASH block 8k+7 (t0, t1, t2 and t3 free)

        "       pmull2  "t4".1q, "res4".2d, "h4".2d                         \n" // GHASH block 8k+4 - high
        "       pmull2  "t5".1q, "res5".2d, "h3".2d                         \n" // GHASH block 8k+5 - high
        "       eor     "t5".16b, "t4".16b, "t5".16b                        \n" // GHASH block 8k+4 - high
        "       eor     "acc_hb", "acc_hb", "t5".16b                        \n" // GHASH block 8k+5 - high

        "       pmull   "h4".1q, "res4".1d, "h4".1d                         \n" // GHASH block 8k+4 - low
        "       pmull   "h3".1q, "res5".1d, "h3".1d                         \n" // GHASH block 8k+5 - low
        "       eor     "acc_lb", "acc_lb", "h4".16b                        \n" // GHASH block 8k+4 - low
        "       eor     "acc_lb", "acc_lb", "h3".16b                        \n" // GHASH block 8k+5 - low

        "       trn1    "t6".2d, "res5".2d, "res4".2d                       \n" // GHASH block 8k+4, 8k+5 - mid
        "       trn2    "res4".2d, "res5".2d, "res4".2d                     \n" // GHASH block 8k+4, 8k+5 - mid
        "       eor     "res4".16b, "res4".16b, "t6".16b                    \n" // GHASH block 8k+4, 8k+5 - mid
        "       pmull2  "t6".1q, "res4".2d, "h34k".2d                       \n" // GHASH block 8k+4 - mid
        "       pmull   "h34k".1q, "res4".1d, "h34k".1d                     \n" // GHASH block 8k+5 - mid
        "       eor     "h34k".16b, "h34k".16b, "t6".16b                    \n" // GHASH block 8k+4 - mid
        "       eor     "acc_mb", "acc_mb", "h34k".16b                      \n" // GHASH block 8k+5 - mid

        "       pmull2  "t7".1q, "res6".2d, "h2".2d                         \n" // GHASH block 8k+6 - high
        "       pmull2  "t8".1q, "res7".2d, "h1".2d                         \n" // GHASH block 8k+7 - high
        "       eor     "t8".16b, "t7".16b, "t8".16b                        \n" // GHASH block 8k+6 - high
        "       eor     "acc_hb", "acc_hb", "t8".16b                        \n" // GHASH block 8k+7 - high

        "       pmull   "h2".1q, "res6".1d, "h2".1d                         \n" // GHASH block 8k+6 - low
        "       pmull   "h1".1q, "res7".1d, "h1".1d                         \n" // GHASH block 8k+7 - low
        "       eor     "h1".16b, "h2".16b, "h1".16b                        \n" // GHASH block 8k+6 - low
        "       eor     "acc_lb", "acc_lb", "h1".16b                        \n" // GHASH block 8k+7 - low

        "       trn1    "t9".2d, "res7".2d, "res6".2d                       \n" // GHASH block 8k+6, 8k+7 - mid
        "       trn2    "res6".2d, "res7".2d, "res6".2d                     \n" // GHASH block 8k+6, 8k+7 - mid
        "       eor     "res6".16b, "res6".16b, "t9".16b                    \n" // GHASH block 8k+6, 8k+7 - mid
        "       pmull2  "t9".1q, "res6".2d, "h12k".2d                       \n" // GHASH block 8k+6 - mid
        "       pmull   "h12k".1q, "res6".1d, "h12k".1d                     \n" // GHASH block 8k+7 - mid
        "       eor     "h12k".16b, "h12k".16b, "t9".16b                    \n" // GHASH block 8k+6, 8k+7 - mid
        "       eor     "acc_mb", "acc_mb", "h12k".16b                      \n" // GHASH block 8k+6, 8k+7 - mid

        "       ldr     "mod_constantd", [%[modulo_constant]]               \n" // MODULO - load modulo constant
        "       eor     "t10".16b, "acc_hb", "acc_lb"                       \n" // MODULO - karatsuba tidy up
        "       eor     "acc_mb", "acc_mb", "t10".16b                       \n" // MODULO - karatsuba tidy up
        "       pmull   "t11".1q, "acc_h".1d, "mod_constant".1d             \n" // MODULO - top 64b align with mid
        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n" // MODULO - other top alignment
        "       eor     "t11".16b, "acc_hb", "t11".16b                      \n" // MODULO - fold into mid
        "       eor     "acc_mb", "acc_mb", "t11".16b                       \n" // MODULO - fold into mid
        "       pmull   "acc_h".1q, "acc_m".1d, "mod_constant".1d           \n" // MODULO - mid 64b align with low
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n" // MODULO - other mid alignment
        "       eor     "acc_lb", "acc_lb", "acc_hb"                        \n" // MODULO - fold into low
        "       eor     "acc_lb", "acc_lb", "acc_mb"                        \n" // MODULO - fold into low

        //compute final AES blocks
        "       ldp     "rk0q", "rk1q", [%[cc], #0]                         \n" // load rk0, rk1

        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 0
        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 1
        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 0
        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 1
        "       aese    "ctr2b", "rk0"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 0
        "       aese    "ctr2b", "rk1"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 1
        "       aese    "ctr3b", "rk0"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 0
        "       aese    "ctr3b", "rk1"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 1
        "       aese    "ctr4b", "rk0"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 0
        "       aese    "ctr4b", "rk1"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 1
        "       aese    "ctr5b", "rk0"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 0
        "       aese    "ctr5b", "rk1"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 1
        "       aese    "ctr6b", "rk0"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 0
        "       aese    "ctr6b", "rk1"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 1
        "       aese    "ctr7b", "rk0"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 0
        "       aese    "ctr7b", "rk1"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 1

        "       ldp     "rk2q", "rk3q", [%[cc], #32]                        \n" // load rk2, rk3

        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 2
        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 3
        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 2
        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 3
        "       aese    "ctr2b", "rk2"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 2
        "       aese    "ctr2b", "rk3"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 3
        "       aese    "ctr3b", "rk2"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 2
        "       aese    "ctr3b", "rk3"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 3
        "       aese    "ctr4b", "rk2"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 2
        "       aese    "ctr4b", "rk3"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 3
        "       aese    "ctr5b", "rk2"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 2
        "       aese    "ctr5b", "rk3"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 3
        "       aese    "ctr6b", "rk2"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 2
        "       aese    "ctr6b", "rk3"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 3
        "       aese    "ctr7b", "rk2"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 2
        "       aese    "ctr7b", "rk3"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 3

        "       ldp     "rk4q", "rk5q", [%[cc], #64]                        \n" // load rk4, rk5

        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 4
        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 5
        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 4
        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 5
        "       aese    "ctr2b", "rk4"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 4
        "       aese    "ctr2b", "rk5"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 5
        "       aese    "ctr3b", "rk4"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 4
        "       aese    "ctr3b", "rk5"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 5
        "       aese    "ctr4b", "rk4"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 4
        "       aese    "ctr4b", "rk5"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 5
        "       aese    "ctr5b", "rk4"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 4
        "       aese    "ctr5b", "rk5"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 5
        "       aese    "ctr6b", "rk4"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 4
        "       aese    "ctr6b", "rk5"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 5
        "       aese    "ctr7b", "rk4"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 4
        "       aese    "ctr7b", "rk5"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 5

        "       ldp     "rk6q", "rk7q", [%[cc], #96]                        \n" // load rk6, rk7

        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 6
        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 7
        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 6
        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 7
        "       aese    "ctr2b", "rk6"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 6
        "       aese    "ctr2b", "rk7"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 7
        "       aese    "ctr3b", "rk6"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 6
        "       aese    "ctr3b", "rk7"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 7
        "       aese    "ctr4b", "rk6"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 6
        "       aese    "ctr4b", "rk7"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 7
        "       aese    "ctr5b", "rk6"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 6
        "       aese    "ctr5b", "rk7"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 7
        "       aese    "ctr6b", "rk6"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 6
        "       aese    "ctr6b", "rk7"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 7
        "       aese    "ctr7b", "rk6"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 6
        "       aese    "ctr7b", "rk7"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 7

        "       ldp     "rk8q", "rk9q", [%[cc], #128]                       \n" // load rk8, rk9

        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 8
        "       aese    "ctr0b", "rk9"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 9
        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 8
        "       aese    "ctr1b", "rk9"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 9
        "       aese    "ctr2b", "rk8"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 8
        "       aese    "ctr2b", "rk9"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 9
        "       aese    "ctr3b", "rk8"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 8
        "       aese    "ctr3b", "rk9"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 9
        "       aese    "ctr4b", "rk8"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 8
        "       aese    "ctr4b", "rk9"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 9
        "       aese    "ctr5b", "rk8"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 8
        "       aese    "ctr5b", "rk9"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 9
        "       aese    "ctr6b", "rk8"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 8
        "       aese    "ctr6b", "rk9"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 9
        "       aese    "ctr7b", "rk8"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 8
        "       aese    "ctr7b", "rk9"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 9

        "       ldp     "rk10q", "rk11q", [%[cc], #160]                     \n" // load rk10, rk11

        "       aese    "ctr0b", "rk10"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 10
        "       aese    "ctr0b", "rk11"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 11
        "       aese    "ctr1b", "rk10"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 10
        "       aese    "ctr1b", "rk11"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 11
        "       aese    "ctr2b", "rk10"  \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 10
        "       aese    "ctr2b", "rk11"  \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 11
        "       aese    "ctr3b", "rk10"  \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 10
        "       aese    "ctr3b", "rk11"  \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 11
        "       aese    "ctr4b", "rk10"  \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 10
        "       aese    "ctr4b", "rk11"  \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 11
        "       aese    "ctr5b", "rk10"  \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 10
        "       aese    "ctr5b", "rk11"  \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 11
        "       aese    "ctr6b", "rk10"  \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 10
        "       aese    "ctr6b", "rk11"  \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 11
        "       aese    "ctr7b", "rk10"  \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 10
        "       aese    "ctr7b", "rk11"  \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 11

        "       ldp     "rk12q", "rk13q", [%[cc], #192]                     \n" // load rk12, rk13
        "       ldr     "rk14q", [%[cc], #224]                              \n" // load rk14

        "       aese    "ctr0b", "rk12"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 12
        "       aese    "ctr0b", "rk13"                                     \n" // AES block 8k+8 - round 13
        "       eor     "ctr0b", "ctr0b", "rk14"                            \n" // AES block 8k+8 - round 14
        "       aese    "ctr1b", "rk12"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 12
        "       aese    "ctr1b", "rk13"                                     \n" // AES block 8k+9 - round 13
        "       eor     "ctr1b", "ctr1b", "rk14"                            \n" // AES block 8k+9 - round 14
        "       aese    "ctr2b", "rk12"  \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 12
        "       aese    "ctr2b", "rk13"                                     \n" // AES block 8k+10 - round 13
        "       eor     "ctr2b", "ctr2b", "rk14"                            \n" // AES block 8k+10 - round 14
        "       aese    "ctr3b", "rk12"  \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 12
        "       aese    "ctr3b", "rk13"                                     \n" // AES block 8k+11 - round 13
        "       eor     "ctr3b", "ctr3b", "rk14"                            \n" // AES block 8k+11 - round 14
        "       aese    "ctr4b", "rk12"  \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 12
        "       aese    "ctr4b", "rk13"                                     \n" // AES block 8k+12 - round 13
        "       eor     "ctr4b", "ctr4b", "rk14"                            \n" // AES block 8k+12 - round 14
        "       aese    "ctr5b", "rk12"  \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 12
        "       aese    "ctr5b", "rk13"                                     \n" // AES block 8k+13 - round 13
        "       eor     "ctr5b", "ctr5b", "rk14"                            \n" // AES block 8k+13 - round 14
        "       aese    "ctr6b", "rk12"  \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 12
        "       aese    "ctr6b", "rk13"                                     \n" // AES block 8k+14 - round 13
        "       eor     "ctr6b", "ctr6b", "rk14"                            \n" // AES block 8k+14 - round 14
        "       aese    "ctr7b", "rk12"  \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 12
        "       aese    "ctr7b", "rk13"                                     \n" // AES block 8k+15 - round 13
        "       eor     "ctr7b", "ctr7b", "rk14"                            \n" // AES block 8k+15 - round 14

        "2:                                                                 \n" // TAIL
        "       sub     "main_end_input_ptr", "end_input_ptr", %[input_ptr] \n" // main_end_input_ptr is number of bytes left to process
        "       ext     "t0".16b, "acc_lb", "acc_lb", #8                    \n" // prepare final partial tag

        "       ldr     "ctr_t0q", [%[input_ptr]], #16                      \n" // AES block 8k+8 - load plaintext
        "       eor     "res1b", "ctr_t0b", "ctr0b"                         \n" // AES block 8k+8 - result

                                                                                // load h8l | h8h
        "       ldp     "h7q", "h8q", [%[cc], #336]                         \n" // load h7l | h7h
                                                                                // load h6l | h6h
        "       ldp     "h5q", "h6q", [%[cc], #304]                         \n" // load h5l | h5h
                                                                                // load h8k | h7k
        "       ldp     "h56kq", "h78kq", [%[cc], #400]                     \n" // load h6k | h5k

        "       cmp     "main_end_input_ptr", #112                          \n"
        "       b.gt    8f                                                  \n"
        // zero accumulators if we aren't directly writing them
        "       movi    "acc_h".8b, #0                                      \n"
        "       movi    "acc_m".8b, #0                                      \n"
        "       movi    "acc_l".8b, #0                                      \n"
        "       mov     "ctr7b", "ctr6b"                                    \n"
        "       mov     "ctr6b", "ctr5b"                                    \n"
        "       mov     "ctr5b", "ctr4b"                                    \n"
        "       mov     "ctr4b", "ctr3b"                                    \n"
        "       mov     "ctr3b", "ctr2b"                                    \n"
        "       mov     "ctr2b", "ctr1b"                                    \n"
        "       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
        "       cmp     "main_end_input_ptr", #96                           \n"
        "       b.gt    9f                                                  \n"

        "       mov     "ctr7b", "ctr6b"                                    \n"
        "       mov     "ctr6b", "ctr5b"                                    \n"
        "       mov     "ctr5b", "ctr4b"                                    \n"
        "       mov     "ctr4b", "ctr3b"                                    \n"
        "       mov     "ctr3b", "ctr1b"                                    \n"
        "       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
        "       cmp     "main_end_input_ptr", #80                           \n"
        "       b.gt    10f                                                 \n"

        "       mov     "ctr7b", "ctr6b"                                    \n"
        "       mov     "ctr6b", "ctr5b"                                    \n"
        "       mov     "ctr5b", "ctr4b"                                    \n"
        "       mov     "ctr4b", "ctr1b"                                    \n"
        "       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
        "       cmp     "main_end_input_ptr", #64                           \n"
        "       b.gt    11f                                                 \n"

        "       mov     "ctr7b", "ctr6b"                                    \n"
        "       mov     "ctr6b", "ctr5b"                                    \n"
        "       mov     "ctr5b", "ctr1b"                                    \n"
        "       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
        "       cmp     "main_end_input_ptr", #48                           \n"
        "       b.gt    3f                                                  \n"

        "       ldr     "h34kq", [%[cc], #384]                              \n" // load h4k | h3k
        "       mov     "ctr7b", "ctr6b"                                    \n"
        "       mov     "ctr6b", "ctr1b"                                    \n"
        "       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
        "       cmp     "main_end_input_ptr", #32                           \n"
        "       b.gt    4f                                                  \n"

        "       mov     "ctr7b", "ctr1b"                                    \n"
        "       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
        "       cmp     "main_end_input_ptr", #16                           \n"
        "       b.gt    5f                                                  \n"

        "       ldr     "h12kq", [%[cc], #368]                              \n" // load h2k | h1k
        "       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
        "       b       6f                                                  \n"
        //// Handle tail ////
        // less than 8 blocks, last block possibly not full
        "8:                                                                 \n" // blocks left >  7
        "       st1     { "res1b" }, [%[output_ptr]], #16                   \n" // AES final-7 block  - store result
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-7 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       pmull2  "acc_h".1q, "res0".2d, "h8".2d                      \n" // GHASH final-7 block - high
        "       pmull   "acc_l".1q, "res0".1d, "h8".1d                      \n" // GHASH final-7 block - low
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-7 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-7 block - mid
        "       ins     "acc_m".d[0], "h78k".d[1]                           \n" // GHASH final-7 block - mid
        "       pmull   "acc_m".1q, "rk4v".1d, "acc_m".1d                   \n" // GHASH final-7 block - mid

        "       ldr     "ctr_t1q", [%[input_ptr]], #16                      \n" // AES final-6 block - load plaintext
        "       eor     "res1b", "ctr_t1b", "ctr1b"                         \n" // AES final-6 block - result

        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

        "9:                                                                 \n" // blocks left >  6
        "       st1     { "res1b" }, [%[output_ptr]], #16                   \n" // AES final-6 block - store result
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-6 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       pmull2  "rk2q1", "res0".2d, "h7".2d                         \n" // GHASH final-6 block - high
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-6 block - high
        "       pmull   "rk3q1", "res0".1d, "h7".1d                         \n" // GHASH final-6 block - low
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-6 block - low
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-6 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-6 block - mid
        "       pmull   "rk4v".1q, "rk4v".1d, "h78k".1d                     \n" // GHASH final-6 block - mid
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-6 block - mid

        "       ldr     "ctr_t1q", [%[input_ptr]], #16                      \n" // AES final-5 block - load plaintext
        "       eor     "res1b", "ctr_t1b", "ctr2b"                         \n" // AES final-5 block - result

        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

        "10:                                                                \n" // blocks left >  5
        "       st1     { "res1b" }, [%[output_ptr]], #16                   \n" // AES final-5 block - store result
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-5 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       pmull2  "rk2q1", "res0".2d, "h6".2d                         \n" // GHASH final-5 block - high
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-5 block - high
        "       pmull   "rk3q1", "res0".1d, "h6".1d                         \n" // GHASH final-5 block - low
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-5 block - low
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-5 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-5 block - mid
        "       ins     "rk4v".d[1], "rk4v".d[0]                            \n" // GHASH final-5 block - mid
        "       pmull2  "rk4v".1q, "rk4v".2d, "h56k".2d                     \n" // GHASH final-5 block - mid
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-5 block - mid

        "       ldr     "ctr_t1q", [%[input_ptr]], #16                      \n" // AES final-4 block - load plaintext
        "       eor     "res1b", "ctr_t1b", "ctr3b"                         \n" // AES final-4 block - result

        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

        "11:                                                                \n" // blocks left >  4
        "       st1     { "res1b" }, [%[output_ptr]], #16                   \n" // AES final-4 block - store result
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-4 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       pmull2  "rk2q1", "res0".2d, "h5".2d                         \n" // GHASH final-4 block - high
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-4 block - high
        "       pmull   "rk3q1", "res0".1d, "h5".1d                         \n" // GHASH final-4 block - low
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-4 block - low
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-4 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-4 block - mid
        "       pmull   "rk4v".1q, "rk4v".1d, "h56k".1d                     \n" // GHASH final-4 block - mid
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-4 block - mid

        "       ldr     "ctr_t1q", [%[input_ptr]], #16                      \n" // AES final-3 block - load plaintext
        "       eor     "res1b", "ctr_t1b", "ctr4b"                         \n" // AES final-3 block - result

        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

        "3:                                                                 \n" // blocks left >  3
        "       ldr     "h4q", [%[cc], #288]                                \n" // load h4l | h4h
        "       ldr     "h34kq", [%[cc], #384]                              \n" // load h4k | h3k

        "       st1     { "res1b" }, [%[output_ptr]], #16                   \n" // AES final-3 block - store result
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-3 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       pmull2  "rk2q1", "res0".2d, "h4".2d                         \n" // GHASH final-3 block - high
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-3 block - high
        "       pmull   "rk3q1", "res0".1d, "h4".1d                         \n" // GHASH final-3 block - low
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-3 block - low
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-3 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-3 block - mid
        "       ins     "rk4v".d[1], "rk4v".d[0]                            \n" // GHASH final-3 block - mid
        "       pmull2  "rk4v".1q, "rk4v".2d, "h34k".2d                     \n" // GHASH final-3 block - mid
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-3 block - mid

        "       ldr     "ctr_t1q", [%[input_ptr]], #16                      \n" // AES final-2 block - load plaintext
        "       eor     "res1b", "ctr_t1b", "ctr5b"                         \n" // AES final-2 block - result

        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

        "4:                                                                 \n" // blocks left >  2
        "       ldr     "h3q", [%[cc], #272]                                \n" // load h3l | h3h

        "       st1     { "res1b" }, [%[output_ptr]], #16                   \n" // AES final-2 block - store result
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-2 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       pmull2  "rk2q1", "res0".2d, "h3".2d                         \n" // GHASH final-2 block - high
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-2 block - high
        "       pmull   "rk3q1", "res0".1d, "h3".1d                         \n" // GHASH final-2 block - low
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-2 block - low
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-2 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-2 block - mid
        "       pmull   "rk4v".1q, "rk4v".1d, "h34k".1d                     \n" // GHASH final-2 block - mid
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-2 block - mid

        "       ldr     "ctr_t1q", [%[input_ptr]], #16                      \n" // AES final-1 block - load plaintext
        "       eor     "res1b", "ctr_t1b", "ctr6b"                         \n" // AES final-1 block - result

        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

        "5:                                                                 \n" // blocks left >  1
        "       ldr     "h2q", [%[cc], #256]                                \n" // load h2l | h2h
        "       ldr     "h12kq", [%[cc], #368]                              \n" // load h2k | h1k
        "       st1     { "res1b" }, [%[output_ptr]], #16                   \n" // AES final-1 block - store result
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-1 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       pmull2  "rk2q1", "res0".2d, "h2".2d                         \n" // GHASH final-1 block - high
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-1 block - high
        "       pmull   "rk3q1", "res0".1d, "h2".1d                         \n" // GHASH final-1 block - low
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-1 block - low
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-1 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-1 block - mid
        "       ins     "rk4v".d[1], "rk4v".d[0]                            \n" // GHASH final-1 block - mid
        "       pmull2  "rk4v".1q, "rk4v".2d, "h12k".2d                     \n" // GHASH final-1 block - mid
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-1 block - mid

        "       ldr     "ctr_t1q", [%[input_ptr]], #16                      \n" // AES final block - load plaintext
        "       eor     "res1b", "ctr_t1b", "ctr7b"                         \n" // AES final block - result

        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

        "6:                                                                 \n" // blocks left <= 1
        "       ldr     "h1q", [%[cc], #240]                                \n" // load h1l | h1h
        // mask out bits of res1 which are not used
        "       and     %[bit_length], %[bit_length], #127                  \n" // bit_length %= 128
        "       mvn     "temp0_x", xzr                                      \n" // temp0_x = 0xffffffffffffffff
        "       sub     %[bit_length], %[bit_length], #128                  \n" // bit_length -= 128
        "       mvn     "temp1_x", xzr                                      \n" // temp1_x = 0xffffffffffffffff
        "       neg     %[bit_length], %[bit_length]                        \n" // bit_length = 128 - #bits in input (in range [1,128])
        "       and     %[bit_length], %[bit_length], #127                  \n" // bit_length %= 128
        "       lsr     "temp0_x", "temp0_x", %[bit_length]                 \n" // temp0_x is mask for top 64b of last block
        "       cmp     %[bit_length], #64                                  \n"
        "       csel    "temp2_x", "temp1_x", "temp0_x", lt                 \n"
        "       csel    "temp3_x", "temp0_x", xzr, lt                       \n"
        "       mov     "ctr0".d[0], "temp2_x"                              \n" // ctr0b is mask for last block
        "       mov     "ctr0".d[1], "temp3_x"                              \n"
        "       and     "res1b", "res1b", "ctr0b"                           \n" // possibly partial last block has zeroes in highest bits
        // end mask out bits of res1 which are not used
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final block
        "       ld1     { "rk0" }, [%[output_ptr]]                          \n" // load existing bytes where the possibly partial last block is to be stored
        "       rev32   "rtmp_ctr".16b, "rtmp_ctr".16b                      \n"
        "       str     "rtmp_ctrq", [%[counter]]                           \n" // store the updated counter
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       bif     "res1b", "rk0", "ctr0b"                             \n" // insert existing bytes in top end of result before storing
        "       ins     "t0".d[0], "res0".d[1]                              \n" // GHASH final block - mid
        "       pmull2  "rk2q1", "res0".2d, "h1".2d                         \n" // GHASH final block - high
        "       pmull   "rk3q1", "res0".1d, "h1".1d                         \n" // GHASH final block - low
        "       st1     { "res1b" }, [%[output_ptr]]                        \n" // store all 16B
        "       eor     "t0".8b, "t0".8b, "res0".8b                         \n" // GHASH final block - mid
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final block - high
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final block - low
        "       pmull   "t0".1q, "t0".1d, "h12k".1d                         \n" // GHASH final block - mid
        "       eor     "acc_mb", "acc_mb", "t0".16b                        \n" // GHASH final block - mid
        "       ldr     "mod_constantd", [%[modulo_constant]]               \n" // MODULO - load modulo constant
        "       eor     "t10".16b, "acc_hb", "acc_lb"                       \n" // MODULO - karatsuba tidy up
        "       eor     "acc_mb", "acc_mb", "t10".16b                       \n" // MODULO - karatsuba tidy up
        "       pmull   "t11".1q, "acc_h".1d, "mod_constant".1d             \n" // MODULO - top 64b align with mid
        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n" // MODULO - other top alignment
        "       eor     "t11".16b, "acc_hb", "t11".16b                      \n" // MODULO - fold into mid
        "       eor     "acc_mb", "acc_mb", "t11".16b                       \n" // MODULO - fold into mid
        "       pmull   "acc_h".1q, "acc_m".1d, "mod_constant".1d           \n" // MODULO - mid 64b align with low
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n" // MODULO - other mid alignment
        "       eor     "acc_lb", "acc_lb", "acc_hb"                        \n" // MODULO - fold into low
        "       eor     "acc_lb", "acc_lb", "acc_mb"                        \n" // MODULO - fold into low
        "       st1     { "acc_l".16b }, [%[current_tag]]                   \n"


        : [input_ptr] "+r" (in_ptr), [output_ptr] "+r" (out_ptr),
          [bit_length] "+r" (bit_length)
        : [cc] "r" (cs->constants->expanded_aes_keys[0].b), [counter] "r" (cs->counter.b), [current_tag] "r" (cs->current_tag.b),
          [counter_increment] "r" (counter_increment), [modulo_constant] "r" (modulo_constant)
        : "v0",  "v1",  "v2",  "v3",  "v4",  "v5",  "v6",  "v7",  "v8",  "v9",  "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
          "x4",  "x5",  "x6",  "x7", "x13", "x14", "memory"
    );

    return SUCCESSFUL_OPERATION;
}

#undef end_input_ptr
#undef main_end_input_ptr
#undef temp0_x
#undef temp1_x
#undef temp2_x
#undef temp3_x

#undef ctr0b
#undef ctr0
#undef ctr0d
#undef ctr1b
#undef ctr1
#undef ctr1d
#undef ctr2b
#undef ctr2
#undef ctr2d
#undef ctr3b
#undef ctr3
#undef ctr3d
#undef ctr4b
#undef ctr4
#undef ctr4d
#undef ctr5b
#undef ctr5
#undef ctr5d
#undef ctr6b
#undef ctr6
#undef ctr6d
#undef ctr7b
#undef ctr7
#undef ctr7d

#undef res0b
#undef res0
#undef res0q
#undef res1b
#undef res1
#undef res1q
#undef res2b
#undef res2
#undef res2q
#undef res3b
#undef res3
#undef res3q
#undef res4b
#undef res4
#undef res4q
#undef res5b
#undef res5
#undef res5q
#undef res6b
#undef res6
#undef res6q
#undef res7b
#undef res7
#undef res7q

#undef ctr_t0
#undef ctr_t0b
#undef ctr_t0q
#undef ctr_t1
#undef ctr_t1b
#undef ctr_t1q
#undef ctr_t2
#undef ctr_t2b
#undef ctr_t2q
#undef ctr_t3
#undef ctr_t3b
#undef ctr_t3q
#undef ctr_t4
#undef ctr_t4b
#undef ctr_t4q
#undef ctr_t5
#undef ctr_t5b
#undef ctr_t5q
#undef ctr_t6
#undef ctr_t6b
#undef ctr_t6q
#undef ctr_t7
#undef ctr_t7b
#undef ctr_t7q

#undef acc_hb
#undef acc_h
#undef acc_mb
#undef acc_m
#undef acc_lb
#undef acc_l

#undef h1
#undef h1q
#undef h12k
#undef h12kq
#undef h2
#undef h2q
#undef h3
#undef h3q
#undef h34k
#undef h34kq
#undef h4
#undef h4q
#undef h5
#undef h5q
#undef h56k
#undef h56kq
#undef h6
#undef h6q
#undef h7
#undef h7q
#undef h78k
#undef h78kq
#undef h8
#undef h8q

#undef t0
#undef t0d

#undef t1
#undef t2
#undef t3

#undef t4
#undef t5
#undef t6

#undef t7
#undef t8
#undef t9

#undef t10
#undef t11

#undef rtmp_ctr
#undef rtmp_ctrq
#undef rctr_inc
#undef rctr_incd

#undef mod_constant
#undef mod_constantd

#undef rk0
#undef rk0q
#undef rk1
#undef rk1q
#undef rk2
#undef rk2q
#undef rk2q1
#undef rk3
#undef rk3q
#undef rk3q1
#undef rk4
#undef rk4q
#undef rk4v
#undef rk5
#undef rk5q
#undef rk6
#undef rk6q
#undef rk7
#undef rk7q
#undef rk8
#undef rk8q
#undef rk9
#undef rk9q
#undef rk10
#undef rk10q
#undef rk11
#undef rk11q
#undef rk12
#undef rk12q
#undef rk13
#undef rk13q
#undef rk14
#undef rk14q
