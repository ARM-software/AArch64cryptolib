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
#define ctr0q       "q0"
#define ctr1b       "v1.16b"
#define ctr1        "v1"
#define ctr1d       "d1"
#define ctr1q       "q1"
#define ctr2b       "v2.16b"
#define ctr2        "v2"
#define ctr2d       "d2"
#define ctr2q       "q2"
#define ctr3b       "v3.16b"
#define ctr3        "v3"
#define ctr3d       "d3"
#define ctr3q       "q3"
#define ctr4b       "v4.16b"
#define ctr4        "v4"
#define ctr4d       "d4"
#define ctr4q       "q4"
#define ctr5b       "v5.16b"
#define ctr5        "v5"
#define ctr5d       "d5"
#define ctr5q       "q5"
#define ctr6b       "v6.16b"
#define ctr6        "v6"
#define ctr6d       "d6"
#define ctr6q       "q6"
#define ctr7b       "v7.16b"
#define ctr7        "v7"
#define ctr7d       "d7"
#define ctr7q       "q7"

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


static operation_result_t aes_gcm_dec_192_kernel(uint8_t * ciphertext, uint64_t ciphertext_length, cipher_state_t * restrict cs, uint8_t * plaintext)
{
    if(ciphertext_length == 0) {
        return SUCCESSFUL_OPERATION;
    }

    uint8_t * in_ptr = ciphertext;
    uint8_t * out_ptr = plaintext;
    uint64_t bit_length = ciphertext_length;

    const uint8_t counter_increment[16] = { 0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 0 };
    const uint8_t modulo_constant[8] = { 0, 0, 0, 0,  0, 0, 0, 0xc2 };

    asm volatile
    (
        "       ld1     { "ctr0b" }, [%[counter]]                           \n" // CTR block 0
        "       ld1     { "rctr_inc".16b }, [%[counter_increment]]          \n" // set up counter increment
        "       rev32   "rtmp_ctr".16b, "ctr0".16b                          \n" // set up reversed counter
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 0
        "       ldp     "rk0q", "rk1q", [%[cc], #0]                         \n" // load rk0, rk1
        "       rev32   "ctr1".16b, "rtmp_ctr".16b                          \n" // CTR block 1
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 1
        "       rev32   "ctr2".16b, "rtmp_ctr".16b                          \n" // CTR block 2
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 2
        "       rev32   "ctr3".16b, "rtmp_ctr".16b                          \n" // CTR block 3
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 3
        "       aese    "ctr3b", "rk0"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 0
        "       rev32   "ctr4".16b, "rtmp_ctr".16b                          \n" // CTR block 4
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 4
        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 0
        "       aese    "ctr2b", "rk0"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 0
        "       rev32   "ctr5".16b, "rtmp_ctr".16b                          \n" // CTR block 5
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 5
        "       rev32   "ctr6".16b, "rtmp_ctr".16b                          \n" // CTR block 6
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 6
        "       aese    "ctr2b", "rk1"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 1
        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 0
        "       lsr     "main_end_input_ptr", %[bit_length], #3             \n" // byte_len
        "       aese    "ctr5b", "rk0"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 0
        "       rev32   "ctr7".16b, "rtmp_ctr".16b                          \n" // CTR block 7
        "       aese    "ctr7b", "rk0"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 0
        "       aese    "ctr6b", "rk0"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 0
        "       aese    "ctr4b", "rk0"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 0
        "       ldp     "rk2q", "rk3q", [%[cc], #32]                        \n" // load rk2, rk3
        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 1
        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 2
        "       aese    "ctr3b", "rk1"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 1
        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 1
        "       aese    "ctr4b", "rk1"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 1
        "       aese    "ctr7b", "rk1"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 1
        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 3
        "       aese    "ctr2b", "rk2"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 2
        "       aese    "ctr3b", "rk2"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 2
        "       aese    "ctr4b", "rk2"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 2
        "       aese    "ctr6b", "rk1"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 1
        "       aese    "ctr5b", "rk1"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 1
        "       aese    "ctr6b", "rk2"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 2
        "       aese    "ctr5b", "rk2"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 2
        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 2
        "       aese    "ctr7b", "rk2"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 2
        "       ldp     "rk4q", "rk5q", [%[cc], #64]                        \n" // load rk4, rk5
        "       aese    "ctr4b", "rk3"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 3
        "       aese    "ctr5b", "rk3"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 3
        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 3
        "       aese    "ctr2b", "rk3"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 3
        "       aese    "ctr7b", "rk3"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 3
        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 4
        "       aese    "ctr7b", "rk4"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 4
        "       aese    "ctr2b", "rk4"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 4
        "       aese    "ctr4b", "rk4"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 4
        "       aese    "ctr3b", "rk3"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 3
        "       aese    "ctr5b", "rk4"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 4
        "       aese    "ctr3b", "rk4"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 4
        "       aese    "ctr6b", "rk3"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 3
        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 4
        "       aese    "ctr6b", "rk4"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 4
        "       ldp     "rk6q", "rk7q", [%[cc], #96]                        \n" // load rk6, rk7
        "       aese    "ctr3b", "rk5"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 5
        "       aese    "ctr4b", "rk5"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 5
        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 5
        "       aese    "ctr2b", "rk5"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 5
        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 5
        "       aese    "ctr6b", "rk5"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 5
        "       aese    "ctr5b", "rk5"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 5
        "       aese    "ctr5b", "rk6"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 6
        "       aese    "ctr3b", "rk6"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 6
        "       aese    "ctr7b", "rk5"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 5
        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 6
        "       aese    "ctr7b", "rk6"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 6
        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 6
        "       aese    "ctr2b", "rk6"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 6
        "       aese    "ctr6b", "rk6"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 6
        "       aese    "ctr4b", "rk6"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 6
        "       aese    "ctr4b", "rk7"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 7
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 7
        "       aese    "ctr2b", "rk7"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 7
        "       aese    "ctr7b", "rk7"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 7
        "       aese    "ctr3b", "rk7"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 7
        "       ldp     "rk8q", "rk9q", [%[cc], #128]                       \n" // load rk8, rk9
        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 7
        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 8
        "       aese    "ctr2b", "rk8"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 8
        "       aese    "ctr6b", "rk7"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 7
        "       aese    "ctr6b", "rk8"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 8
        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 7
        "       aese    "ctr4b", "rk8"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 8
        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 8
        "       aese    "ctr7b", "rk8"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 8
        "       aese    "ctr3b", "rk8"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 8
        "       aese    "ctr5b", "rk7"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 7
        "       aese    "ctr5b", "rk8"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 8
        "       ldp     "rk10q", "rk11q", [%[cc], #160]                     \n" // load rk10, rk11
        "       ld1     { "acc_lb" }, [%[current_tag]]                      \n"
        "       aese    "ctr0b", "rk9"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 9
        "       aese    "ctr6b", "rk9"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 9
        "       aese    "ctr2b", "rk9"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 9
        "       aese    "ctr1b", "rk9"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 9
        "       aese    "ctr4b", "rk9"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 9
        "       aese    "ctr3b", "rk9"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 9
        "       aese    "ctr7b", "rk9"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 9
        "       aese    "ctr5b", "rk9"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 9
        "       ldr     "rk12q", [%[cc], #192]                              \n" // load rk12
        "       aese    "ctr2b", "rk10"  \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 10
        "       aese    "ctr4b", "rk10"  \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 10
        "       aese    "ctr1b", "rk10"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 10
        "       aese    "ctr7b", "rk10"  \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 10
        "       aese    "ctr6b", "rk10"  \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 10
        "       aese    "ctr0b", "rk10"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 10
        "       aese    "ctr5b", "rk10"  \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 10
        "       aese    "ctr3b", "rk10"  \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 10
        "       aese    "ctr7b", "rk11"                                     \n" // AES block 7 - round 11
        "       aese    "ctr5b", "rk11"                                     \n" // AES block 5 - round 11
        "       aese    "ctr1b", "rk11"                                     \n" // AES block 1 - round 11
        "       aese    "ctr3b", "rk11"                                     \n" // AES block 3 - round 11
        "       aese    "ctr2b", "rk11"                                     \n" // AES block 2 - round 11
        "       aese    "ctr0b", "rk11"                                     \n" // AES block 0 - round 11
        "       aese    "ctr6b", "rk11"                                     \n" // AES block 6 - round 11
        "       aese    "ctr4b", "rk11"                                     \n" // AES block 4 - round 11
        "       eor     "ctr3b", "ctr3b", "rk12"                            \n" // AES block 3 - round 12
        "       eor     "ctr1b", "ctr1b", "rk12"                            \n" // AES block 1 - round 12
        "       eor     "ctr6b", "ctr6b", "rk12"                            \n" // AES block 6 - round 12
        "       eor     "ctr2b", "ctr2b", "rk12"                            \n" // AES block 2 - round 12
        "       eor     "ctr0b", "ctr0b", "rk12"                            \n" // AES block 0 - round 12
        "       eor     "ctr4b", "ctr4b", "rk12"                            \n" // AES block 4 - round 12
        "       sub     "main_end_input_ptr", "main_end_input_ptr", #1      \n" // byte_len - 1
        "       eor     "ctr5b", "ctr5b", "rk12"                            \n" // AES block 5 - round 12
        "       eor     "ctr7b", "ctr7b", "rk12"                            \n" // AES block 7 - round 12
        "       and     "main_end_input_ptr", "main_end_input_ptr", #0xffffffffffffff80\n" // number of bytes to be processed in main loop (at least 1 byte must be handled by tail)
        "       add     "main_end_input_ptr", "main_end_input_ptr", %[input_ptr]\n"
        "       add     "end_input_ptr", %[input_ptr], %[bit_length], LSR #3\n" // end_input_ptr
        "       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // check if we have <= 8 blocks
        "       b.ge    2f                                                  \n" // handle tail
        "       ldp     "res0q", "res1q", [%[input_ptr]], #32               \n" // AES block 0, 1 - load ciphertext
        "       eor     "ctr1b", "res1b", "ctr1b"                           \n" // AES block 1 - result
        "       eor     "ctr0b", "res0b", "ctr0b"                           \n" // AES block 0 - result
        "       stp     "ctr0q", "ctr1q", [%[output_ptr]], #32              \n" // AES block 0, 1 - store result
        "       rev32   "ctr0".16b, "rtmp_ctr".16b                          \n" // CTR block 8
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8
        "       ldp     "res2q", "res3q", [%[input_ptr]], #32               \n" // AES block 2, 3 - load ciphertext
        "       eor     "ctr3b", "res3b", "ctr3b"                           \n" // AES block 3 - result
        "       eor     "ctr2b", "res2b", "ctr2b"                           \n" // AES block 2 - result
        "       stp     "ctr2q", "ctr3q", [%[output_ptr]], #32              \n" // AES block 2, 3 - store result
        "       rev32   "ctr1".16b, "rtmp_ctr".16b                          \n" // CTR block 9
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 9
        "       ldp     "res4q", "res5q", [%[input_ptr]], #32               \n" // AES block 4, 5 - load ciphertext
        "       eor     "ctr5b", "res5b", "ctr5b"                           \n" // AES block 5 - result
        "       eor     "ctr4b", "res4b", "ctr4b"                           \n" // AES block 4 - result
        "       stp     "ctr4q", "ctr5q", [%[output_ptr]], #32              \n" // AES block 4, 5 - store result
        "       rev32   "ctr2".16b, "rtmp_ctr".16b                          \n" // CTR block 10
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 10
        "       ldp     "res6q", "res7q", [%[input_ptr]], #32               \n" // AES block 6, 7 - load ciphertext
        "       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // check if we have <= 8 blocks
        "       eor     "ctr6b", "res6b", "ctr6b"                           \n" // AES block 6 - result
        "       rev32   "ctr3".16b, "rtmp_ctr".16b                          \n" // CTR block 11
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 11
        "       eor     "ctr7b", "res7b", "ctr7b"                           \n" // AES block 7 - result
        "       stp     "ctr6q", "ctr7q", [%[output_ptr]], #32              \n" // AES block 6, 7 - store result
        "       rev32   "ctr4".16b, "rtmp_ctr".16b                          \n" // CTR block 12
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 12
        "       b.ge    7f                                                  \n" // do prepretail
        "1:                                                                 \n" // main loop start
        "       rev64   "res5b", "res5b"                                    \n" // GHASH block 8k+5 (t0, t1, t2 and t3 free)
        "       ext     "acc_lb", "acc_lb", "acc_lb", #8                    \n" // PRE 0
        "       rev64   "res6b", "res6b"                                    \n" // GHASH block 8k+6 (t0, t1, and t2 free)
        "       ldp     "h7q", "h8q", [%[cc], #336]                         \n" // load h7l | h7h
        "       ldp     "h5q", "h6q", [%[cc], #304]                         \n" // load h5l | h5h
        "       rev64   "res2b", "res2b"                                    \n" // GHASH block 8k+2
        "       rev64   "res0b", "res0b"                                    \n" // GHASH block 8k
        "       rev64   "res1b", "res1b"                                    \n" // GHASH block 8k+1
        "       rev64   "res3b", "res3b"                                    \n" // GHASH block 8k+3
        "       eor     "res0b", "res0b", "acc_lb"                          \n" // PRE 1
        "       rev64   "res7b", "res7b"                                    \n" // GHASH block 8k+7 (t0, t1, t2 and t3 free)
        "       pmull2  "t1".1q, "res2".2d, "h6".2d                         \n" // GHASH block 8k+2 - high
        "       pmull2  "t0".1q, "res1".2d, "h7".2d                         \n" // GHASH block 8k+1 - high
        "       pmull   "h7".1q, "res1".1d, "h7".1d                         \n" // GHASH block 8k+1 - low
        "       pmull2  "acc_h".1q, "res0".2d, "h8".2d                      \n" // GHASH block 8k - high
        "       rev32   "ctr5".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+13
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+13
        "       rev64   "res4b", "res4b"                                    \n" // GHASH block 8k+4 (t0, t1, and t2 free)
        "       pmull   "acc_l".1q, "res0".1d, "h8".1d                      \n" // GHASH block 8k - low
        "       trn1    "acc_m".2d, "res1".2d, "res0".2d                    \n" // GHASH block 8k, 8k+1 - mid
        "       trn2    "res0".2d, "res1".2d, "res0".2d                     \n" // GHASH block 8k, 8k+1 - mid
        "       pmull2  "t2".1q, "res3".2d, "h5".2d                         \n" // GHASH block 8k+3 - high
        "       eor     "t1".16b, "t1".16b, "t2".16b                        \n" // GHASH block 8k+2 - high
        "       eor     "acc_hb", "acc_hb", "t0".16b                        \n" // GHASH block 8k+1 - high
        "       eor     "acc_lb", "acc_lb", "h7".16b                        \n" // GHASH block 8k+1 - low
        "       ldp     "h3q", "h4q", [%[cc], #272]                         \n" // load h3l | h3h
        "       pmull   "h6".1q, "res2".1d, "h6".1d                         \n" // GHASH block 8k+2 - low
        "       rev32   "ctr6".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+14
        "       eor     "acc_hb", "acc_hb", "t1".16b                        \n" // GHASH block 8k+3 - high
        "       ldp     "rk0q", "rk1q", [%[cc], #0]                         \n" // load rk0, rk1
        "       aese    "ctr3b", "rk0"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 0
        "       trn1    "t3".2d, "res3".2d, "res2".2d                       \n" // GHASH block 8k+2, 8k+3 - mid
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+14
        "       ldp     "h56kq", "h78kq", [%[cc], #400]                     \n" // load h6k | h5k
        "       trn2    "res2".2d, "res3".2d, "res2".2d                     \n" // GHASH block 8k+2, 8k+3 - mid
        "       eor     "res0".16b, "res0".16b, "acc_m".16b                 \n" // GHASH block 8k, 8k+1 - mid
        "       trn1    "t6".2d, "res5".2d, "res4".2d                       \n" // GHASH block 8k+4, 8k+5 - mid
        "       aese    "ctr4b", "rk0"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 0
        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 0
        "       aese    "ctr5b", "rk0"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 0
        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 0
        "       pmull   "h5".1q, "res3".1d, "h5".1d                         \n" // GHASH block 8k+3 - low
        "       eor     "t2".16b, "h6".16b, "h5".16b                        \n" // GHASH block 8k+2 - low
        "       eor     "res2".16b, "res2".16b, "t3".16b                    \n" // GHASH block 8k+2, 8k+3 - mid
        "       rev32   "ctr7".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+15
        "       ldp     "h1q", "h2q", [%[cc], #240]                         \n" // load h1l | h1h
        "       pmull2  "acc_m".1q, "res0".2d, "h78k".2d                    \n" // GHASH block 8k   - mid
        "       pmull   "h78k".1q, "res0".1d, "h78k".1d                     \n" // GHASH block 8k+1 - mid
        "       pmull2  "t4".1q, "res4".2d, "h4".2d                         \n" // GHASH block 8k+4 - high
        "       pmull   "h4".1q, "res4".1d, "h4".1d                         \n" // GHASH block 8k+4 - low
        "       trn2    "res4".2d, "res5".2d, "res4".2d                     \n" // GHASH block 8k+4, 8k+5 - mid
        "       pmull2  "t3".1q, "res2".2d, "h56k".2d                       \n" // GHASH block 8k+2 - mid
        "       pmull   "h56k".1q, "res2".1d, "h56k".1d                     \n" // GHASH block 8k+3 - mid
        "       aese    "ctr3b", "rk1"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 1
        "       pmull2  "t5".1q, "res5".2d, "h3".2d                         \n" // GHASH block 8k+5 - high
        "       pmull   "h3".1q, "res5".1d, "h3".1d                         \n" // GHASH block 8k+5 - low
        "       eor     "acc_lb", "acc_lb", "t2".16b                        \n" // GHASH block 8k+3 - low
        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 1
        "       aese    "ctr4b", "rk1"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 1
        "       aese    "ctr7b", "rk0"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 0
        "       aese    "ctr6b", "rk0"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 0
        "       aese    "ctr2b", "rk0"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 0
        "       ldp     "rk2q", "rk3q", [%[cc], #32]                        \n" // load rk2, rk3
        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 1
        "       eor     "acc_mb", "acc_mb", "h78k".16b                      \n" // GHASH block 8k+1 - mid
        "       aese    "ctr5b", "rk1"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 1
        "       pmull2  "t7".1q, "res6".2d, "h2".2d                         \n" // GHASH block 8k+6 - high
        "       pmull   "h2".1q, "res6".1d, "h2".1d                         \n" // GHASH block 8k+6 - low
        "       eor     "h56k".16b, "h56k".16b, "t3".16b                    \n" // GHASH block 8k+2 - mid
        "       ldr     "h34kq", [%[cc], #384]                              \n" // load h4k | h3k
        "       eor     "t5".16b, "t4".16b, "t5".16b                        \n" // GHASH block 8k+4 - high
        "       aese    "ctr7b", "rk1"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 1
        "       aese    "ctr5b", "rk2"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 2
        "       aese    "ctr7b", "rk2"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 2
        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 2
        "       aese    "ctr4b", "rk2"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 2
        "       eor     "res4".16b, "res4".16b, "t6".16b                    \n" // GHASH block 8k+4, 8k+5 - mid
        "       eor     "acc_lb", "acc_lb", "h4".16b                        \n" // GHASH block 8k+4 - low
        "       aese    "ctr2b", "rk1"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 1
        "       aese    "ctr6b", "rk1"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 1
        "       trn1    "t9".2d, "res7".2d, "res6".2d                       \n" // GHASH block 8k+6, 8k+7 - mid
        "       trn2    "res6".2d, "res7".2d, "res6".2d                     \n" // GHASH block 8k+6, 8k+7 - mid
        "       aese    "ctr2b", "rk2"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 2
        "       aese    "ctr6b", "rk2"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 2
        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 2
        "       eor     "res6".16b, "res6".16b, "t9".16b                    \n" // GHASH block 8k+6, 8k+7 - mid
        "       pmull2  "t6".1q, "res4".2d, "h34k".2d                       \n" // GHASH block 8k+4 - mid
        "       aese    "ctr7b", "rk3"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 3
        "       aese    "ctr3b", "rk2"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 2
        "       eor     "acc_mb", "acc_mb", "h56k".16b                      \n" // GHASH block 8k+3 - mid
        "       ldp     "rk4q", "rk5q", [%[cc], #64]                        \n" // load rk4, rk5
        "       pmull   "h34k".1q, "res4".1d, "h34k".1d                     \n" // GHASH block 8k+5 - mid
        "       aese    "ctr5b", "rk3"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 3
        "       ldr     "h12kq", [%[cc], #368]                              \n" // load h2k | h1k
        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 3
        "       pmull2  "t8".1q, "res7".2d, "h1".2d                         \n" // GHASH block 8k+7 - high
        "       aese    "ctr3b", "rk3"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 3
        "       aese    "ctr4b", "rk3"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 3
        "       aese    "ctr2b", "rk3"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 3
        "       pmull   "h1".1q, "res7".1d, "h1".1d                         \n" // GHASH block 8k+7 - low
        "       aese    "ctr6b", "rk3"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 3
        "       aese    "ctr4b", "rk4"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 4
        "       aese    "ctr3b", "rk4"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 4
        "       aese    "ctr2b", "rk4"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 4
        "       aese    "ctr5b", "rk4"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 4
        "       aese    "ctr6b", "rk4"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 4
        "       aese    "ctr7b", "rk4"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 4
        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 4
        "       aese    "ctr5b", "rk5"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 5
        "       eor     "t8".16b, "t7".16b, "t8".16b                        \n" // GHASH block 8k+6 - high
        "       eor     "h34k".16b, "h34k".16b, "t6".16b                    \n" // GHASH block 8k+4 - mid
        "       eor     "h1".16b, "h2".16b, "h1".16b                        \n" // GHASH block 8k+6 - low
        "       eor     "acc_lb", "acc_lb", "h3".16b                        \n" // GHASH block 8k+5 - low
        "       eor     "acc_hb", "acc_hb", "t5".16b                        \n" // GHASH block 8k+5 - high
        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 3
        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 4
        "       aese    "ctr6b", "rk5"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 5
        "       ldr     "mod_constantd", [%[modulo_constant]]               \n" // MODULO - load modulo constant
        "       ldp     "rk6q", "rk7q", [%[cc], #96]                        \n" // load rk6, rk7
        "       aese    "ctr2b", "rk5"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 5
        "       aese    "ctr4b", "rk5"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 5
        "       aese    "ctr3b", "rk5"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 5
        "       pmull2  "t9".1q, "res6".2d, "h12k".2d                       \n" // GHASH block 8k+6 - mid
        "       pmull   "h12k".1q, "res6".1d, "h12k".1d                     \n" // GHASH block 8k+7 - mid
        "       eor     "h12k".16b, "h12k".16b, "t9".16b                    \n" // GHASH block 8k+6, 8k+7 - mid
        "       eor     "acc_hb", "acc_hb", "t8".16b                        \n" // GHASH block 8k+7 - high
        "       eor     "acc_lb", "acc_lb", "h1".16b                        \n" // GHASH block 8k+7 - low
        "       aese    "ctr7b", "rk5"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 5
        "       aese    "ctr6b", "rk6"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 6
        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 5
        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 6
        "       aese    "ctr7b", "rk6"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 6
        "       aese    "ctr5b", "rk6"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 6
        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 5
        "       eor     "acc_mb", "acc_mb", "h34k".16b                      \n" // GHASH block 8k+5 - mid
        "       aese    "ctr3b", "rk6"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 6
        "       aese    "ctr2b", "rk6"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 6
        "       aese    "ctr7b", "rk7"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 7
        "       aese    "ctr2b", "rk7"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 7
        "       eor     "t10".16b, "acc_hb", "acc_lb"                       \n" // MODULO - karatsuba tidy up
        "       eor     "acc_mb", "acc_mb", "h12k".16b                      \n" // GHASH block 8k+6, 8k+7 - mid
        "       pmull   "t11".1q, "acc_h".1d, "mod_constant".1d             \n" // MODULO - top 64b align with mid
        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 6
        "       aese    "ctr4b", "rk6"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 6
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+15
        "       aese    "ctr3b", "rk7"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 7
        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 7
        "       aese    "ctr6b", "rk7"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 7
        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n" // MODULO - other top alignment
        "       ldp     "rk8q", "rk9q", [%[cc], #128]                       \n" // load rk8, rk9
        "       aese    "ctr5b", "rk7"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 7
        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 7
        "       aese    "ctr4b", "rk7"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 7
        "       rev32   "h1".16b, "rtmp_ctr".16b                            \n" // CTR block 8k+16
        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 8
        "       aese    "ctr5b", "rk8"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 8
        "       aese    "ctr6b", "rk8"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 8
        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 8
        "       aese    "ctr7b", "rk8"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 8
        "       aese    "ctr3b", "rk8"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 8
        "       aese    "ctr2b", "rk8"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 8
        "       aese    "ctr4b", "rk8"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 8
        "       eor     "acc_mb", "acc_mb", "t10".16b                       \n" // MODULO - karatsuba tidy up
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+16
        "       ldp     "rk10q", "rk11q", [%[cc], #160]                     \n" // load rk10, rk11
        "       ldp     "res0q", "res1q", [%[input_ptr]], #32               \n" // AES block 8k+8, 8k+9 - load ciphertext
        "       aese    "ctr3b", "rk9"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 9
        "       aese    "ctr4b", "rk9"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 9
        "       rev32   "h2".16b, "rtmp_ctr".16b                            \n" // CTR block 8k+17
        "       ldp     "res2q", "res3q", [%[input_ptr]], #32               \n" // AES block 8k+10, 8k+11 - load ciphertext
        "       aese    "ctr7b", "rk9"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 9
        "       aese    "ctr1b", "rk9"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 9
        "       aese    "ctr6b", "rk9"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 9
        "       aese    "ctr2b", "rk9"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 9
        "       aese    "ctr0b", "rk9"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 9
        "       aese    "ctr5b", "rk9"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 9
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+17
        "       eor     "t11".16b, "acc_hb", "t11".16b                      \n" // MODULO - fold into mid
        "       ldp     "res4q", "res5q", [%[input_ptr]], #32               \n" // AES block 8k+12, 8k+13 - load ciphertext
        "       aese    "ctr3b", "rk10"  \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 10
        "       aese    "ctr5b", "rk10"  \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 10
        "       aese    "ctr2b", "rk10"  \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 10
        "       aese    "ctr0b", "rk10"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 10
        "       ldr     "rk12q", [%[cc], #192]                              \n" // load rk12
        "       aese    "ctr6b", "rk10"  \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 10
        "       aese    "ctr4b", "rk10"  \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 10
        "       eor     "acc_mb", "acc_mb", "t11".16b                       \n" // MODULO - fold into mid
        "       aese    "ctr7b", "rk10"  \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 10
        "       aese    "ctr3b", "rk11"                                     \n" // AES block 8k+11 - round 11
        "       aese    "ctr1b", "rk10"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 10
        "       aese    "ctr0b", "rk11"                                     \n" // AES block 8k+8 - round 11
        "       rev32   "h3".16b, "rtmp_ctr".16b                            \n" // CTR block 8k+18
        "       aese    "ctr4b", "rk11"                                     \n" // AES block 8k+12 - round 11
        "       aese    "ctr1b", "rk11"                                     \n" // AES block 8k+9 - round 11
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+18
        "       aese    "ctr7b", "rk11"                                     \n" // AES block 8k+15 - round 11
        "       aese    "ctr5b", "rk11"                                     \n" // AES block 8k+13 - round 11
        "       aese    "ctr6b", "rk11"                                     \n" // AES block 8k+14 - round 11
        "       aese    "ctr2b", "rk11"                                     \n" // AES block 8k+10 - round 11
        "       rev32   "h4".16b, "rtmp_ctr".16b                            \n" // CTR block 8k+19
        "       eor     "ctr0b", "ctr0b", "rk12"                            \n" // AES block 8k+8 - round 12
        "       eor     "ctr7b", "ctr7b", "rk12"                            \n" // AES block 8k+15 - round 12
        "       pmull   "acc_h".1q, "acc_m".1d, "mod_constant".1d           \n" // MODULO - mid 64b align with low
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n" // MODULO - other mid alignment
        "       eor     "ctr1b", "ctr1b", "rk12"                            \n" // AES block 8k+9 - round 12
        "       eor     "ctr3b", "ctr3b", "rk12"                            \n" // AES block 8k+11 - round 12
        "       ldp     "res6q", "res7q", [%[input_ptr]], #32               \n" // AES block 8k+14, 8k+15 - load ciphertext
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+19
        "       eor     "ctr4b", "ctr4b", "rk12"                            \n" // AES block 8k+12 - round 12
        "       eor     "ctr5b", "ctr5b", "rk12"                            \n" // AES block 8k+13 - round 12
        "       eor     "ctr6b", "ctr6b", "rk12"                            \n" // AES block 8k+14 - round 12
        "       eor     "ctr2b", "ctr2b", "rk12"                            \n" // AES block 8k+10 - round 12
        "       eor     "acc_lb", "acc_lb", "acc_hb"                        \n" // MODULO - fold into low
        "       eor     "ctr6b", "res6b", "ctr6b"                           \n" // AES block 8k+14 - result
        "       eor     "ctr1b", "res1b", "ctr1b"                           \n" // AES block 8k+9 - result
        "       eor     "ctr0b", "res0b", "ctr0b"                           \n" // AES block 8k+8 - result
        "       eor     "ctr3b", "res3b", "ctr3b"                           \n" // AES block 8k+11 - result
        "       stp     "ctr0q", "ctr1q", [%[output_ptr]], #32              \n" // AES block 8k+8, 8k+9 - store result
        "       mov     "ctr0".16b, "h1".16b                                \n" // CTR block 8k+16
        "       eor     "ctr2b", "res2b", "ctr2b"                           \n" // AES block 8k+10 - result
        "       eor     "acc_lb", "acc_lb", "acc_mb"                        \n" // MODULO - fold into low
        "       eor     "ctr5b", "res5b", "ctr5b"                           \n" // AES block 8k+13 - result
        "       eor     "ctr4b", "res4b", "ctr4b"                           \n" // AES block 8k+12 - result
        "       stp     "ctr2q", "ctr3q", [%[output_ptr]], #32              \n" // AES block 8k+10, 8k+11 - store result
        "       stp     "ctr4q", "ctr5q", [%[output_ptr]], #32              \n" // AES block 8k+12, 8k+13 - store result
        "       rev32   "ctr4".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+20
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+20
        "       mov     "ctr3".16b, "h4".16b                                \n" // CTR block 8k+19
        "       eor     "ctr7b", "res7b", "ctr7b"                           \n" // AES block 8k+15 - result
        "       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // LOOP CONTROL
        "       stp     "ctr6q", "ctr7q", [%[output_ptr]], #32              \n" // AES block 8k+14, 8k+15 - store result
        "       mov     "ctr2".16b, "h3".16b                                \n" // CTR block 8k+18
        "       mov     "ctr1".16b, "h2".16b                                \n" // CTR block 8k+17
        "       b.lt    1b                                                  \n"
        "7:                                                                 \n" // PREPRETAIL
        "       rev32   "ctr5".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+13
        "       ldp     "rk0q", "rk1q", [%[cc], #0]                         \n" // load rk0, rk1
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+13
        "       ldp     "h5q", "h6q", [%[cc], #304]                         \n" // load h5l | h5h
        "       rev64   "res0b", "res0b"                                    \n" // GHASH block 8k
        "       ext     "acc_lb", "acc_lb", "acc_lb", #8                    \n" // PRE 0
        "       rev64   "res3b", "res3b"                                    \n" // GHASH block 8k+3
        "       rev64   "res2b", "res2b"                                    \n" // GHASH block 8k+2
        "       pmull2  "t1".1q, "res2".2d, "h6".2d                         \n" // GHASH block 8k+2 - high
        "       rev64   "res1b", "res1b"                                    \n" // GHASH block 8k+1
        "       ldp     "h7q", "h8q", [%[cc], #336]                         \n" // load h7l | h7h
        "       pmull2  "t0".1q, "res1".2d, "h7".2d                         \n" // GHASH block 8k+1 - high
        "       pmull   "h7".1q, "res1".1d, "h7".1d                         \n" // GHASH block 8k+1 - low
        "       eor     "res0b", "res0b", "acc_lb"                          \n" // PRE 1
        "       trn1    "acc_m".2d, "res1".2d, "res0".2d                    \n" // GHASH block 8k, 8k+1 - mid
        "       pmull   "acc_l".1q, "res0".1d, "h8".1d                      \n" // GHASH block 8k - low
        "       pmull2  "acc_h".1q, "res0".2d, "h8".2d                      \n" // GHASH block 8k - high
        "       trn2    "res0".2d, "res1".2d, "res0".2d                     \n" // GHASH block 8k, 8k+1 - mid
        "       pmull2  "t2".1q, "res3".2d, "h5".2d                         \n" // GHASH block 8k+3 - high
        "       eor     "acc_hb", "acc_hb", "t0".16b                        \n" // GHASH block 8k+1 - high
        "       eor     "t1".16b, "t1".16b, "t2".16b                        \n" // GHASH block 8k+2 - high
        "       rev32   "ctr6".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+14
        "       rev64   "res6b", "res6b"                                    \n" // GHASH block 8k+6 (t0, t1, and t2 free)
        "       aese    "ctr4b", "rk0"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 0
        "       eor     "acc_lb", "acc_lb", "h7".16b                        \n" // GHASH block 8k+1 - low
        "       eor     "res0".16b, "res0".16b, "acc_m".16b                 \n" // GHASH block 8k, 8k+1 - mid
        "       pmull   "h5".1q, "res3".1d, "h5".1d                         \n" // GHASH block 8k+3 - low
        "       eor     "acc_hb", "acc_hb", "t1".16b                        \n" // GHASH block 8k+3 - high
        "       trn1    "t3".2d, "res3".2d, "res2".2d                       \n" // GHASH block 8k+2, 8k+3 - mid
        "       pmull   "h6".1q, "res2".1d, "h6".1d                         \n" // GHASH block 8k+2 - low
        "       trn2    "res2".2d, "res3".2d, "res2".2d                     \n" // GHASH block 8k+2, 8k+3 - mid
        "       ldp     "h3q", "h4q", [%[cc], #272]                         \n" // load h3l | h3h
        "       rev64   "res4b", "res4b"                                    \n" // GHASH block 8k+4 (t0, t1, and t2 free)
        "       eor     "res2".16b, "res2".16b, "t3".16b                    \n" // GHASH block 8k+2, 8k+3 - mid
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+14
        "       eor     "t2".16b, "h6".16b, "h5".16b                        \n" // GHASH block 8k+2 - low
        "       rev64   "res7b", "res7b"                                    \n" // GHASH block 8k+7 (t0, t1, t2 and t3 free)
        "       ldp     "h1q", "h2q", [%[cc], #240]                         \n" // load h1l | h1h
        "       ldp     "h56kq", "h78kq", [%[cc], #400]                     \n" // load h6k | h5k
        "       rev64   "res5b", "res5b"                                    \n" // GHASH block 8k+5 (t0, t1, t2 and t3 free)
        "       pmull2  "acc_m".1q, "res0".2d, "h78k".2d                    \n" // GHASH block 8k   - mid
        "       pmull   "h78k".1q, "res0".1d, "h78k".1d                     \n" // GHASH block 8k+1 - mid
        "       pmull2  "t4".1q, "res4".2d, "h4".2d                         \n" // GHASH block 8k+4 - high
        "       pmull   "h4".1q, "res4".1d, "h4".1d                         \n" // GHASH block 8k+4 - low
        "       aese    "ctr2b", "rk0"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 0
        "       pmull2  "t3".1q, "res2".2d, "h56k".2d                       \n" // GHASH block 8k+2 - mid
        "       pmull   "h56k".1q, "res2".1d, "h56k".1d                     \n" // GHASH block 8k+3 - mid
        "       eor     "h56k".16b, "h56k".16b, "t3".16b                    \n" // GHASH block 8k+2 - mid
        "       trn1    "t6".2d, "res5".2d, "res4".2d                       \n" // GHASH block 8k+4, 8k+5 - mid
        "       eor     "acc_lb", "acc_lb", "t2".16b                        \n" // GHASH block 8k+3 - low
        "       eor     "acc_mb", "acc_mb", "h78k".16b                      \n" // GHASH block 8k+1 - mid
        "       trn2    "res4".2d, "res5".2d, "res4".2d                     \n" // GHASH block 8k+4, 8k+5 - mid
        "       rev32   "ctr7".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+15
        "       pmull2  "t7".1q, "res6".2d, "h2".2d                         \n" // GHASH block 8k+6 - high
        "       pmull   "h2".1q, "res6".1d, "h2".1d                         \n" // GHASH block 8k+6 - low
        "       ldr     "h34kq", [%[cc], #384]                              \n" // load h4k | h3k
        "       pmull2  "t5".1q, "res5".2d, "h3".2d                         \n" // GHASH block 8k+5 - high
        "       pmull   "h3".1q, "res5".1d, "h3".1d                         \n" // GHASH block 8k+5 - low
        "       trn1    "t9".2d, "res7".2d, "res6".2d                       \n" // GHASH block 8k+6, 8k+7 - mid
        "       eor     "res4".16b, "res4".16b, "t6".16b                    \n" // GHASH block 8k+4, 8k+5 - mid
        "       aese    "ctr3b", "rk0"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 0
        "       aese    "ctr5b", "rk0"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 0
        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 0
        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 0
        "       trn2    "res6".2d, "res7".2d, "res6".2d                     \n" // GHASH block 8k+6, 8k+7 - mid
        "       eor     "t5".16b, "t4".16b, "t5".16b                        \n" // GHASH block 8k+4 - high
        "       eor     "acc_lb", "acc_lb", "h4".16b                        \n" // GHASH block 8k+4 - low
        "       aese    "ctr7b", "rk0"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 0
        "       eor     "acc_mb", "acc_mb", "h56k".16b                      \n" // GHASH block 8k+3 - mid
        "       ldr     "h12kq", [%[cc], #368]                              \n" // load h2k | h1k
        "       aese    "ctr2b", "rk1"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 1
        "       aese    "ctr6b", "rk0"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 0
        "       aese    "ctr3b", "rk1"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 1
        "       aese    "ctr6b", "rk1"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 1
        "       aese    "ctr4b", "rk1"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 1
        "       ldp     "rk2q", "rk3q", [%[cc], #32]                        \n" // load rk2, rk3
        "       pmull2  "t6".1q, "res4".2d, "h34k".2d                       \n" // GHASH block 8k+4 - mid
        "       pmull   "h34k".1q, "res4".1d, "h34k".1d                     \n" // GHASH block 8k+5 - mid
        "       pmull2  "t8".1q, "res7".2d, "h1".2d                         \n" // GHASH block 8k+7 - high
        "       aese    "ctr7b", "rk1"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 1
        "       eor     "res6".16b, "res6".16b, "t9".16b                    \n" // GHASH block 8k+6, 8k+7 - mid
        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 1
        "       aese    "ctr5b", "rk1"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 1
        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 1
        "       pmull   "h1".1q, "res7".1d, "h1".1d                         \n" // GHASH block 8k+7 - low
        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 2
        "       aese    "ctr3b", "rk2"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 2
        "       aese    "ctr7b", "rk2"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 2
        "       aese    "ctr6b", "rk2"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 2
        "       aese    "ctr2b", "rk2"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 2
        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 2
        "       aese    "ctr5b", "rk2"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 2
        "       aese    "ctr4b", "rk2"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 2
        "       ldp     "rk4q", "rk5q", [%[cc], #64]                        \n" // load rk4, rk5
        "       eor     "acc_hb", "acc_hb", "t5".16b                        \n" // GHASH block 8k+5 - high
        "       eor     "h1".16b, "h2".16b, "h1".16b                        \n" // GHASH block 8k+6 - low
        "       eor     "h34k".16b, "h34k".16b, "t6".16b                    \n" // GHASH block 8k+4 - mid
        "       eor     "t8".16b, "t7".16b, "t8".16b                        \n" // GHASH block 8k+6 - high
        "       eor     "acc_lb", "acc_lb", "h3".16b                        \n" // GHASH block 8k+5 - low
        "       ldr     "mod_constantd", [%[modulo_constant]]               \n" // MODULO - load modulo constant
        "       aese    "ctr4b", "rk3"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 3
        "       aese    "ctr2b", "rk3"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 3
        "       pmull2  "t9".1q, "res6".2d, "h12k".2d                       \n" // GHASH block 8k+6 - mid
        "       aese    "ctr5b", "rk3"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 3
        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 3
        "       pmull   "h12k".1q, "res6".1d, "h12k".1d                     \n" // GHASH block 8k+7 - mid
        "       aese    "ctr7b", "rk3"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 3
        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 3
        "       aese    "ctr3b", "rk3"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 3
        "       aese    "ctr6b", "rk3"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 3
        "       aese    "ctr6b", "rk4"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 4
        "       aese    "ctr5b", "rk4"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 4
        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 4
        "       eor     "acc_lb", "acc_lb", "h1".16b                        \n" // GHASH block 8k+7 - low
        "       eor     "acc_mb", "acc_mb", "h34k".16b                      \n" // GHASH block 8k+5 - mid
        "       aese    "ctr3b", "rk4"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 4
        "       eor     "h12k".16b, "h12k".16b, "t9".16b                    \n" // GHASH block 8k+6, 8k+7 - mid
        "       eor     "acc_hb", "acc_hb", "t8".16b                        \n" // GHASH block 8k+7 - high
        "       aese    "ctr2b", "rk4"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 4
        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 4
        "       aese    "ctr7b", "rk4"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 4
        "       aese    "ctr4b", "rk4"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 4
        "       aese    "ctr2b", "rk5"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 5
        "       aese    "ctr7b", "rk5"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 5
        "       aese    "ctr4b", "rk5"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 5
        "       ldp     "rk6q", "rk7q", [%[cc], #96]                        \n" // load rk6, rk7
        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 5
        "       eor     "acc_mb", "acc_mb", "h12k".16b                      \n" // GHASH block 8k+6, 8k+7 - mid
        "       pmull   "t11".1q, "acc_h".1d, "mod_constant".1d             \n" // MODULO - top 64b align with mid
        "       aese    "ctr3b", "rk5"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 5
        "       aese    "ctr5b", "rk5"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 5
        "       aese    "ctr6b", "rk5"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 5
        "       eor     "t10".16b, "acc_hb", "acc_lb"                       \n" // MODULO - karatsuba tidy up
        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n" // MODULO - other top alignment
        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 5
        "       aese    "ctr6b", "rk6"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 6
        "       aese    "ctr4b", "rk6"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 6
        "       aese    "ctr7b", "rk6"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 6
        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 6
        "       aese    "ctr2b", "rk6"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 6
        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 6
        "       aese    "ctr5b", "rk6"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 6
        "       aese    "ctr3b", "rk6"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 6
        "       ldp     "rk8q", "rk9q", [%[cc], #128]                       \n" // load rk8, rk9
        "       eor     "t11".16b, "acc_hb", "t11".16b                      \n" // MODULO - fold into mid
        "       eor     "acc_mb", "acc_mb", "t10".16b                       \n" // MODULO - karatsuba tidy up
        "       aese    "ctr3b", "rk7"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 7
        "       aese    "ctr5b", "rk7"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 7
        "       aese    "ctr7b", "rk7"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 7
        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 7
        "       aese    "ctr6b", "rk7"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 7
        "       aese    "ctr6b", "rk8"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 8
        "       aese    "ctr5b", "rk8"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 8
        "       aese    "ctr3b", "rk8"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 8
        "       aese    "ctr7b", "rk8"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 8
        "       aese    "ctr2b", "rk7"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 7
        "       aese    "ctr2b", "rk8"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 8
        "       aese    "ctr4b", "rk7"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 7
        "       aese    "ctr4b", "rk8"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 8
        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 7
        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 8
        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 8
        "       ldp     "rk10q", "rk11q", [%[cc], #160]                     \n" // load rk10, rk11
        "       aese    "ctr1b", "rk9"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 9
        "       aese    "ctr2b", "rk9"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 9
        "       eor     "acc_mb", "acc_mb", "t11".16b                       \n" // MODULO - fold into mid
        "       aese    "ctr7b", "rk9"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 9
        "       aese    "ctr0b", "rk9"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 9
        "       aese    "ctr3b", "rk9"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 9
        "       pmull   "acc_h".1q, "acc_m".1d, "mod_constant".1d           \n" // MODULO - mid 64b align with low
        "       aese    "ctr5b", "rk9"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 9
        "       aese    "ctr6b", "rk9"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 9
        "       aese    "ctr4b", "rk9"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 9
        "       aese    "ctr2b", "rk10"  \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 10
        "       aese    "ctr1b", "rk10"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 10
        "       aese    "ctr5b", "rk10"  \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 10
        "       aese    "ctr7b", "rk10"  \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 10
        "       aese    "ctr0b", "rk10"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 10
        "       aese    "ctr3b", "rk10"  \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 10
        "       aese    "ctr6b", "rk10"  \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 10
        "       aese    "ctr4b", "rk10"  \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 10
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n" // MODULO - other mid alignment
        "       ldr     "rk12q", [%[cc], #192]                              \n" // load rk12
        "       aese    "ctr2b", "rk11"                                     \n" // AES block 8k+10 - round 11
        "       aese    "ctr6b", "rk11"                                     \n" // AES block 8k+14 - round 11
        "       aese    "ctr3b", "rk11"                                     \n" // AES block 8k+11 - round 11
        "       aese    "ctr4b", "rk11"                                     \n" // AES block 8k+12 - round 11
        "       eor     "acc_lb", "acc_lb", "acc_hb"                        \n" // MODULO - fold into low
        "       aese    "ctr1b", "rk11"                                     \n" // AES block 8k+9 - round 11
        "       aese    "ctr7b", "rk11"                                     \n" // AES block 8k+15 - round 11
        "       aese    "ctr0b", "rk11"                                     \n" // AES block 8k+8 - round 11
        "       eor     "ctr4b", "ctr4b", "rk12"                            \n" // AES block 8k+12 - round 12
        "       eor     "acc_lb", "acc_lb", "acc_mb"                        \n" // MODULO - fold into low
        "       aese    "ctr5b", "rk11"                                     \n" // AES block 8k+13 - round 11
        "       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+15
        "       eor     "ctr5b", "ctr5b", "rk12"                            \n" // AES block 8k+13 - round 12
        "       eor     "ctr2b", "ctr2b", "rk12"                            \n" // AES block 8k+10 - round 12
        "       eor     "ctr0b", "ctr0b", "rk12"                            \n" // AES block 8k+8 - round 12
        "       eor     "ctr1b", "ctr1b", "rk12"                            \n" // AES block 8k+9 - round 12
        "       eor     "ctr7b", "ctr7b", "rk12"                            \n" // AES block 8k+15 - round 12
        "       eor     "ctr6b", "ctr6b", "rk12"                            \n" // AES block 8k+14 - round 12
        "       eor     "ctr3b", "ctr3b", "rk12"                            \n" // AES block 8k+11 - round 12
        "2:                                                                 \n" // TAIL
        "       ldr     "h56kq", [%[cc], #400]                              \n" // load h6k | h5k
        "       ldr     "h7q", [%[cc], #336]                                \n" // load h7l | h7h
        "       ldr     "h78kq", [%[cc], #416]                              \n" // load h8k | h7k
        "       sub     "main_end_input_ptr", "end_input_ptr", %[input_ptr] \n" // main_end_input_ptr is number of bytes left to process
        "       ldr     "h6q", [%[cc], #320]                                \n" // load h6l | h6h
        "       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES block 8k+8 - load ciphertext
        "       ext     "t0".16b, "acc_lb", "acc_lb", #8                    \n" // prepare final partial tag
        "       cmp     "main_end_input_ptr", #112                          \n"
        "       eor     "res4b", "res1b", "ctr0b"                           \n" // AES block 8k+8 - result
        "       ldr     "h5q", [%[cc], #304]                                \n" // load h5l | h5h
        "       ldr     "h8q", [%[cc], #352]                                \n" // load h8l | h8h
        "       b.gt    8f                                                  \n"
        "       mov     "ctr7b", "ctr6b"                                    \n"
        "       mov     "ctr6b", "ctr5b"                                    \n"
        "       mov     "ctr5b", "ctr4b"                                    \n"
        "       movi    "acc_h".8b, #0                                      \n"
        "       movi    "acc_m".8b, #0                                      \n"
        "       cmp     "main_end_input_ptr", #96                           \n"
        "       mov     "ctr4b", "ctr3b"                                    \n"
        "       movi    "acc_l".8b, #0                                      \n"
        "       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
        "       mov     "ctr3b", "ctr2b"                                    \n"
        "       mov     "ctr2b", "ctr1b"                                    \n"
        "       b.gt    9f                                                  \n"
        "       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
        "       mov     "ctr7b", "ctr6b"                                    \n"
        "       mov     "ctr6b", "ctr5b"                                    \n"
        "       mov     "ctr5b", "ctr4b"                                    \n"
        "       mov     "ctr4b", "ctr3b"                                    \n"
        "       mov     "ctr3b", "ctr1b"                                    \n"
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
        "       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
        "       cmp     "main_end_input_ptr", #32                           \n"
        "       mov     "ctr7b", "ctr6b"                                    \n"
        "       mov     "ctr6b", "ctr1b"                                    \n"
        "       b.gt    4f                                                  \n"
        "       cmp     "main_end_input_ptr", #16                           \n"
        "       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
        "       mov     "ctr7b", "ctr1b"                                    \n"
        "       b.gt    5f                                                  \n"
        "       ldr     "h12kq", [%[cc], #368]                              \n" // load h2k | h1k
        "       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
        "       b       6f                                                  \n"
        "8:                                                                 \n" // blocks left >  7
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-7 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       ins     "acc_m".d[0], "h78k".d[1]                           \n" // GHASH final-7 block - mid
        "       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final-6 block - load ciphertext
        "       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-7 block  - store result
        "       eor     "res4b", "res1b", "ctr1b"                           \n" // AES final-6 block - result
        "       pmull2  "acc_h".1q, "res0".2d, "h8".2d                      \n" // GHASH final-7 block - high
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-7 block - mid
        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-7 block - mid
        "       pmull   "acc_l".1q, "res0".1d, "h8".1d                      \n" // GHASH final-7 block - low
        "       pmull   "acc_m".1q, "rk4v".1d, "acc_m".1d                   \n" // GHASH final-7 block - mid
        "9:                                                                 \n" // blocks left >  6
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-6 block
        "       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final-5 block - load ciphertext
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-6 block - mid
        "       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-6 block - store result
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-6 block - mid
        "       pmull   "rk4v".1q, "rk4v".1d, "h78k".1d                     \n" // GHASH final-6 block - mid
        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in
        "       pmull   "rk3q1", "res0".1d, "h7".1d                         \n" // GHASH final-6 block - low
        "       pmull2  "rk2q1", "res0".2d, "h7".2d                         \n" // GHASH final-6 block - high
        "       eor     "res4b", "res1b", "ctr2b"                           \n" // AES final-5 block - result
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-6 block - mid
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-6 block - high
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-6 block - low
        "10:                                                                \n" // blocks left >  5
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-5 block
        "       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final-4 block - load ciphertext
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in
        "       pmull2  "rk2q1", "res0".2d, "h6".2d                         \n" // GHASH final-5 block - high
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-5 block - mid
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-5 block - high
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-5 block - mid
        "       ins     "rk4v".d[1], "rk4v".d[0]                            \n" // GHASH final-5 block - mid
        "       pmull2  "rk4v".1q, "rk4v".2d, "h56k".2d                     \n" // GHASH final-5 block - mid
        "       pmull   "rk3q1", "res0".1d, "h6".1d                         \n" // GHASH final-5 block - low
        "       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-5 block - store result
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-5 block - low
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-5 block - mid
        "       eor     "res4b", "res1b", "ctr3b"                           \n" // AES final-4 block - result
        "11:                                                                \n" // blocks left >  4
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-4 block
        "       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final-3 block - load ciphertext
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       pmull2  "rk2q1", "res0".2d, "h5".2d                         \n" // GHASH final-4 block - high
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-4 block - high
        "       pmull   "rk3q1", "res0".1d, "h5".1d                         \n" // GHASH final-4 block - low
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-4 block - mid
        "       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-4 block - store result
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-4 block - mid
        "       pmull   "rk4v".1q, "rk4v".1d, "h56k".1d                     \n" // GHASH final-4 block - mid
        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-4 block - mid
        "       eor     "res4b", "res1b", "ctr4b"                           \n" // AES final-3 block - result
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-4 block - low
        "3:                                                                 \n" // blocks left >  3
        "       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-3 block - store result
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-3 block
        "       ldr     "h4q", [%[cc], #288]                                \n" // load h4l | h4h
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in
        "       pmull   "rk3q1", "res0".1d, "h4".1d                         \n" // GHASH final-3 block - low
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-3 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-3 block - mid
        "       ins     "rk4v".d[1], "rk4v".d[0]                            \n" // GHASH final-3 block - mid
        "       ldr     "h34kq", [%[cc], #384]                              \n" // load h4k | h3k
        "       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final-2 block - load ciphertext
        "       pmull2  "rk4v".1q, "rk4v".2d, "h34k".2d                     \n" // GHASH final-3 block - mid
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-3 block - low
        "       pmull2  "rk2q1", "res0".2d, "h4".2d                         \n" // GHASH final-3 block - high
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-3 block - mid
        "       eor     "res4b", "res1b", "ctr5b"                           \n" // AES final-2 block - result
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-3 block - high
        "4:                                                                 \n" // blocks left >  2
        "       ldr     "h3q", [%[cc], #272]                                \n" // load h3l | h3h
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-2 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-2 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-2 block - mid
        "       pmull   "rk3q1", "res0".1d, "h3".1d                         \n" // GHASH final-2 block - low
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-2 block - low
        "       pmull2  "rk2q1", "res0".2d, "h3".2d                         \n" // GHASH final-2 block - high
        "       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final-1 block - load ciphertext
        "       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-2 block - store result
        "       pmull   "rk4v".1q, "rk4v".1d, "h34k".1d                     \n" // GHASH final-2 block - mid
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-2 block - mid
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-2 block - high
        "       eor     "res4b", "res1b", "ctr6b"                           \n" // AES final-1 block - result
        "5:                                                                 \n" // blocks left >  1
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-1 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       ldr     "h12kq", [%[cc], #368]                              \n" // load h2k | h1k
        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in
        "       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-1 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-1 block - mid
        "       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-1 block - store result
        "       ins     "rk4v".d[1], "rk4v".d[0]                            \n" // GHASH final-1 block - mid
        "       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final block - load ciphertext
        "       ldr     "h2q", [%[cc], #256]                                \n" // load h2l | h2h
        "       eor     "res4b", "res1b", "ctr7b"                           \n" // AES final block - result
        "       pmull   "rk3q1", "res0".1d, "h2".1d                         \n" // GHASH final-1 block - low
        "       pmull2  "rk2q1", "res0".2d, "h2".2d                         \n" // GHASH final-1 block - high
        "       pmull2  "rk4v".1q, "rk4v".2d, "h12k".2d                     \n" // GHASH final-1 block - mid
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-1 block - mid
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-1 block - high
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-1 block - low
        "6:                                                                 \n" // blocks left <= 1
        "       ldr     "h1q", [%[cc], #240]                                \n" // load h1l | h1h
        "       ld1     { "rk0" }, [%[output_ptr]]                          \n" // load existing bytes where the possibly partial last block is to be stored
        "       and     %[bit_length], %[bit_length], #127                  \n" // bit_length %= 128
        "       sub     %[bit_length], %[bit_length], #128                  \n" // bit_length -= 128
        "       neg     %[bit_length], %[bit_length]                        \n" // bit_length = 128 - #bits in input (in range [1,128])
        "       and     %[bit_length], %[bit_length], #127                  \n" // bit_length %= 128
        "       mvn     "temp0_x", xzr                                      \n" // temp0_x = 0xffffffffffffffff
        "       lsr     "temp0_x", "temp0_x", %[bit_length]                 \n" // temp0_x is mask for top 64b of last block
        "       cmp     %[bit_length], #64                                  \n"
        "       csel    "temp3_x", "temp0_x", xzr, lt                       \n"
        "       mvn     "temp1_x", xzr                                      \n" // temp1_x = 0xffffffffffffffff
        "       csel    "temp2_x", "temp1_x", "temp0_x", lt                 \n"
        "       mov     "ctr0".d[1], "temp3_x"                              \n"
        "       mov     "ctr0".d[0], "temp2_x"                              \n" // ctr0b is mask for last block
        "       and     "res1b", "res1b", "ctr0b"                           \n" // possibly partial last block has zeroes in highest bits
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       ins     "t0".d[0], "res0".d[1]                              \n" // GHASH final block - mid
        "       eor     "t0".8b, "t0".8b, "res0".8b                         \n" // GHASH final block - mid
        "       pmull   "t0".1q, "t0".1d, "h12k".1d                         \n" // GHASH final block - mid
        "       pmull2  "rk2q1", "res0".2d, "h1".2d                         \n" // GHASH final block - high
        "       bif     "res4b", "rk0", "ctr0b"                             \n" // insert existing bytes in top end of result before storing
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final block - high
        "       pmull   "rk3q1", "res0".1d, "h1".1d                         \n" // GHASH final block - low
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final block - low
        "       eor     "acc_mb", "acc_mb", "t0".16b                        \n" // GHASH final block - mid
        "       ldr     "mod_constantd", [%[modulo_constant]]               \n" // MODULO - load modulo constant
        "       pmull   "t11".1q, "acc_h".1d, "mod_constant".1d             \n" // MODULO - top 64b align with mid
        "       eor     "t10".16b, "acc_hb", "acc_lb"                       \n" // MODULO - karatsuba tidy up
        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n" // MODULO - other top alignment
        "       eor     "acc_mb", "acc_mb", "t10".16b                       \n" // MODULO - karatsuba tidy up
        "       eor     "t11".16b, "acc_hb", "t11".16b                      \n" // MODULO - fold into mid
        "       eor     "acc_mb", "acc_mb", "t11".16b                       \n" // MODULO - fold into mid
        "       pmull   "acc_h".1q, "acc_m".1d, "mod_constant".1d           \n" // MODULO - mid 64b align with low
        "       rev32   "rtmp_ctr".16b, "rtmp_ctr".16b                      \n"
        "       str     "rtmp_ctrq", [%[counter]]                           \n" // store the updated counter
        "       eor     "acc_lb", "acc_lb", "acc_hb"                        \n" // MODULO - fold into low
        "       st1     { "res4b" }, [%[output_ptr]]                        \n" // store all 16B
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n" // MODULO - other mid alignment
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
#undef ctr0q
#undef ctr1b
#undef ctr1
#undef ctr1d
#undef ctr1q
#undef ctr2b
#undef ctr2
#undef ctr2d
#undef ctr2q
#undef ctr3b
#undef ctr3
#undef ctr3d
#undef ctr3q
#undef ctr4b
#undef ctr4
#undef ctr4d
#undef ctr4q
#undef ctr5b
#undef ctr5
#undef ctr5d
#undef ctr5q
#undef ctr6b
#undef ctr6
#undef ctr6d
#undef ctr6q
#undef ctr7b
#undef ctr7
#undef ctr7d
#undef ctr7q

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
#undef t12

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
