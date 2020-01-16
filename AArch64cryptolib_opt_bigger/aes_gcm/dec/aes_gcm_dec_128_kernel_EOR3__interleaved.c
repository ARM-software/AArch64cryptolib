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


static operation_result_t aes_gcm_dec_128_kernel(uint8_t * ciphertext, uint64_t ciphertext_length, cipher_state_t * restrict cs, uint8_t * plaintext)
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

// cycle 0
"       lsr     "main_end_input_ptr", %[bit_length], #3             \n" // byte_len
"       ld1     { "ctr0b" }, [%[counter]]                           \n" // CTR block 0

// cycle 1
"       ldp     "rk0q", "rk1q", [%[cc], #0]                         \n" // load rk0, rk1
"       sub     "main_end_input_ptr", "main_end_input_ptr", #1      \n" // byte_len - 1

// cycle 2
"       ld1     { "rctr_inc".16b }, [%[counter_increment]]          \n" // set up counter increment
"       ld1     { "acc_lb" }, [%[current_tag]]                      \n"

// cycle 5
"       rev32   "rtmp_ctr".16b, "ctr0".16b                          \n" // set up reversed counter

// cycle 6
"       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 0

// cycle 7
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 0

// cycle 9
"       rev32   "ctr1".16b, "rtmp_ctr".16b                          \n" // CTR block 1
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 1

// cycle 10
"       and     "main_end_input_ptr", "main_end_input_ptr", #0xffffffffffffff80\n" // number of bytes to be processed in main loop (at least 1 byte must be handled by tail)

// cycle 11
"       rev32   "ctr2".16b, "rtmp_ctr".16b                          \n" // CTR block 2
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 2
"       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 0

// cycle 13
"       rev32   "ctr3".16b, "rtmp_ctr".16b                          \n" // CTR block 3
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 3

// cycle 14
"       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 1
"       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 1

// cycle 15
"       rev32   "ctr4".16b, "rtmp_ctr".16b                          \n" // CTR block 4
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 4

// cycle 17
"       rev32   "ctr5".16b, "rtmp_ctr".16b                          \n" // CTR block 5
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 5

// cycle 18
"       aese    "ctr2b", "rk0"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 0

// cycle 19
"       rev32   "ctr6".16b, "rtmp_ctr".16b                          \n" // CTR block 6
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 6
"       aese    "ctr5b", "rk0"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 0

// cycle 20
"       aese    "ctr3b", "rk0"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 0
"       aese    "ctr4b", "rk0"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 0

// cycle 21
"       rev32   "ctr7".16b, "rtmp_ctr".16b                          \n" // CTR block 7

// cycle 22
"       aese    "ctr6b", "rk0"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 0
"       aese    "ctr2b", "rk1"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 1

// cycle 23
"       aese    "ctr7b", "rk0"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 0

// cycle 24
"       ldp     "rk2q", "rk3q", [%[cc], #32]                        \n" // load rk2, rk3

// cycle 26
"       aese    "ctr6b", "rk1"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 1
"       aese    "ctr5b", "rk1"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 1

// cycle 27
"       aese    "ctr4b", "rk1"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 1
"       aese    "ctr7b", "rk1"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 1

// cycle 29
"       aese    "ctr7b", "rk2"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 2
"       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 2
"       aese    "ctr3b", "rk1"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 1

// cycle 30
"       aese    "ctr6b", "rk2"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 2
"       aese    "ctr2b", "rk2"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 2
"       aese    "ctr5b", "rk2"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 2

// cycle 31
"       aese    "ctr4b", "rk2"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 2
"       aese    "ctr3b", "rk2"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 2
"       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 2

// cycle 32
"       aese    "ctr6b", "rk3"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 3
"       aese    "ctr2b", "rk3"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 3

// cycle 33
"       ldp     "rk4q", "rk5q", [%[cc], #64]                        \n" // load rk4, rk5
"       aese    "ctr5b", "rk3"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 3

// cycle 34
"       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 3
"       aese    "ctr7b", "rk3"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 3

// cycle 35
"       aese    "ctr3b", "rk3"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 3
"       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 3

// cycle 38
"       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 4
"       aese    "ctr7b", "rk4"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 4
"       aese    "ctr4b", "rk3"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 3

// cycle 39
"       aese    "ctr6b", "rk4"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 4
"       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 4
"       aese    "ctr3b", "rk4"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 4

// cycle 40
"       aese    "ctr5b", "rk4"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 4
"       aese    "ctr4b", "rk4"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 4
"       aese    "ctr2b", "rk4"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 4

// cycle 42
"       ldp     "rk6q", "rk7q", [%[cc], #96]                        \n" // load rk6, rk7
"       aese    "ctr2b", "rk5"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 5
"       aese    "ctr3b", "rk5"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 5

// cycle 43
"       aese    "ctr6b", "rk5"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 5
"       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 5

// cycle 44
"       aese    "ctr7b", "rk5"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 5
"       aese    "ctr5b", "rk5"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 5

// cycle 46
"       aese    "ctr4b", "rk5"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 5

// cycle 47
"       aese    "ctr3b", "rk6"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 6
"       aese    "ctr2b", "rk6"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 6
"       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 5

// cycle 48
"       aese    "ctr5b", "rk6"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 6
"       aese    "ctr4b", "rk6"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 6
"       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 6

// cycle 49
"       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 6
"       aese    "ctr7b", "rk6"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 6
"       aese    "ctr6b", "rk6"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 6

// cycle 50
"       aese    "ctr3b", "rk7"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 7
"       aese    "ctr4b", "rk7"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 7
"       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 7

// cycle 51
"       aese    "ctr7b", "rk7"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 7
"       aese    "ctr5b", "rk7"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 7
"       ldp     "rk8q", "rk9q", [%[cc], #128]                       \n" // load rk8, rk9

// cycle 52
"       aese    "ctr6b", "rk7"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 7
"       aese    "ctr2b", "rk7"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 7
"       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 7

// cycle 55
"       add     "main_end_input_ptr", "main_end_input_ptr", %[input_ptr]\n"
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 7

// cycle 56
"       aese    "ctr6b", "rk8"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 6 - round 8
"       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 8

// cycle 57
"       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 8
"       aese    "ctr7b", "rk8"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 7 - round 8
"       aese    "ctr3b", "rk8"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 8

// cycle 58
"       aese    "ctr5b", "rk8"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 5 - round 8
"       aese    "ctr2b", "rk8"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 8
"       aese    "ctr4b", "rk8"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 4 - round 8

// cycle 59
"       aese    "ctr0b", "rk9"                                      \n" // AES block 0 - round 9
"       aese    "ctr1b", "rk9"                                      \n" // AES block 1 - round 9
"       aese    "ctr6b", "rk9"                                      \n" // AES block 6 - round 9

// cycle 60
"       ldr     "rk10q", [%[cc], #160]                              \n" // load rk10
"       aese    "ctr4b", "rk9"                                      \n" // AES block 4 - round 9
"       aese    "ctr3b", "rk9"                                      \n" // AES block 3 - round 9

// cycle 61
"       aese    "ctr2b", "rk9"                                      \n" // AES block 2 - round 9
"       aese    "ctr5b", "rk9"                                      \n" // AES block 5 - round 9
"       aese    "ctr7b", "rk9"                                      \n" // AES block 7 - round 9

// cycle 62
"       add     "end_input_ptr", %[input_ptr], %[bit_length], LSR #3\n" // end_input_ptr
"       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // check if we have <= 8 blocks
"       b.ge    2f                                                  \n" // handle tail

// cycle 0
"       ldp     "res0q", "res1q", [%[input_ptr]], #32               \n" // AES block 0, 1 - load ciphertext

// cycle 5
"       eor3    "ctr0b", "res0b", "ctr0b", "rk10"                   \n" // AES block 0 - result
"       eor3    "ctr1b", "res1b", "ctr1b", "rk10"                   \n" // AES block 1 - result
"       stp     "ctr0q", "ctr1q", [%[output_ptr]], #32              \n" // AES block 0, 1 - store result

// cycle 6
"       rev32   "ctr0".16b, "rtmp_ctr".16b                          \n" // CTR block 8
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8
"       ldp     "res2q", "res3q", [%[input_ptr]], #32               \n" // AES block 2, 3 - load ciphertext

// cycle 7
"       ldp     "res4q", "res5q", [%[input_ptr]], #32               \n" // AES block 4, 5 - load ciphertext

// cycle 8
"       rev32   "ctr1".16b, "rtmp_ctr".16b                          \n" // CTR block 9
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 9
"       ldp     "res6q", "res7q", [%[input_ptr]], #32               \n" // AES block 6, 7 - load ciphertext

// cycle 11
"       eor3    "ctr3b", "res3b", "ctr3b", "rk10"                   \n" // AES block 3 - result
"       eor3    "ctr2b", "res2b", "ctr2b", "rk10"                   \n" // AES block 2 - result
"       stp     "ctr2q", "ctr3q", [%[output_ptr]], #32              \n" // AES block 2, 3 - store result

// cycle 12
"       rev32   "ctr2".16b, "rtmp_ctr".16b                          \n" // CTR block 10
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 10

// cycle 13
"       eor3    "ctr6b", "res6b", "ctr6b", "rk10"                   \n" // AES block 6 - result

// cycle 14
"       rev32   "ctr3".16b, "rtmp_ctr".16b                          \n" // CTR block 11
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 11

// cycle 15
"       eor3    "ctr4b", "res4b", "ctr4b", "rk10"                   \n" // AES block 4 - result
"       eor3    "ctr5b", "res5b", "ctr5b", "rk10"                   \n" // AES block 5 - result
"       stp     "ctr4q", "ctr5q", [%[output_ptr]], #32              \n" // AES block 4, 5 - store result

// cycle 16
"       eor3    "ctr7b", "res7b", "ctr7b", "rk10"                   \n" // AES block 7 - result
"       stp     "ctr6q", "ctr7q", [%[output_ptr]], #32              \n" // AES block 6, 7 - store result
"       rev32   "ctr4".16b, "rtmp_ctr".16b                          \n" // CTR block 12

// cycle 17
"       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // check if we have <= 8 blocks
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 12
"       b.ge    7f                                                  \n" // do prepretail

// cycle 0
"1:                                                                 \n" // main loop start
"       ldp     "h7q", "h8q", [%[cc], #336]                         \n" // load h7l | h7h

// cycle 1
"       rev64   "res1b", "res1b"                                    \n" // GHASH block 8k+1
"       rev64   "res0b", "res0b"                                    \n" // GHASH block 8k
"       ext     "acc_lb", "acc_lb", "acc_lb", #8                    \n" // PRE 0

// cycle 2
"       rev64   "res6b", "res6b"                                    \n" // GHASH block 8k+6
"       ldp     "h5q", "h6q", [%[cc], #304]                         \n" // load h5l | h5h

// cycle 3
"       eor     "res0b", "res0b", "acc_lb"                          \n" // PRE 1
"       rev32   "ctr5".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+13
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+13

// cycle 4
"       rev64   "res2b", "res2b"                                    \n" // GHASH block 8k+2
"       rev64   "res4b", "res4b"                                    \n" // GHASH block 8k+4
"       ldp     "rk0q", "rk1q", [%[cc], #0]                         \n" // load rk0, rk1

// cycle 5
"       rev32   "ctr6".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+14
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+14
"       ldp     "h56kq", "h78kq", [%[cc], #400]                     \n" // load h6k | h5k

// cycle 6
"       pmull2  "t0".1q, "res1".2d, "h7".2d                         \n" // GHASH block 8k+1 - high
"       pmull2  "acc_h".1q, "res0".2d, "h8".2d                      \n" // GHASH block 8k - high
"       rev64   "res3b", "res3b"                                    \n" // GHASH block 8k+3

// cycle 7
"       rev32   "ctr7".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+15
"       trn1    "acc_m".2d, "res1".2d, "res0".2d                    \n" // GHASH block 8k, 8k+1 - mid
"       rev64   "res5b", "res5b"                                    \n" // GHASH block 8k+5

// cycle 8
"       pmull   "h7".1q, "res1".1d, "h7".1d                         \n" // GHASH block 8k+1 - low
"       pmull   "acc_l".1q, "res0".1d, "h8".1d                      \n" // GHASH block 8k - low
"       trn2    "res0".2d, "res1".2d, "res0".2d                     \n" // GHASH block 8k, 8k+1 - mid

// cycle 9
"       pmull2  "t1".1q, "res2".2d, "h6".2d                         \n" // GHASH block 8k+2 - high
"       aese    "ctr4b", "rk0"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 0
"       pmull2  "t2".1q, "res3".2d, "h5".2d                         \n" // GHASH block 8k+3 - high

// cycle 10
"       aese    "ctr6b", "rk0"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 0
"       aese    "ctr5b", "rk0"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 0
"       aese    "ctr7b", "rk0"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 0

// cycle 11
"       aese    "ctr3b", "rk0"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 0
"       aese    "ctr2b", "rk0"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 0
"       eor     "acc_hb", "acc_hb", "t0".16b                        \n" // GHASH block 8k+1 - high

// cycle 12
"       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 0
"       eor     "res0".16b, "res0".16b, "acc_m".16b                 \n" // GHASH block 8k, 8k+1 - mid
"       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 0

// cycle 13
"       aese    "ctr2b", "rk1"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 1
"       eor     "acc_lb", "acc_lb", "h7".16b                        \n" // GHASH block 8k+1 - low
"       eor3    "acc_hb", "acc_hb", "t1".16b, "t2".16b              \n" // GHASH block 8k+2, 8k+3 - high

// cycle 14
"       ldp     "rk2q", "rk3q", [%[cc], #32]                        \n" // load rk2, rk3
"       trn1    "t3".2d, "res3".2d, "res2".2d                       \n" // GHASH block 8k+2, 8k+3 - mid
"       aese    "ctr7b", "rk1"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 1

// cycle 15
"       pmull   "h6".1q, "res2".1d, "h6".1d                         \n" // GHASH block 8k+2 - low
"       trn2    "res2".2d, "res3".2d, "res2".2d                     \n" // GHASH block 8k+2, 8k+3 - mid
"       pmull2  "acc_m".1q, "res0".2d, "h78k".2d                    \n" // GHASH block 8k   - mid

// cycle 16
"       ldp     "h3q", "h4q", [%[cc], #272]                         \n" // load h3l | h3h
"       pmull   "h78k".1q, "res0".1d, "h78k".1d                     \n" // GHASH block 8k+1 - mid
"       aese    "ctr6b", "rk1"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 1

// cycle 17
"       aese    "ctr4b", "rk1"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 1
"       aese    "ctr5b", "rk1"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 1
"       pmull   "h5".1q, "res3".1d, "h5".1d                         \n" // GHASH block 8k+3 - low

// cycle 18
"       aese    "ctr3b", "rk1"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 1
"       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 1
"       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 1

// cycle 19
"       aese    "ctr7b", "rk2"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 2
"       aese    "ctr2b", "rk2"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 2
"       eor3    "acc_lb", "acc_lb", "h6".16b, "h5".16b              \n" // GHASH block 8k+2, 8k+3 - low

// cycle 20
"       aese    "ctr4b", "rk2"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 2
"       eor     "res2".16b, "res2".16b, "t3".16b                    \n" // GHASH block 8k+2, 8k+3 - mid
"       ldp     "h1q", "h2q", [%[cc], #240]                         \n" // load h1l | h1h

// cycle 21
"       eor     "acc_mb", "acc_mb", "h78k".16b                      \n" // GHASH block 8k+1 - mid
"       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 2
"       aese    "ctr3b", "rk2"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 2

// cycle 22
"       trn1    "t6".2d, "res5".2d, "res4".2d                       \n" // GHASH block 8k+4, 8k+5 - mid
"       aese    "ctr5b", "rk2"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 2
"       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 2

// cycle 23
"       aese    "ctr6b", "rk2"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 2
"       pmull2  "t3".1q, "res2".2d, "h56k".2d                       \n" // GHASH block 8k+2 - mid
"       pmull   "h56k".1q, "res2".1d, "h56k".1d                     \n" // GHASH block 8k+3 - mid

// cycle 24
"       aese    "ctr7b", "rk3"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 3
"       rev64   "res7b", "res7b"                                    \n" // GHASH block 8k+7
"       pmull2  "t4".1q, "res4".2d, "h4".2d                         \n" // GHASH block 8k+4 - high

// cycle 25
"       ldp     "rk4q", "rk5q", [%[cc], #64]                        \n" // load rk4, rk5
"       pmull   "h4".1q, "res4".1d, "h4".1d                         \n" // GHASH block 8k+4 - low
"       eor3    "acc_mb", "acc_mb", "h56k".16b, "t3".16b            \n" // GHASH block 8k+2, 8k+3 - mid

// cycle 26
"       ldp     "h12kq", "h34kq", [%[cc], #368]                     \n" // load h2k | h1k
"       aese    "ctr2b", "rk3"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 3
"       trn2    "res4".2d, "res5".2d, "res4".2d                     \n" // GHASH block 8k+4, 8k+5 - mid

// cycle 27
"       aese    "ctr4b", "rk3"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 3
"       aese    "ctr3b", "rk3"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 3
"       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 3

// cycle 28
"       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 3
"       aese    "ctr6b", "rk3"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 3
"       aese    "ctr5b", "rk3"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 3

// cycle 29
"       pmull2  "t5".1q, "res5".2d, "h3".2d                         \n" // GHASH block 8k+5 - high
"       pmull   "h3".1q, "res5".1d, "h3".1d                         \n" // GHASH block 8k+5 - low
"       pmull2  "t7".1q, "res6".2d, "h2".2d                         \n" // GHASH block 8k+6 - high

// cycle 30
"       pmull   "h2".1q, "res6".1d, "h2".1d                         \n" // GHASH block 8k+6 - low
"       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 4
"       aese    "ctr7b", "rk4"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 4

// cycle 31
"       eor     "res4".16b, "res4".16b, "t6".16b                    \n" // GHASH block 8k+4, 8k+5 - mid
"       trn1    "t9".2d, "res7".2d, "res6".2d                       \n" // GHASH block 8k+6, 8k+7 - mid
"       aese    "ctr3b", "rk4"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 4

// cycle 32
"       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 4
"       aese    "ctr5b", "rk4"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 4
"       aese    "ctr6b", "rk4"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 4

// cycle 33
"       aese    "ctr2b", "rk4"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 4
"       aese    "ctr4b", "rk4"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 4
"       trn2    "res6".2d, "res7".2d, "res6".2d                     \n" // GHASH block 8k+6, 8k+7 - mid

// cycle 34
"       ldp     "rk6q", "rk7q", [%[cc], #96]                        \n" // load rk6, rk7
"       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 5
"       pmull2  "t6".1q, "res4".2d, "h34k".2d                       \n" // GHASH block 8k+4 - mid

// cycle 35
"       aese    "ctr2b", "rk5"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 5
"       eor     "res6".16b, "res6".16b, "t9".16b                    \n" // GHASH block 8k+6, 8k+7 - mid
"       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 5

// cycle 36
"       pmull   "h34k".1q, "res4".1d, "h34k".1d                     \n" // GHASH block 8k+5 - mid
"       aese    "ctr6b", "rk5"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 5
"       aese    "ctr7b", "rk5"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 5

// cycle 37
"       aese    "ctr3b", "rk5"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 5
"       aese    "ctr5b", "rk5"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 5
"       aese    "ctr4b", "rk5"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 5

// cycle 38
"       pmull2  "t8".1q, "res7".2d, "h1".2d                         \n" // GHASH block 8k+7 - high
"       eor3    "acc_mb", "acc_mb", "h34k".16b, "t6".16b            \n" // GHASH block 8k+4, 8k+5 - mid
"       eor3    "acc_lb", "acc_lb", "h4".16b, "h3".16b              \n" // GHASH block 8k+4, 8k+5 - low

// cycle 39
"       aese    "ctr3b", "rk6"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 6
"       eor3    "acc_hb", "acc_hb", "t4".16b, "t5".16b              \n" // GHASH block 8k+4, 8k+5 - high
"       aese    "ctr7b", "rk6"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 6

// cycle 40
"       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 6
"       pmull2  "t9".1q, "res6".2d, "h12k".2d                       \n" // GHASH block 8k+6 - mid
"       aese    "ctr6b", "rk6"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 6

// cycle 41
"       aese    "ctr2b", "rk6"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 6
"       aese    "ctr5b", "rk6"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 6
"       pmull   "h1".1q, "res7".1d, "h1".1d                         \n" // GHASH block 8k+7 - low

// cycle 42
"       pmull   "h12k".1q, "res6".1d, "h12k".1d                     \n" // GHASH block 8k+7 - mid
"       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 6
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+15

// cycle 43
"       eor3    "acc_hb", "acc_hb", "t7".16b, "t8".16b              \n" // GHASH block 8k+6, 8k+7 - high
"       aese    "ctr4b", "rk6"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 6
"       ldp     "rk8q", "rk9q", [%[cc], #128]                       \n" // load rk8, rk9

// cycle 44
"       ldr     "mod_constantd", [%[modulo_constant]]               \n" // MODULO - load modulo constant
"       eor3    "acc_lb", "acc_lb", "h2".16b, "h1".16b              \n" // GHASH block 8k+6, 8k+7 - low
"       aese    "ctr5b", "rk7"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 7

// cycle 45
"       rev32   "h1".16b, "rtmp_ctr".16b                            \n" // CTR block 8k+16
"       eor3    "acc_mb", "acc_mb", "h12k".16b, "t9".16b            \n" // GHASH block 8k+6, 8k+7 - mid
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+16

// cycle 46
"       aese    "ctr6b", "rk7"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 7
"       aese    "ctr3b", "rk7"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 7
"       aese    "ctr7b", "rk7"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 7

// cycle 47
"       aese    "ctr2b", "rk7"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 7
"       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 7
"       rev32   "h2".16b, "rtmp_ctr".16b                            \n" // CTR block 8k+17

// cycle 48
"       aese    "ctr4b", "rk7"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 7
"       ext     "t11".16b, "acc_hb", "acc_hb", #8                   \n" // MODULO - other top alignment
"       pmull   "t12".1q, "acc_h".1d, "mod_constant".1d             \n" // MODULO - top 64b align with mid

// cycle 49
"       eor3    "acc_mb", "acc_mb", "acc_hb", "acc_lb"              \n" // MODULO - karatsuba tidy up
"       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 7
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+17

// cycle 50
"       aese    "ctr5b", "rk8"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 8
"       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 8
"       ldp     "res0q", "res1q", [%[input_ptr]], #32               \n" // AES block 8k+8, 8k+9 - load ciphertext

// cycle 51
"       ldp     "res2q", "res3q", [%[input_ptr]], #32               \n" // AES block 8k+10, 8k+11 - load ciphertext
"       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 8
"       rev32   "h3".16b, "rtmp_ctr".16b                            \n" // CTR block 8k+18

// cycle 52
"       ldp     "res4q", "res5q", [%[input_ptr]], #32               \n" // AES block 8k+12, 8k+13 - load ciphertext
"       aese    "ctr4b", "rk8"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 8
"       eor3    "acc_mb", "acc_mb", "t12".16b, "t11".16b            \n" // MODULO - fold into mid

// cycle 53
"       ldp     "res6q", "res7q", [%[input_ptr]], #32               \n" // AES block 8k+14, 8k+15 - load ciphertext
"       aese    "ctr3b", "rk8"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 8
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+18

// cycle 54
"       aese    "ctr7b", "rk8"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 8
"       aese    "ctr2b", "rk8"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 8
"       aese    "ctr6b", "rk8"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 8

// cycle 55
"       aese    "ctr0b", "rk9"                                      \n" // AES block 8k+8 - round 9
"       aese    "ctr1b", "rk9"                                      \n" // AES block 8k+9 - round 9
"       ldr     "rk10q", [%[cc], #160]                              \n" // load rk10

// cycle 56
"       aese    "ctr6b", "rk9"                                      \n" // AES block 8k+14 - round 9
"       pmull   "acc_h".1q, "acc_m".1d, "mod_constant".1d           \n" // MODULO - mid 64b align with low
"       aese    "ctr2b", "rk9"                                      \n" // AES block 8k+10 - round 9

// cycle 57
"       aese    "ctr7b", "rk9"                                      \n" // AES block 8k+15 - round 9
"       aese    "ctr4b", "rk9"                                      \n" // AES block 8k+12 - round 9
"       ext     "t11".16b, "acc_mb", "acc_mb", #8                   \n" // MODULO - other mid alignment

// cycle 58
"       rev32   "h4".16b, "rtmp_ctr".16b                            \n" // CTR block 8k+19
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+19

// cycle 59
"       aese    "ctr3b", "rk9"                                      \n" // AES block 8k+11 - round 9
"       aese    "ctr5b", "rk9"                                      \n" // AES block 8k+13 - round 9
"       eor3    "ctr1b", "res1b", "ctr1b", "rk10"                   \n" // AES block 8k+9 - result

// cycle 60
"       eor3    "ctr0b", "res0b", "ctr0b", "rk10"                   \n" // AES block 8k+8 - result
"       eor3    "ctr7b", "res7b", "ctr7b", "rk10"                   \n" // AES block 8k+15 - result
"       eor3    "ctr6b", "res6b", "ctr6b", "rk10"                   \n" // AES block 8k+14 - result

// cycle 61
"       eor3    "ctr2b", "res2b", "ctr2b", "rk10"                   \n" // AES block 8k+10 - result
"       stp     "ctr0q", "ctr1q", [%[output_ptr]], #32              \n" // AES block 8k+8, 8k+9 - store result
"       mov     "ctr1".16b, "h2".16b                                \n" // CTR block 8k+17

// cycle 62
"       eor3    "ctr4b", "res4b", "ctr4b", "rk10"                   \n" // AES block 8k+12 - result
"       eor3    "acc_lb", "acc_lb", "acc_hb", "t11".16b             \n" // MODULO - fold into low
"       mov     "ctr0".16b, "h1".16b                                \n" // CTR block 8k+16

// cycle 63
"       eor3    "ctr3b", "res3b", "ctr3b", "rk10"                   \n" // AES block 8k+11 - result
"       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // LOOP CONTROL
"       stp     "ctr2q", "ctr3q", [%[output_ptr]], #32              \n" // AES block 8k+10, 8k+11 - store result

// cycle 64
"       eor3    "ctr5b", "res5b", "ctr5b", "rk10"                   \n" // AES block 8k+13 - result
"       mov     "ctr2".16b, "h3".16b                                \n" // CTR block 8k+18

// cycle 65
"       stp     "ctr4q", "ctr5q", [%[output_ptr]], #32              \n" // AES block 8k+12, 8k+13 - store result
"       rev32   "ctr4".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+20
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+20

// cycle 66
"       stp     "ctr6q", "ctr7q", [%[output_ptr]], #32              \n" // AES block 8k+14, 8k+15 - store result
"       mov     "ctr3".16b, "h4".16b                                \n" // CTR block 8k+19
"       b.lt    1b                                                  \n"

// cycle 0
"7:                                                                 \n" // PREPRETAIL
"       rev64   "res3b", "res3b"                                    \n" // GHASH block 8k+3
"       ext     "acc_lb", "acc_lb", "acc_lb", #8                    \n" // PRE 0
"       rev64   "res0b", "res0b"                                    \n" // GHASH block 8k

// cycle 1
"       rev64   "res2b", "res2b"                                    \n" // GHASH block 8k+2
"       rev32   "ctr5".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+13
"       ldp     "rk0q", "rk1q", [%[cc], #0]                         \n" // load rk0, rk1

// cycle 2
"       ldp     "h7q", "h8q", [%[cc], #336]                         \n" // load h7l | h7h
"       eor     "res0b", "res0b", "acc_lb"                          \n" // PRE 1
"       rev64   "res1b", "res1b"                                    \n" // GHASH block 8k+1

// cycle 3
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+13
"       ldp     "h5q", "h6q", [%[cc], #304]                         \n" // load h5l | h5h
"       rev64   "res5b", "res5b"                                    \n" // GHASH block 8k+5

// cycle 4
"       rev64   "res4b", "res4b"                                    \n" // GHASH block 8k+4

// cycle 5
"       rev64   "res6b", "res6b"                                    \n" // GHASH block 8k+6

// cycle 6
"       ldp     "h56kq", "h78kq", [%[cc], #400]                     \n" // load h6k | h5k
"       rev32   "ctr6".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+14
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+14

// cycle 7
"       pmull2  "t0".1q, "res1".2d, "h7".2d                         \n" // GHASH block 8k+1 - high
"       pmull   "acc_l".1q, "res0".1d, "h8".1d                      \n" // GHASH block 8k - low
"       pmull2  "acc_h".1q, "res0".2d, "h8".2d                      \n" // GHASH block 8k - high

// cycle 8
"       trn1    "acc_m".2d, "res1".2d, "res0".2d                    \n" // GHASH block 8k, 8k+1 - mid
"       trn2    "res0".2d, "res1".2d, "res0".2d                     \n" // GHASH block 8k, 8k+1 - mid
"       pmull2  "t1".1q, "res2".2d, "h6".2d                         \n" // GHASH block 8k+2 - high

// cycle 9
"       pmull   "h7".1q, "res1".1d, "h7".1d                         \n" // GHASH block 8k+1 - low
"       pmull2  "t2".1q, "res3".2d, "h5".2d                         \n" // GHASH block 8k+3 - high
"       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 0

// cycle 10
"       eor     "acc_hb", "acc_hb", "t0".16b                        \n" // GHASH block 8k+1 - high
"       aese    "ctr4b", "rk0"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 0
"       eor     "res0".16b, "res0".16b, "acc_m".16b                 \n" // GHASH block 8k, 8k+1 - mid

// cycle 11
"       pmull   "h6".1q, "res2".1d, "h6".1d                         \n" // GHASH block 8k+2 - low
"       rev32   "ctr7".16b, "rtmp_ctr".16b                          \n" // CTR block 8k+15
"       aese    "ctr3b", "rk0"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 0

// cycle 12
"       eor3    "acc_hb", "acc_hb", "t1".16b, "t2".16b              \n" // GHASH block 8k+2, 8k+3 - high
"       trn1    "t3".2d, "res3".2d, "res2".2d                       \n" // GHASH block 8k+2, 8k+3 - mid
"       trn2    "res2".2d, "res3".2d, "res2".2d                     \n" // GHASH block 8k+2, 8k+3 - mid

// cycle 13
"       aese    "ctr2b", "rk0"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 0
"       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 0
"       aese    "ctr5b", "rk0"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 0

// cycle 14
"       pmull2  "acc_m".1q, "res0".2d, "h78k".2d                    \n" // GHASH block 8k   - mid
"       pmull   "h78k".1q, "res0".1d, "h78k".1d                     \n" // GHASH block 8k+1 - mid
"       pmull   "h5".1q, "res3".1d, "h5".1d                         \n" // GHASH block 8k+3 - low

// cycle 15
"       aese    "ctr2b", "rk1"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 1
"       aese    "ctr7b", "rk0"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 0
"       aese    "ctr6b", "rk0"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 0

// cycle 16
"       eor     "acc_lb", "acc_lb", "h7".16b                        \n" // GHASH block 8k+1 - low
"       eor     "res2".16b, "res2".16b, "t3".16b                    \n" // GHASH block 8k+2, 8k+3 - mid
"       eor     "acc_mb", "acc_mb", "h78k".16b                      \n" // GHASH block 8k+1 - mid

// cycle 17
"       aese    "ctr6b", "rk1"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 1
"       aese    "ctr4b", "rk1"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 1
"       aese    "ctr5b", "rk1"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 1

// cycle 18
"       ldp     "rk2q", "rk3q", [%[cc], #32]                        \n" // load rk2, rk3
"       eor3    "acc_lb", "acc_lb", "h6".16b, "h5".16b              \n" // GHASH block 8k+2, 8k+3 - low
"       pmull2  "t3".1q, "res2".2d, "h56k".2d                       \n" // GHASH block 8k+2 - mid

// cycle 19
"       ldp     "h3q", "h4q", [%[cc], #272]                         \n" // load h3l | h3h
"       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 1
"       pmull   "h56k".1q, "res2".1d, "h56k".1d                     \n" // GHASH block 8k+3 - mid

// cycle 20
"       aese    "ctr3b", "rk1"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 1
"       aese    "ctr7b", "rk1"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 1
"       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 1

// cycle 21
"       ldp     "h1q", "h2q", [%[cc], #240]                         \n" // load h1l | h1h
"       eor3    "acc_mb", "acc_mb", "h56k".16b, "t3".16b            \n" // GHASH block 8k+2, 8k+3 - mid

// cycle 23
"       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 2
"       aese    "ctr6b", "rk2"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 2
"       aese    "ctr2b", "rk2"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 2

// cycle 24
"       aese    "ctr4b", "rk2"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 2
"       trn1    "t6".2d, "res5".2d, "res4".2d                       \n" // GHASH block 8k+4, 8k+5 - mid
"       aese    "ctr7b", "rk2"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 2

// cycle 25
"       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 2
"       aese    "ctr5b", "rk2"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 2
"       aese    "ctr3b", "rk2"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 2

// cycle 26
"       pmull2  "t4".1q, "res4".2d, "h4".2d                         \n" // GHASH block 8k+4 - high
"       pmull   "h4".1q, "res4".1d, "h4".1d                         \n" // GHASH block 8k+4 - low
"       trn2    "res4".2d, "res5".2d, "res4".2d                     \n" // GHASH block 8k+4, 8k+5 - mid

// cycle 27
"       ldp     "rk4q", "rk5q", [%[cc], #64]                        \n" // load rk4, rk5
"       rev64   "res7b", "res7b"                                    \n" // GHASH block 8k+7
"       aese    "ctr6b", "rk3"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 3

// cycle 28
"       ldp     "h12kq", "h34kq", [%[cc], #368]                     \n" // load h2k | h1k
"       pmull2  "t5".1q, "res5".2d, "h3".2d                         \n" // GHASH block 8k+5 - high
"       pmull   "h3".1q, "res5".1d, "h3".1d                         \n" // GHASH block 8k+5 - low

// cycle 29
"       aese    "ctr2b", "rk3"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 3
"       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 3
"       trn1    "t9".2d, "res7".2d, "res6".2d                       \n" // GHASH block 8k+6, 8k+7 - mid

// cycle 30
"       pmull2  "t7".1q, "res6".2d, "h2".2d                         \n" // GHASH block 8k+6 - high
"       pmull   "h2".1q, "res6".1d, "h2".1d                         \n" // GHASH block 8k+6 - low
"       trn2    "res6".2d, "res7".2d, "res6".2d                     \n" // GHASH block 8k+6, 8k+7 - mid

// cycle 31
"       aese    "ctr4b", "rk3"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 3
"       aese    "ctr3b", "rk3"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 3
"       aese    "ctr7b", "rk3"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 3

// cycle 32
"       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 3
"       aese    "ctr5b", "rk3"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 3
"       eor     "res4".16b, "res4".16b, "t6".16b                    \n" // GHASH block 8k+4, 8k+5 - mid

// cycle 33
"       eor3    "acc_hb", "acc_hb", "t4".16b, "t5".16b              \n" // GHASH block 8k+4, 8k+5 - high
"       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 4
"       aese    "ctr2b", "rk4"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 4

// cycle 34
"       eor     "res6".16b, "res6".16b, "t9".16b                    \n" // GHASH block 8k+6, 8k+7 - mid
"       aese    "ctr5b", "rk4"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 4
"       pmull2  "t6".1q, "res4".2d, "h34k".2d                       \n" // GHASH block 8k+4 - mid

// cycle 35
"       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 4
"       aese    "ctr6b", "rk4"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 4
"       aese    "ctr4b", "rk4"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 4

// cycle 36
"       aese    "ctr7b", "rk4"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 4
"       aese    "ctr3b", "rk4"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 4
"       pmull   "h34k".1q, "res4".1d, "h34k".1d                     \n" // GHASH block 8k+5 - mid

// cycle 37
"       pmull2  "t8".1q, "res7".2d, "h1".2d                         \n" // GHASH block 8k+7 - high
"       pmull2  "t9".1q, "res6".2d, "h12k".2d                       \n" // GHASH block 8k+6 - mid
"       pmull   "h12k".1q, "res6".1d, "h12k".1d                     \n" // GHASH block 8k+7 - mid

// cycle 38
"       ldp     "rk6q", "rk7q", [%[cc], #96]                        \n" // load rk6, rk7
"       eor3    "acc_mb", "acc_mb", "h34k".16b, "t6".16b            \n" // GHASH block 8k+4, 8k+5 - mid
"       aese    "ctr6b", "rk5"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 5

// cycle 39
"       ldr     "mod_constantd", [%[modulo_constant]]               \n" // MODULO - load modulo constant
"       pmull   "h1".1q, "res7".1d, "h1".1d                         \n" // GHASH block 8k+7 - low
"       eor3    "acc_lb", "acc_lb", "h4".16b, "h3".16b              \n" // GHASH block 8k+4, 8k+5 - low

// cycle 40
"       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 5
"       aese    "ctr2b", "rk5"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 5
"       aese    "ctr4b", "rk5"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 5

// cycle 41
"       aese    "ctr3b", "rk5"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 5
"       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 5
"       aese    "ctr5b", "rk5"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 5

// cycle 42
"       aese    "ctr7b", "rk5"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 5
"       eor3    "acc_mb", "acc_mb", "h12k".16b, "t9".16b            \n" // GHASH block 8k+6, 8k+7 - mid
"       eor3    "acc_lb", "acc_lb", "h2".16b, "h1".16b              \n" // GHASH block 8k+6, 8k+7 - low

// cycle 43
"       aese    "ctr4b", "rk6"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 6
"       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 6
"       aese    "ctr2b", "rk6"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 6

// cycle 44
"       eor3    "acc_hb", "acc_hb", "t7".16b, "t8".16b              \n" // GHASH block 8k+6, 8k+7 - high
"       aese    "ctr5b", "rk6"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 6
"       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 6

// cycle 45
"       aese    "ctr3b", "rk6"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 6
"       aese    "ctr6b", "rk6"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 6
"       aese    "ctr7b", "rk6"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 6

// cycle 46
"       aese    "ctr4b", "rk7"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 7
"       eor3    "acc_mb", "acc_mb", "acc_hb", "acc_lb"              \n" // MODULO - karatsuba tidy up
"       ldp     "rk8q", "rk9q", [%[cc], #128]                       \n" // load rk8, rk9

// cycle 47
"       pmull   "t12".1q, "acc_h".1d, "mod_constant".1d             \n" // MODULO - top 64b align with mid
"       aese    "ctr3b", "rk7"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 7
"       ext     "t11".16b, "acc_hb", "acc_hb", #8                   \n" // MODULO - other top alignment

// cycle 48
"       aese    "ctr5b", "rk7"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 7
"       aese    "ctr6b", "rk7"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 7
"       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 7

// cycle 49
"       aese    "ctr7b", "rk7"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 7
"       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 7
"       aese    "ctr2b", "rk7"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 7

// cycle 50
"       eor3    "acc_mb", "acc_mb", "t12".16b, "t11".16b            \n" // MODULO - fold into mid
"       ldr     "rk10q", [%[cc], #160]                              \n" // load rk10

// cycle 51
"       aese    "ctr3b", "rk8"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 8k+11 - round 8
"       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 8k+8 - round 8

// cycle 52
"       pmull   "acc_h".1q, "acc_m".1d, "mod_constant".1d           \n" // MODULO - mid 64b align with low
"       aese    "ctr6b", "rk8"   \n  aesmc   "ctr6b", "ctr6b"       \n" // AES block 8k+14 - round 8
"       ext     "t11".16b, "acc_mb", "acc_mb", #8                   \n" // MODULO - other mid alignment

// cycle 53
"       aese    "ctr2b", "rk8"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 8k+10 - round 8
"       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 8k+9 - round 8
"       aese    "ctr7b", "rk8"   \n  aesmc   "ctr7b", "ctr7b"       \n" // AES block 8k+15 - round 8

// cycle 54
"       aese    "ctr6b", "rk9"                                      \n" // AES block 8k+14 - round 9
"       aese    "ctr5b", "rk8"   \n  aesmc   "ctr5b", "ctr5b"       \n" // AES block 8k+13 - round 8
"       aese    "ctr4b", "rk8"   \n  aesmc   "ctr4b", "ctr4b"       \n" // AES block 8k+12 - round 8

// cycle 55
"       eor3    "acc_lb", "acc_lb", "acc_hb", "t11".16b             \n" // MODULO - fold into low
"       add     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n" // CTR block 8k+15
"       aese    "ctr2b", "rk9"                                      \n" // AES block 8k+10 - round 9

// cycle 56
"       aese    "ctr3b", "rk9"                                      \n" // AES block 8k+11 - round 9
"       aese    "ctr5b", "rk9"                                      \n" // AES block 8k+13 - round 9
"       aese    "ctr0b", "rk9"                                      \n" // AES block 8k+8 - round 9

// cycle 57
"       aese    "ctr4b", "rk9"                                      \n" // AES block 8k+12 - round 9
"       aese    "ctr1b", "rk9"                                      \n" // AES block 8k+9 - round 9
"       aese    "ctr7b", "rk9"                                      \n" // AES block 8k+15 - round 9

// cycle 58
"2:                                                                 \n" // TAIL

// cycle 0
"       mov     "t1".16b, "rk10"                                    \n"
"       sub     "main_end_input_ptr", "end_input_ptr", %[input_ptr] \n" // main_end_input_ptr is number of bytes left to process

// cycle 1
"       cmp     "main_end_input_ptr", #112                          \n"

// cycle 2
"       ldr     "h8q", [%[cc], #352]                                \n" // load h8l | h8h
"       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES block 8k+8 - load ciphertext

// cycle 3
"       ldr     "h5q", [%[cc], #304]                                \n" // load h5l | h5h
"       ext     "t0".16b, "acc_lb", "acc_lb", #8                    \n" // prepare final partial tag
"       ldr     "h56kq", [%[cc], #400]                              \n" // load h6k | h5k

// cycle 4
"       ldr     "h7q", [%[cc], #336]                                \n" // load h7l | h7h
"       ldr     "h78kq", [%[cc], #416]                              \n" // load h8k | h7k

// cycle 5
"       ldr     "h6q", [%[cc], #320]                                \n" // load h6l | h6h

// cycle 6
"       eor3    "res4b", "res1b", "ctr0b", "t1".16b                 \n" // AES block 8k+8 - result
"       b.gt    8f                                                  \n"

// cycle 0
"       cmp     "main_end_input_ptr", #96                           \n"
"       mov     "ctr7b", "ctr6b"                                    \n"
"       movi    "acc_l".8b, #0                                      \n"

// cycle 1
"       movi    "acc_h".8b, #0                                      \n"
"       mov     "ctr6b", "ctr5b"                                    \n"
"       mov     "ctr5b", "ctr4b"                                    \n"

// cycle 2
"       mov     "ctr4b", "ctr3b"                                    \n"
"       mov     "ctr3b", "ctr2b"                                    \n"
"       mov     "ctr2b", "ctr1b"                                    \n"

// cycle 3
"       movi    "acc_m".8b, #0                                      \n"
"       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
"       b.gt    9f                                                  \n"

// cycle 0
"       cmp     "main_end_input_ptr", #80                           \n"
"       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"

// cycle 1
"       mov     "ctr7b", "ctr6b"                                    \n"
"       mov     "ctr6b", "ctr5b"                                    \n"
"       mov     "ctr5b", "ctr4b"                                    \n"

// cycle 2
"       mov     "ctr4b", "ctr3b"                                    \n"
"       mov     "ctr3b", "ctr1b"                                    \n"
"       b.gt    10f                                                 \n"

// cycle 0
"       cmp     "main_end_input_ptr", #64                           \n"

// cycle 1
"       mov     "ctr7b", "ctr6b"                                    \n"
"       mov     "ctr6b", "ctr5b"                                    \n"
"       mov     "ctr5b", "ctr4b"                                    \n"

// cycle 2
"       mov     "ctr4b", "ctr1b"                                    \n"
"       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
"       b.gt    11f                                                 \n"

// cycle 0
"       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
"       mov     "ctr7b", "ctr6b"                                    \n"
"       mov     "ctr6b", "ctr5b"                                    \n"

// cycle 1
"       mov     "ctr5b", "ctr1b"                                    \n"
"       cmp     "main_end_input_ptr", #48                           \n"
"       b.gt    3f                                                  \n"

// cycle 0
"       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
"       mov     "ctr7b", "ctr6b"                                    \n"
"       cmp     "main_end_input_ptr", #32                           \n"

// cycle 1
"       ldr     "h34kq", [%[cc], #384]                              \n" // load h4k | h3k
"       mov     "ctr6b", "ctr1b"                                    \n"
"       b.gt    4f                                                  \n"

// cycle 0
"       cmp     "main_end_input_ptr", #16                           \n"

// cycle 1
"       mov     "ctr7b", "ctr1b"                                    \n"
"       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
"       b.gt    5f                                                  \n"

// cycle 0
"       sub     "rtmp_ctr".4s, "rtmp_ctr".4s, "rctr_inc".4s         \n"
"       ldr     "h12kq", [%[cc], #368]                              \n" // load h2k | h1k
"       b       6f                                                  \n"
"8:                                                                 \n" // blocks left >  7
"       rev64   "res0b", "res1b"                                    \n" // GHASH final-7 block

// cycle 2
"       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag

// cycle 3
"       ins     "acc_m".d[0], "h78k".d[1]                           \n" // GHASH final-7 block - mid

// cycle 4
"       pmull   "acc_l".1q, "res0".1d, "h8".1d                      \n" // GHASH final-7 block - low
"       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-7 block - mid

// cycle 5
"       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in
"       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final-6 block - load ciphertext

// cycle 7
"       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-7 block - mid

// cycle 9
"       pmull2  "acc_h".1q, "res0".2d, "h8".2d                      \n" // GHASH final-7 block - high
"       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-7 block  - store result
"       eor3    "res4b", "res1b", "ctr1b", "t1".16b                 \n" // AES final-6 block - result

// cycle 10
"       pmull   "acc_m".1q, "rk4v".1d, "acc_m".1d                   \n" // GHASH final-7 block - mid
"9:                                                                 \n" // blocks left >  6

// cycle 0
"       rev64   "res0b", "res1b"                                    \n" // GHASH final-6 block

// cycle 2
"       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag

// cycle 4
"       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-6 block - mid

// cycle 7
"       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-6 block - mid

// cycle 8
"       pmull   "rk3q1", "res0".1d, "h7".1d                         \n" // GHASH final-6 block - low
"       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final-5 block - load ciphertext
"       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

// cycle 9
"       pmull   "rk4v".1q, "rk4v".1d, "h78k".1d                     \n" // GHASH final-6 block - mid
"       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-6 block - store result
"       pmull2  "rk2q1", "res0".2d, "h7".2d                         \n" // GHASH final-6 block - high

// cycle 11
"       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-6 block - low
"       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-6 block - high

// cycle 12
"       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-6 block - mid
"       eor3    "res4b", "res1b", "ctr2b", "t1".16b                 \n" // AES final-5 block - result
"10:                                                                \n" // blocks left >  5

// cycle 0
"       rev64   "res0b", "res1b"                                    \n" // GHASH final-5 block

// cycle 1
"       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final-4 block - load ciphertext
"       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-5 block - store result

// cycle 2
"       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag

// cycle 4
"       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-5 block - mid

// cycle 6
"       eor3    "res4b", "res1b", "ctr3b", "t1".16b                 \n" // AES final-4 block - result

// cycle 7
"       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-5 block - mid

// cycle 9
"       ins     "rk4v".d[1], "rk4v".d[0]                            \n" // GHASH final-5 block - mid
"       pmull   "rk3q1", "res0".1d, "h6".1d                         \n" // GHASH final-5 block - low
"       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

// cycle 12
"       pmull2  "rk4v".1q, "rk4v".2d, "h56k".2d                     \n" // GHASH final-5 block - mid
"       pmull2  "rk2q1", "res0".2d, "h6".2d                         \n" // GHASH final-5 block - high
"       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-5 block - low

// cycle 14
"       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-5 block - mid
"       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-5 block - high
"11:                                                                \n" // blocks left >  4

// cycle 0
"       rev64   "res0b", "res1b"                                    \n" // GHASH final-4 block

// cycle 2
"       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
"       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final-3 block - load ciphertext

// cycle 4
"       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-4 block - mid
"       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in
"       pmull2  "rk2q1", "res0".2d, "h5".2d                         \n" // GHASH final-4 block - high

// cycle 5
"       pmull   "rk3q1", "res0".1d, "h5".1d                         \n" // GHASH final-4 block - low

// cycle 6
"       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-4 block - high

// cycle 7
"       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-4 block - store result
"       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-4 block - mid

// cycle 8
"       eor3    "res4b", "res1b", "ctr4b", "t1".16b                 \n" // AES final-3 block - result
"       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-4 block - low

// cycle 9
"       pmull   "rk4v".1q, "rk4v".1d, "h56k".1d                     \n" // GHASH final-4 block - mid

// cycle 11
"       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-4 block - mid
"3:                                                                 \n" // blocks left >  3

// cycle 0
"       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-3 block - store result
"       rev64   "res0b", "res1b"                                    \n" // GHASH final-3 block

// cycle 2
"       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag

// cycle 4
"       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-3 block - mid

// cycle 6
"       ldr     "h4q", [%[cc], #288]                                \n" // load h4l | h4h
"       ldr     "h34kq", [%[cc], #384]                              \n" // load h4k | h3k

// cycle 7
"       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-3 block - mid

// cycle 8
"       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final-2 block - load ciphertext

// cycle 10
"       ins     "rk4v".d[1], "rk4v".d[0]                            \n" // GHASH final-3 block - mid
"       pmull   "rk3q1", "res0".1d, "h4".1d                         \n" // GHASH final-3 block - low
"       pmull2  "rk2q1", "res0".2d, "h4".2d                         \n" // GHASH final-3 block - high

// cycle 12
"       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in
"       eor3    "res4b", "res1b", "ctr5b", "t1".16b                 \n" // AES final-2 block - result
"       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-3 block - low

// cycle 13
"       pmull2  "rk4v".1q, "rk4v".2d, "h34k".2d                     \n" // GHASH final-3 block - mid

// cycle 15
"       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-3 block - high
"       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-3 block - mid
"4:                                                                 \n" // blocks left >  2

// cycle 0
"       rev64   "res0b", "res1b"                                    \n" // GHASH final-2 block

// cycle 1
"       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-2 block - store result

// cycle 2
"       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
"       ldr     "h3q", [%[cc], #272]                                \n" // load h3l | h3h
"       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

// cycle 4
"       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-2 block - mid

// cycle 7
"       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-2 block - mid

// cycle 8
"       pmull   "rk3q1", "res0".1d, "h3".1d                         \n" // GHASH final-2 block - low

// cycle 9
"       pmull2  "rk2q1", "res0".2d, "h3".2d                         \n" // GHASH final-2 block - high
"       pmull   "rk4v".1q, "rk4v".1d, "h34k".1d                     \n" // GHASH final-2 block - mid
"       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final-1 block - load ciphertext

// cycle 11
"       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-2 block - mid

// cycle 12
"       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-2 block - low

// cycle 13
"       eor3    "res4b", "res1b", "ctr6b", "t1".16b                 \n" // AES final-1 block - result
"       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-2 block - high
"5:                                                                 \n" // blocks left >  1

// cycle 0
"       st1     { "res4b" }, [%[output_ptr]], #16                   \n" // AES final-1 block - store result
"       rev64   "res0b", "res1b"                                    \n" // GHASH final-1 block

// cycle 1
"       ldr     "h2q", [%[cc], #256]                                \n" // load h2l | h2h

// cycle 2
"       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag

// cycle 3
"       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

// cycle 4
"       ins     "rk4v".d[0], "res0".d[1]                            \n" // GHASH final-1 block - mid

// cycle 5
"       ldr     "res1q", [%[input_ptr]], #16                        \n" // AES final block - load ciphertext
"       pmull2  "rk2q1", "res0".2d, "h2".2d                         \n" // GHASH final-1 block - high

// cycle 7
"       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-1 block - mid
"       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-1 block - high
"       ldr     "h12kq", [%[cc], #368]                              \n" // load h2k | h1k

// cycle 9
"       ins     "rk4v".d[1], "rk4v".d[0]                            \n" // GHASH final-1 block - mid
"       eor3    "res4b", "res1b", "ctr7b", "t1".16b                 \n" // AES final block - result

// cycle 11
"       pmull   "rk3q1", "res0".1d, "h2".1d                         \n" // GHASH final-1 block - low

// cycle 12
"       pmull2  "rk4v".1q, "rk4v".2d, "h12k".2d                     \n" // GHASH final-1 block - mid

// cycle 13
"       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-1 block - low

// cycle 14
"       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-1 block - mid
"6:                                                                 \n" // blocks left <= 1

// cycle 0
"       and     %[bit_length], %[bit_length], #127                  \n" // bit_length %= 128

// cycle 1
"       sub     %[bit_length], %[bit_length], #128                  \n" // bit_length -= 128

// cycle 2
"       neg     %[bit_length], %[bit_length]                        \n" // bit_length = 128 - #bits in input (in range [1,128])

// cycle 3
"       mvn     "temp0_x", xzr                                      \n" // temp0_x = 0xffffffffffffffff
"       and     %[bit_length], %[bit_length], #127                  \n" // bit_length %= 128

// cycle 4
"       lsr     "temp0_x", "temp0_x", %[bit_length]                 \n" // temp0_x is mask for top 64b of last block
"       cmp     %[bit_length], #64                                  \n"
"       mvn     "temp1_x", xzr                                      \n" // temp1_x = 0xffffffffffffffff

// cycle 5
"       csel    "temp2_x", "temp1_x", "temp0_x", lt                 \n"
"       csel    "temp3_x", "temp0_x", xzr, lt                       \n"

// cycle 6
"       mov     "ctr0".d[1], "temp3_x"                              \n"
"       mov     "ctr0".d[0], "temp2_x"                              \n" // ctr0b is mask for last block

// cycle 8
"       ldr     "h1q", [%[cc], #240]                                \n" // load h1l | h1h
"       ld1     { "rk0" }, [%[output_ptr]]                          \n" // load existing bytes where the possibly partial last block is to be stored

// cycle 14
"       and     "res1b", "res1b", "ctr0b"                           \n" // possibly partial last block has zeroes in highest bits

// cycle 16
"       rev64   "res0b", "res1b"                                    \n" // GHASH final block

// cycle 18
"       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag

// cycle 20
"       pmull2  "rk2q1", "res0".2d, "h1".2d                         \n" // GHASH final block - high
"       ins     "t0".d[0], "res0".d[1]                              \n" // GHASH final block - mid

// cycle 23
"       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final block - high
"       eor     "t0".8b, "t0".8b, "res0".8b                         \n" // GHASH final block - mid

// cycle 24
"       bif     "res4b", "rk0", "ctr0b"                             \n" // insert existing bytes in top end of result before storing

// cycle 25
"       pmull   "t0".1q, "t0".1d, "h12k".1d                         \n" // GHASH final block - mid
"       st1     { "res4b" }, [%[output_ptr]]                        \n" // store all 16B

// cycle 26
"       pmull   "rk3q1", "res0".1d, "h1".1d                         \n" // GHASH final block - low

// cycle 27
"       eor     "acc_mb", "acc_mb", "t0".16b                        \n" // GHASH final block - mid
"       ldr     "mod_constantd", [%[modulo_constant]]               \n" // MODULO - load modulo constant

// cycle 28
"       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final block - low

// cycle 30
"       eor     "t10".16b, "acc_hb", "acc_lb"                       \n" // MODULO - karatsuba tidy up

// cycle 31
"       pmull   "t11".1q, "acc_h".1d, "mod_constant".1d             \n" // MODULO - top 64b align with mid
"       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n" // MODULO - other top alignment

// cycle 32
"       eor     "acc_mb", "acc_mb", "t10".16b                       \n" // MODULO - karatsuba tidy up

// cycle 33
"       eor     "t11".16b, "acc_hb", "t11".16b                      \n" // MODULO - fold into mid

// cycle 35
"       eor     "acc_mb", "acc_mb", "t11".16b                       \n" // MODULO - fold into mid

// cycle 37
"       pmull   "acc_h".1q, "acc_m".1d, "mod_constant".1d           \n" // MODULO - mid 64b align with low
"       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n" // MODULO - other mid alignment

// cycle 39
"       eor     "acc_lb", "acc_lb", "acc_hb"                        \n" // MODULO - fold into low

// cycle 41
"       eor     "acc_lb", "acc_lb", "acc_mb"                        \n" // MODULO - fold into low
"       st1     { "acc_l".16b }, [%[current_tag]]                   \n"
"       rev32   "rtmp_ctr".16b, "rtmp_ctr".16b                      \n"

// cycle 42
"       str     "rtmp_ctrq", [%[counter]]                           \n" // store the updated counter


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