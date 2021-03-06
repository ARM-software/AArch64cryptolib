//Copyright (c) 2018-2019, ARM Limited. All rights reserved.
//
//SPDX-License-Identifier:        BSD-3-Clause

/*
Approach - assume we don't want to reload constants, so reserve ~half of vector register file for constants

main loop to act on 4 16B blocks per iteration, and then do modulo of the accumulated intermediate hashes from the 4 blocks

 ____________________________________________________
|                                                    |
| PRE                                                |
|____________________________________________________|
|                |                |                  |
| CTR block 4k+8 | AES block 4k+4 | GHASH block 4k+0 |
|________________|________________|__________________|
|                |                |                  |
| CTR block 4k+9 | AES block 4k+5 | GHASH block 4k+1 |
|________________|________________|__________________|
|                |                |                  |
| CTR block 4k+10| AES block 4k+6 | GHASH block 4k+2 |
|________________|________________|__________________|
|                |                |                  |
| CTR block 4k+11| AES block 4k+7 | GHASH block 4k+3 |
|________________|____(mostly)____|__________________|
|                                                    |
| MODULO                                             |
|____________________________________________________|

PRE:
        Ensure previous generated intermediate hash is aligned and merged with result for GHASH 4k+0
    EXT low_acc, low_acc, low_acc, #8
    EOR res_curr (4k+0), res_curr (4k+0), low_acc   // needs merging after res_curr has been byte reversed

CTR block:
        Increment and byte reverse counter in scalar registers and transfer to SIMD registers
    REV     ctr32, rev_ctr32
    ORR     ctr64, constctr96_top32, ctr32, LSL #32
    INS     ctr_next.d[0], constctr96_bottom64      // Keeping this in scalar registers to free up space in SIMD RF
    INS     ctr_next.d[1], ctr64X
    ADD     rev_ctr32, #1

AES block:
        Do AES encryption on CTR block X and EOR it with input block X
        Doing small trick here of loading input in scalar registers, EORing with last key and then transferring
        Given we are very constrained in our ASIMD registers this is quite important
    LDR     input_low, [ input_ptr ], #8
    LDR     input_high, [ input_ptr ], #8
    EOR     input_low, k10_low
    EOR     input_high, k10_high
    INS     res_curr.d[0], input_low
    INS     res_curr.d[1], input_high
    AESE    ctr_curr, k0; AESMC ctr_curr, ctr_curr
    AESE    ctr_curr, k1; AESMC ctr_curr, ctr_curr
    AESE    ctr_curr, k2; AESMC ctr_curr, ctr_curr
    AESE    ctr_curr, k3; AESMC ctr_curr, ctr_curr
    AESE    ctr_curr, k4; AESMC ctr_curr, ctr_curr
    AESE    ctr_curr, k5; AESMC ctr_curr, ctr_curr
    AESE    ctr_curr, k6; AESMC ctr_curr, ctr_curr
    AESE    ctr_curr, k7; AESMC ctr_curr, ctr_curr
    AESE    ctr_curr, k8; AESMC ctr_curr, ctr_curr
    AESE    ctr_curr, k9
    EOR     res_curr, res_curr, ctr_curr
    ST1     { res_curr.16b }, [ output_ptr ], #16

GHASH block X:
        do 128b karatsuba polynomial multiplication on block

        We only have 64b->128b polynomial multipliers, naively that means we need to do 4 64b multiplies to generate a 128b multiplication:
            Pmull(A,B) == (Pmull(Ah,Bh)<<128 | Pmull(Al,Bl)) ^ (Pmull(Ah,Bl) ^ Pmull(Al,Bh))<<64

        The idea behind Karatsuba multiplication is that we can do just 3 64b multiplies:
            Pmull(A,B) == (Pmull(Ah,Bh)<<128 | Pmull(Al,Bl)) ^ (Pmull(Ah^Al,Bh^Bl) ^ Pmull(Ah,Bh) ^ Pmull(Al,Bl))<<64

        There is some complication here because the bit order of GHASH's PMULL is reversed compared to elsewhere, so we are multiplying with "twisted" powers of H

        Note: We can PMULL directly into the acc_x in first GHASH of the loop
        Note: For scheduling big cores we want to split the processing to happen over two loop iterations - otherwise the critical path latency dominates the performance
              This has a knock on effect on register pressure, so we have to be a bit more clever with our temporary registers than indicated here
    REV64   res_curr, res_curr
    INS     t_m.d[0], res_curr.d[1]
    EOR     t_m.8B, t_m.8B, res_curr.8B
    PMULL2  t_h, res_curr, HX
    PMULL   t_l, res_curr, HX
    PMULL   t_m, t_m, HX_k
    EOR     acc_h, acc_h, t_h
    EOR     acc_l, acc_l, t_l
    EOR     acc_m, acc_m, t_m

MODULO: take the partial accumulators (~representing sum of 256b multiplication results), from GHASH and do modulo reduction on them

        There is some complication here because the bit order of GHASH's PMULL is reversed compared to elsewhere, so we are doing modulo with a reversed constant
    EOR     acc_m, acc_m, acc_h
    EOR     acc_m, acc_m, acc_l                     // Finish off karatsuba processing
    PMULL   t_mod, acc_h, mod_constant
    EXT     acc_h, acc_h, acc_h, #8
    EOR     acc_m, acc_m, acc_h
    EOR     acc_m, acc_m, t_mod
    PMULL   acc_h, acc_m, mod_constant
    EXT     acc_m, acc_m, acc_m, #8
    EOR     acc_l, acc_l, acc_h
    EOR     acc_l, acc_l, acc_m

Scalar RF:
x0  input_ptr   //expected - will use asm input operand
x1  bit_length  //expected - will use asm input
x2  cs_ptr      //expected - will use asm input
x3  output_ptr  //expected - will use asm input
x4  end_input_ptr       // start_input_ptr + (bit_length >> 3)
x5  main_end_input_ptr  // start_input_ptr + 16 + (bit_length >> (3 (bits->bytes)+4 (bytes->blocks)+2 (multiple of 4 blocks)))
x6  input_l
x7  input_h
x9  ctr32
x10 constctr96_top32
x11 constctr96_bot64
x12 rev_ctr32
x13 rk10_l
x14 rk10_h


ASIMD RF layout:
v0-v3 ctr output of CTR and main variable for AES
    v0  ctr0
    v1  ctr1
    v2  ctr2
    v3  ctr3
v4-v7 res output of previous iteration of AES-CTR, input to this round of GHASH
      (also used as temps when they are consumed)
    v4  res0
    v5  res1
    v6  res2
    v7  res3
v8  various_temps / Modulo constant
v9  acc_h
v10 acc_m
v11 acc_l
v12-v17  Constant hash powers
    v12 h1l | h1h
    v13 k2k | h1k
    v14 h2l | h2h
    v15 h3l | h3h
    v16 h4k | h3k
    v17 h4l | h4h
v18-v27 Constant AES round keys (only need 10 for 128b AES, but reserving 4 more for 256b AES for minimal code changes)
    v18 rk0
    v19 rk1
    v20 rk2
    v21 rk3
    v22 rk4
    v23 rk5
    v24 rk6
    v25 rk7
    v26 rk8
    v27 rk9
v28-v31 various temps
*/

#define end_input_ptr       "x4"
#define main_end_input_ptr  "x5"
#define input_l0     "x6"
#define input_h0     "x7"
#define input_l1     "x19"
#define input_h1     "x20"
#define input_l2     "x21"
#define input_h2     "x22"
#define input_l3     "x23"
#define input_h3     "x24"

#define ctr32w      "w9"
#define ctr32x      "x9"
#define ctr96_b64x  "x10"
#define ctr96_t32w  "w11"
#define ctr96_t32x  "x11"
#define rctr32w     "w12"
#define rctr32x     "x12"

#define rk10_l      "x13"
#define rk10_h      "x14"

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

#define res0b       "v4.16b"
#define res0        "v4"
#define res0d       "d4"
#define res1b       "v5.16b"
#define res1        "v5"
#define res1d       "d5"
#define res2b       "v6.16b"
#define res2        "v6"
#define res2d       "d6"
#define res3b       "v7.16b"
#define res3        "v7"
#define res3d       "d7"

#define acc_hb      "v9.16b"
#define acc_h       "v9"
#define acc_hd      "d9"
#define acc_mb      "v10.16b"
#define acc_m       "v10"
#define acc_md      "d10"
#define acc_lb      "v11.16b"
#define acc_l       "v11"
#define acc_ld      "d11"

#define h1          "v12"
#define h1q         "q12"
#define h2          "v13"
#define h2q         "q13"
#define h3          "v14"
#define h3q         "q14"
#define h4          "v15"
#define h4q         "q15"
#define h12k        "v16"
#define h34k        "v17"

#define t0          "v8" //temp 1st hash (8 free)
#define t0d         "d8"

#define t1          "v28" //temp 2nd hash high (4, 8 free)
#define t1d         "d28"
#define t2          "v29" //temp 2nd hash low
#define t2d         "d29"
#define t3          "v30" //temp 2nd hash mid
#define t3d         "d30"

#define t4          "v8" //temp 3rd hash high (4, 5, 8 free)
#define t4d         "d8"
#define t5          "v28" //temp 3rd hash low
#define t5d         "d28"
#define t6          "v31" //temp 3rd hash mid
#define t6d         "d31"

#define t7          "v4" //temp 4th hash high  (4, 5, 6, 8 free)
#define t7d         "d4"
#define t8          "v29" //temp 4th hash low
#define t8d         "d29"
#define t9          "v30" //temp 4th hash mid
#define t9d         "d30"

#define ctr_t0      "v4"
#define ctr_t0d     "d4"
#define ctr_t0b     "v4.16b"
#define ctr_t1      "v5"
#define ctr_t1d     "d5"
#define ctr_t1b     "v5.16b"
#define ctr_t2      "v6"
#define ctr_t2d     "d6"
#define ctr_t2b     "v6.16b"
#define ctr_t3      "v7"
#define ctr_t3d     "d7"
#define ctr_t3b     "v7.16b"

#define mod_constantd "d8"
#define mod_constant  "v8"
#define mod_t         "v31"

#define rk0         "v18.16b"
#define rk0q        "q18"
#define rk1         "v19.16b"
#define rk1q        "q19"
#define rk2         "v20.16b"
#define rk2q        "q20"
#define rk2q1       "v20.1q"
#define rk3         "v21.16b"
#define rk3q        "q21"
#define rk3q1       "v21.1q"
#define rk4         "v22.16b"
#define rk4q        "q22"
#define rk4v        "v22"
#define rk4d        "d22"
#define rk5         "v23.16b"
#define rk5q        "q23"
#define rk6         "v24.16b"
#define rk6q        "q24"
#define rk7         "v25.16b"
#define rk7q        "q25"
#define rk8         "v26.16b"
#define rk8q        "q26"
#define rk9         "v27.16b"
#define rk9q        "q27"

// Given a set up cipher_constants_t and the IPsec salt and ESPIV, perform encryption in place
static operation_result_t encrypt_from_constants_IPsec_128(
    const cipher_constants_t * cc,
    uint32_t salt,
    uint64_t ESPIV,
    const uint8_t * restrict aad,   uint64_t aad_byte_length,       //aad_byte_length 8 or 12
    uint8_t * plaintext,      uint64_t plaintext_byte_length, //Inputs
    uint8_t * tag)                                            //Outputs
{
    uint8_t * in_ptr = plaintext;
    uint8_t * out_ptr = plaintext;

    // moved this to separate inline asm as ran out of inputs
    __asm __volatile
    (
        //// Set initial ctr ////
        "       mov     "rctr32w", #1                                       \n"
        "       lsr     "ctr96_t32x", %[ESPIV], #32                         \n"
        "       orr     "ctr96_b64x", %[salt], %[ESPIV], lsl #32            \n"
        :
        : [salt] "r" ((uint64_t) salt), [ESPIV] "r" (ESPIV)
        : rctr32w, ctr96_t32x, ctr96_b64x
    );

    __asm __volatile
    (
        //// Initial ////
        // set up counter for final+1 and potential 0-3 blocks
        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR final+1 block
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR final+1 block
        "       fmov    "res0d", "ctr96_b64x"                               \n" // CTR final+1 block
        "       fmov    "res0".d[1], "ctr32x"                               \n" // CTR final+1 block
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR final+1 block

        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 0
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 0
        "       fmov    "ctr0d", "ctr96_b64x"                               \n" // CTR block 0
        "       fmov    "ctr0".d[1], "ctr32x"                               \n" // CTR block 0
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 0

        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 1
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 1
        "       fmov    "ctr1d", "ctr96_b64x"                               \n" // CTR block 1
        "       fmov    "ctr1".d[1], "ctr32x"                               \n" // CTR block 1
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 1

        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 2
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 2
        "       fmov    "ctr2d", "ctr96_b64x"                               \n" // CTR block 2
        "       fmov    "ctr2".d[1], "ctr32x"                               \n" // CTR block 2
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 2

        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 3
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 3
        "       fmov    "ctr3d", "ctr96_b64x"                               \n" // CTR block 3
        "       fmov    "ctr3".d[1], "ctr32x"                               \n" // CTR block 3
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 3

        "       add     "end_input_ptr", %[input_ptr], %[plaintext_length], LSR #3\n" // end_input_ptr
        "       lsr     "main_end_input_ptr", %[plaintext_length], #3       \n" // byte_len
        "       sub     "main_end_input_ptr", "main_end_input_ptr", #1      \n" // byte_len - 1
        "       and     "main_end_input_ptr", "main_end_input_ptr", #0xffffffffffffffc0\n" // number of bytes to be processed in main loop (at least 1 byte must be handled by tail)
        "       add     "main_end_input_ptr", "main_end_input_ptr", %[input_ptr]\n"
        // load constants
        "       ldr     "rk0q", [%[cc], #0]                                 \n" // load rk0
        "       ldr     "rk1q", [%[cc], #16]                                \n" // load rk1
        "       ldr     "rk2q", [%[cc], #32]                                \n" // load rk2
        "       ldr     "rk3q", [%[cc], #48]                                \n" // load rk3
        "       ldr     "rk4q", [%[cc], #64]                                \n" // load rk4
        "       ldr     "rk5q", [%[cc], #80]                                \n" // load rk5
        "       ldr     "rk6q", [%[cc], #96]                                \n" // load rk6
        "       ldr     "rk7q", [%[cc], #112]                               \n" // load rk7
        "       ldr     "rk8q", [%[cc], #128]                               \n" // load rk8
        "       ldr     "rk9q", [%[cc], #144]                               \n" // load rk9
        "       ldp     "rk10_l", "rk10_h", [%[cc], #160]                   \n" // load rk10

        "       ldr     "h1q", [%[cc], #240]                                \n" // load h1l | h1h
        "       ldr     "h2q", [%[cc], #256]                                \n" // load h2l | h2h
        "       ldr     "h3q", [%[cc], #272]                                \n" // load h3l | h3h
        "       ldr     "h4q", [%[cc], #288]                                \n" // load h4l | h4h
        "       trn1    "t0".2d,    "h1".2d,    "h2".2d                     \n" // h2h | h1h
        "       trn2    "h12k".2d,  "h1".2d,    "h2".2d                     \n" // h2l | h1l
        "       eor     "h12k".16b, "h12k".16b, "t0".16b                    \n" // h2k | h1k
        "       trn1    "acc_h".2d, "h3".2d,    "h4".2d                     \n" // h4h | h3h
        "       trn2    "h34k".2d,  "h3".2d,    "h4".2d                     \n" // h4l | h3l
        "       eor     "h34k".16b, "h34k".16b, "acc_h".16b                 \n" // h4k | h3k

        "       aese    "res0b", "rk0"   \n  aesmc   "res0b", "res0b"       \n" // AES block final+1 - round 0
        "       aese    "res0b", "rk1"   \n  aesmc   "res0b", "res0b"       \n" // AES block final+1 - round 1
        "       aese    "res0b", "rk2"   \n  aesmc   "res0b", "res0b"       \n" // AES block final+1 - round 2
        "       aese    "res0b", "rk3"   \n  aesmc   "res0b", "res0b"       \n" // AES block final+1 - round 3
        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 0
        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 1
        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 2
        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 3
        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 0
        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 1
        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 2
        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 3
        "       aese    "ctr2b", "rk0"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 0
        "       aese    "ctr2b", "rk1"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 1
        "       aese    "ctr2b", "rk2"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 2
        "       aese    "ctr2b", "rk3"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 3
        "       aese    "ctr3b", "rk0"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 0
        "       aese    "ctr3b", "rk1"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 1
        "       aese    "ctr3b", "rk2"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 2
        "       aese    "ctr3b", "rk3"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 3

        "       aese    "res0b", "rk4"   \n  aesmc   "res0b", "res0b"       \n" // AES block final+1 - round 4
        "       aese    "res0b", "rk5"   \n  aesmc   "res0b", "res0b"       \n" // AES block final+1 - round 5
        "       aese    "res0b", "rk6"   \n  aesmc   "res0b", "res0b"       \n" // AES block final+1 - round 6
        "       aese    "res0b", "rk7"   \n  aesmc   "res0b", "res0b"       \n" // AES block final+1 - round 7
        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 4
        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 5
        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 6
        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 7
        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 4
        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 5
        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 6
        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 7
        "       aese    "ctr2b", "rk4"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 4
        "       aese    "ctr2b", "rk5"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 5
        "       aese    "ctr2b", "rk6"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 6
        "       aese    "ctr2b", "rk7"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 7
        "       aese    "ctr3b", "rk4"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 4
        "       aese    "ctr3b", "rk5"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 5
        "       aese    "ctr3b", "rk6"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 6
        "       aese    "ctr3b", "rk7"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 7

        "       aese    "res0b", "rk8"   \n  aesmc   "res0b", "res0b"       \n" // AES block final+1 - round 8
        "       aese    "res0b", "rk9"                                      \n" // AES block final+1 - round 9
        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 8
        "       aese    "ctr0b", "rk9"                                      \n" // AES block 0 - round 9
        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 1 - round 8
        "       aese    "ctr1b", "rk9"                                      \n" // AES block 1 - round 9
        "       aese    "ctr2b", "rk8"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 2 - round 8
        "       aese    "ctr2b", "rk9"                                      \n" // AES block 2 - round 9
        "       aese    "ctr3b", "rk8"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 3 - round 8
        "       aese    "ctr3b", "rk9"                                      \n" // AES block 3 - round 9

        "       mov     "input_l0", "res0".d[0]                             \n" // AES final+1 block - mov low
        "       mov     "input_h0", "res0".d[1]                             \n" // AES final+1 block - mov high
        "       eor     "input_l0", "input_l0", "rk10_l"                    \n" // AES final+1 block - round 10 low
        "       eor     "input_h0", "input_h0", "rk10_h"                    \n" // AES final+1 block - round 10 high
        "       stp     "input_l0", "input_h0", [sp, #-16]!                 \n" // AES final+1 block - round 10 high

        // GHASH AAD ////
        "       movi    "mod_constant".8b, #0xc2                            \n"
        "       shl     "mod_constantd", "mod_constantd", #56               \n" // mod_constant
        "       ld1     { "res1b" }, [%[aad_ptr]]                           \n" // GHASH aad block
        "       rev64   "res1b", "res1b"                                    \n" // GHASH aad block
        "       mov     "acc_md", "res1".d[1]                               \n" // GHASH aad block
        "       pmull2  "acc_h".1q, "res1".2d, "h1".2d                      \n" // GHASH aad block
        "       eor     "acc_m".8b, "acc_m".8b, "res1".8b                   \n" // GHASH aad block
        "       pmull   "acc_l".1q, "res1".1d, "h1".1d                      \n" // GHASH aad block
        "       pmull   "acc_m".1q, "acc_m".1d, "h12k".1d                   \n" // GHASH aad block
        // final modulo
        "       eor     "acc_mb", "acc_mb", "acc_hb"                        \n" // GHASH aad block
        "       eor     "acc_mb", "acc_mb", "acc_lb"                        \n" // GHASH aad block
        "       pmull   "res2".1q, "acc_h".1d, "mod_constant".1d            \n" // GHASH aad block
        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n" // GHASH aad block
        "       eor     "acc_mb", "acc_mb", "res2".16b                      \n" // GHASH aad block
        "       eor     "acc_mb", "acc_mb", "acc_hb"                        \n" // GHASH aad block
        "       pmull   "res2".1q, "acc_m".1d, "mod_constant".1d            \n" // GHASH aad block
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n" // GHASH aad block
        "       eor     "acc_lb", "acc_lb", "res2".16b                      \n" // GHASH aad block
        "       eor     "acc_lb", "acc_lb", "acc_mb"                        \n" // GHASH aad block

        // input_ptr vs. end_ptr comparison here
        "       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // check if we have <= 4 blocks
        // jump past merged aes-gcm if plaintext length is 0
        "       cbz     %[plaintext_length], 8f                             \n"
        // possibly jump to end
        "       b.ge    2f                                                  \n" // handle tail

        "       ldp     "input_l0", "input_h0", [%[input_ptr], #0]          \n" // AES block 0 - load plaintext
        "       eor     "input_l0", "input_l0", "rk10_l"                    \n" // AES block 0 - round 10 low
        "       eor     "input_h0", "input_h0", "rk10_h"                    \n" // AES block 0 - round 10 high
        "       fmov    "ctr_t0d", "input_l0"                               \n" // AES block 0 - mov low
        "       fmov    "ctr_t0".d[1], "input_h0"                           \n" // AES block 0 - mov high
        "       eor     "res0b", "ctr_t0b", "ctr0b"                         \n" // AES block 0 - result
        "       st1     { "res0b" }, [%[output_ptr]], #16                   \n" // AES block 0 - store result

        "       ldp     "input_l1", "input_h1", [%[input_ptr], #16]         \n" // AES block 1 - load plaintext
        "       eor     "input_l1", "input_l1", "rk10_l"                    \n" // AES block 1 - round 10 low
        "       eor     "input_h1", "input_h1", "rk10_h"                    \n" // AES block 1 - round 10 high
        "       fmov    "ctr_t1d", "input_l1"                               \n" // AES block 1 - mov low
        "       fmov    "ctr_t1".d[1], "input_h1"                           \n" // AES block 1 - mov high
        "       eor     "res1b", "ctr_t1b", "ctr1b"                         \n" // AES block 1 - result
        "       st1     { "res1b" }, [%[output_ptr]], #16                   \n" // AES block 1 - store result

        "       ldp     "input_l2", "input_h2", [%[input_ptr], #32]         \n" // AES block 2 - load plaintext
        "       eor     "input_l2", "input_l2", "rk10_l"                    \n" // AES block 2 - round 10 low
        "       eor     "input_h2", "input_h2", "rk10_h"                    \n" // AES block 2 - round 10 high
        "       fmov    "ctr_t2d", "input_l2"                               \n" // AES block 2 - mov low
        "       fmov    "ctr_t2".d[1], "input_h2"                           \n" // AES block 2 - mov high
        "       eor     "res2b", "ctr_t2b", "ctr2b"                         \n" // AES block 2 - result
        "       st1     { "res2b" }, [%[output_ptr]], #16                   \n" // AES block 2 - store result

        "       ldp     "input_l3", "input_h3", [%[input_ptr], #48]         \n" // AES block 3 - load plaintext
        "       eor     "input_l3", "input_l3", "rk10_l"                    \n" // AES block 3 - round 10 low
        "       eor     "input_h3", "input_h3", "rk10_h"                    \n" // AES block 3 - round 10 high
        "       fmov    "ctr_t3d", "input_l3"                               \n" // AES block 3 - mov low
        "       fmov    "ctr_t3".d[1], "input_h3"                           \n" // AES block 3 - mov high
        "       eor     "res3b", "ctr_t3b", "ctr3b"                         \n" // AES block 3 - result
        "       st1     { "res3b" }, [%[output_ptr]], #16                   \n" // AES block 3 - store result

        "       add     %[input_ptr], %[input_ptr], #64                     \n" // AES input_ptr update

        "       fmov    "ctr0d", "ctr96_b64x"                               \n" // CTR block 4
        "       fmov    "ctr1d", "ctr96_b64x"                               \n" // CTR block 5
        "       fmov    "ctr2d", "ctr96_b64x"                               \n" // CTR block 6

        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 4
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 4
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 4
        "       fmov    "ctr0".d[1], "ctr32x"                               \n" // CTR block 4

        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 5
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 5
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 5
        "       fmov    "ctr1".d[1], "ctr32x"                               \n" // CTR block 5

        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 6
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 6
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 6
        "       fmov    "ctr2".d[1], "ctr32x"                               \n" // CTR block 6

        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 7
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 7

        // !!! POSSIBLY JUMP TO PREPRETAIL - just GHASH these and then TAIL !!!
        "       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // check if we have <= 8 blocks
        "       b.ge    7f                                                  \n" // do prepretail

        //// Main loop ////
        // parts described above
        "1:                                                                 \n" // main loop start
        "       fmov    "ctr3d", "ctr96_b64x"                               \n" // CTR block 4k+3
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 4k+3
        "       fmov    "ctr3".d[1], "ctr32x"                               \n" // CTR block 4k+3

        "       ext     "acc_lb", "acc_lb", "acc_lb", #8                    \n" // PRE 0
        "       rev64   "res0b", "res0b"                                    \n" // GHASH block 4k (only t0 is free)
        "       eor     "res0b", "res0b", "acc_lb"                          \n" // PRE 1
        "       pmull2  "acc_h".1q, "res0".2d, "h4".2d                      \n" // GHASH block 4k - high
        "       pmull   "acc_l".1q, "res0".1d, "h4".1d                      \n" // GHASH block 4k - low
        "       mov     "t0d", "res0".d[1]                                  \n" // GHASH block 4k - mid
        "       eor     "t0".8b, "t0".8b, "res0".8b                         \n" // GHASH block 4k - mid
        "       mov     "acc_md", "h34k".d[1]                               \n" // GHASH block 4k - mid
        "       pmull   "acc_m".1q, "t0".1d, "acc_m".1d                     \n" // GHASH block 4k - mid

        "       rev64   "res1b", "res1b"                                    \n" // GHASH block 4k+1 (t0 and t1 free)
        "       pmull2  "t1".1q, "res1".2d, "h3".2d                         \n" // GHASH block 4k+1 - high
        "       eor     "acc_hb", "acc_hb", "t1".16b                        \n" // GHASH block 4k+1 - high
        "       pmull   "t2".1q, "res1".1d, "h3".1d                         \n" // GHASH block 4k+1 - low
        "       eor     "acc_lb", "acc_lb", "t2".16b                        \n" // GHASH block 4k+1 - low
        "       mov     "t3d", "res1".d[1]                                  \n" // GHASH block 4k+1 - mid
        "       eor     "t3".8b, "t3".8b, "res1".8b                         \n" // GHASH block 4k+1 - mid
        "       pmull   "t3".1q, "t3".1d, "h34k".1d                         \n" // GHASH block 4k+1 - mid
        "       eor     "acc_mb", "acc_mb", "t3".16b                        \n" // GHASH block 4k+1 - mid

        "       rev64   "res2b", "res2b"                                    \n" // GHASH block 4k+2 (t0, t1, and t2 free)
        "       pmull2  "t4".1q, "res2".2d, "h2".2d                         \n" // GHASH block 4k+2 - high
        "       eor     "acc_hb", "acc_hb", "t4".16b                        \n" // GHASH block 4k+2 - high
        "       pmull   "t5".1q, "res2".1d, "h2".1d                         \n" // GHASH block 4k+2 - low
        "       eor     "acc_lb", "acc_lb", "t5".16b                        \n" // GHASH block 4k+2 - low
        "       mov     "t6d", "res2".d[1]                                  \n" // GHASH block 4k+2 - mid
        "       eor     "t6".8b, "t6".8b, "res2".8b                         \n" // GHASH block 4k+2 - mid
        "       ins     "t6".d[1], "t6".d[0]                                \n" // GHASH block 4k+2 - mid
        "       pmull2  "t6".1q, "t6".2d, "h12k".2d                         \n" // GHASH block 4k+2 - mid
        "       eor     "acc_mb", "acc_mb", "t6".16b                        \n" // GHASH block 4k+2 - mid

        "       rev64   "res3b", "res3b"                                    \n" // GHASH block 4k+3 (t0, t1, t2 and t3 free)
        "       pmull2  "t7".1q, "res3".2d, "h1".2d                         \n" // GHASH block 4k+3 - high
        "       eor     "acc_hb", "acc_hb", "t7".16b                        \n" // GHASH block 4k+3 - high
        "       pmull   "t8".1q, "res3".1d, "h1".1d                         \n" // GHASH block 4k+3 - low
        "       eor     "acc_lb", "acc_lb", "t8".16b                        \n" // GHASH block 4k+3 - low
        "       mov     "t9d", "res3".d[1]                                  \n" // GHASH block 4k+3 - mid
        "       eor     "t9".8b, "t9".8b, "res3".8b                         \n" // GHASH block 4k+3 - mid
        "       pmull   "t9".1q, "t9".1d, "h12k".1d                         \n" // GHASH block 4k+3 - mid
        "       eor     "acc_mb", "acc_mb", "t9".16b                        \n" // GHASH block 4k+3 - mid

        "       movi    "mod_constant".8b, #0xc2                            \n"
        "       shl     "mod_constantd", "mod_constantd", #56               \n" // mod_constant
        "       eor     "t9".16b, "acc_lb", "acc_hb"                        \n" // MODULO - karatsuba tidy up
        "       eor     "acc_mb", "acc_mb", "t9".16b                        \n" // MODULO - karatsuba tidy up
        "       pmull   "mod_t".1q, "acc_h".1d, "mod_constant".1d           \n" // MODULO - top 64b align with mid
        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n" // MODULO - other top alignment
        "       eor     "acc_mb", "acc_mb", "mod_t".16b                     \n" // MODULO - fold into mid
        "       eor     "acc_mb", "acc_mb", "acc_hb"                        \n" // MODULO - fold into mid
        "       pmull   "acc_h".1q, "acc_m".1d, "mod_constant".1d           \n" // MODULO - mid 64b align with low
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n" // MODULO - other mid alignment
        "       eor     "acc_lb", "acc_lb", "acc_hb"                        \n" // MODULO - fold into low
        "       eor     "acc_lb", "acc_lb", "acc_mb"                        \n" // MODULO - fold into low

        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 0
        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 1
        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 2
        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 3
        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 0
        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 1
        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 2
        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 3
        "       aese    "ctr2b", "rk0"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 0
        "       aese    "ctr2b", "rk1"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 1
        "       aese    "ctr2b", "rk2"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 2
        "       aese    "ctr2b", "rk3"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 3
        "       aese    "ctr3b", "rk0"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 0
        "       aese    "ctr3b", "rk1"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 1
        "       aese    "ctr3b", "rk2"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 2
        "       aese    "ctr3b", "rk3"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 3

        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 4
        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 5
        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 6
        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 7
        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 4
        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 5
        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 6
        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 7
        "       aese    "ctr2b", "rk4"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 4
        "       aese    "ctr2b", "rk5"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 5
        "       aese    "ctr2b", "rk6"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 6
        "       aese    "ctr2b", "rk7"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 7
        "       aese    "ctr3b", "rk4"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 4
        "       aese    "ctr3b", "rk5"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 5
        "       aese    "ctr3b", "rk6"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 6
        "       aese    "ctr3b", "rk7"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 7

        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 8
        "       aese    "ctr0b", "rk9"                                      \n" // AES block 4k+4 - round 9
        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 8
        "       aese    "ctr1b", "rk9"                                      \n" // AES block 4k+5 - round 9
        "       aese    "ctr2b", "rk8"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 8
        "       aese    "ctr2b", "rk9"                                      \n" // AES block 4k+6 - round 9
        "       aese    "ctr3b", "rk8"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 8
        "       aese    "ctr3b", "rk9"                                      \n" // AES block 4k+7 - round 9

        "       ldp     "input_l0", "input_h0", [%[input_ptr], #0]          \n" // AES block 4k+4 - load plaintext
        "       eor     "input_l0", "input_l0", "rk10_l"                    \n" // AES block 4k+4 - round 10 low
        "       eor     "input_h0", "input_h0", "rk10_h"                    \n" // AES block 4k+4 - round 10 high
        "       fmov    "ctr_t0d", "input_l0"                               \n" // AES block 4k+4 - mov low
        "       fmov    "ctr_t0".d[1], "input_h0"                           \n" // AES block 4k+4 - mov high
        "       eor     "res0b", "ctr_t0b", "ctr0b"                         \n" // AES block 4k+4 - result
        "       st1     { "res0b" }, [%[output_ptr]], #16                   \n" // AES block 4k+4 - store result

        "       ldp     "input_l1", "input_h1", [%[input_ptr], #16]         \n" // AES block 4k+5 - load plaintext
        "       eor     "input_l1", "input_l1", "rk10_l"                    \n" // AES block 4k+5 - round 10 low
        "       eor     "input_h1", "input_h1", "rk10_h"                    \n" // AES block 4k+5 - round 10 high
        "       fmov    "ctr_t1d", "input_l1"                               \n" // AES block 4k+5 - mov low
        "       fmov    "ctr_t1".d[1], "input_h1"                           \n" // AES block 4k+5 - mov high
        "       eor     "res1b", "ctr_t1b", "ctr1b"                         \n" // AES block 4k+5 - result
        "       st1     { "res1b" }, [%[output_ptr]], #16                   \n" // AES block 4k+5 - store result

        "       ldp     "input_l2", "input_h2", [%[input_ptr], #32]         \n" // AES block 4k+6 - load plaintext
        "       eor     "input_l2", "input_l2", "rk10_l"                    \n" // AES block 4k+6 - round 10 low
        "       eor     "input_h2", "input_h2", "rk10_h"                    \n" // AES block 4k+6 - round 10 high
        "       fmov    "ctr_t2d", "input_l2"                               \n" // AES block 4k+6 - mov low
        "       fmov    "ctr_t2".d[1], "input_h2"                           \n" // AES block 4k+6 - mov high
        "       eor     "res2b", "ctr_t2b", "ctr2b"                         \n" // AES block 4k+6 - result
        "       st1     { "res2b" }, [%[output_ptr]], #16                   \n" // AES block 4k+6 - store result

        "       ldp     "input_l3", "input_h3", [%[input_ptr], #48]         \n" // AES block 4k+3 - load plaintext
        "       eor     "input_l3", "input_l3", "rk10_l"                    \n" // AES block 4k+3 - round 10 low
        "       eor     "input_h3", "input_h3", "rk10_h"                    \n" // AES block 4k+3 - round 10 high
        "       fmov    "ctr_t3d", "input_l3"                               \n" // AES block 4k+3 - mov low
        "       fmov    "ctr_t3".d[1], "input_h3"                           \n" // AES block 4k+3 - mov high
        "       eor     "res3b", "ctr_t3b", "ctr3b"                         \n" // AES block 4k+3 - result
        "       st1     { "res3b" }, [%[output_ptr]], #16                   \n" // AES block 4k+3 - store result

        "       add     %[input_ptr], %[input_ptr], #64                     \n" // AES input_ptr update

        "       fmov    "ctr0d", "ctr96_b64x"                               \n" // CTR block 4k+8
        "       fmov    "ctr1d", "ctr96_b64x"                               \n" // CTR block 4k+9
        "       fmov    "ctr2d", "ctr96_b64x"                               \n" // CTR block 4k+10

        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 4k+8
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 4k+8
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 4k+8
        "       fmov    "ctr0".d[1], "ctr32x"                               \n" // CTR block 4k+8

        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 4k+9
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 4k+9
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 4k+9
        "       fmov    "ctr1".d[1], "ctr32x"                               \n" // CTR block 4k+9

        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 4k+10
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 4k+10
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 4k+10
        "       fmov    "ctr2".d[1], "ctr32x"                               \n" // CTR block 4k+10

        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 4k+11
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 4k+11

        "       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // LOOP CONTROL
        "       b.lt    1b                                                  \n"

        "7:                                                                 \n" // PREPRETAIL
        "       fmov    "ctr3d", "ctr96_b64x"                               \n" // CTR block 4k+3
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 4k+3
        "       fmov    "ctr3".d[1], "ctr32x"                               \n" // CTR block 4k+3

        "       ext     "acc_lb", "acc_lb", "acc_lb", #8                    \n" // PRE 0
        "       rev64   "res0b", "res0b"                                    \n" // GHASH block 4k (only t0 is free)
        "       eor     "res0b", "res0b", "acc_lb"                          \n" // PRE 1
        "       pmull2  "acc_h".1q, "res0".2d, "h4".2d                      \n" // GHASH block 4k - high
        "       pmull   "acc_l".1q, "res0".1d, "h4".1d                      \n" // GHASH block 4k - low
        "       mov     "t0d", "res0".d[1]                                  \n" // GHASH block 4k - mid
        "       eor     "t0".8b, "t0".8b, "res0".8b                         \n" // GHASH block 4k - mid
        "       mov     "acc_md", "h34k".d[1]                               \n" // GHASH block 4k - mid
        "       pmull   "acc_m".1q, "t0".1d, "acc_m".1d                     \n" // GHASH block 4k - mid

        "       rev64   "res1b", "res1b"                                    \n" // GHASH block 4k+1 (t0 and t1 free)
        "       pmull2  "t1".1q, "res1".2d, "h3".2d                         \n" // GHASH block 4k+1 - high
        "       eor     "acc_hb", "acc_hb", "t1".16b                        \n" // GHASH block 4k+1 - high
        "       pmull   "t2".1q, "res1".1d, "h3".1d                         \n" // GHASH block 4k+1 - low
        "       eor     "acc_lb", "acc_lb", "t2".16b                        \n" // GHASH block 4k+1 - low
        "       mov     "t3d", "res1".d[1]                                  \n" // GHASH block 4k+1 - mid
        "       eor     "t3".8b, "t3".8b, "res1".8b                         \n" // GHASH block 4k+1 - mid
        "       pmull   "t3".1q, "t3".1d, "h34k".1d                         \n" // GHASH block 4k+1 - mid
        "       eor     "acc_mb", "acc_mb", "t3".16b                        \n" // GHASH block 4k+1 - mid

        "       rev64   "res2b", "res2b"                                    \n" // GHASH block 4k+2 (t0, t1, and t2 free)
        "       pmull2  "t4".1q, "res2".2d, "h2".2d                         \n" // GHASH block 4k+2 - high
        "       eor     "acc_hb", "acc_hb", "t4".16b                        \n" // GHASH block 4k+2 - high
        "       pmull   "t5".1q, "res2".1d, "h2".1d                         \n" // GHASH block 4k+2 - low
        "       eor     "acc_lb", "acc_lb", "t5".16b                        \n" // GHASH block 4k+2 - low
        "       mov     "t6d", "res2".d[1]                                  \n" // GHASH block 4k+2 - mid
        "       eor     "t6".8b, "t6".8b, "res2".8b                         \n" // GHASH block 4k+2 - mid
        "       ins     "t6".d[1], "t6".d[0]                                \n" // GHASH block 4k+2 - mid
        "       pmull2  "t6".1q, "t6".2d, "h12k".2d                         \n" // GHASH block 4k+2 - mid
        "       eor     "acc_mb", "acc_mb", "t6".16b                        \n" // GHASH block 4k+2 - mid

        "       rev64   "res3b", "res3b"                                    \n" // GHASH block 4k+3 (t0, t1, t2 and t3 free)
        "       pmull2  "t7".1q, "res3".2d, "h1".2d                         \n" // GHASH block 4k+3 - high
        "       eor     "acc_hb", "acc_hb", "t7".16b                        \n" // GHASH block 4k+3 - high
        "       pmull   "t8".1q, "res3".1d, "h1".1d                         \n" // GHASH block 4k+3 - low
        "       eor     "acc_lb", "acc_lb", "t8".16b                        \n" // GHASH block 4k+3 - low
        "       mov     "t9d", "res3".d[1]                                  \n" // GHASH block 4k+3 - mid
        "       eor     "t9".8b, "t9".8b, "res3".8b                         \n" // GHASH block 4k+3 - mid
        "       pmull   "t9".1q, "t9".1d, "h12k".1d                         \n" // GHASH block 4k+3 - mid
        "       eor     "acc_mb", "acc_mb", "t9".16b                        \n" // GHASH block 4k+3 - mid

        "       movi    "mod_constant".8b, #0xc2                            \n"
        "       shl     "mod_constantd", "mod_constantd", #56               \n" // mod_constant

        "       eor     "acc_mb", "acc_mb", "acc_hb"                        \n" // karatsuba tidy up
        "       eor     "acc_mb", "acc_mb", "acc_lb"                        \n"
        "       pmull   "t1".1q, "acc_h".1d, "mod_constant".1d              \n"
        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n"
        "       eor     "acc_mb", "acc_mb", "t1".16b                        \n"
        "       eor     "acc_mb", "acc_mb", "acc_hb"                        \n"
        "       pmull   "t1".1q, "acc_m".1d, "mod_constant".1d              \n"
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n"
        "       eor     "acc_lb", "acc_lb", "t1".16b                        \n"
        "       eor     "acc_lb", "acc_lb", "acc_mb"                        \n"

        //compute final AES blocks
        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 0
        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 1
        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 2
        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 3
        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 0
        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 1
        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 2
        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 3
        "       aese    "ctr2b", "rk0"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 0
        "       aese    "ctr2b", "rk1"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 1
        "       aese    "ctr2b", "rk2"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 2
        "       aese    "ctr2b", "rk3"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 3
        "       aese    "ctr3b", "rk0"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 0
        "       aese    "ctr3b", "rk1"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 1
        "       aese    "ctr3b", "rk2"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 2
        "       aese    "ctr3b", "rk3"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 3

        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 4
        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 5
        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 6
        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 7
        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 4
        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 5
        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 6
        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 7
        "       aese    "ctr2b", "rk4"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 4
        "       aese    "ctr2b", "rk5"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 5
        "       aese    "ctr2b", "rk6"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 6
        "       aese    "ctr2b", "rk7"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 7
        "       aese    "ctr3b", "rk4"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 4
        "       aese    "ctr3b", "rk5"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 5
        "       aese    "ctr3b", "rk6"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 6
        "       aese    "ctr3b", "rk7"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 7

        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 8
        "       aese    "ctr0b", "rk9"                                      \n" // AES block 4k+4 - round 9
        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+5 - round 8
        "       aese    "ctr1b", "rk9"                                      \n" // AES block 4k+5 - round 9
        "       aese    "ctr2b", "rk8"   \n  aesmc   "ctr2b", "ctr2b"       \n" // AES block 4k+6 - round 8
        "       aese    "ctr2b", "rk9"                                      \n" // AES block 4k+6 - round 9
        "       aese    "ctr3b", "rk8"   \n  aesmc   "ctr3b", "ctr3b"       \n" // AES block 4k+7 - round 8
        "       aese    "ctr3b", "rk9"                                      \n" // AES block 4k+7 - round 9

        "2:                                                                 \n" // TAIL
        "       sub     "main_end_input_ptr", "end_input_ptr", %[input_ptr] \n" // main_end_input_ptr is number of bytes left to process
        "       ext     "t0".16b, "acc_lb", "acc_lb", #8                    \n" // prepare final partial tag

        "       ldp     "input_l0", "input_h0", [%[input_ptr]], #16         \n" // AES block 4k+4 - load plaintext
        "       eor     "input_l0", "input_l0", "rk10_l"                    \n" // AES block 4k+4 - round 10 low
        "       eor     "input_h0", "input_h0", "rk10_h"                    \n" // AES block 4k+4 - round 10 high
        "       fmov    "ctr_t0d", "input_l0"                               \n" // AES block 4k+4 - mov low
        "       fmov    "ctr_t0".d[1], "input_h0"                           \n" // AES block 4k+4 - mov high
        "       eor     "res1b", "ctr_t0b", "ctr0b"                         \n" // AES block 4k+4 - result

        "       cmp     "main_end_input_ptr", #48                           \n"
        "       b.gt    3f                                                  \n"
        // zero accumulators if we aren't directly writing them
        "       movi    "acc_h".8b, #0                                      \n"
        "       movi    "acc_m".8b, #0                                      \n"
        "       movi    "acc_l".8b, #0                                      \n"
        "       mov     "ctr3b", "ctr2b"                                    \n"
        "       mov     "ctr2b", "ctr1b"                                    \n"
        "       sub     "rctr32w", "rctr32w", #1                            \n"
        "       cmp     "main_end_input_ptr", #32                           \n"
        "       b.gt    4f                                                  \n"
        "       mov     "ctr3b", "ctr1b"                                    \n"
        "       sub     "rctr32w", "rctr32w", #1                            \n"
        "       cmp     "main_end_input_ptr", #16                           \n"
        "       b.gt    5f                                                  \n"
        "       sub     "rctr32w", "rctr32w", #1                            \n"
        "       b       6f                                                  \n"
        //// Handle tail ////
        // less than 4 blocks, last block possibly not full
        "3:                                                                 \n" // blocks left >  3
        "       st1     { "res1b" }, [%[output_ptr]], #16                   \n" // AES final-3 block  - store result
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-3 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       pmull2  "acc_h".1q, "res0".2d, "h4".2d                      \n" // GHASH final-3 block - high
        "       pmull   "acc_l".1q, "res0".1d, "h4".1d                      \n" // GHASH final-3 block - low
        "       mov     "rk4d", "res0".d[1]                                 \n" // GHASH final-3 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-3 block - mid
        "       mov     "acc_md", "h34k".d[1]                               \n" // GHASH final-3 block - mid
        "       pmull   "acc_m".1q, "rk4v".1d, "acc_m".1d                   \n" // GHASH final-3 block - mid

        "       ldp     "input_l0", "input_h0", [%[input_ptr]], #16         \n" // AES final-2 block - load input low & high
        "       eor     "input_l0", "input_l0", "rk10_l"                    \n" // AES final-2 block - round 10 low
        "       eor     "input_h0", "input_h0", "rk10_h"                    \n" // AES final-2 block - round 10 high
        "       fmov    "res1d", "input_l0"                                 \n" // AES final-2 block - mov low
        "       fmov    "res1".d[1], "input_h0"                             \n" // AES final-2 block - mov high
        "       eor     "res1b", "res1b", "ctr1b"                           \n" // AES final-2 block - result

        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

        "4:                                                                 \n" // blocks left >  2
        "       st1     { "res1b" }, [%[output_ptr]], #16                   \n" // AES final-2 block - store result
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-2 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       pmull2  "rk2q1", "res0".2d, "h3".2d                         \n" // GHASH final-2 block - high
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-2 block - high
        "       pmull   "rk3q1", "res0".1d, "h3".1d                         \n" // GHASH final-2 block - low
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-2 block - low
        "       mov     "rk4d", "res0".d[1]                                 \n" // GHASH final-2 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-2 block - mid
        "       pmull   "rk4v".1q, "rk4v".1d, "h34k".1d                     \n" // GHASH final-2 block - mid
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-2 block - mid

        "       ldp     "input_l0", "input_h0", [%[input_ptr]], #16         \n" // AES final-1 block - load input low & high
        "       eor     "input_l0", "input_l0", "rk10_l"                    \n" // AES final-1 block - round 10 low
        "       eor     "input_h0", "input_h0", "rk10_h"                    \n" // AES final-1 block - round 10 high
        "       fmov    "res1d", "input_l0"                                 \n" // AES final-1 block - mov low
        "       fmov    "res1".d[1], "input_h0"                             \n" // AES final-1 block - mov high
        "       eor     "res1b", "res1b", "ctr2b"                           \n" // AES final-1 block - result

        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

        "5:                                                                 \n" // blocks left >  1
        "       st1     { "res1b" }, [%[output_ptr]], #16                   \n" // AES final-1 block - store result
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final-1 block
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       pmull2  "rk2q1", "res0".2d, "h2".2d                         \n" // GHASH final-1 block - high
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final-1 block - high
        "       pmull   "rk3q1", "res0".1d, "h2".1d                         \n" // GHASH final-1 block - low
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final-1 block - low
        "       mov     "rk4d", "res0".d[1]                                 \n" // GHASH final-1 block - mid
        "       eor     "rk4v".8b, "rk4v".8b, "res0".8b                     \n" // GHASH final-1 block - mid
        "       ins     "rk4v".d[1], "rk4v".d[0]                            \n" // GHASH final-1 block - mid
        "       pmull2  "rk4v".1q, "rk4v".2d, "h12k".2d                     \n" // GHASH final-1 block - mid
        "       eor     "acc_mb", "acc_mb", "rk4v".16b                      \n" // GHASH final-1 block - mid

        "       ldp     "input_l0", "input_h0", [%[input_ptr]], #16         \n" // AES final block - load input low & high
        "       eor     "input_l0", "input_l0", "rk10_l"                    \n" // AES final block - round 10 low
        "       eor     "input_h0", "input_h0", "rk10_h"                    \n" // AES final block - round 10 high
        "       fmov    "res1d", "input_l0"                                 \n" // AES final block - mov low
        "       fmov    "res1".d[1], "input_h0"                             \n" // AES final block - mov high
        "       eor     "res1b", "res1b", "ctr3b"                           \n" // AES final block - result

        "       movi    "t0".8b, #0                                         \n" // surpress further partial tag feed in

        "6:                                                                 \n" // blocks left <= 1
        // mask out bits of res1 which are not used
        "       and     "input_h3", %[plaintext_length], #127               \n" // bit_length %= 128
        "       mvn     "rk10_h", xzr                                       \n" // rk10_h = 0xffffffffffffffff
        "       sub     "input_h3", "input_h3", #128                        \n" // bit_length -= 128
        "       mvn     "rk10_l", xzr                                       \n" // rk10_l = 0xffffffffffffffff
        "       neg     "input_h3", "input_h3"                              \n" // bit_length = 128 - #bits in input (in range [1,128])
        "       and     "input_h3", "input_h3", #127                        \n" // bit_length %= 128
        "       lsr     "rk10_h", "rk10_h", "input_h3"                      \n" // rk10_h is mask for top 64b of last block
        "       cmp     "input_h3", #64                                     \n"
        "       csel    "input_l0", "rk10_l", "rk10_h", lt                  \n"
        "       csel    "input_h0", "rk10_h", xzr, lt                       \n"
        "       fmov    "ctr0d", "input_l0"                                 \n" // ctr0b is mask for last block
        "       fmov    "ctr0".d[1], "input_h0"                             \n"
        "       and     "res1b", "res1b", "ctr0b"                           \n" // possibly partial last block has zeroes in highest bits
        // end mask out bits of res1 which are not used
        "       rev64   "res0b", "res1b"                                    \n" // GHASH final block
        "       rev     "ctr32w", "rctr32w"                                 \n"
        "       eor     "res0b", "res0b", "t0".16b                          \n" // feed in partial tag
        "       st1     { "res1b" }, [%[output_ptr]]                        \n" // store all 16B
        "       pmull2  "rk2q1", "res0".2d, "h1".2d                         \n" // GHASH final block - high
        "       eor     "acc_hb", "acc_hb", "rk2"                           \n" // GHASH final block - high
        "       pmull   "rk3q1", "res0".1d, "h1".1d                         \n" // GHASH final block - low
        "       eor     "acc_lb", "acc_lb", "rk3"                           \n" // GHASH final block - low
        "       mov     "t0d", "res0".d[1]                                  \n" // GHASH final block - mid
        "       eor     "t0".8b, "t0".8b, "res0".8b                         \n" // GHASH final block - mid
        "       pmull   "t0".1q, "t0".1d, "h12k".1d                         \n" // GHASH final block - mid
        "       eor     "acc_mb", "acc_mb", "t0".16b                        \n" // GHASH final block - mid
        // final modulo
        "       movi    "mod_constant".8b, #0xc2                            \n"
        "       shl     "mod_constantd", "mod_constantd", #56               \n" // mod_constant
        "       eor     "t9".16b, "acc_lb", "acc_hb"                        \n" // MODULO - karatsuba tidy up
        "       eor     "acc_mb", "acc_mb", "t9".16b                        \n" // MODULO - karatsuba tidy up
        "       pmull   "mod_t".1q, "acc_h".1d, "mod_constant".1d           \n" // MODULO - top 64b align with mid
        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n" // MODULO - other top alignment
        "       eor     "acc_mb", "acc_mb", "mod_t".16b                     \n" // MODULO - fold into mid
        "       eor     "acc_mb", "acc_mb", "acc_hb"                        \n" // MODULO - fold into mid
        "       pmull   "acc_h".1q, "acc_m".1d, "mod_constant".1d           \n" // MODULO - mid 64b align with low
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n" // MODULO - other mid alignment
        "       eor     "acc_lb", "acc_lb", "acc_hb"                        \n" // MODULO - fold into low
        "       eor     "acc_lb", "acc_lb", "acc_mb"                        \n" // MODULO - fold into low

        // end of merged aes-gcm
        "8:                                                                 \n"

        //// GHASH final+1 block ////
        "       fmov    "ctr1d", %[aad_length]                              \n" // GHASH final+1 block
        "       fmov    "ctr1".d[1], %[plaintext_length]                    \n" // GHASH final+1 block
        "       ext     "res2".16b, "acc_lb", "acc_lb", #8                  \n" // GHASH final+1 block
        "       ld1     { "ctr0b" }, [sp]                                   \n" // finalize
        "       eor     "ctr1b", "ctr1b", "res2".16b                        \n" // GHASH final+1 block
        "       movi    "rk0", #0                                           \n" // finalize ensure that we remove sensitive data from stack
        "       st1     { "rk0" }, [sp], #16                                \n" // finalize ensure that we remove sensitive data from stack
        "       mov     "acc_md", "ctr1".d[1]                               \n" // GHASH final+1 block
        "       pmull2  "acc_h".1q, "ctr1".2d, "h1".2d                      \n" // GHASH final+1 block
        "       eor     "acc_m".8b, "acc_m".8b, "ctr1".8b                   \n" // GHASH final+1 block
        "       pmull   "acc_l".1q, "ctr1".1d, "h1".1d                      \n" // GHASH final+1 block
        "       pmull   "acc_m".1q, "acc_m".1d, "h12k".1d                   \n" // GHASH final+1 block
        // final+1 modulo
        "       eor     "acc_mb", "acc_mb", "acc_hb"                        \n" // GHASH final+1 block
        "       eor     "acc_mb", "acc_mb", "acc_lb"                        \n" // GHASH final+1 block
        "       pmull   "res2".1q, "acc_h".1d, "mod_constant".1d            \n" // GHASH final+1 block
        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n" // GHASH final+1 block
        "       eor     "acc_mb", "acc_mb", "res2".16b                      \n" // GHASH final+1 block
        "       eor     "acc_mb", "acc_mb", "acc_hb"                        \n" // GHASH final+1 block
        "       pmull   "res2".1q, "acc_m".1d, "mod_constant".1d            \n" // GHASH final+1 block
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n" // GHASH final+1 block
        "       eor     "acc_lb", "acc_lb", "res2".16b                      \n" // GHASH final+1 block
        "       eor     "acc_lb", "acc_lb", "acc_mb"                        \n" // GHASH final+1 block

        //// FINALIZE ////
        "       rev64   "acc_lb", "acc_lb"                                  \n" // finalize
        "       ext     "acc_lb", "acc_lb", "acc_lb", #8                    \n" // finalize
        "       eor     "acc_lb", "acc_lb", "ctr0b"                         \n" // finalize
        "       st1     { "acc_lb" }, [%[tag]]                              \n" // finalize

        : [input_ptr] "+r" (in_ptr), [output_ptr] "+r" (out_ptr), [cc] "+r" (cc)
        : [aad_ptr] "r" (aad),
          [plaintext_length] "r" (plaintext_byte_length<<3), [aad_length] "r" (aad_byte_length<<3),
          [tag] "r" (tag)
        : "v0",  "v1",  "v2",  "v3",  "v4",  "v5",  "v6",  "v7",  "v8",  "v9",  "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
          "x4",  "x5",  "x6",  "x7",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15", "x19", "x20", "x21", "x22", "x23", "x24", "memory"
    );

    return SUCCESSFUL_OPERATION;
}

#undef end_input_ptr
#undef main_end_input_ptr
#undef input_l0
#undef input_h0
#undef input_l1
#undef input_h1
#undef input_l2
#undef input_h2
#undef input_l3
#undef input_h3

#undef ctr32w
#undef ctr32x
#undef ctr96_b64x
#undef ctr96_t32w
#undef ctr96_t32x
#undef rctr32w
#undef rctr32x

#undef rk10_l
#undef rk10_h

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

#undef res0b
#undef res0
#undef res0d
#undef res1b
#undef res1
#undef res1d
#undef res2b
#undef res2
#undef res2d
#undef res3b
#undef res3
#undef res3d

#undef acc_hb
#undef acc_h
#undef acc_hd
#undef acc_mb
#undef acc_m
#undef acc_md
#undef acc_lb
#undef acc_l
#undef acc_ld

#undef h1
#undef h1q
#undef h2
#undef h2q
#undef h3
#undef h3q
#undef h4
#undef h4q
#undef h12k
#undef h34k

#undef t0
#undef t0d

#undef t1
#undef t1d
#undef t2
#undef t2d
#undef t3
#undef t3d

#undef t4
#undef t4d
#undef t5
#undef t5d
#undef t6
#undef t6d

#undef t7
#undef t7d
#undef t8
#undef t8d
#undef t9
#undef t9d

#undef ctr_t0
#undef ctr_t0d
#undef ctr_t0b
#undef ctr_t1
#undef ctr_t1d
#undef ctr_t1b
#undef ctr_t2
#undef ctr_t2d
#undef ctr_t2b
#undef ctr_t3
#undef ctr_t3d
#undef ctr_t3b

#undef mod_constantd
#undef mod_constant
#undef mod_t

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
#undef rk4d
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
