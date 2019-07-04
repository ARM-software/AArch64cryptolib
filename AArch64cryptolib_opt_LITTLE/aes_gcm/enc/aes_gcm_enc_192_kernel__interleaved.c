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
| CTR block 4k+2 | AES block 4k+1 | GHASH block 4k+0 |
|________________|________________|__________________|
|                |                |                  |
| CTR block 4k+3 | AES block 4k+2 | GHASH block 4k+1 |
|________________|________________|__________________|
|                |                |                  |
| CTR block 4k+4 | AES block 4k+3 | GHASH block 4k+2 |
|________________|________________|__________________|
|                |                |                  |
| CTR block 4k+5 | AES block 4k+4 | GHASH block 4k+3 |
|________________|________________|__________________|
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
        Given on little cores we are limited by SIMD throughput this should give a ~4% uplift
    LDR     input_low, [ input_ptr ], #8
    LDR     input_high, [ input_ptr ], #8
    EOR     input_low, k14_low
    EOR     input_high, k14_high
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
    AESE    ctr_curr, k9; AESMC ctr_curr, ctr_curr
    AESE    ctr_curr, k10; AESMC ctr_curr, ctr_curr
    AESE    ctr_curr, k11
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
    PMULL   t_mod, acc_m, mod_constant
    EXT     acc_m, acc_m, acc_m, #8
    EOR     acc_l, acc_l, t_mod
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
x13 rk12_l
x14 rk12_h


ASIMD RF layout:
v0  ctr_next / ctr_curr
v1  ctr_curr / ctr_next
v2  res_curr
v3  t_h
v4  t_m
v5  t_l
v6  acc_h
v7  acc_m
v8  acc_l
v9-v16  Constant hash powers (we unpack the karatsuba powers so that we can always EOR with .8B when generating t_m in GHASH)
    v9  h1l | h1h
    v10  -  | h1k
    v11 h2l | h2h
    v12  -  | h2k
    v13 h3l | h3h
    v14  -  | h3k
    v15 h4l | h4h
    v16  -  | h4k
v17     Modulo reduction constant
    v17  -  | 0xC200_0000_0000_0000
v18-v31 Constant AES round keys (only need 10 for 128b AES, but reserving 4 more for 256b AES for minimal code changes)
    v20 rk0
    v21 rk1
    v22 rk2
    v23 rk3
    v24 rk4
    v25 rk5
    v26 rk6
    v27 rk7
    v28 rk8
    v29 rk9
    v30 rk10
    v31 rk11
*/

#define end_input_ptr       "x4"
#define main_end_input_ptr  "x5"
#define input_l     "x6"
#define input_h     "x7"

#define ctr32w      "w9"
#define ctr32x      "x9"
#define ctr96_b64x  "x10"
#define ctr96_t32w  "w11"
#define ctr96_t32x  "x11"
#define rctr32w     "w12"
#define rctr32x     "x12"

#define rk12_l      "x13"
#define rk12_h      "x14"

#define ctr0b       "v0.16b"
#define ctr0        "v0"
#define ctr1b       "v1.16b"
#define ctr1        "v1"
#define res_currb   "v2.16b"
#define res_curr    "v2"

#define t_h         "v3"
#define t_m         "v4"
#define t_l         "v5"

#define acc_hb      "v6.16b"
#define acc_h       "v6"
#define acc_mb      "v7.16b"
#define acc_m       "v7"
#define acc_lb      "v8.16b"
#define acc_l       "v8"

#define h1          "v9"
#define h1q         "q9"
#define h1d         "d9"
#define h1k         "v10"
#define h1kd        "d10"
#define h2          "v11"
#define h2q         "q11"
#define h2d         "d11"
#define h2k         "v12"
#define h2kd        "d12"
#define h3          "v13"
#define h3q         "q13"
#define h3d         "d13"
#define h3k         "v14"
#define h3kd        "d14"
#define h4          "v15"
#define h4q         "q15"
#define h4d         "d15"
#define h4k         "v16"
#define h4kd        "d16"

#define mod_constantd "d17"
#define mod_constant "v17"

#define rk0         "v20.16b"
#define rk0q        "q20"
#define rk1         "v21.16b"
#define rk1q        "q21"
#define rk2         "v22.16b"
#define rk2q        "q22"
#define rk3         "v23.16b"
#define rk3q        "q23"
#define rk4         "v24.16b"
#define rk4q        "q24"
#define rk5         "v25.16b"
#define rk5q        "q25"
#define rk6         "v26.16b"
#define rk6q        "q26"
#define rk7         "v27.16b"
#define rk7q        "q27"
#define rk8         "v28.16b"
#define rk8q        "q28"
#define rk9         "v29.16b"
#define rk9q        "q29"
#define rk10        "v30.16b"
#define rk10q       "q30"
#define rk11        "v31.16b"
#define rk11q       "q31"


static operation_result_t aes_gcm_enc_192_kernel(uint8_t * plaintext,
                                          uint64_t plaintext_length,
                                          cipher_state_t * restrict cs,
                                          uint8_t * ciphertext)
{
    if(plaintext_length == 0) {
        return SUCCESSFUL_OPERATION;
    }

    uint8_t * in_ptr = plaintext;
    uint8_t * out_ptr = ciphertext;
    uint64_t bit_length = plaintext_length;

    __asm __volatile
    (
        //// Initial ////
        "       ld1     { "ctr0b" }, [%[counter]]                           \n" // special case vector load initial counter so we can start first AES block as quickly as possible
        "       add     "end_input_ptr", %[input_ptr], %[bit_length], LSR #3\n" // end_input_ptr
        // load constants
        "       ldr     "rk0q", [%[cc], #0]                                 \n" // load rk0
        "       lsr     "main_end_input_ptr", %[bit_length], #3             \n" // byte_len
        "       ldr     "rk1q", [%[cc], #16]                                \n" // load rk1
        "       sub     "main_end_input_ptr", "main_end_input_ptr", #1      \n" // byte_len - 1
        "       ldr     "rk2q", [%[cc], #32]                                \n" // load rk2
        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 0
        "       ldr     "rk3q", [%[cc], #48]                                \n" // load rk3
        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 1
        "       ldr     "rk4q", [%[cc], #64]                                \n" // load rk4
        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 2
        "       ldr     "rk5q", [%[cc], #80]                                \n" // load rk5
        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 3
        "       ldr     "rk6q", [%[cc], #96]                                \n" // load rk6
        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 4
        "       ldr     "rk7q", [%[cc], #112]                               \n" // load rk7
        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 5
        "       ldr     "rk8q", [%[cc], #128]                               \n" // load rk8
        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 6
        "       ldr     "rk9q", [%[cc], #144]                               \n" // load rk9
        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 7
        "       ldr     "rk10q", [%[cc], #160]                              \n" // load rk10
        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 8
        "       ldr     "rk11q", [%[cc], #176]                              \n" // load rk11
        "       aese    "ctr0b", "rk9"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 0 - round 9
        "       ldp     "rk12_l", "rk12_h", [%[cc], #192]                   \n" // load rk12
        "       aese    "ctr0b", "rk10"   \n  aesmc   "ctr0b", "ctr0b"      \n" // AES block 0 - round 10
        "       aese    "ctr0b", "rk11"                                     \n" // AES block 0 - round 11
        "       ldr     "input_l", [%[input_ptr]], #8                       \n" // AES block 0 - load input low
        "       and     "main_end_input_ptr", "main_end_input_ptr", #0xffffffffffffffc0\n" // number of bytes to be processed in main loop (at least 1 byte must be handled by tail)
        "       ldr     "input_h", [%[input_ptr]], #8                       \n" // AES block 0 - load input high
        "       eor     "input_l", "input_l", "rk12_l"                      \n" // AES block 0 - round 12 low
        "       eor     "input_h", "input_h", "rk12_h"                      \n" // AES block 0 - round 12 high
        "       mov     "res_curr".d[0], "input_l"                          \n" // AES block 0 - mov low
        "       mov     "res_curr".d[1], "input_h"                          \n" // AES block 0 - mov high
        "       eor     "res_currb", "res_currb", "ctr0b"                   \n" // AES block 0 - result
        "       add     "main_end_input_ptr", "main_end_input_ptr", %[input_ptr]\n"

        "       ldr     "h1q", [%[cc], #240]                                \n" // load h1l | h1h
        "       ldr     "h2q", [%[cc], #256]                                \n" // load h2l | h2h
        "       ldr     "h3q", [%[cc], #272]                                \n" // load h3l | h3h
        "       ldr     "h4q", [%[cc], #288]                                \n" // load h4l | h4h
        "       mov     "h1kd", "h1".d[1]                                   \n" // mov   -  | h1l
        "       mov     "h2kd", "h2".d[1]                                   \n" // mov   -  | h2l
        "       mov     "h3kd", "h3".d[1]                                   \n" // mov   -  | h3l
        "       mov     "h4kd", "h4".d[1]                                   \n" // mov   -  | h4l
        "       eor     "h1k".8b, "h1k".8b, "h1".8b                         \n" // eor   -  | h1k
        "       eor     "h2k".8b, "h2k".8b, "h2".8b                         \n" // eor   -  | h2k
        "       eor     "h3k".8b, "h3k".8b, "h3".8b                         \n" // eor   -  | h3k
        "       eor     "h4k".8b, "h4k".8b, "h4".8b                         \n" // eor   -  | h4k

        "       movi    "mod_constant".8b, #0xc2                            \n"
        "       shl     "mod_constantd", "mod_constantd", #56               \n" // mod_constant
        // load counter and current_tag
        "       ldp     "ctr96_b64x", "ctr96_t32x", [%[counter]]            \n" // ctr96_b64, ctr96_t32
        "       lsr     "rctr32x ", "ctr96_t32x", #32                       \n"
        "       orr     "ctr96_t32w", "ctr96_t32w", "ctr96_t32w"            \n"
        "       rev     "rctr32w", "rctr32w"                                \n" // rev_ctr32
        "       add     "rctr32w", "rctr32w", #1                            \n" // increment rev_ctr32
        "       ld1     { "acc_lb" }, [%[current_tag]]                      \n"

        // set up counter for potential second block
        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 1
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 1
        "       ins     "ctr1".d[0], "ctr96_b64x"                           \n" // CTR block 1
        "       ins     "ctr1".d[1], "ctr32x"                               \n" // CTR block 1
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 1

        // possibly jump to end
        // input_ptr vs. end_ptr comparison here
        "       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // LOOP CONTROL
        "       b.ge    2f                                                  \n" // handle tail

        //// Main loop ////
        // parts described above
        "1:                                                                 \n" // main loop start

        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+1 - round 0
        "       ext     "acc_lb", "acc_lb", "acc_lb", #8                    \n" // PRE 0
        "       ldr     "input_l", [%[input_ptr]], #8                       \n" // AES block 4k+1 - load input low

        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+1 - round 1
        "       st1     { "res_currb" }, [%[output_ptr]], #16               \n" // AES block 4k   - store result
        "       ldr     "input_h", [%[input_ptr]], #8                       \n" // AES block 4k+1 - load input high

        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+1 - round 2
        "       rev64   "res_currb", "res_currb"                            \n" // GHASH block 4k
        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 4k+2

        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+1 - round 3
        "       eor     "res_currb", "res_currb", "acc_lb"                  \n" // PRE 1
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 4k+2

        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+1 - round 4
        "       pmull2  "acc_h".1q, "res_curr".2d, "h4".2d                  \n" // GHASH block 4k
        "       eor     "input_l", "input_l", "rk12_l"                      \n" // AES block 4k+1 - round 12 low

        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+1 - round 5
        "       pmull   "acc_l".1q, "res_curr".1d, "h4".1d                  \n" // GHASH block 4k
        "       eor     "input_h", "input_h", "rk12_h"                      \n" // AES block 4k+1 - round 12 high

        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+1 - round 6
        "       ins     "t_m".d[0], "res_curr".d[1]                         \n" // GHASH block 4k
        "       mov     "res_curr".d[1], "input_h"                          \n" // AES block 4k+1 - mov high

        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+1 - round 7
        "       eor     "t_m".8b, "t_m".8b, "res_curr".8b                   \n" // GHASH block 4k
        "       mov     "res_curr".d[0], "input_l"                          \n" // AES block 4k+1 - mov low

        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+1 - round 8
        "       pmull   "acc_m".1q, "t_m".1d, "h4k".1d                      \n" // GHASH block 4k
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 4k+2

        "       aese    "ctr1b", "rk9"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+1 - round 9
        "       ins     "ctr0".d[0], "ctr96_b64x"                           \n" // CTR block 4k+2
        "       ins     "ctr0".d[1], "ctr32x"                               \n" // CTR block 4k+2

        "       aese    "ctr1b", "rk10"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+1 - round 10
        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+2 - round 0

        "       aese    "ctr1b", "rk11"                                     \n" // AES block 4k+1 - round 11
        "       ldr     "input_l", [%[input_ptr]], #8                       \n" // AES block 4k+2 - load input low

        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+2 - round 1
        "       eor     "res_currb", "res_currb", "ctr1b"                   \n" // AES block 4k+1 - result
        "       ldr     "input_h", [%[input_ptr]], #8                       \n" // AES block 4k+2 - load input high

        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+2 - round 2
        "       st1     { "res_currb" }, [%[output_ptr]], #16               \n" // AES block 4k+1 - store result
        "       eor     "input_l", "input_l", "rk12_l"                      \n" // AES block 4k+2 - round 12 low



        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+2 - round 3
        "       rev64   "res_currb", "res_currb"                            \n" // GHASH block 4k+1
        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 4k+3

        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+2 - round 4
        "       pmull2  "t_h".1q, "res_curr".2d, "h3".2d                    \n" // GHASH block 4k+1
        "       eor     "input_h", "input_h", "rk12_h"                      \n" // AES block 4k+2 - round 12 high

        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+2 - round 5
        "       pmull   "t_l".1q, "res_curr".1d, "h3".1d                    \n" // GHASH block 4k+1
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 4k+3

        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+2 - round 6
        "       ins     "t_m".d[0], "res_curr".d[1]                         \n" // GHASH block 4k+1
        "       mov     "res_curr".d[1], "input_h"                          \n" // AES block 4k+2 - mov high

        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+2 - round 7
        "       eor     "t_m".8b, "t_m".8b, "res_curr".8b                   \n" // GHASH block 4k+1
        "       mov     "res_curr".d[0], "input_l"                          \n" // AES block 4k+2 - mov low

        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+2 - round 8
        "       pmull   "t_m".1q, "t_m".1d, "h3k".1d                        \n" // GHASH block 4k+1
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 4k+3

        "       aese    "ctr0b", "rk9"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+2 - round 9
        "       ins     "ctr1".d[0], "ctr96_b64x"                           \n" // CTR block 4k+3
        "       ins     "ctr1".d[1], "ctr32x"                               \n" // CTR block 4k+3

        "       aese    "ctr0b", "rk10"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+2 - round 10
        "       eor     "acc_hb", "acc_hb", "t_h".16b                       \n" // GHASH block 4k+1
        "       ldr     "input_l", [%[input_ptr]], #8                       \n" // AES block 4k+3 - load input low

        "       aese    "ctr0b", "rk11"                                     \n" // AES block 4k+2 - round 11
        "       ldr     "input_h", [%[input_ptr]], #8                       \n" // AES block 4k+3 - load input high

        "       eor     "acc_lb", "acc_lb", "t_l".16b                       \n" // GHASH block 4k+1
        "       eor     "input_l", "input_l", "rk12_l"                      \n" // AES block 4k+3 - round 12 low

        "       eor     "acc_mb", "acc_mb", "t_m".16b                       \n" // GHASH block 4k+1
        "       eor     "input_h", "input_h", "rk12_h"                      \n" // AES block 4k+3 - round 12 high

        "       eor     "res_currb", "res_currb", "ctr0b"                   \n" // AES block 4k+2 - result
        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 4k+4

        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+3 - round 0
        "       st1     { "res_currb" }, [%[output_ptr]], #16               \n" // AES block 4k+2 - store result
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 4k+4



        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+3 - round 1
        "       rev64   "res_currb", "res_currb"                            \n" // GHASH block 4k+2
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 4k+4

        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+3 - round 2
        "       ins     "t_m".d[0], "res_curr".d[1]                         \n" // GHASH block 4k+2
        "       ins     "ctr0".d[0], "ctr96_b64x"                           \n" // CTR block 4k+4

        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+3 - round 3
        "       eor     "t_m".8b, "t_m".8b, "res_curr".8b                   \n" // GHASH block 4k+2
        "       ins     "ctr0".d[1], "ctr32x"                               \n" // CTR block 4k+4

        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+3 - round 4
        "       pmull2  "t_h".1q, "res_curr".2d, "h2".2d                    \n" // GHASH block 4k+2
        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR block 4k+5

        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+3 - round 5
        "       pmull   "t_l".1q, "res_curr".1d, "h2".1d                    \n" // GHASH block 4k+2
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR block 4k+5

        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+3 - round 6
        "       mov     "res_curr".d[1], "input_h"                          \n" // AES block 4k+3 - mov high
        "       mov     "res_curr".d[0], "input_l"                          \n" // AES block 4k+3 - mov low

        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+3 - round 7
        "       pmull   "t_m".1q, "t_m".1d, "h2k".1d                        \n" // GHASH block 4k+2
        "       ldr     "input_l", [%[input_ptr]], #8                       \n" // AES block 4k+4 - load input low

        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+3 - round 8
        "       eor     "acc_hb", "acc_hb", "t_h".16b                       \n" // GHASH block 4k+2
        "       ldr     "input_h", [%[input_ptr]], #8                       \n" // AES block 4k+4 - load input high

        "       aese    "ctr1b", "rk9"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+3 - round 9
        "       eor     "acc_lb", "acc_lb", "t_l".16b                       \n" // GHASH block 4k+2
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR block 4k+5

        "       aese    "ctr1b", "rk10"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES block 4k+3 - round 10
        "       eor     "acc_mb", "acc_mb", "t_m".16b                       \n" // GHASH block 4k+2
        "       eor     "input_l", "input_l", "rk12_l"                      \n" // AES block 4k+4 - round 12 low

        "       aese    "ctr1b", "rk11"                                     \n" // AES block 4k+3 - round 11
        "       cmp     %[input_ptr], "main_end_input_ptr"                  \n" // LOOP CONTROL

        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 0
        "       eor     "res_currb", "res_currb", "ctr1b"                   \n" // AES block 4k+3 - result
        "       eor     "input_h", "input_h", "rk12_h"                      \n" // AES block 4k+4 - round 12 high

        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 1
        "       st1     { "res_currb" }, [%[output_ptr]], #16               \n" // AES block 4k+3 - store result
        "       rev64   "res_currb", "res_currb"                            \n" // GHASH block 4k+3



        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 2
        "       pmull2  "t_h".1q, "res_curr".2d, "h1".2d                    \n" // GHASH block 4k+3

        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 3
        "       pmull   "t_l".1q, "res_curr".1d, "h1".1d                    \n" // GHASH block 4k+3

        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 4
        "       ins     "t_m".d[0], "res_curr".d[1]                         \n" // GHASH block 4k+3
        "       mov     "res_curr".d[1], "input_h"                          \n" // AES block 4k+4 - mov high

        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 5
        "       eor     "t_m".8b, "t_m".8b, "res_curr".8b                   \n" // GHASH block 4k+3
        "       mov     "res_curr".d[0], "input_l"                          \n" // AES block 4k+4 - mov low

        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 6
        "       pmull   "t_m".1q, "t_m".1d, "h1k".1d                        \n" // GHASH block 4k+3

        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 7
        "       eor     "acc_hb", "acc_hb", "t_h".16b                       \n" // GHASH block 4k+3

        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 8
        "       eor     "acc_lb", "acc_lb", "t_l".16b                       \n" // GHASH block 4k+3

        "       aese    "ctr0b", "rk9"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 9
        "       eor     "acc_mb", "acc_mb", "t_m".16b                       \n" // GHASH block 4k+3

        "       aese    "ctr0b", "rk10"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES block 4k+4 - round 10
        "       eor     "acc_mb", "acc_mb", "acc_hb"                        \n" // MODULO - karatsuba tidy up

        "       eor     "acc_mb", "acc_mb", "acc_lb"                        \n" // MODULO - karatsuba tidy up

        "       pmull   "t_h".1q, "acc_h".1d, "mod_constant".1d             \n" // MODULO - top 64b align with mid

        "       aese    "ctr0b", "rk11"                                     \n" // AES block 4k+4 - round 11
        "       ins     "ctr1".d[0], "ctr96_b64x"                           \n" // CTR block 4k+5
        "       ins     "ctr1".d[1], "ctr32x"                               \n" // CTR block 4k+5

        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n" // MODULO - other top alignment

        "       eor     "res_currb", "res_currb", "ctr0b"                   \n" // AES block 4k+4 - result

        "       eor     "acc_mb", "acc_mb", "t_h".16b                       \n" // MODULO - fold into mid
        "       eor     "acc_mb", "acc_mb", "acc_hb"                        \n" // MODULO - fold into mid
        "       pmull   "t_h".1q, "acc_m".1d, "mod_constant".1d             \n" // MODULO - mid 64b align with low
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n" // MODULO - other mid alignment
        "       eor     "acc_lb", "acc_lb", "t_h".16b                       \n" // MODULO - fold into low
        "       eor     "acc_lb", "acc_lb", "acc_mb"                        \n" // MODULO - fold into low

        "       b.lt    1b                                                  \n"

        "2:     sub     "main_end_input_ptr", "end_input_ptr", %[input_ptr] \n" // main_end_input_ptr is number of bytes left to process
        "       ext     "t_h".16b, "acc_lb", "acc_lb", #8                   \n" // prepare final partial tag
        // zero accumulators
        "       movi    "acc_h".8b, #0                                      \n"
        "       movi    "acc_m".8b, #0                                      \n"
        "       movi    "acc_l".8b, #0                                      \n"
        "       cmp     "main_end_input_ptr", #0                            \n"
        "       b.le    5f                                                  \n"
        "       cmp     "main_end_input_ptr", #16                           \n"
        "       b.le    4f                                                  \n"
        "       cmp     "main_end_input_ptr", #32                           \n"
        "       mov     "ctr0b", "ctr1b"                                    \n"
        "       b.le    3f                                                  \n"

        //// Handle tail ////
        // less than 4 blocks, last block possibly not full
        "                                                                   \n" // blocks left >  3
        "       ldr     "input_l", [%[input_ptr]], #8                       \n" // AES final-2 block - load input low

        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final-2 block - round 0
        "       st1     { "res_currb" }, [%[output_ptr]], #16               \n" // AES final-3 block - store result
        "       ldr     "input_h", [%[input_ptr]], #8                       \n" // AES final-2 block - load input high

        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final-2 block - round 1
        "       rev64   "res_currb", "res_currb"                            \n" // GHASH final-3 block
        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR final-1 block

        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final-2 block - round 2
        "       eor     "res_currb", "res_currb", "t_h".16b                 \n" // feed in partial tag
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR final-1 block

        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final-2 block - round 3
        "       pmull2  "acc_h".1q, "res_curr".2d, "h4".2d                  \n" // GHASH final-3 block
        "       eor     "input_l", "input_l", "rk12_l"                      \n" // AES final-2 block - round 12 low

        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final-2 block - round 4
        "       pmull   "acc_l".1q, "res_curr".1d, "h4".1d                  \n" // GHASH final-3 block
        "       eor     "input_h", "input_h", "rk12_h"                      \n" // AES final-2 block - round 12 high

        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final-2 block - round 5
        "       ins     "t_m".d[0], "res_curr".d[1]                         \n" // GHASH final-3 block
        "       mov     "res_curr".d[1], "input_h"                          \n" // AES final-2 block - mov high

        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final-2 block - round 6
        "       eor     "t_m".8b, "t_m".8b, "res_curr".8b                   \n" // GHASH final-3 block
        "       mov     "res_curr".d[0], "input_l"                          \n" // AES final-2 block - mov low

        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final-2 block - round 7
        "       pmull   "acc_m".1q, "t_m".1d, "h4k".1d                      \n" // GHASH final-3 block
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR final-1 block

        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final-2 block - round 8
        "       ins     "ctr0".d[0], "ctr96_b64x"                           \n" // CTR final-1 block
        "       ins     "ctr0".d[1], "ctr32x"                               \n" // CTR final-1 block

        "       aese    "ctr1b", "rk9"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final-2 block - round 9

        "       aese    "ctr1b", "rk10"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final-2 block - round 10

        "       aese    "ctr1b", "rk11"                                     \n" // AES final-2 block - round 11
        "       movi    "t_h".8b, #0                                        \n" // surpress further partial tag feed in

        "       eor     "res_currb", "res_currb", "ctr1b"                   \n" // AES final-2 block - result

        "3:                                                                 \n" // blocks left >  2
        "       ldr     "input_l", [%[input_ptr]], #8                       \n" // AES final-1 block - load input low

        "       aese    "ctr0b", "rk0"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES final-1 block - round 0
        "       st1     { "res_currb" }, [%[output_ptr]], #16               \n" // AES final-2 block - store result
        "       ldr     "input_h", [%[input_ptr]], #8                       \n" // AES final-1 block - load input high

        "       aese    "ctr0b", "rk1"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES final-1 block - round 1
        "       rev64   "res_currb", "res_currb"                            \n" // GHASH final-2 block
        "       rev     "ctr32w", "rctr32w"                                 \n" // CTR final block

        "       aese    "ctr0b", "rk2"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES final-1 block - round 2
        "       eor     "res_currb", "res_currb", "t_h".16b                 \n" // feed in partial tag
        "       orr     "ctr32x", "ctr96_t32x", "ctr32x", lsl #32           \n" // CTR final block

        "       aese    "ctr0b", "rk3"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES final-1 block - round 3
        "       pmull2  "t_h".1q, "res_curr".2d, "h3".2d                    \n" // GHASH final-2 block
        "       eor     "input_l", "input_l", "rk12_l"                      \n" // AES final-1 block - round 12 low

        "       aese    "ctr0b", "rk4"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES final-1 block - round 4
        "       pmull   "t_l".1q, "res_curr".1d, "h3".1d                    \n" // GHASH final-2 block
        "       eor     "input_h", "input_h", "rk12_h"                      \n" // AES final-1 block - round 12 high

        "       aese    "ctr0b", "rk5"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES final-1 block - round 5
        "       ins     "t_m".d[0], "res_curr".d[1]                         \n" // GHASH final-2 block
        "       mov     "res_curr".d[1], "input_h"                          \n" // AES final-1 block - mov high

        "       aese    "ctr0b", "rk6"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES final-1 block - round 6
        "       eor     "t_m".8b, "t_m".8b, "res_curr".8b                   \n" // GHASH final-2 block
        "       mov     "res_curr".d[0], "input_l"                          \n" // AES final-1 block - mov low

        "       aese    "ctr0b", "rk7"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES final-1 block - round 7
        "       pmull   "t_m".1q, "t_m".1d, "h3k".1d                        \n" // GHASH final-2 block
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR final block

        "       aese    "ctr0b", "rk8"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES final-1 block - round 8
        "       ins     "ctr1".d[0], "ctr96_b64x"                           \n" // CTR final block
        "       ins     "ctr1".d[1], "ctr32x"                               \n" // CTR final block

        "       aese    "ctr0b", "rk9"   \n  aesmc   "ctr0b", "ctr0b"       \n" // AES final-1 block - round 9
        "       eor     "acc_hb", "acc_hb", "t_h".16b                       \n" // GHASH final-2 block

        "       aese    "ctr0b", "rk10"  \n  aesmc   "ctr0b", "ctr0b"       \n" // AES final-1 block - round 10
        "       eor     "acc_lb", "acc_lb", "t_l".16b                       \n" // GHASH final-2 block

        "       aese    "ctr0b", "rk11"                                     \n" // AES final-1 block - round 11
        "       eor     "acc_mb", "acc_mb", "t_m".16b                       \n" // GHASH final-2 block

        "       movi    "t_h".8b, #0                                        \n" // surpress further partial tag feed in

        "       eor     "res_currb", "res_currb", "ctr0b"                   \n" // AES final-1 block - result

        "4:                                                                 \n" // blocks left >  1
        "       ldr     "input_l", [%[input_ptr]], #8                       \n" // AES final block - load input low



        "       aese    "ctr1b", "rk0"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final block - round 0
        "       st1     { "res_currb" }, [%[output_ptr]], #16               \n" // AES final-1 block - store result
        "       ldr     "input_h", [%[input_ptr]], #8                       \n" // AES final block - load input high

        "       aese    "ctr1b", "rk1"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final block - round 1
        "       rev64   "res_currb", "res_currb"                            \n" // GHASH final-1 block
        "       add     "rctr32w", "rctr32w", #1                            \n" // CTR rctr32w tidy-up

        "       aese    "ctr1b", "rk2"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final block - round 2
        "       eor     "res_currb", "res_currb", "t_h".16b                 \n" // feed in partial tag

        "       aese    "ctr1b", "rk3"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final block - round 3
        "       pmull2  "t_h".1q, "res_curr".2d, "h2".2d                    \n" // GHASH final-1 block
        "       eor     "input_l", "input_l", "rk12_l"                      \n" // AES final block - round 12 low

        "       aese    "ctr1b", "rk4"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final block - round 4
        "       pmull   "t_l".1q, "res_curr".1d, "h2".1d                    \n" // GHASH final-1 block
        "       eor     "input_h", "input_h", "rk12_h"                      \n" // AES final block - round 12 high

        "       aese    "ctr1b", "rk5"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final block - round 5
        "       ins     "t_m".d[0], "res_curr".d[1]                         \n" // GHASH final-1 block
        "       mov     "res_curr".d[1], "input_h"                          \n" // AES final block - mov high

        "       aese    "ctr1b", "rk6"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final block - round 6
        "       eor     "t_m".8b, "t_m".8b, "res_curr".8b                   \n" // GHASH final-1 block
        "       mov     "res_curr".d[0], "input_l"                          \n" // AES final block - mov low

        "       aese    "ctr1b", "rk7"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final block - round 7
        "       pmull   "t_m".1q, "t_m".1d, "h2k".1d                        \n" // GHASH final-1 block

        "       aese    "ctr1b", "rk8"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final block - round 8
        "       eor     "acc_hb", "acc_hb", "t_h".16b                       \n" // GHASH final-1 block

        "       aese    "ctr1b", "rk9"   \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final block - round 9
        "       eor     "acc_lb", "acc_lb", "t_l".16b                       \n" // GHASH final-1 block

        "       aese    "ctr1b", "rk10"  \n  aesmc   "ctr1b", "ctr1b"       \n" // AES final block - round 10
        "       eor     "acc_mb", "acc_mb", "t_m".16b                       \n" // GHASH final-1 block

        "       aese    "ctr1b", "rk11"                                     \n" // AES final block - round 11
        "       movi    "t_h".8b, #0                                        \n" // surpress further partial tag feed in

        "       eor     "res_currb", "res_currb", "ctr1b"                   \n" // AES final block - result

        "5:                                                                 \n" // blocks left <= 1
        "       ld1     { "rk0" }, [%[output_ptr]]                          \n" // load existing bytes where the possibly partial last block is to be stored
        "       sub     "rctr32w", "rctr32w", #1                            \n" // CTR rctr32w tidy-up
        // mask out bits of res_curr which are not used
        "       and     %[bit_length], %[bit_length], #127                  \n" // bit_length %= 128
        "       mvn     "rk12_h", xzr                                       \n" // rk12_h = 0xffffffffffffffff
        "       sub     %[bit_length], %[bit_length], #128                  \n" // bit_length -= 128
        "       mvn     "rk12_l", xzr                                       \n" // rk12_l = 0xffffffffffffffff
        "       neg     %[bit_length], %[bit_length]                        \n" // bit_length = 128 - #bits in input (in range [1,128])
        "       rev     "ctr32w", "rctr32w"                                 \n"
        "       and     %[bit_length], %[bit_length], #127                  \n" // bit_length %= 128
        "       str     "ctr32w", [%[counter], #12]                         \n" // store the updated counter
        "       lsr     "rk12_h", "rk12_h", %[bit_length]                   \n" // rk12_h is mask for top 64b of last block
        "       cmp     %[bit_length], #64                                  \n"
        "       csel    "input_l", "rk12_l", "rk12_h", lt                   \n"
        "       csel    "input_h", "rk12_h", xzr, lt                        \n"
        "       mov     "ctr0".d[0], "input_l"                              \n" // ctr0b is mask for last block
        "       mov     "ctr0".d[1], "input_h"                              \n"
        "       and     "res_currb", "res_currb", "ctr0b"                   \n" // possibly partial last block has zeroes in highest bits
        // end mask out bits of res_curr which are not used

        "       rev64   "ctr1b", "res_currb"                                \n" // GHASH final block
        "       eor     "ctr1b", "ctr1b", "t_h".16b                         \n" // feed in partial tag
        "       ins     "t_m".d[0], "ctr1".d[1]                             \n" // GHASH final block
        "       eor     "t_m".8b, "t_m".8b, "ctr1".8b                       \n" // GHASH final block
        "       pmull2  "t_h".1q, "ctr1".2d, "h1".2d                        \n" // GHASH final block
        "       pmull   "t_l".1q, "ctr1".1d, "h1".1d                        \n" // GHASH final block
        "       pmull   "t_m".1q, "t_m".1d, "h1k".1d                        \n" // GHASH final block
        "       eor     "acc_hb", "acc_hb", "t_h".16b                       \n" // GHASH final block
        "       eor     "acc_lb", "acc_lb", "t_l".16b                       \n" // GHASH final block
        "       eor     "acc_mb", "acc_mb", "t_m".16b                       \n" // GHASH final block

        "       bif     "res_currb", "rk0", "ctr0b"                         \n" // insert existing bytes in top end of result before storing
        "       st1     { "res_currb" }, [%[output_ptr]]                    \n" // store all 16B

        // final modulo
        "       eor     "acc_mb", "acc_mb", "acc_hb"                        \n" // karatsuba tidy up
        "       eor     "acc_mb", "acc_mb", "acc_lb"                        \n"
        "       pmull   "t_h".1q, "acc_h".1d, "mod_constant".1d             \n"
        "       ext     "acc_hb", "acc_hb", "acc_hb", #8                    \n"
        "       eor     "acc_mb", "acc_mb", "t_h".16b                       \n"
        "       eor     "acc_mb", "acc_mb", "acc_hb"                        \n"
        "       pmull   "t_h".1q, "acc_m".1d, "mod_constant".1d             \n"
        "       ext     "acc_mb", "acc_mb", "acc_mb", #8                    \n"
        "       eor     "acc_lb", "acc_lb", "t_h".16b                       \n"
        "       eor     "acc_lb", "acc_lb", "acc_mb"                        \n"

        "6:     st1     { "acc_l".16b }, [%[current_tag]]                   \n"


        : [input_ptr] "+r" (in_ptr), [output_ptr] "+r" (out_ptr),
          [bit_length] "+r" (bit_length)
        : [cc] "r" (cs->constants->expanded_aes_keys[0].b), [counter] "r" (cs->counter.b), [current_tag] "r" (cs->current_tag.b)
        : "v0",  "v1",  "v2",  "v3",  "v4",  "v5",  "v6",  "v7",  "v8",  "v9",  "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
          "x4",  "x5",  "x6",  "x7",  "x9",  "x10", "x11", "x12", "x13", "x14"
    );

    return SUCCESSFUL_OPERATION;
}

#undef end_input_ptr
#undef main_end_input_ptr
#undef output_l
#undef output_h

#undef ctr32w
#undef ctr32x
#undef ctr96_b64x
#undef ctr96_t32w
#undef ctr96_t32x
#undef rctr32w
#undef rctr32x

#undef rk12_l
#undef rk12_h

#undef ctr0b
#undef ctr0
#undef ctr1b
#undef ctr1
#undef res_currb
#undef res_curr

#undef t_h
#undef t_m
#undef t_l

#undef acc_hb
#undef acc_h
#undef acc_mb
#undef acc_m
#undef acc_lb
#undef acc_l

#undef h1
#undef h1q
#undef h1d
#undef h1k
#undef h1kd
#undef h2
#undef h2q
#undef h2d
#undef h2k
#undef h2kd
#undef h3
#undef h3q
#undef h3d
#undef h3k
#undef h3kd
#undef h4
#undef h4q
#undef h4d
#undef h4k
#undef h4kd

#undef mod_constantd
#undef mod_constant

#undef rk0
#undef rk0q
#undef rk1
#undef rk1q
#undef rk2
#undef rk2q
#undef rk3
#undef rk3q
#undef rk4
#undef rk4q
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
