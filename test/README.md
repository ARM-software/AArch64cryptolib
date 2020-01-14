# Copyright (c) 2018-2019, ARM Limited. All rights reserved.
#
# SPDX-License-Identifier:        BSD-3-Clause

# Building Included Testing Applications
`./make all` at top level directory will build binaries for a functional and speed test for each crypto algorithm

To enable output of debug messages, add flag `DEFINE=-DTEST_DEBUG`

# Functional Test
* `aesgcm_test_functional <reference_file>`
* `aescbc_test_functional <reference_file>`

These binaries take a single .rsp file as input and tests all the applicable flavours of encryption and decryption for the given target, printing out inconsistencies or errors if they are detected.

Provided in the `testvectors__NIST_aesgcm` and `testvectors__NIST_aescbc` directories are the testvectors provided by NIST. These tests only exercise a small number of the possible paths in the code, with predominantly small inputs being tested. It also doesn't check the computed one's complement checksum for the IPsec variants of AES-GCM.

Additionally, the `SL_functional_tests.rsp` tests a larger range of inputs sizes, and test the checksum functionality.

# Performance Test
* `aesgcm_test_speed <reference_file> <test_count default=1000000> <encrypt default=1> <IPsec default=1> <overwrite_buffer_length default=reference_size>`
* `aescbc_test_speed <reference_file> <test_count default=1000000> <encrypt default=1> <overwrite_buffer_length default=reference_size>`

These binaries take a number of ordered parameters with the intent to allow the user to measure the average performance of specific modes of AArch64cryptolib functionality with a tool such as perf. A number of reference files are provided in the `testvectors__speed` directory.

An example of usage is as follows:
```bash
$ perf stat taskset -c 1 ./aesgcm_test_speed test/testvectors__speed_aesgcm/speedtest256_16384.rsp 1000000 1 0 16384
Using reference file test/testvectors__speed_aesgcm/speedtest256_16384.rsp
Encrypt - Generic
1000000 runs
16384 bytes
Result is Success

 Performance counter stats for 'taskset -c 1 ./aesgcm_test_speed test/testvectors__speed_aesgcm/speedtest256_16384.rsp 1000000 1 0 16384':

      11680.133832      task-clock:u (msec)       #    0.999 CPUs utilized
                 0      context-switches:u        #    0.000 K/sec
                 0      cpu-migrations:u          #    0.000 K/sec
                38      page-faults:u             #    0.003 K/sec
       23346878718      cycles:u                  #    1.999 GHz
       53327865537      instructions:u            #    2.28  insn per cycle
   <not supported>      branches:u
           1015755      branch-misses:u           #    0.00% of all branches

      11.696282334 seconds time elapsed
```
In this example we encrypted 16384 bytes 1000000 times (131.072 Gb) with AES-GCM-256. We measured it took 11.696 seconds - so we have a rate of 11.206 Gb/s. Using the reported cycle count, we can also see we achieved ~0.702 B/cycle.

This is a synthetic test, and as we are reusing the same memory regions repeatedly the performance in a real application may be lower - but for reasonably sized buffers, it would be expected that the performance should not degrade very much, as HW prefetchers should find it easy to hide memory latency for such a linear access pattern.

# License
Files in folder `testvectors__NIST_aesgcm` and `testvectors__NIST_aescbc` are downloaded from NIST:

https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/

For other files, please refer to file header for license info.

# Authors
* Samuel Lee
* Ruifeng Wang (ruifeng.wang@arm.com)
