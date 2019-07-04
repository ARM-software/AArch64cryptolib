AArch64cryptolib
====

# Purpose
AArch64cryptolib is a from scratch implementation of cryptographic primitives aiming for optimal performance on Arm A-class cores.

The core concept of the AES-GCM implementations is to optimally schedule a "merged" AES-GCM kernel to make effective use of the available pipeline resources in existing CPUs.

Current optimisation targets:
1. LITTLE (Cortex-A53, Cortex-A55 and Neoverse-E1).
2. big (Cortex-A57, Cortex-A72, Cortex-A75, Cortex-A76 and Neoverse-N1).

# Functionality
The library currently supports:
* AES-GCM
    * Encrypt and decrypt
    * 128b, 192b, and 256b keys
    * Bespoke IPsec variants which make some domain specific assumptions, and merges UDP checksum into AES-GCM decryption

# Structure
AArch64cryptolib consists of:
1. A header file (AArch64cryptolib.h) with the interfaces to the library
2. A top implementation file (aesgcm\_AArch64cryptolib.c) which provides several C functions supporting the library
3. Several asm optimised functions (in AArch64cryptolib\_\* folders) which target big and LITTLE microarchitectures, and are included inline in aesgcm\_AArch64cryptolib.c when the pertinent compilation flags are set

# Usage
## Source files
Users of AArch64cryptolib have to include AArch64cryptolib.h in their source file and use the API described in that file.

## Compiler flags
Select one of the code paths optimised for big or LITTLE CPU implementations:
1. -DPERF\_GCM\_BIG
2. -DPERF\_GCM\_LITTLE

Enable use of SIMD and crypto instructions:
* -march=armv8-a+simd+crypto

# Requirements
The implementation requires the Armv8 _Cryptography Extensions_.

# Restrictions
The big/little selection is done at compile time.

# License
SPDX BSD-3-Clause
See the included file 'LICENSE.md' for the license text.

# Author
Samuel Lee

# Maintainer
Ola Liljedahl (ola.liljedahl@arm.com)
