AArch64cryptolib
====

# Purpose
AArch64cryptolib is a from scratch implementation of cryptographic primitives aiming for optimal performance on Arm A-class cores.

The core concept of the AES-GCM implementations is to optimally schedule a "merged" AES-GCM kernel to make effective use of the available pipeline resources in existing CPUs.

Current optimisation targets:

1. LITTLE (Cortex-A53, Cortex-A55).
2. big (Cortex-A57, Cortex-A72, Cortex-A75, Cortex-A76 and Neoverse N1).
2. bigger (Neoverse V1).
3. biggereor3 (Neoverse V1).

# Functionality
The library currently supports:

* AES-GCM
    * Encrypt and decrypt
    * 128b, 192b, and 256b keys
    * Bespoke IPsec variants which make some domain specific assumptions, and merges UDP checksum into AES-GCM decryption

* AES-CBC
    * Encrypt and decrypt
	* 128b key
	* SHA-1 and SHA-256 hash
	* Chained cipher + auth

# Structure
AArch64cryptolib consists of:

1. A header file (AArch64cryptolib.h) with the interface to the library
2. Top implementation files (AArch64cryptolib_aes_gcm.c, AArch64cryptolib_aes_cbc.c) which provide several C functions supporting the library
3. Several asm optimised functions (in AArch64cryptolib\_\* folders) which target big, bigger and LITTLE microarchitectures, and are included inline in AArch64cryptolib_*.c when the pertinent compilation flags are set

# Usage
## Source files
Users of AArch64cryptolib have to include AArch64cryptolib.h in their source file and use the API described in that file.

## Building library
* Native compilation with GCC basically need _make_
* To cross compile, use CROSS flag and point it to your cross compiler. e.g. _make CROSS=aarch64-linux-gnu-_

## Compiler flags
Select one of the code paths optimised for big or LITTLE CPU implementations:

1. OPT=little
2. OPT=big
3. OPT=bigger
4. OPT=biggereor3

Add extra compiler flags or override default flags:

* EXTRA_CFLAGS=

# Requirements
The implementation requires the Armv8a _Cryptography Extensions_.
The biggereor3 implementation option requires the Armv8.2a _SHA3 extension_.

# Restrictions
The choice of AES-GCM implementation is done at compile time.

# License
SPDX BSD-3-Clause

See the included file 'LICENSE.md' for the license text.

# Original Authors
* Samuel Lee (AES-GCM)
* Zbigniew Bodek (AES-CBC)

# Maintainer
Ola Liljedahl (ola.liljedahl@arm.com)
