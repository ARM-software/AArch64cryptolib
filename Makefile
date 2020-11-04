#
#   BSD LICENSE
#
#   Copyright (C) Cavium networks Ltd. 2016.
#   Copyright (c) 2019-2020 Arm Limited
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Cavium networks nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

SRCDIR := ${CURDIR}
OBJDIR := ${CURDIR}/obj
PCDIR := ${CURDIR}/pkgconfig

#DEFINE += -DTEST_DEBUG

# build flags
CC = gcc
CFLAGS += -O3
CFLAGS += -Wall -static
CFLAGS += -I$(SRCDIR)
CFLAGS += -march=armv8-a+simd+crypto
CFLAGS += -flax-vector-conversions
CFLAGS += $(DEFINE)
CFLAGS += $(EXTRA_CFLAGS)

# Customizable optimization flags
ifneq (,$(filter $(OPT),little LITTLE))
CFLAGS += -DPERF_GCM_LITTLE -mtune=cortex-a53
else ifeq ($(OPT),big)
CFLAGS += -DPERF_GCM_BIG -mtune=cortex-a57
else
endif

# library AES-CBC c files
SRCS += $(SRCDIR)/AArch64cryptolib_aes_cbc.c
# library AES-CBC asm files
SRCS += $(SRCDIR)/AArch64cryptolib_opt_big/aes/aes_core.S
SRCS += $(SRCDIR)/AArch64cryptolib_opt_big/sha1/sha1_core.S
SRCS += $(SRCDIR)/AArch64cryptolib_opt_big/sha256/sha256_core.S
SRCS += $(SRCDIR)/AArch64cryptolib_opt_big/aes_cbc_sha1/aes128cbc_sha1_hmac.S
SRCS += $(SRCDIR)/AArch64cryptolib_opt_big/aes_cbc_sha256/aes128cbc_sha256_hmac.S
SRCS += $(SRCDIR)/AArch64cryptolib_opt_big/aes_cbc_sha1/sha1_hmac_aes128cbc_dec.S
SRCS += $(SRCDIR)/AArch64cryptolib_opt_big/aes_cbc_sha256/sha256_hmac_aes128cbc_dec.S
# library AES-GCM c files
SRCS += $(SRCDIR)/AArch64cryptolib_aes_gcm.c

OBJS  := $(SRCS:.S=.o)
OBJS  += $(SRCS:.c=.o)

# List of unit test executable files
TEST_TARGETS = aesgcm_test_functional aesgcm_test_speed aescbc_test_functional aescbc_test_speed
TEST_SRCS += $(SRCDIR)/test/aesgcm_test_functional.c
TEST_SRCS += $(SRCDIR)/test/aesgcm_test_speed.c
TEST_SRCS += $(SRCDIR)/test/aescbc_test_functional.c
TEST_SRCS += $(SRCDIR)/test/aescbc_test_speed.c
TEST_OBJS += $(TEST_SRCS:.c=.o)

# pkg-config metadata
PACKAGE_NAME=libAArch64crypto
PACKAGE_DESCRIPTION=AArch64 Crypto Library
PACKAGE_URL=https://github.com/ARM-software/AArch64cryptolib
PACKAGE_VERSION=20.01
PKGCONFIG = ${PCDIR}/${PACKAGE_NAME}.pc

all: libAArch64crypto.a $(TEST_TARGETS) $(PACKAGE_NAME).pc

.PHONY:	clean
clean:
	@rm -rf $(SRCDIR)/assym.s *.a $(OBJDIR) $(TEST_TARGETS) ${PCDIR}

$(TEST_TARGETS): $(TEST_OBJS) libAArch64crypto.a
	@echo "--- Linking $@"
	$(CC) $(CFLAGS) -L$(SRCDIR) $(OBJDIR)/$(addsuffix .o,$@) -lAArch64crypto -o $@

# build-time generated assembly symbols
assym.s: genassym.c
	@$(CC) $(CFLAGS) -O0 -S $< -o - | \
		awk '($$1 == "<genassym>") { print "#define " $$2 "\t" $$3 }' > \
		$(SRCDIR)/$@
$(OBJDIR):
	mkdir $(OBJDIR)

%.o: %.S $(OBJDIR) assym.s
	$(CC) $(CFLAGS) -c $< -o $(OBJDIR)/$(notdir $@)

%.o: %.c $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $(OBJDIR)/$(notdir $@)


libAArch64crypto.a: $(OBJS)
	ar -rcs $@ $(OBJDIR)/*.o

$(PACKAGE_NAME).pc:
	mkdir ${PCDIR}
	@echo '--- Creating pkg-config file'
	@echo 'prefix='$(shell pwd) >> ${PKGCONFIG}
	@echo 'exec_prefix=$${prefix}' >> ${PKGCONFIG}
	@echo 'libdir=$${prefix}' >> ${PKGCONFIG}
	@echo 'includedir=$${prefix}' >> ${PKGCONFIG}
	@echo '' >> ${PKGCONFIG}
	@echo 'Name: '$(PACKAGE_NAME) >> ${PKGCONFIG}
	@echo 'Description: '$(PACKAGE_DESCRIPTION) >> ${PKGCONFIG}
	@echo 'URL: '$(PACKAGE_URL) >> ${PKGCONFIG}
	@echo 'Version: '$(PACKAGE_VERSION) >> ${PKGCONFIG}
	@echo 'Libs: -L$${libdir} -lAArch64crypto' >> ${PKGCONFIG}
	@echo 'Cflags: -I$${includedir}' >> ${PKGCONFIG}
