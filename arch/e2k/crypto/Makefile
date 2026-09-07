# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2026 MCST

#
# E2K crypto algorithms
#

# Enable to use compiler headers for SIMD intrinsics
subdir-ccflags-y += -isystem $(shell $(CC) -print-file-name=include)

obj-$(CONFIG_CRYPTO_CHACHA_E2K)		+= chacha-e2k.o
chacha-e2k-y := chacha-e2kv6.o chacha-e2kv3.o chacha-glue.o

obj-$(CONFIG_CRYPTO_CRC32C_E2K)		+= crc32c-e2k.o
crc32c-e2k-y := crc32c-e2kv6.o crc32c-glue.o

# Disable compiler IR blocks size limit
CFLAGS_chacha-e2kv3.o	+= $(call lcc-option,-fblock-size-limit=65535)
CFLAGS_chacha-e2kv6.o	+= $(call lcc-option,-fblock-size-limit=65535)
CFLAGS_crc32c-e2kv6.o	+= $(call lcc-option,-fblock-size-limit=65535)

CFLAGS_REMOVE_chacha-e2kv3.o = $(CFLAGS_ALL_CPUS)
CFLAGS_chacha-e2kv3.o	+= -march=elbrus-v3
CFLAGS_REMOVE_chacha-e2kv6.o = $(CFLAGS_ALL_CPUS)
CFLAGS_chacha-e2kv6.o	+= -march=elbrus-v6

CFLAGS_REMOVE_crc32c-e2kv6.o = $(CFLAGS_ALL_CPUS)
CFLAGS_crc32c-e2kv6.o	+= -march=elbrus-v6
