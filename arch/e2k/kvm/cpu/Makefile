 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
CFLAGS_REMOVE_iset_v3.o = $(CFLAGS_ALL_CPUS)
CFLAGS_REMOVE_iset_v5.o = $(CFLAGS_ALL_CPUS)
CFLAGS_REMOVE_iset_v6.o = $(CFLAGS_ALL_CPUS)

CFLAGS_iset_v3.o := -march=elbrus-v3
CFLAGS_iset_v5.o := -march=elbrus-v5
CFLAGS_iset_v6.o := -march=elbrus-v6

obj-$(CONFIG_VIRTUALIZATION) := iset_v3.o iset_v5.o iset_v6.o
