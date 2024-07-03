 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
#
# Makefile for the linux E2K-specific parts of the memory manager.
#

subdir-ccflags-y := -Werror -Wswitch -Wenum-compare

obj-y	 := init.o fault.o mmap.o mmu.o memory.o ioremap.o pageattr.o \
	    pgtable.o tlbflush.o

obj-$(CONFIG_SOFTWARE_SWAP_TAGS) += tag_mem.o
obj-$(CONFIG_SWAP) += page_io.o
obj-$(CONFIG_HUGETLB_PAGE) += hugetlbpage.o
obj-$(CONFIG_TRACE_PT_ATOMIC) += pgtable-atomic.o
obj-$(CONFIG_DEBUG_VIRTUAL) += physaddr.o
