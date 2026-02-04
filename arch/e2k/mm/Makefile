# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

#
# Makefile for the linux E2K-specific parts of the memory manager.
#

obj-y	 := init.o fault.o mmap.o mmu.o memory.o ioremap.o pageattr.o \
	    pgtable.o tlbflush.o page_tags.o fmempool.o pool.o

obj-$(CONFIG_SWAP) += swap.o
obj-$(CONFIG_HUGETLB_PAGE) += hugetlbpage.o
obj-$(CONFIG_STRICT_KERNEL_RWX) += ptdump.o
obj-$(CONFIG_TRACE_PT_ATOMIC) += pgtable-atomic.o
obj-$(CONFIG_DEBUG_VIRTUAL) += physaddr.o
KASAN_SANITIZE_physaddr.o := n
obj-$(CONFIG_TEST_PAGE_OFFSET_PAGE_COLLAPSE) += test_collapse.o
obj-$(CONFIG_KASAN) += kasan_init.o
KASAN_SANITIZE_kasan_init.o := n
obj-$(CONFIG_TEST_KERNEL_PT_SYNC) += test_kernel_pt_sync.o
obj-$(CONFIG_TEST_POOL) += test_pool.o
