#
# Makefile for the linux E2K-specific parts of the memory manager.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#
# Note 2! The CFLAGS definition is now in the main makefile...

obj-y	 := init.o fault.o mmap.o mmu.o memory.o ioremap.o pageattr.o \
	    pgtable.o

obj-$(CONFIG_SOFTWARE_SWAP_TAGS) += tag_mem.o
obj-$(CONFIG_SWAP) += page_io.o
obj-$(CONFIG_HUGETLB_PAGE) += hugetlbpage.o
obj-$(CONFIG_NUMA) += node_vmap.o
