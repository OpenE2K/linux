/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/crash_dump.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/uio.h>
#include <linux/highmem-internal.h>

ssize_t copy_oldmem_page(struct iov_iter *iter, unsigned long pfn,
			 size_t csize, unsigned long offset)
{
	phys_addr_t paddr = __pfn_to_phys(pfn);
	void *vaddr = __va(paddr);

	if (!csize)
		return 0;

	return copy_to_iter(vaddr + offset, csize, iter);
}

ssize_t elfcorehdr_read(char *buf, size_t count, u64 *ppos)
{
	memcpy(buf, __va(*ppos), count);
	*ppos += count;

	return count;
}

ssize_t elfcorehdr_read_notes(char *buf, size_t count, u64 *ppos)
{
	memcpy(buf, __va((void *)*ppos), count);
	*ppos += count;
	return count;
}
