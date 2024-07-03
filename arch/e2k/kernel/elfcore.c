/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/elf.h>
#include <linux/coredump.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/binfmts.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/uaccess.h>

#include <asm/elf.h>
#include <asm/copy-hw-stacks.h>
/*
 * from file binfmt_elf.c
 */

static struct vm_area_struct *first_vma(struct task_struct *tsk,
					struct vm_area_struct *gate_vma)
{
	struct vm_area_struct *ret = tsk->mm->mmap;

	if (ret)
		return ret;
	return gate_vma;
}
/*
 * Helper function for iterating across a vma list.  It ensures that the caller
 * will visit `gate_vma' prior to terminating the search.
 */
static struct vm_area_struct *next_vma(struct vm_area_struct *this_vma,
					struct vm_area_struct *gate_vma)
{
	struct vm_area_struct *ret;

	ret = this_vma->vm_next;
	if (ret)
		return ret;
	if (this_vma == gate_vma)
		return NULL;
	return gate_vma;
}

/*
 * Support for tags dumping
 */

Elf64_Half elf_core_extra_phdrs(void)
{
	struct pt_regs *regs = find_host_regs(current_thread_info()->pt_regs);

	/*
	 * Dump all user registers
	 */
	if (regs)
		do_user_hw_stacks_copy_full(&regs->stacks, regs, NULL);

	return current->mm->map_count;
}

int elf_core_write_extra_phdrs(struct coredump_params *cprm, loff_t offset)
{
	struct elf_phdr phdr;
	struct vm_area_struct *vma;
	unsigned long mm_flags = cprm->mm_flags;
	struct vm_area_struct *gate_vma = get_gate_vma(current->mm);

	for (vma = first_vma(current, gate_vma); vma != NULL;
			vma = next_vma(vma, gate_vma)) {
		phdr.p_type = PT_E2K_TAGS;
		phdr.p_offset = offset;
		phdr.p_vaddr = vma->vm_start;
		phdr.p_paddr = 0;
		phdr.p_filesz = vma_dump_size(vma, mm_flags) / 16;
		phdr.p_memsz = 0;
		offset += phdr.p_filesz;
		phdr.p_flags = 0;
		phdr.p_align = 1;
		if (!dump_emit(cprm, &phdr, sizeof(phdr)))
			return 0;
	}
	return 1;
}

int elf_core_write_extra_data(struct coredump_params *cprm)
{
	struct vm_area_struct *vma;
	unsigned long mm_flags = cprm->mm_flags;
	struct vm_area_struct *gate_vma = get_gate_vma(current->mm);
	unsigned long addr;
	unsigned long end;
	struct page *page;
	int stop;

	for (vma = first_vma(current, gate_vma); vma != NULL;
			vma = next_vma(vma, gate_vma)) {
		end = vma->vm_start + vma_dump_size(vma, mm_flags);
		for (addr = vma->vm_start; addr < end; addr += PAGE_SIZE) {
			page = get_dump_page(addr);
			if (page) {
				/* 2 bytes of tags correspond
				 * to 32 bytes of data */
				u16 tags[PAGE_SIZE / 32];
				void *kaddr = kmap(page);
				int i;

				for (i = 0; i < PAGE_SIZE / 32; i++) {
					extract_tags_32(&tags[i],
							kaddr + 32 * i);
				}
				stop = !dump_emit(cprm, tags, sizeof(tags));
				kunmap(page);
				put_page(page);
			} else {
				/* The last pages of CUT are not allocated
				 * and they might be skipped in tags section
				 * of core file, so we have to write the very
				 * last page to make sure that core file size
				 * is the same as declared in ELF headers. */
				if (addr == end - PAGE_SIZE) {
					stop = !dump_emit(cprm,
						(void *)empty_zero_page,
						PAGE_SIZE / 16);
				} else {
					stop = !dump_skip(cprm, PAGE_SIZE / 16);
				}
			}
			if (stop)
				return 0;
		}
	}
	return 1;
}

size_t elf_core_extra_data_size(struct coredump_params *cprm)
{
	struct vm_area_struct *vma;
	unsigned long mm_flags = cprm->mm_flags;
	struct vm_area_struct *gate_vma = get_gate_vma(current->mm);
	unsigned long addr;
	unsigned long end;
	size_t size = 0;

	for (vma = first_vma(current, gate_vma); vma != NULL;
			vma = next_vma(vma, gate_vma)) {
		end = vma->vm_start + vma_dump_size(vma, mm_flags);
		for (addr = vma->vm_start; addr < end; addr += PAGE_SIZE) {
			size += PAGE_SIZE / 16;
		}
	}
	return size;
}
