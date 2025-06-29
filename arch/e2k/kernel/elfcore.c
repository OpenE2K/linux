/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/elfcore.h>
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
 * Support for tags and cokors dumping
 */

#define MEM_HAS_COLORS	(cpu_has(CPU_FEAT_ISET_V7) && !cpu_has(CPU_FEAT_E48C_MAKET) && \
				TASK_IS_PROTECTED(current))

Elf64_Half elf_core_extra_phdrs(struct coredump_params *cprm)
{
	struct pt_regs *regs = cprm->regs;

	/*
	 * Dump all user registers
	 */
	if (regs)
		do_user_hw_stacks_copy_full(&regs->stacks, regs, NULL);

	return current->mm->map_count;
}

static int elf_core_write_color_phdrs(struct coredump_params *cprm, loff_t offset)
{
	struct elf_phdr phdr;
	struct vm_area_struct *vma = NULL;
	unsigned long mm_flags = cprm->mm_flags;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *gate_vma = get_gate_vma(mm);
	MA_STATE(mas, &mm->mm_mt, 0, 0);

	while ((vma = coredump_next_vma(&mas, vma, gate_vma)) != NULL) {
		phdr.p_type = PT_E2K_COLORS;
		phdr.p_offset = offset;
		phdr.p_vaddr = vma->vm_start;
		phdr.p_paddr = 0;
		phdr.p_filesz = vma_dump_size(vma, mm_flags) / 32;
		phdr.p_memsz = 0;
		offset += phdr.p_filesz;
		phdr.p_flags = 0;
		phdr.p_align = 1;
		if (!dump_emit(cprm, &phdr, sizeof(phdr)))
			return 0;
	}
	return 1;
}

int elf_core_write_extra_phdrs(struct coredump_params *cprm, loff_t offset)
{
	struct elf_phdr phdr;
	struct vm_area_struct *vma = NULL;
	unsigned long mm_flags = cprm->mm_flags;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *gate_vma = get_gate_vma(mm);
	MA_STATE(mas, &mm->mm_mt, 0, 0);

	while ((vma = coredump_next_vma(&mas, vma, gate_vma)) != NULL) {
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
	if (MEM_HAS_COLORS) {
		return elf_core_write_color_phdrs(cprm, offset);
	}
	return 1;
}

static int elf_core_write_colors(struct coredump_params *cprm)
{
	struct vm_area_struct *vma = NULL;
	unsigned long mm_flags = cprm->mm_flags;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *gate_vma = get_gate_vma(mm);
	MA_STATE(mas, &mm->mm_mt, 0, 0);
	unsigned long addr;
	unsigned long end;
	struct page *page;
	int stop = 0;
	ldst_rec_op_t ld_op = (ldst_rec_op_t) {
				.prot = 1,
				.fmt_h = LDST_MCOLOR_FMT_H,
				.mas = MAS_BYPASS_L1_CACHE
			};

	while ((vma = coredump_next_vma(&mas, vma, gate_vma)) != NULL) {
		end = vma->vm_start + vma_dump_size(vma, mm_flags);

		for (addr = vma->vm_start; addr < end; addr += PAGE_SIZE) {
			/* 1 byte of colors corresponds to 32 bytes of data */
			u8 colors[PAGE_SIZE / 32];
			page = get_dump_page(addr);

			if (page) {
				void *kaddr = kmap(page);
				u64 color;
				int i;

				for (i = 0; i < PAGE_SIZE / 32; i++) {
					NATIVE_RECOVERY_LOAD_TO((u64 *)(kaddr + 32 * i),
							AW(ld_op), color, 0);
					colors[i] = color & 0x7;
					NATIVE_RECOVERY_LOAD_TO((u64 *)(kaddr + 32 * i +16),
							AW(ld_op), color, 0);
					colors[i] = colors[i] | ((color & 0x7) << 4);
				}
				stop = !dump_emit(cprm, colors, sizeof(colors));
				kunmap(page);
				put_page(page);
			} else if (addr == end - PAGE_SIZE) {
				/* The last pages of CUT are not allocated
				 * and they might be skipped in tags section
				 * of core file, so we have to write the very
				 * last page to make sure that core file size
				 * is the same as declared in ELF headers. */
				stop = !dump_emit(cprm, (void *)empty_zero_page,
						  PAGE_SIZE / 32);
			} else {
				dump_skip(cprm, PAGE_SIZE / 32);
			}

			if (stop)
				return 0;
		}
	}
	return 1;
}


int elf_core_write_extra_data(struct coredump_params *cprm)
{
	struct vm_area_struct *vma = NULL;
	unsigned long mm_flags = cprm->mm_flags;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *gate_vma = get_gate_vma(mm);
	MA_STATE(mas, &mm->mm_mt, 0, 0);
	unsigned long addr;
	unsigned long end;
	struct page *page;
	int stop = 0;

	while ((vma = coredump_next_vma(&mas, vma, gate_vma)) != NULL) {
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
			} else if (addr == end - PAGE_SIZE) {
				/* The last pages of CUT are not allocated
				 * and they might be skipped in tags section
				 * of core file, so we have to write the very
				 * last page to make sure that core file size
				 * is the same as declared in ELF headers. */
				stop = !dump_emit(cprm, (void *)empty_zero_page,
						  PAGE_SIZE / 16);
			} else {
				dump_skip(cprm, PAGE_SIZE / 16);
			}

			if (stop)
				return 0;
		}
	}
	if (MEM_HAS_COLORS) {
		return elf_core_write_colors(cprm);
	}
	return 1;
}

size_t elf_core_extra_data_size(struct coredump_params *cprm)
{
	struct vm_area_struct *vma = NULL;
	unsigned long mm_flags = cprm->mm_flags;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *gate_vma = get_gate_vma(mm);
	MA_STATE(mas, &mm->mm_mt, 0, 0);
	unsigned long addr;
	unsigned long end;
	size_t size = 0;

	while ((vma = coredump_next_vma(&mas, vma, gate_vma)) != NULL) {
		end = vma->vm_start + vma_dump_size(vma, mm_flags);
		for (addr = vma->vm_start; addr < end; addr += PAGE_SIZE) {
			size += PAGE_SIZE / 16;
			if (MEM_HAS_COLORS) {
				/* 1 bite for 2 colors. 1 color for 16 bytes */
				size += PAGE_SIZE / 32;
			}
		}
	}
	return size;
}
