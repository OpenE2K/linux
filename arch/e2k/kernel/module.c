/* 
 * Kernel module help for E2K.
 */
#include <linux/moduleloader.h>
#include <linux/elf.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include <asm/alternative.h>
#include <asm/machdep.h>
#include <asm/pgtable.h>

extern struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
					unsigned long start, unsigned long end);

void *module_alloc(unsigned long size)
{
	if (PAGE_ALIGN(size) > MODULES_END - MODULES_VADDR)
		return NULL;

	return __vmalloc_node_range(size, 8, MODULES_VADDR, MODULES_END,
			GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
			__builtin_return_address(0));
}

int apply_relocate_add(Elf64_Shdr *sechdrs,
		       const char *strtab,
		       unsigned int symindex,
		       unsigned int relsec,
		       struct module *me)
{
	unsigned int i;
	Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;
	Elf64_Sym *sym;
	u64 *location;
	u32 *loc32;

	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		Elf64_Addr v;

		/* This is where to make the change */
		location = (u64 *) ((u8 *)sechdrs[sechdrs[relsec].sh_info].sh_addr
			+ rel[i].r_offset);
		loc32 = (u32 *) location;

		/* This is the symbol it is referring to.  Note that all
		   undefined symbols have been resolved.  */
		sym = (Elf64_Sym *)sechdrs[symindex].sh_addr
			+ ELF64_R_SYM(rel[i].r_info);
		v = sym->st_value + rel[i].r_addend;

		switch (ELF64_R_TYPE(rel[i].r_info) & 0xff) {
		case R_E2K_NONE:
			break;
		case R_E2K_64_ABS:
			*location = v;
			break;

		case R_E2K_64_ABS_LIT:
			loc32[0] = (u32)(v >> 32);
			loc32[1] = (u32)(v & 0xffffffff);
			break;

		case R_E2K_64_CALL:
			/* As far as field r_addend holds offset within
			 * wide command to where we change, we need to
			 * deduct r_addend in order to obtain correct address.
			 * Therefore we need to add r_addend to the address,
			 * where we change to.
			 */
			v -= (Elf64_Addr) location;
			v -= rel[i].r_addend;
			loc32 = (Elf32_Addr *) ((char *)loc32 + rel[i].r_addend);

			*loc32 = (*loc32 & 0xf0000000) | ((v >> 3) & 0x0fffffff);
			break;

		case R_E2K_DISP:
                        v -= (Elf64_Addr) location;
                        *loc32 = (*loc32 & 0xf0000000) | ((v >> 3) & 0x0fffffff);
                        break;

		case R_E2K_32_PC:
			v -= (Elf64_Addr) location;
			*loc32 = v;
			if ((s64) v > INT_MAX || (s64) v < INT_MIN)
				goto overflow;
			break;

		default:
			printk(KERN_ERR "module %s: Unknown relocation: %d\n",
			       me->name,
			       (int) (ELF64_R_TYPE(rel[i].r_info) & 0xff));
			return -ENOEXEC;
		};
	}

	return 0;

overflow:
	pr_err("module %s: Relocation (type %u) overflow\n",
		me->name, ELF64_R_TYPE(rel[i].r_info) & 0xff);
	return -ERANGE;
}

int module_finalize(const Elf_Ehdr *hdr,
		    const Elf_Shdr *sechdrs,
		    struct module *me)
{
	const Elf_Shdr *s;
	char *secstrings;

	secstrings = (void *) hdr + sechdrs[hdr->e_shstrndx].sh_offset;
	for (s = sechdrs; s < sechdrs + hdr->e_shnum; s++) {
		if (!strcmp(".altinstructions", secstrings + s->sh_name)) {
			/* patch .altinstructions */
			void *aseg = (void *) s->sh_addr;

			apply_alternatives(aseg, aseg + s->sh_size);
		}
	}

	return 0;
}
