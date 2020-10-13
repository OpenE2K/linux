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

#include <asm/machdep.h>
#include <asm/pgtable.h>

#if 0
#define DEBUGP printk
#else
#define DEBUGP(fmt...)
#endif

extern struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
					unsigned long start, unsigned long end);

void *module_alloc(unsigned long size)
{
	struct vm_struct *area;
	struct page **pages;
	unsigned int array_size, i;

	size = PAGE_ALIGN(size);
	if (!size)
		return NULL;

	area = __get_vm_area(size, VM_ALLOC, MODULE_START, MODULE_END);
	if (!area)
		return NULL;

	area->nr_pages = size >> PAGE_SHIFT;
	array_size = area->nr_pages * sizeof(struct page *);
	area->pages = pages = kmalloc(array_size, GFP_KERNEL);
	if (!area->pages) {
		remove_vm_area(area->addr);
		kfree(area);
		return NULL;
	}

	memset(pages, 0, array_size);

	for (i = 0; i < area->nr_pages; i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		if (unlikely(!pages[i])) {
			area->nr_pages = i;
			goto out_no_pages;
		}
	}

	if (map_vm_area(area, PAGE_KERNEL_MODULE, &pages))
		goto out_no_pages;
	return area->addr;

 out_no_pages:
	vfree(area->addr);
	return NULL;
}


/*
 * Free memory returned from module_alloc
 */
void module_free(struct module *mod, void *module_region)
{
	/* FIXME: If module_region == mod->init_region, trim exception
           table entries.
	if (mod->arch.init_unw_table && module_region == mod->module_init) {
		unw_remove_unwind_table(mod->arch.init_unw_table);
		mod->arch.init_unw_table = NULL;
	}
	*/
	vfree(module_region);
}

/*
 * We don't need anything special?
 */
int module_frob_arch_sections(Elf_Ehdr *hdr,
			      Elf_Shdr *sechdrs,
			      char *secstrings,
			      struct module *mod)
{
	return 0;
}

/* FIXME в asm-e2k/elf.h */
#define R_E2K_64_ABS            50              /* Direct 64 bit */             
#define R_E2K_64_ABS_LIT        51              /* Direct 64 bit for LTS syllable */
#define R_E2K_64_CALL           52              /* PC relative 64 bit for DISP */
#define R_E2K_DISP           	110             /* PC relative 28-bit for DISP */

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
//printk("--- location=0x%lx, \tv=0x%lx\n", (long) location, (long) v);
//printk("--- rel[i].r_offset = %ld\n", rel[i].r_offset);

		switch (ELF64_R_TYPE(rel[i].r_info) & 0xff) {
		case R_E2K_64_ABS:
			*location = v;
			break;

		case R_E2K_64_ABS_LIT:
			loc32[0] = (u32)(v >> 32);
			loc32[1] = (u32)(v & 0xffffffff);
			break;

		case R_E2K_64_CALL:
			/* Поскольку в поле r_addend записано смещение внутри широкой команды,
			   в которую сделано перемещение, то дополнительно вычтем r_addend,
			   чтобы получить правильное значение адреса, на который сделано
			   перемещение. Далее прибавим r_addend к тому месту, куда будем
			   записывать перемещение.  */
			v -= (Elf64_Addr) location;
			v -= rel[i].r_addend;
			loc32 = (Elf32_Addr *) ((char *)loc32 + rel[i].r_addend);

			*loc32 = (*loc32 & 0xf0000000) | ((v >> 3) & 0x0fffffff);
			break;

		case R_E2K_DISP:
                        v -= (Elf64_Addr) location;
                        *loc32 = (*loc32 & 0xf0000000) | ((v >> 3) & 0x0fffffff);
                        break;

		default:
			printk(KERN_ERR "module %s: Unknown relocation: %d\n",
			       me->name,
			       (int) (ELF64_R_TYPE(rel[i].r_info) & 0xff));
			return -ENOEXEC;
		};
	}

	return 0;
//	printk(KERN_ERR "module %s: ADD RELOCATION unsupported\n",
//	       me->name);
//	return -ENOEXEC;
}

extern void apply_alternatives(void *start, void *end); 

int module_finalize(const Elf_Ehdr *hdr,
		    const Elf_Shdr *sechdrs,
		    struct module *me)
{
	/* I-cache is fully coherent?  */
	return 0;
}

void module_arch_cleanup(struct module *mod)
{
}
