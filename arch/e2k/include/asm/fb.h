#ifndef _ASM_E2K_FB_H
#define _ASM_E2K_FB_H

#include <linux/fb.h>
#include <linux/fs.h>
#include <asm/pgtable.h>
#include <asm/mman.h>

static inline void fb_pgprotect(struct file *file, struct vm_area_struct *vma,
				unsigned long off)
{
	vma->vm_page_prot = (cpu_has(CPU_FEAT_WC_PCI_PREFETCH) &&
			     vma->vm_flags & VM_WRITECOMBINED) ?
				pgprot_writecombine(vma->vm_page_prot) :
				pgprot_noncached(vma->vm_page_prot);
}

extern int fb_is_primary_device(struct fb_info *info);
#endif /* _ASM_E2K_FB_H */
