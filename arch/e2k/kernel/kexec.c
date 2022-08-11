/*
 * drivers/mcst/kexec.c
 *
 * Elbrus kexec pseudo driver.
 *
 * Copyright (C) 2015-2020 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/reboot.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/memblock.h>
#include <linux/fs.h>

#include <uapi/asm/kexec.h>

#include <asm/console.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/sic_regs.h>
#include <asm-l/hw_irq.h>
#include <asm/boot_recovery.h>
#include <asm/p2v/boot_init.h>
#include <asm/pic.h>
#include <asm/l-iommu.h>


#define IMAGE_KERNEL_CODE_OFFSET	0x10000
#define IMAGE_BOOTBLOCK_OFFSET		0x100

#define IMAGE_LINTEL_ENTRY_OFFSET	0x800

#define KEXEC_CHUNKS_COUNT_MAX		16

#define __switch_to_phys__	__attribute__((__section__(".switch_to_phys")))

#undef	DEBUG_KEXEC_MODE
#undef	DebugKE
#define	DEBUG_KEXEC_MODE	0
#define DebugBootKE		if (DEBUG_KEXEC_MODE) do_boot_printk
#define DebugKE(fmt, ...)							\
		if (DEBUG_KEXEC_MODE)						\
			pr_err("%d %d %s: " fmt, raw_smp_processor_id(),	\
				current->pid, __func__, ##__VA_ARGS__)

struct smp_kexec_reboot_param;
typedef void (*kexec_reboot_func_ptr)(struct smp_kexec_reboot_param *);


struct kexec_mem_chunk {
	void *start;
	int  size;
};

struct kexec_mem_ptr {
	struct kexec_mem_chunk chunks[KEXEC_CHUNKS_COUNT_MAX];
	int  chunks_count;
	u64  size;
	u64  valid_size;
	u64  phys_addr;
};

struct smp_kexec_reboot_param {
	struct bootblock_struct	*bootblock;
	struct kexec_mem_ptr	*image;
	struct kexec_mem_ptr	*initrd;
	kexec_reboot_func_ptr	reboot;
};

static DEFINE_MUTEX(kexec_mutex);


/*
 * kexec memory block
 */

static void free_kexec_mem(struct kexec_mem_ptr *mem)
{
	struct kexec_mem_chunk *chunk;
	int i;

	if (!mem->size)
		return;

	for (i = 0, chunk = mem->chunks; i < mem->chunks_count; i++, chunk++) {
		DebugKE("free memory from 0x%llx of 0x%x bytes\n",
			chunk->start, chunk->size);
		free_pages_exact(chunk->start, chunk->size);

		if (memblock_free(virt_to_phys(chunk->start), chunk->size))
			DebugKE("remove memory chunk %d from memblock failed\n",
				i);
		else
			DebugKE("remove memory chunk %d from memblock succeeded\n",
				i);
	}
}

static int alloc_kexec_mem(struct kexec_mem_ptr *mem, u64 size)
{
	int chunk_size, ret;
	u64 max_chunk_size = (PAGE_SIZE << (MAX_ORDER - 1));
	struct kexec_mem_chunk *chunk;

	DebugKE("allocating kexec memory started for size 0x%llx\n",
		size);

	if (!size) {
		mem->size = 0;
		return 0;
	}

	mem->valid_size = size;

	size = PAGE_ALIGN_DOWN(size);

	mem->size = size;
	mem->chunks_count = 0;

	chunk = mem->chunks;
	chunk_size = (size < max_chunk_size) ? size : max_chunk_size;

	while ((chunk_size >= PAGE_SIZE) && size &&
			(mem->chunks_count < KEXEC_CHUNKS_COUNT_MAX)) {
		DebugKE("allocating memory of size 0x%x bytes from 0x%llx bytes\n",
			chunk_size, size);

		if (chunk->start = alloc_pages_exact(chunk_size, GFP_ATOMIC)) {
			DebugKE("memory of chunk %d allocated from 0x%llx\n",
				mem->chunks_count, chunk->start);

			chunk->size = chunk_size;
			mem->chunks_count++;

			if (ret = memblock_reserve(virt_to_phys(chunk->start),
						   chunk_size)) {
				DebugKE("adding memory chunk %d to memblock failed\n",
					mem->chunks_count - 1);
				goto out;
			} else {
				DebugKE("adding memory chunk %d to memblock succeeded\n",
					mem->chunks_count - 1);
			}

			chunk++;

			size -= chunk_size;

			if (chunk_size > size)
				chunk_size = size;
		} else {
			DebugKE("allocating memory failed\n");

			chunk_size /= 2;
		}
	}

	if (!size) {
		DebugKE("allocating kexec memory succeed\n");
		return 0;
	}

	ret = -ENOMEM;

out:
	DebugKE("allocating kexec memory failed\n");

	free_kexec_mem(mem);

	return -ENOMEM;
}

static int copy_kexec_mem_from_user(struct kexec_mem_ptr *to,
				    const void __user *from)
{
	u64 offset = 0;
	int i;

	if (!to->size)
		return 0;

	for (i = 0; i < to->chunks_count; i++) {
		u64 copy_size;

		copy_size = (i == to->chunks_count - 1) ?
				to->chunks[i].size + to->valid_size - to->size :
				to->chunks[i].size;

		DebugKE("copy 0x%llx bytes from 0x%llx to 0x%llx\n",
			copy_size, from + offset, to->chunks[i].start);
		if (copy_from_user(to->chunks[i].start, from + offset,
				   copy_size)) {
			DebugKE("failed to copy memory from user\n");
			return -EFAULT;
		}

		offset += to->chunks[i].size;
	}

	return 0;
}

static void unreserve_continuous_kexec_mem(struct kexec_mem_ptr *mem)
{
	DebugKE("free memblock memory from 0x%llx size 0x%llx\n",
		mem->phys_addr, mem->size);
	if (memblock_free(mem->phys_addr, mem->size))
		DebugKE("memblock memory free failed\n");
}

static int find_continuous_kexec_mem(struct kexec_mem_ptr *mem, bool huge_align,
				     bool lowmem)
{
	u64 align = (huge_align) ? HPAGE_SIZE : PAGE_SIZE;
	u64 base = 0;
	u64 end = memblock.current_limit;
	int ret = 0;

	if (!mem->size)
		return 0;

	if (lowmem) {
		e2k_rt_mlo_struct_t mlo;

		mlo.E2K_RT_MLO_reg = sic_read_node_nbsr_reg(0, SIC_rt_mlo0);

		base = mlo.E2K_RT_MLO_bgn << E2K_SIC_ALIGN_RT_MLO;
		end = mlo.E2K_RT_MLO_end << E2K_SIC_ALIGN_RT_MLO;
	}

	DebugKE("find continuous address for kexec memory in range from 0x%llx to 0x%llx\n",
		base, end);
	mem->phys_addr =
		memblock_find_in_range(base, end, mem->size, align);

	if (!mem->phys_addr) {
		DebugKE("failed to find continuous address for kexec memory 0x%llx\n",
			mem);
		return -ENOMEM;
	} else {
		DebugKE("continuous address for kexec memory 0x%llx is 0x%llx\n",
			mem, mem->phys_addr);

		DebugKE("reserve memblock memory from 0x%llx size 0x%llx\n",
			mem->phys_addr, mem->size);
		if (ret = memblock_reserve(mem->phys_addr, mem->size))
			DebugKE("memblock memory reserve failed\n");
	}

	return 0;
}

static void kexec_mem_to_phys(struct kexec_mem_ptr *mem)
{
	int i;

	if (!mem->size)
		return;

	for (i = 0; i < mem->chunks_count; i++) {
		DebugKE("converting chunk %d virt address 0x%llx\n",
			i, mem->chunks[i].start);
		mem->chunks[i].start =
			(void *)virt_to_phys(mem->chunks[i].start);
		DebugKE("chunk %d phys address 0x%llx\n",
			i, mem->chunks[i].start);
	}
}

static void boot_merge_kexec_mem(struct kexec_mem_ptr *mem)
{
	u64 offset = 0;
	int i;

	if (!mem->size)
		return;

	for (i = 0; i < mem->chunks_count; i++) {
		DebugBootKE("copy 0x%x bytes from 0x%llx to 0x%llx\n",
			mem->chunks[i].size, mem->chunks[i].start,
			mem->phys_addr + offset);
		boot_fast_memcpy((void *)(mem->phys_addr + offset),
			mem->chunks[i].start, mem->chunks[i].size);

		offset += mem->chunks[i].size;
	}
}


/*
 * bootblock block
 */

static void free_bootblock_mem(bootblock_struct_t *bootblock)
{
	DebugKE("free bootblock memory from 0x%llx\n", bootblock);
	kfree(bootblock);

	if (memblock_free(virt_to_phys(bootblock), PAGE_SIZE))
		DebugKE("remove bootblock memory from memblock failed\n");
	else
		DebugKE("remove bootblock memory from memblock succeeded\n");
}

static int alloc_bootblock_mem(struct bootblock_struct **bootblock)
{
	int ret;

	DebugKE("allocating bootblock memory of size %d bytes\n",
		BOOTBLOCK_SIZE);
	if (!(*bootblock = kmalloc(BOOTBLOCK_SIZE, GFP_ATOMIC))) {
		DebugKE("allocating bootblock memory failed\n");
		return -ENOMEM;
	}
	DebugKE("bootblock memory allocated from 0x%llx\n", *bootblock);

	if (ret = memblock_reserve(virt_to_phys(*bootblock), PAGE_SIZE))
		DebugKE("adding bootblock memory to memblock failed\n");
	else
		DebugKE("adding bootblock memory to memblock succeeded\n");

	return 0;
}

static int copy_bootblock_mem(struct bootblock_struct *to,
			      struct bootblock_struct *from)
{
	DebugKE("copy %d bytes of bootblock from 0x%llx to 0x%llx\n",
		BOOTBLOCK_SIZE, from, to);
	memcpy(to, from, BOOTBLOCK_SIZE);
	return 0;
}


/*
 * initrd block
 */

static void free_initrd_mem(struct kexec_mem_ptr *initrd)
{
	DebugKE("free initrd memory 0x%llx\n", initrd);
	free_kexec_mem(initrd);
}

static int alloc_initrd_mem(u64 initrd_size, struct kexec_mem_ptr *initrd)
{
	DebugKE("allocating initrd memory 0x%llx of size 0x%llx\n",
		initrd, initrd_size);
	return alloc_kexec_mem(initrd, initrd_size);
}

static int copy_initrd_mem(struct kexec_mem_ptr *to, const void __user *from)
{
	DebugKE("copy initrd memory 0x%llx from user 0x%llx\n", to, from);
	return copy_kexec_mem_from_user(to, from);
}

static void unreserve_continuous_initrd_mem(struct kexec_mem_ptr *initrd)
{
	DebugKE("unreserve continuous memory for initrd 0x%llx\n", initrd);
	unreserve_continuous_kexec_mem(initrd);
}

static int find_continuous_initrd_mem(struct kexec_mem_ptr *initrd)
{
	DebugKE("try to find continuous memory for initrd 0x%llx\n", initrd);
	return find_continuous_kexec_mem(initrd, 0, 0);
}

static void boot_merge_initrd_mem(struct kexec_mem_ptr *initrd)
{
	DebugBootKE("merge chunks of initrd memory 0x%llx\n", initrd);
	return boot_merge_kexec_mem(initrd);
}


/*
 * kernel image block
 */

static void free_kernel_code_mem(struct kexec_mem_ptr *image)
{
	DebugKE("free kernel code memory 0x%llx\n", image);
	free_kexec_mem(image);
}

static int alloc_kernel_code_mem(u64 image_size, struct kexec_mem_ptr *image)
{
	DebugKE("allocating kernel code memory 0x%llx of size 0x%llx\n",
		image, image_size);
	return alloc_kexec_mem(image, image_size);
}

static int
copy_kernel_code_mem(struct kexec_mem_ptr *to, const void __user *from)
{
	DebugKE("copy kernel code memory 0x%llx from user 0x%llx\n", to, from);
	return copy_kexec_mem_from_user(to, from);
}

static void unreserve_continuous_kernel_code_mem(struct kexec_mem_ptr *image)
{
	DebugKE("unreserve continuous memory for kernel code 0x%llx\n", image);
	unreserve_continuous_kexec_mem(image);
}

static int find_continuous_kernel_code_mem(struct kexec_mem_ptr *image)
{
	DebugKE("try to find continuous memory for kernel code 0x%llx\n",
		image);
	return find_continuous_kexec_mem(image, 1, 0);
}

static void boot_merge_kernel_code_mem(struct kexec_mem_ptr *image)
{
	DebugBootKE("merge chunks of kernel code memory 0x%llx\n", image);
	return boot_merge_kexec_mem(image);
}


/*
 * lintel code block
 */

static void free_lintel_code_mem(struct kexec_mem_ptr *image)
{
	DebugKE("free lintel code memory 0x%llx\n", image);
	free_kexec_mem(image);
}

static int alloc_lintel_code_mem(u64 image_size, struct kexec_mem_ptr *image)
{
	DebugKE("allocating lintel code memory 0x%llx of size 0x%llx\n",
		image, image_size);
	return alloc_kexec_mem(image, image_size);
}

static int
copy_lintel_code_mem(struct kexec_mem_ptr *to, const void __user *from)
{
	DebugKE("copy lintel code memory 0x%llx from user 0x%llx\n", to, from);
	return copy_kexec_mem_from_user(to, from);
}

static int find_continuous_lintel_code_mem(struct kexec_mem_ptr *image)
{
	DebugKE("try to find continuous memory for lintel code 0x%llx\n",
		image);
	return find_continuous_kexec_mem(image, 0, 1);
}

static void boot_merge_lintel_code_mem(struct kexec_mem_ptr *image)
{
	DebugBootKE("merge chunks of lintel code memory 0x%llx\n", image);
	return boot_merge_kexec_mem(image);
}


/*
 * smp and switch to phys block
 */

static void smp_kexec_reboot_param_to_phys(struct smp_kexec_reboot_param *p)
{
	DebugKE("converting smp param 0x%llx to phys\n", p);

	DebugKE("converting bootblock virt address 0x%llx\n", p->bootblock);
	p->bootblock = (void *)virt_to_phys(p->bootblock);
	DebugKE("bootblock phys address 0x%llx\n", p->bootblock);

	DebugKE("converting image virt address 0x%llx\n", p->image);
	kexec_mem_to_phys(p->image);
	p->image = (void *)virt_to_phys(p->image);
	DebugKE("image phys address 0x%llx\n", p->image);

	DebugKE("converting reboot virt address 0x%llx\n", p->reboot);
	p->reboot = (kexec_reboot_func_ptr)kernel_va_to_pa(p->reboot);
	DebugKE("reboot phys address 0x%llx\n", p->reboot);

	if (!p->initrd)
		return;

	DebugKE("converting initrd virt address 0x%llx\n", p->initrd);
	kexec_mem_to_phys(p->initrd);
	p->initrd = (void *)virt_to_phys(p->initrd);
	DebugKE("initrd phys address 0x%llx\n", p->initrd);
}

static noinline void __switch_to_phys__
kexec_switch_to_phys(struct smp_kexec_reboot_param *p)
{
	bootmem_areas_t		*bootmem = &kernel_bootmem;
	e2k_rwap_lo_struct_t	reg_lo;
	e2k_rwap_hi_struct_t	reg_hi;
	e2k_rwap_lo_struct_t	stack_reg_lo;
	e2k_rwap_hi_struct_t	stack_reg_hi;
	e2k_usbr_t		usbr = { {0} };
	int			cpuid = hard_smp_processor_id();

	NATIVE_FLUSHCPU;

	/*
	 * Take into account PS guard page from ttable_entry12
	 */
	reg_lo.PSP_lo_half = 0;
#ifndef	CONFIG_SMP
	reg_lo.PSP_lo_base = bootmem->boot_ps.phys;
#else
	reg_lo.PSP_lo_base = bootmem->boot_ps[cpuid].phys;
#endif
	reg_lo._PSP_lo_rw = E2K_PSP_RW_PROTECTIONS;
	reg_hi.PSP_hi_half = 0;
#ifndef	CONFIG_SMP
	reg_hi.PSP_hi_size = bootmem->boot_ps.size + PAGE_SIZE;
#else
	reg_hi.PSP_hi_size = bootmem->boot_ps[cpuid].size + PAGE_SIZE;
#endif
	reg_hi.PSP_hi_ind = 0;
	NATIVE_NV_WRITE_PSP_REG(reg_hi, reg_lo);

	/*
	 * Take into account PCS guard page from ttable_entry12
	 */
	reg_lo.PCSP_lo_half = 0;
#ifndef	CONFIG_SMP
	reg_lo.PCSP_lo_base = bootmem->boot_pcs.phys;
#else
	reg_lo.PCSP_lo_base = bootmem->boot_pcs[cpuid].phys;
#endif
	reg_lo._PCSP_lo_rw = E2K_PCSR_RW_PROTECTIONS;
	reg_hi.PCSP_hi_half = 0;
#ifndef	CONFIG_SMP
	reg_hi.PCSP_hi_size = bootmem->boot_pcs.size + PAGE_SIZE;
#else
	reg_hi.PCSP_hi_size = bootmem->boot_pcs[cpuid].size + PAGE_SIZE;
#endif
	reg_hi.PCSP_hi_ind = 0;
	NATIVE_NV_WRITE_PCSP_REG(reg_hi, reg_lo);

#ifndef	CONFIG_SMP
	bootmem->boot_stack.phys_offset = bootmem->boot_stack.size;
#else
	bootmem->boot_stack[cpuid].phys_offset =
			bootmem->boot_stack[cpuid].size;
#endif

	stack_reg_lo.USD_lo_half = 0;
	stack_reg_hi.USD_hi_half = 0;
#ifndef	CONFIG_SMP
	usbr.USBR_base = bootmem->boot_stack.phys + bootmem->boot_stack.size;
	stack_reg_lo.USD_lo_base = bootmem->boot_stack.phys +
					bootmem->boot_stack.phys_offset;
	stack_reg_hi.USD_hi_size = bootmem->boot_stack.phys_offset;
#else
	usbr.USBR_base = bootmem->boot_stack[cpuid].phys +
				bootmem->boot_stack[cpuid].size;
	stack_reg_lo.USD_lo_base = bootmem->boot_stack[cpuid].phys +
					bootmem->boot_stack[cpuid].phys_offset;
	stack_reg_hi.USD_hi_size = bootmem->boot_stack[cpuid].phys_offset;
#endif
	stack_reg_lo.USD_lo_p = 0;
	NATIVE_NV_WRITE_USBR_USD_REG(usbr, stack_reg_hi, stack_reg_lo);

#ifndef	CONFIG_NUMA
	reg_lo.CUD_lo_base = bootmem->text.phys;
#else
	reg_lo.CUD_lo_base = bootmem->text.nodes[BOOT_BS_NODE_ID].phys;
#endif
	reg_lo._CUD_lo_rw = E2K_CUD_RW_PROTECTIONS;
	reg_lo.CUD_lo_c = CUD_CFLAG_SET;
	NATIVE_WRITE_CUD_LO_REG(reg_lo);
	NATIVE_WRITE_OSCUD_LO_REG(reg_lo);

#ifndef	CONFIG_NUMA
	reg_lo.GD_lo_base = bootmem->data.phys;
#else
	reg_lo.GD_lo_base = bootmem->data.nodes[BOOT_BS_NODE_ID].phys;
#endif
	reg_lo._GD_lo_rw = E2K_GD_RW_PROTECTIONS;
	NATIVE_WRITE_GD_LO_REG(reg_lo);
	NATIVE_WRITE_OSGD_LO_REG(reg_lo);

	WRITE_CURRENT_REG_VALUE(cpuid);

	E2K_CLEAR_CTPRS();
	__E2K_WAIT_ALL;

	NATIVE_WRITE_MMU_CR(MMU_CR_KERNEL_OFF);
	__E2K_WAIT_ALL;

	E2K_JUMP_ABSOLUTE_WITH_ARGUMENTS_1(p->reboot, p);
}

static void do_kexec_reboot(void *info)
{
	struct smp_kexec_reboot_param	*param = info;

	all_irq_disable();
	disable_local_APIC();

	DebugKE("switch to phys memory started for smp param 0x%llx\n", param);
	kexec_switch_to_phys(
		(struct smp_kexec_reboot_param *)virt_to_phys(param));
}


/*
 * common helpful block
 */

static void unreserve_stack_mem(u64 stack)
{
	DebugKE("unreserve stack memory from 0x%llx size 0x%lx\n",
		stack - PAGE_SIZE, 2 * PAGE_SIZE);
	if (memblock_free(stack - PAGE_SIZE, 2 * PAGE_SIZE))
		DebugKE("stack memory unreserve failed\n");
}

static int reserve_stack_mem(u64 stack)
{
	int ret = 0;

	stack = PAGE_ALIGN_UP(stack);

	DebugKE("reserve stack memory from 0x%llx size 0x%lx\n",
		stack - 2 * PAGE_SIZE, 4 * PAGE_SIZE);
	if (ret = memblock_reserve(stack - 2 * PAGE_SIZE, 4 * PAGE_SIZE))
		DebugKE("stack memory reserve failed\n");

	return ret;
}


/*
 * kernel exec block
 */

static void boot_scall2(bootblock_struct_t *bootblock)
{
	E2K_SYSCALL(START_KERNEL_SYSCALL, 0, 1, bootblock);
}

static void
boot_kexec_setup_image_regs(bootblock_struct_t *bootblock, u64 image)
{
	e2k_rwap_lo_struct_t	reg_lo;
	e2k_rwap_hi_struct_t	reg_hi;
	u64			base, size;

	base = image;
	size = bootblock->info.kernel_size;

	reg_lo.CUD_lo_base = base;
	reg_lo.CUD_lo_c = E2K_CUD_CHECKED_FLAG;
	reg_lo._CUD_lo_rw = E2K_CUD_RW_PROTECTIONS;
	reg_hi.CUD_hi_size = size;
	reg_hi._CUD_hi_curptr = 0;
	WRITE_CUD_REG(reg_hi, reg_lo);
	WRITE_OSCUD_REG(reg_hi, reg_lo);

	reg_lo.GD_lo_base = base;
	reg_lo._GD_lo_rw = E2K_GD_RW_PROTECTIONS;
	reg_hi.GD_hi_size = size;
	reg_hi._GD_hi_curptr = 0;
	WRITE_GD_REG(reg_hi, reg_lo);
	WRITE_OSGD_REG(reg_hi, reg_lo);
}

static void boot_kexec_reboot_sequel(struct smp_kexec_reboot_param *p)
{
	struct bootblock_struct *bootblock = p->bootblock;

	boot_sync_all_processors();

	/*
	 * Be sure, these functions are properly working on phys memory
	 */
	flush_TLB_all();
	flush_ICACHE_all();

	boot_native_invalidate_CACHE_L12();

	if (boot_early_pic_is_bsp()) {
		boot_merge_initrd_mem(p->initrd);
		boot_merge_kernel_code_mem(p->image);
	}

	boot_sync_all_processors();

	DebugBootKE("Jumping to ttable_entry12 of kernel base 0x%llx on cpu %ld\n",
		p->image->phys_addr, boot_smp_processor_id());

	boot_kexec_setup_image_regs(bootblock, p->image->phys_addr);
	boot_scall2(bootblock);
}

static int kexec_setup_bootblock(bootblock_struct_t *bootblock,
		bootblock_struct_t *image_bootblock,
		struct kexec_mem_ptr *image, struct kexec_mem_ptr *initrd,
		char *cmdline)
{
	int	ret = 0;
	u64	kernel_size;
	u32	kernel_csum;
	int	cmdline_len;

	DebugKE("image_bootblock is 0x%llx\n", image_bootblock);

	DebugKE("get %ld bytes of image_bootblock from 0x%llx to 0x%llx\n",
		sizeof(kernel_size),
		&image_bootblock->info.kernel_size,
		&kernel_size);
	if (ret = get_user(kernel_size, &image_bootblock->info.kernel_size)) {
		DebugKE("failed to get kernel_size from image_bootblock\n");
		return ret;
	}
	DebugKE("kernel_size is 0x%llx\n", kernel_size);

	DebugKE("get %ld bytes of image_bootblock from 0x%llx to 0x%llx\n",
		sizeof(kernel_csum),
		&image_bootblock->info.kernel_csum,
		&kernel_csum);
	if (ret = get_user(kernel_csum, &image_bootblock->info.kernel_csum)) {
		DebugKE("failed to get kernel_csum from image_bootblock\n");
		return ret;
	}
	DebugKE("kernel_csum is 0x%x\n", kernel_csum);

	DebugKE("setup bootblock variables\n");

	bootblock->info.kernel_size = kernel_size;
	bootblock->info.kernel_csum = kernel_csum;

	cmdline_len = strlen(cmdline);
	if (cmdline_len >= KSTRMAX_SIZE) {
		strcpy(bootblock->info.kernel_args_string,
			KERNEL_ARGS_STRING_EX_SIGNATURE);
		strcpy(bootblock->info.bios.kernel_args_string_ex, cmdline);
	} else {
		strcpy(bootblock->info.kernel_args_string, cmdline);
	}

	bootblock->info.kernel_base = image->phys_addr;

	bootblock->info.ramdisk_base = initrd->phys_addr;
	bootblock->info.ramdisk_size = initrd->size;

	return ret;
}

static long kexec_reboot(struct kexec_reboot_param __user *param)
{
	struct kexec_reboot_param	p;
	char				cmdline[KSTRMAX_SIZE_EX];
	struct kexec_mem_ptr		image, initrd;
	bootblock_struct_t		*bootblock;
	bootblock_struct_t		*image_bootblock;
	usd_struct_t			usd;
	struct smp_kexec_reboot_param	smp_param;
	int				ret = 0;

	DebugKE("copy %ld bytes of kexec_reboot_param struct from 0x%llx to 0x%llx\n",
		sizeof(struct kexec_reboot_param), param, &p);
	if (copy_from_user(&p, param, sizeof(struct kexec_reboot_param))) {
		DebugKE("failed to copy kexec_reboot_param struct from user\n");
		return -EFAULT;
	}
	DebugKE("cmdline=0x%llx cmdline_size=%d image=0x%llx image_size=0x%llx\n",
		p.cmdline, p.cmdline_size, p.image, p.image_size);

	if (p.cmdline_size >= KSTRMAX_SIZE_EX) {
		DebugKE("cmdline_size %d > %d\n",
			p.cmdline_size, KSTRMAX_SIZE_EX);
		return -EINVAL;
	}

	DebugKE("copy %d bytes of cmdline from 0x%llx to 0x%llx\n",
		p.cmdline_size, p.cmdline, cmdline);
	if (copy_from_user(cmdline, p.cmdline, p.cmdline_size)) {
		DebugKE("failed to copy cmdline from user\n");
		return -EFAULT;
	}
	cmdline[p.cmdline_size] = 0;
	DebugKE("cmdline is '%s'\n", cmdline);

	image_bootblock =
		(bootblock_struct_t *)(p.image + IMAGE_BOOTBLOCK_OFFSET);

	read_USD_reg(&usd);

	if (ret = alloc_bootblock_mem(&bootblock))
		return ret;

	if (ret = alloc_kernel_code_mem(
			p.image_size - IMAGE_KERNEL_CODE_OFFSET, &image))
		goto out_bootblock;

	if (ret = alloc_initrd_mem(p.initrd_size, &initrd))
		goto out_code;

	if (ret = copy_bootblock_mem(bootblock, bootblock_virt))
		goto out_initrd;

	if (ret = copy_kernel_code_mem(&image,
			p.image + IMAGE_KERNEL_CODE_OFFSET))
		goto out_initrd;

	if (ret = copy_initrd_mem(&initrd, p.initrd))
		goto out_initrd;

	if (ret = reserve_stack_mem(usd.USD_base))
		goto out_initrd;

	if (ret = find_continuous_kernel_code_mem(&image))
		goto out_stack;

	if (ret = find_continuous_initrd_mem(&initrd))
		goto out_code_cont;

	if (DEBUG_KEXEC_MODE)
		__memblock_dump_all();

	if (ret = kexec_setup_bootblock(bootblock, image_bootblock, &image,
			&initrd, cmdline))
		goto out_initrd_cont;

	DebugKE("shutdown devices, point of noreturn\n");
	kernel_restart_prepare(NULL);
	l_iommu_stop_all();
	disable_IO_APIC();

	smp_param.bootblock = bootblock;
	smp_param.image = &image;
	smp_param.initrd = &initrd;
	smp_param.reboot = boot_kexec_reboot_sequel;

	smp_kexec_reboot_param_to_phys(&smp_param);

	smp_call_function(do_kexec_reboot, &smp_param, 0);
	do_kexec_reboot(&smp_param);

	BUG();

out_initrd_cont:
	unreserve_continuous_initrd_mem(&initrd);
out_code_cont:
	unreserve_continuous_kernel_code_mem(&image);
out_stack:
	unreserve_stack_mem(usd.USD_base);
out_initrd:
	free_initrd_mem(&initrd);
out_code:
	free_kernel_code_mem(&image);
out_bootblock:
	free_bootblock_mem(bootblock);

	return ret;
}


/*
 * lintel exec block
 */

static void boot_lintel_reboot_sequel(struct smp_kexec_reboot_param *p)
{
	struct bootblock_struct *bootblock = p->bootblock;
	u64 jmp_addr = p->image->phys_addr + p->image->valid_size -
		       IMAGE_LINTEL_ENTRY_OFFSET;

	boot_sync_all_processors();

	/*
	 * Be sure, these functions are properly working on phys memory
	 */
	flush_TLB_all();
	flush_ICACHE_all();

	boot_native_invalidate_CACHE_L12();

	if (boot_early_pic_is_bsp())
		boot_merge_lintel_code_mem(p->image);

	boot_sync_all_processors();

	DebugKE("Jumping to lintel entry 0x%llx on cpu %d\n",
		jmp_addr, boot_early_pic_read_id());
	E2K_MOVE_DREG_TO_DGREG(1, bootblock);
	((void (*)(void))jmp_addr)();
}

static long lintel_reboot(struct lintel_reboot_param __user *param)
{
	struct lintel_reboot_param	p;
	struct kexec_mem_ptr		image;
	bootblock_struct_t		*bootblock;
	usd_struct_t			usd;
	struct smp_kexec_reboot_param	smp_param;
	int				ret = 0;

	DebugKE("copy %ld bytes of lintel_reboot_param struct from 0x%llx to 0x%llx\n",
		sizeof(struct lintel_reboot_param), param, &p);
	if (copy_from_user(&p, param, sizeof(struct lintel_reboot_param))) {
		DebugKE("failed to copy lintel_reboot_param struct from user\n");
		return -EFAULT;
	}

	DebugKE("image=0x%llx image_size=0x%llx\n", p.image, p.image_size);

	if (!PAGE_ALIGNED(p.image_size))
		return -EINVAL;

	read_USD_reg(&usd);

	if (ret = alloc_bootblock_mem(&bootblock))
		return ret;

	if (ret = alloc_lintel_code_mem(p.image_size, &image))
		goto out_bootblock;

	if (ret = copy_bootblock_mem(bootblock, bootblock_virt))
		goto out_code;

	if (ret = copy_lintel_code_mem(&image, p.image))
		goto out_code;

	if (ret = reserve_stack_mem(usd.USD_base))
		goto out_code;

	if (ret = find_continuous_lintel_code_mem(&image))
		goto out_stack;

	if (DEBUG_KEXEC_MODE)
		__memblock_dump_all();

	DebugKE("shutdown devices, point of noreturn\n");
	kernel_restart_prepare(NULL);
	disable_IO_APIC();

	smp_param.bootblock = bootblock;
	smp_param.image = &image;
	smp_param.initrd = 0;
	smp_param.reboot = boot_lintel_reboot_sequel;

	smp_kexec_reboot_param_to_phys(&smp_param);

	smp_call_function(do_kexec_reboot, &smp_param, 0);
	do_kexec_reboot(&smp_param);

	BUG();

out_stack:
	unreserve_stack_mem(usd.USD_base);
out_code:
	free_lintel_code_mem(&image);
out_bootblock:
	free_bootblock_mem(bootblock);

	return ret;
}


/*
 * common init block
 */

static long kexec_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct pid_namespace	*pid_ns = task_active_pid_ns(current);
	long			ret = 0;

	if (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))
		return -EPERM;

	if (!mutex_trylock(&kexec_mutex))
		return -EBUSY;

	DebugKE("kexec ioctl started: cmd=0x%x, arg=0x%lx\n", cmd, arg);

	switch (cmd) {
	case KEXEC_REBOOT:
		ret = kexec_reboot((struct kexec_reboot_param *)arg);
		break;
	case LINTEL_REBOOT:
		ret = lintel_reboot((struct lintel_reboot_param *)arg);
		break;
	default:
		ret = -EINVAL;
	}

	mutex_unlock(&kexec_mutex);

	return ret;
}

static const struct file_operations kexec_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= kexec_ioctl,
};

static struct miscdevice kexec_miscdev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "kexec",
	.fops		= &kexec_fops,
};

static int __init kexec_init(void)
{
	int	rval = 0;

	rval = misc_register(&kexec_miscdev);
	if (rval) {
		pr_info("kexec: cannot register miscdev on minor %d (err %d)\n",
			kexec_miscdev.minor, rval);
		return rval;
	}

	DebugKE("kexec driver registered on minor %d: KEXEC_REBOOT=0x%lx LINTEL_REBOOT=0x%lx\n",
		kexec_miscdev.minor, KEXEC_REBOOT, LINTEL_REBOOT);

	return rval;
}

static void __exit kexec_exit(void)
{
	misc_deregister(&kexec_miscdev);
	DebugKE("kexec driver deregistered\n");
}

module_init(kexec_init);
module_exit(kexec_exit);

MODULE_AUTHOR("Pavel V. Panteleev");
MODULE_DESCRIPTION("Elbrus kernel and lintel exec driver");
MODULE_LICENSE("GPL");
