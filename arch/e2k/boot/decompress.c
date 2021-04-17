#define DEBUG_BOOT_MODE 0
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/pic.h>
#include <asm/bootinfo.h>
#include <asm/cpu_regs.h>
#include <asm/e2k_api.h>
#include <asm/head.h>
#include <asm/string.h>
#include <asm/mpspec.h>

#define BOOT_HEAP_SIZE	0x1000000
static unsigned long free_mem_ptr;
static unsigned long free_mem_end_ptr;

#define STATIC static

static void error_loop(char *s);
#define assert(condition) \
do { \
	if (unlikely(!(condition))) \
		error_loop("Assertion failed: " #condition); \
} while (0)

#ifdef CONFIG_KERNEL_GZIP
#include "../../../../lib/decompress_inflate.c"
#endif

#ifdef CONFIG_KERNEL_BZIP2
#include "../../../../lib/decompress_bunzip2.c"
#endif

#ifdef CONFIG_KERNEL_LZ4
#include "../../../../lib/decompress_unlz4.c"
#endif

#ifdef CONFIG_KERNEL_XZ
#define memmove memmove
#include "../../../../lib/decompress_unxz.c"
#endif

#ifdef CONFIG_KERNEL_LZMA
#include "../../../../lib/decompress_unlzma.c"
#endif

#ifdef CONFIG_KERNEL_LZO
#include "../../../../lib/decompress_unlzo.c"
#endif

/* Symbols defined by linker scripts */
extern char _bss[], _ebss[];
extern char _kernel[], _ekernel[];
extern char _start[], _end[];
extern char __orig_kernel_size[];

struct mem_bank {
	unsigned long mb_bottom;
	unsigned long mb_top;
};

/* Add some number to account for banks being broken by reserved memory */
#define MAX_MEM_BANKS (L_MAX_MEM_NUMNODES * L_MAX_NODE_PHYS_BANKS + 64)
struct board_mem {
	unsigned long bm_size;
	unsigned bm_nBanks;
	struct mem_bank bm_Banks[MAX_MEM_BANKS];
};

/*
 * Put `unpacking_in_progress' into compiler-initialized
 * .data section so that all processors can access it
 * before .bss section is cleared.
 */
static int unpacking_in_progress = 1;

static boot_info_t *boot_info;

static unsigned long kernel_address;

static unsigned long io_area_phys_base;

static e2k_idr_t read_idr(void)
{
	return native_read_IDR_reg();
}

static void dec_writeb(u8 b, void __iomem *addr)
{
	NATIVE_WRITE_MAS_B((unsigned long) addr, b, MAS_IOADDR);
}

static u8 dec_readb(void __iomem *addr)
{
	return NATIVE_READ_MAS_B((unsigned long) addr, MAS_IOADDR);
}

static inline u8 am85c30_com_inb_command(u64 iomem_addr, u8 reg_num)
{
	dec_writeb(reg_num, (void __iomem *) iomem_addr);
	return dec_readb((void __iomem *) iomem_addr);
}

static inline void am85c30_com_outb(u64 iomem_addr, u8 byte)
{
	dec_writeb(byte, (void __iomem *) iomem_addr);
}

#define AM85C30_RR0	0x00
#define AM85C30_D2	(0x01 << 2)
static void am85c30_putc(unsigned long port, char c)
{
	/*
	 * Output to ttyS0
	 */
	while ((am85c30_com_inb_command(port, AM85C30_RR0) & AM85C30_D2) == 0)
		E2K_NOP(7);
	am85c30_com_outb(port + 0x01, c);

	/*
	 * Output to ttyS1
	 */
	port += 2;
	while ((am85c30_com_inb_command(port, AM85C30_RR0) & AM85C30_D2) == 0)
		E2K_NOP(7);
	am85c30_com_outb(port + 0x01, c);
}

static void __putc(unsigned long port, char c)
{
	am85c30_putc(port, c);
}

static void putc(char c)
{
	unsigned long port = boot_info->serial_base;

	if (!port)
		return;

	__putc(port, c);
	if (c == '\n')
		__putc(port, '\r');
}

static void puts(char *s)
{
	while (*s)
		putc(*s++);
}

/*
 * Use global variables to prevent using data stack
 */
static const char hex_numbers_for_debug[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

static void put_u64(u64 num, int newline)
{
	char u64_char[18];
	int i;

	if (newline) {
		u64_char[16] = '\n';
		u64_char[17] = 0;
	} else {
		u64_char[16] = 0;
	}

	for (i = 0; i < 16; i++) {
		u64_char[15 - i] = hex_numbers_for_debug[num % 16];
		num = num / 16;
	}
	puts(u64_char);
}


static void error(char *str)
{
	puts(str);
	putc('\n');
}

static void error_loop(char *s)
{
	puts(s);
	for (;;)
		E2K_NOP(7);
}

static void probe_node_memory(bootblock_struct_t *bootblock, int node,
		bank_info_t *bank_info, bank_info_t **bank_info_ex_p,
		struct board_mem *bm)
{
	boot_info_t *bootinfo = &bootblock->info;
	bank_info_t	*bank_info_ex = *bank_info_ex_p;
	int		bank, bm_bank;

	for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank++) {
		unsigned long bank_start, bank_end;

		if (bank >= L_MAX_NODE_PHYS_BANKS_FUSTY) {
			int banks_ex_id = bank_info - bootinfo->bios.banks_ex;

			if (bank == L_MAX_NODE_PHYS_BANKS_FUSTY) {
				bank_info = bank_info_ex;
				banks_ex_id = bank_info -
						bootinfo->bios.banks_ex;
			}
			if (banks_ex_id >= L_MAX_PHYS_BANKS_EX) {
				bank_info_ex = bank_info;
				puts("WARNING: Node has phys banks in extended area, but extended area is full, ignored\n");
				goto out;
			}
		}

		if (bank_info->size == 0) {
			if (bank >= L_MAX_NODE_PHYS_BANKS_FUSTY)
				bank_info_ex = bank_info + 1;
			goto out; /* no more banks on node */
		}

		bank_start = bank_info->address;
		bank_end = bank_start + bank_info->size;

#ifdef DEBUG
		puts("Memory bank from 0x");
		put_u64(bank_start, false);
		puts(" to 0x");
		put_u64(bank_end, true);
#endif

		bm_bank = bm->bm_nBanks;
		if (bm_bank > 0 &&
		    bm->bm_Banks[bm_bank - 1].mb_top == bank_start) {
			/* Continue previous bank */
			--bm_bank;
			bm->bm_Banks[bm_bank].mb_top = bank_end;
		} else {
			/* Add new bank */
			assert(bm_bank < MAX_MEM_BANKS);
			bm->bm_Banks[bm_bank].mb_bottom = bank_start;
			bm->bm_Banks[bm_bank].mb_top = bank_end;
			++bm->bm_nBanks;
		}

		++bank_info;
	}

	if (bank == L_MAX_NODE_PHYS_BANKS) {
		bank_info_ex = bank_info;
		puts("WARNING: Node last phys bank for node in extended area is not null, ignored\n");
		goto out;
	}

	if (bank < L_MAX_NODE_PHYS_BANKS_FUSTY) {
		for (; bank < L_MAX_NODE_PHYS_BANKS_FUSTY; bank++) {
			if (!bank_info++->size)
				goto out;
		}
	} else {
		bank_info_ex = bank_info;
	}

	while (bank_info_ex++->size) {
		if (++bank >= L_MAX_NODE_PHYS_BANKS) {
			puts("WARNING: Node last phys bank for node in extended area is not null, ignored\n");
			break;
		}
		if (bank_info_ex - bootinfo->bios.banks_ex >=
				L_MAX_PHYS_BANKS_EX) {
			puts("WARNING: Node last phys bank in extended area is not null, ignored\n");
			break;
		}
	}

out:
	*bank_info_ex_p = bank_info_ex;
}

/*
 * probe_memory - initialize free memory list
 */
static void probe_memory(bootblock_struct_t *bootblock, struct board_mem *bm)
{
	boot_info_t *bootinfo = &bootblock->info;
	bank_info_t *bank_info_ex = bootinfo->bios.banks_ex;
	u_int64_t phys_nodes_map = bootinfo->nodes_map;
	int node;

	for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
		bank_info_t *bank_info = bootinfo->nodes_mem[node].banks;

		if (!(phys_nodes_map & (1UL << node)) || bank_info->size == 0)
			continue;

		probe_node_memory(bootblock, node, bank_info,
				  &bank_info_ex, bm);
	}
}

static int intersect(struct mem_bank *b1, const struct mem_bank *b2,
		     struct mem_bank *b3, int ignore_busy)
{
	assert(b1->mb_top >= b1->mb_bottom && b2->mb_top >= b2->mb_bottom);

	if (b1->mb_bottom < b2->mb_bottom && b1->mb_top > b2->mb_top) {
		/* Cut one bank into two */
		b3->mb_bottom = b1->mb_bottom;
		b3->mb_top = b2->mb_bottom;
		b3++;
		b3->mb_bottom = b2->mb_top;
		b3->mb_top = b1->mb_top;
		return 2;
	}

	if (b1->mb_bottom >= b2->mb_top || b1->mb_top <= b2->mb_bottom) {
		/* No intersection */
		*b3 = *b1;
	} else {
		/* Do not allow double reservations */
		assert(ignore_busy || (b1->mb_bottom <= b2->mb_bottom &&
				       b1->mb_top >= b2->mb_top));

		/* Intersection */
		b3->mb_bottom = (b1->mb_bottom < b2->mb_bottom) ?
				b1->mb_bottom : b2->mb_top;
		b3->mb_top = (b1->mb_top > b2->mb_top) ? b1->mb_top :
							 b2->mb_bottom;
	}

	if (b3->mb_bottom < b3->mb_top)
		return 1;

	*b3 = (struct mem_bank) {0, 0};

	return 0;
}

static void sub(struct board_mem *from, const struct mem_bank *b,
		struct board_mem *to, int ignore_busy)
{
	int n, i;

	for(i = 0, n = 0; i < from->bm_nBanks; i++)
		n += intersect(&from->bm_Banks[i], b,
			       &to->bm_Banks[n], ignore_busy);

	to->bm_nBanks = n;
}

static struct board_mem bm_tmp;
static void reserve_memory_area(struct board_mem *bm, unsigned long phys_addr,
				 unsigned long mem_size, int ignore_busy,
				 char *name)
{
	struct mem_bank reserved;
	unsigned long end_addr = phys_addr + mem_size;

	assert(mem_size);

	phys_addr = round_down(phys_addr, PAGE_SIZE);
	end_addr = round_up(end_addr, PAGE_SIZE);
	mem_size = end_addr - phys_addr;

#ifdef DEBUG
	puts("Reserved ");
	puts(name);
	puts(" area: address 0x");
	put_u64(phys_addr, false);
	puts(", size 0x");
	put_u64(mem_size, true);
#endif

	reserved.mb_bottom = phys_addr;
	reserved.mb_top = end_addr;

	sub(bm, &reserved, &bm_tmp, ignore_busy);

	/* Do not allow double reservations */
	assert(ignore_busy || bm->bm_nBanks != bm_tmp.bm_nBanks ||
	       memcmp(bm->bm_Banks, &bm_tmp.bm_Banks, sizeof(*bm)));

	memcpy(bm, &bm_tmp, sizeof(*bm));
}

/*
 * Reserve the needed memory from MP - tables
 */

static void boot_reserve_mp_table(boot_info_t *bootinfo, struct board_mem *bm)
{
	struct intel_mp_floating *mpf;

	if (bootinfo->mp_table_base == 0UL)
		return;

	/*
	 * MP floating specification table
	 */
	reserve_memory_area(bm, bootinfo->mp_table_base, PAGE_SIZE,
			     1, "MP floating table");

	mpf = (struct intel_mp_floating *) bootinfo->mp_table_base;

	/*
	 * MP configuration table
	 */
	if (mpf->mpf_physptr != 0UL)
		reserve_memory_area(bm, mpf->mpf_physptr, PAGE_SIZE,
				     1, "MP configuration table");
}

static void reserve_memory(boot_info_t *bootinfo, struct board_mem *bm)
{
	unsigned long area_base, area_size;
	unsigned long load_offset;
	psp_struct_t	PSP = {{{0}}, {{0}}};
	pcsp_struct_t	PCSP  = {{{0}}, {{0}}};
	e2k_usbr_t	USBR = {{0}};
	usd_struct_t	USD  = {{{0}}, {{0}}};
	int		bank;

	reserve_memory_area(bm, 0, PAGE_SIZE, 0, "0-page");

	load_offset = AS(NATIVE_READ_OSCUD_LO_REG()).base - 0x10000;
	reserve_memory_area(bm, (unsigned long) _start + load_offset,
			(unsigned long) (_end - _start), 0, "kernel image");

	reserve_memory_area(bm, 640 * 1024 /* ROM, VGA ... */,
			(1024 - 640) * 1024, 0, "PC");

	for (bank = 0; bank < bootinfo->num_of_busy; bank++) {
		bank_info_t *busy_area = &bootinfo->busy[bank];

		reserve_memory_area(bm, busy_area->address, busy_area->size,
				1, "BIOS data");
	}

	if (boot_info->ramdisk_size)
		reserve_memory_area(bm, boot_info->ramdisk_base,
				boot_info->ramdisk_size, 1, "ramdisk");

	reserve_memory_area(bm, 0x7ee00000, PAGE_SIZE, 1, "APIC page");

	boot_reserve_mp_table(bootinfo, bm);

	PSP = NATIVE_NV_READ_PSP_REG();
	reserve_memory_area(bm, PSP.PSP_base, PSP.PSP_size, 1,
			"kernel boot-time procedures stack");

	PCSP = NATIVE_NV_READ_PCSP_REG();
	reserve_memory_area(bm, PCSP.PCSP_base, PCSP.PCSP_size, 1,
			"kernel boot-time procedure chain stack");

	USBR = read_USBR_reg();
	area_base = USBR.USBR_base;
	read_USD_reg(&USD);
	area_size = area_base - USD.USD_base + USD.USD_size;
	area_base -= area_size;
	reserve_memory_area(bm, area_base, area_size, 1,
			"kernel boot-time data stack");
}

static unsigned long find_free_memory(struct board_mem *bm,
		unsigned long size, unsigned long align)
{
	unsigned long start, end;
	struct mem_bank *bank;
	int search_low = 0;
	int i;

retry:
	for (i = 0; i < bm->bm_nBanks; i++) {
		bank = &bm->bm_Banks[i];
		start = round_up(bank->mb_bottom, align);
		end = round_down(bank->mb_top, align);

		if (start < end && size <= end - start &&
		    (search_low || start >= 0x100000000UL)) {
			reserve_memory_area(bm, start, size, 0, "allocated");
			return start;
		}
	}

	/* First try to find non-DMA memory */
	if (!search_low) {
		search_low = 1;
		goto retry;
	}

	return -ENOMEM;
}

static __always_inline void jump_to_image(unsigned long kernel_address,
					  int n, bootblock_struct_t *bootblock)
{
	e2k_oscud_lo_t oscud_lo;

	/*
	 * Before jumping we must correct %oscud and %cud
	 * registers which contain kernel entry address.
	 */
	oscud_lo = NATIVE_READ_OSCUD_LO_REG();
	AS(oscud_lo).base = kernel_address;
	NATIVE_WRITE_OSCUD_LO_REG(oscud_lo);
	NATIVE_WRITE_CUD_LO_REG(oscud_lo);

	E2K_JUMP_ABSOLUTE_WITH_ARGUMENTS_2(kernel_address + 0x6000,
					   n, bootblock);
}

static struct board_mem memory;

__section(.boot_entry)
void decompress_kernel(int n, bootblock_struct_t *bootblock)
{
	unsigned long load_offset;
	struct board_mem *bm = &memory;
	e2k_idr_t idr;
	int ret;

	/*
	 * Only bootstrap processor proceeds to unpacking
	 */
	idr = read_idr();
	if (idr.mdl >= IDR_E12C_MDL)
		ret = boot_epic_is_bsp();
	else
		ret = boot_apic_is_bsp();

	if (!ret) {
		while (unpacking_in_progress)
			E2K_NOP(7);
		/* Barrier between reading `unpacking_in_progress'
		 * and reading unpacked kernel */
		smp_rmb();
		jump_to_image(kernel_address, n, bootblock);
	}

	/*
	 * Clear .bss ASAP
	 */
	load_offset = AS(NATIVE_READ_OSCUD_LO_REG()).base - 0x10000;

	memset(_bss + load_offset, 0, _ebss - _bss);

	/*
	 * Initialize console and say hello
	 */
	boot_info = &bootblock->info;

	if (read_idr().mdl == IDR_E1CP_MDL)
		io_area_phys_base = E2K_LEGACY_SIC_IO_AREA_PHYS_BASE;
	else
		io_area_phys_base = E2K_FULL_SIC_IO_AREA_PHYS_BASE;

	puts("\nDecompressor started\n");

#ifdef DEBUG
	puts("Cleared .bss at 0x");
	put_u64((unsigned long) _bss + load_offset, false);
	puts(", size 0x");
	put_u64(_ebss - _bss, true);
#endif

	/*
	 * Mark free and reserved memory
	 */
	probe_memory(bootblock, bm);

	reserve_memory(&bootblock->info, bm);

	/*
	 * Find free memory area for heap
	 */
	free_mem_ptr = find_free_memory(bm, BOOT_HEAP_SIZE + PAGE_SIZE, 8);
	if (IS_ERR_VALUE(free_mem_ptr))
		error_loop("ERROR: could not find free memory area for heap\n");

	/* free_mem_ptr must not be equal to 0 */
	if (!free_mem_ptr)
		free_mem_ptr += PAGE_SIZE;
	free_mem_end_ptr = free_mem_ptr + BOOT_HEAP_SIZE;

	puts("Heap from 0x");
	put_u64(free_mem_ptr, false);
	puts(" to 0x");
	put_u64(free_mem_end_ptr, true);

	/*
	 * Decompress the kernel
	 */
	kernel_address = find_free_memory(bm,
			(unsigned long) __orig_kernel_size, 0x400000);
	if (IS_ERR_VALUE(kernel_address))
		error_loop("ERROR: could not find free memory area to unpack kernel to\n");

	puts("Unpacking 0x");
	put_u64((u64) __orig_kernel_size, false);
	puts(" bytes from 0x");
	put_u64((unsigned long) _kernel + load_offset, false);
	puts(" to 0x");
	put_u64(kernel_address, false);
	puts("...\n");

	ret = __decompress(_kernel + load_offset, _ekernel - _kernel, NULL,
			   NULL, (char *) kernel_address, 0, NULL, error);
	if (ret)
		error_loop("ERROR: failed to unpack kernel\n");

	puts("Done\n");

	/*
	 * Tell others they can proceed
	 */
	bootblock->info.kernel_base = kernel_address;
	bootblock->info.kernel_size = (unsigned long) __orig_kernel_size;
	smp_wmb(); /* Wait for unpacked kernel and bootblock changes */
	unpacking_in_progress = 0;

	/*
	 * Jump to the kernel
	 */
	jump_to_image(kernel_address, n, bootblock);
}
