/*
 *  linux/arch/e2k/kernel/e2k_ide_drv.c
 *
 */

#include <linux/config.h>
#include <linux/ide.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/delay.h>

#include <asm/bootinfo.h>
#include <asm/cpu_regs_access.h>
#include <asm/e2k_debug.h>

#undef DebugIO
#define	DEBUG_IO	0
#define	DebugIO		if (DEBUG_IO) rom_printk

#define DRIVE_NUM 0
#define E2K_IDE_TIMEOUT 1000000

#define E2K_IDE_BASE 0x1f0
#define E2K_IDE_DATA_REG (E2K_IDE_BASE + 0)
#define E2K_IDE_ERROR_REG (E2K_IDE_BASE + 1)
#define E2K_IDE_FEATURE_REG (E2K_IDE_BASE + 1)
#define E2K_IDE_NSECTOR_REG (E2K_IDE_BASE + 2)
#define E2K_IDE_SECTOR_REG (E2K_IDE_BASE + 3)
#define E2K_IDE_LCYL_REG (E2K_IDE_BASE + 4)
#define E2K_IDE_HCYL_REG (E2K_IDE_BASE + 5)
#define E2K_IDE_SELECT_REG (E2K_IDE_BASE + 6)
#define E2K_IDE_STATUS_REG (E2K_IDE_BASE + 7)
#define E2K_IDE_COMMAND_REG (E2K_IDE_BASE + 7)

#define E2K_CMD_IDENTIFY 	0xEC
#define E2K_CMD_READ_DMA	0xC8
#define E2K_CMD_READ_SECTORS	0x20
#define E2K_CMD_READ_MULTIPLE	0xC4
#define E2K_CMD_WRITE_DMA	0xCA
#define E2K_CMD_WRITE_SECTORS	0x30
#define E2K_CMD_WRITE_MULTIPLE	0xC5

#define E2K_ERR_BBK	0x80
#define E2K_ERR_UNC	0x40
#define E2K_ERR_MC	0x20
#define E2K_ERR_IDNF	0x10
#define E2K_ERR_MCR	0x08
#define E2K_ERR_ABRT	0x04
#define E2K_ERR_TK0NF	0x02
#define E2K_ERR_AMNF	0x01

#define E2K_GET_STAT()	inb_p(E2K_IDE_STATUS_REG)
#define E2K_GET_ERR()	inb_p(E2K_IDE_ERROR_REG)


#define BLOCK_SHIFT 0x103f0

struct hd_driveid drive_id;
struct hd_driveid* id = &drive_id;
byte io_32bit = 0;
byte status;
byte id_loaded = 0;
int switch_off = 0;
unsigned long vars_start, vars_end;
unsigned long bblock_start, bblock_end;

int nado_loadid = 0;

static unsigned char inb_p(unsigned long port)
{

	unsigned char byte;

	DebugIO("inb_p entered.\n");

	byte = E2K_READ_MAS_B(E2K_X86_IO_AREA_PHYS_BASE + port, MAS_IOADDR);

	DebugIO("inb_p exited.\n");

	return byte;
}

static void outb_p(unsigned char byte, unsigned long port)
{
	DebugIO("outb_p entered.\n");

	E2K_WRITE_MAS_B(E2K_X86_IO_AREA_PHYS_BASE + port, byte, MAS_IOADDR);

	DebugIO("outb_p exited.\n");
}

/*static void outb(unsigned long port, char byte)
{
	char *addr = (char *) E2K_X86_IO_BASE;
	*(addr + port) = byte;
}

static char inb(unsigned long port)
	{
	char *addr = (char *) E2K_X86_IO_BASE;
	return *(addr + port);
}*/

void report_error(void) {
	byte error;
	error = inb_p(E2K_IDE_ERROR_REG);
	if (error & E2K_ERR_BBK)
		rom_printk("Bad block mark was detected\n");
	if (error & E2K_ERR_UNC)
		rom_printk("Uncorrectable data error\n");
	if (error & E2K_ERR_MC)
		rom_printk("Reserved for removable drives\n");
	if (error & E2K_ERR_IDNF)
		rom_printk("Requested sector's ID was not found\n");
	if (error & E2K_ERR_MCR)
		rom_printk("Reserved for removable drives\n");
	if (error & E2K_ERR_ABRT)
		rom_printk("Requested command has beed aborted due to a drive status error\n");
	if (error & E2K_ERR_TK0NF)
		rom_printk("Track 0 has not been found\n");
	if (error & E2K_ERR_AMNF)
		rom_printk("Data address mark has not been found\n");
}

int inline wait_for_bsy0(void) {
	unsigned long timeout = E2K_IDE_TIMEOUT / 50000;
	unsigned long loc_timeout;
	do {
		if (!((status = inb_p(E2K_IDE_STATUS_REG)) & BUSY_STAT))
			return 0;
		loc_timeout = 5000;
		while (loc_timeout--);
		timeout--;
	} while (timeout);
	return 1;
}

int inline wait_for_drq1(void) {
	unsigned long timeout = E2K_IDE_TIMEOUT / 1000;
	unsigned long loc_timeout;
	do {
		if ((status = inb_p(E2K_IDE_STATUS_REG)) & DRQ_STAT)
			return 0;
		loc_timeout = 1000;
		while (loc_timeout--);
		timeout--;
	} while (timeout);
	return 1;
}

extern inline u16 e2k_fast_inw_p(unsigned long port)
{
	return E2K_READ_MAS_H(E2K_X86_IO_AREA_PHYS_BASE + port, MAS_IOADDR);
}

void e2k_ide_input_data_16bit(void *buffer, unsigned int wcount)
{
	u16 *hw_p = (u16 *)buffer;
	u16 temp;

	wcount = wcount << 1;

	//DebugIO1("insw entered.\n");

	//DebugIO1("insw(): port=%lx dst=%lx count=%lx\n", E2K_IDE_DATA_REG, buffer, wcount);

        if (((unsigned long)buffer) & 0x1) {
                rom_printk("insw: memory address is not short aligned");
        }
        if (!wcount)
                return;

	while (wcount--) {
		temp = e2k_fast_inw_p(E2K_IDE_DATA_REG);
		//if (*hw_p != temp)
		//	rom_printk("Difference - addr: 0x%X mem: %d disk: %d\n", (unsigned long)hw_p, *hw_p, temp);
		if (((unsigned long)hw_p >= vars_start) && ((unsigned long)hw_p < vars_end)) {
			//rom_printk("VARS zone\n");
			hw_p++;
			continue;
		}
		if (((unsigned long)hw_p >= bblock_start) && ((unsigned long)hw_p < bblock_end)) {
			hw_p++;
			continue;
		}
		if (!switch_off) {
			//if (*hw_p != temp)
			//	rom_printk("Difference - addr: 0x%X mem: %d disk: %d\n", (unsigned long)hw_p, *hw_p, temp);
			*hw_p++ = temp;
		} else
			hw_p++;
		//*hw_p++ = e2k_fast_inw_p(E2K_IDE_DATA_REG);
	}

	//DebugIO1("insw exited.\n");
}

void inline e2k_ide_drv_input_data(void *buffer, unsigned int wcount) {
	if (io_32bit)
		rom_printk("32bit IO is not supported");
	else
		e2k_ide_input_data_16bit(buffer, wcount);
}

int load_id(void) {
	outb_p(E2K_CMD_IDENTIFY, E2K_IDE_COMMAND_REG);
	if (wait_for_bsy0())
		return 1;
	if (wait_for_drq1())
		return 1;
	if (status & BAD_R_STAT) {
		rom_printk("Drive has refused ID command\n");
		report_error();
		return 1;
	}
	e2k_ide_drv_input_data((void*)id, SECTOR_WORDS);
	return 0;
}

int inline select_drive(void) {
	/*  1, LBA or CHS, 1, 0=drive, 0, .. 0 */
	outb_p(0xE0, E2K_IDE_SELECT_REG);
	return wait_for_bsy0();
}

int read_data_chs(void* buffer, unsigned long block, int nsect) {
	unsigned int sect,head,cyl,track;
	int i;

if (nado_loadid) rom_printk("Starting to read page\n");
	outb_p(8, E2K_IDE_NSECTOR_REG);

	track = block / id->sectors;
        sect  = block % id->sectors + 1;
        outb_p(sect,E2K_IDE_SECTOR_REG);
        head  = track % id->heads;
        cyl   = track / id->heads;
        outb_p(cyl, E2K_IDE_LCYL_REG);
        outb_p(cyl>>8, E2K_IDE_HCYL_REG);
        outb_p(head| 0xE0, E2K_IDE_SELECT_REG);
	//rom_printk("Block is 0x%lx, track - %d, sect - %d, head - %d, cyl - %d\n", block, track, sect, head, cyl);

if (nado_loadid) rom_printk("Command\n");
	outb_p(E2K_CMD_READ_SECTORS, E2K_IDE_COMMAND_REG);
	for (i = 0; i < nsect; i++) {
		if (wait_for_bsy0())
			return 1;
		if (wait_for_drq1())
			return 1;
		if (status & BAD_R_STAT) {
			rom_printk("Drive has refused READ_SECTORS command\n");
			report_error();
			return 1;
		}
		e2k_ide_drv_input_data(buffer, SECTOR_WORDS);
		buffer += 512;
	}
	return 0;
}

int inline read_page_chs(void* buffer, unsigned long block) {
	return read_data_chs(buffer, block, 8);
}

long io_error = 0;

void e2k_read_data(void * data, int blocknr) {
	if (io_error)
		return;
	rom_printk("Recovery: reading page to 0x%X\n", (unsigned long)data);
	
	if (read_page_chs(data, BLOCK_SHIFT + blocknr*8)) {
		rom_printk("Read failed\n");
		io_error = 1;
	}
}

#define VERSION_NUMBER '4'
extern bootblock_struct_t      *bootblock;

void load_machine_state_new(boot_info_t *boot_info) {
	long nr_pages, nr_block;
	unsigned long* page = (unsigned long*)PAGE_SIZE;
	int bank;
	unsigned int cached_irq_mask;
	unsigned int* mask_ptr;
	bank_info_t *bank_info;
	int num_of_banks = boot_info->num_of_banks;
	int page_is_valid;
	e2k_psp_hi_t psp_hi;
	e2k_psp_lo_t psp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_pcsp_lo_t pcsp_lo;

	switch_off = 0;
	if (!id_loaded) {
	       	if (load_id()) {
			rom_printk("Disk ID cannot be loaded. Memory will not be loaded.\n");
			io_error = 1;
			id_loaded = 1;
			return;
		}
	} else {
		rom_printk("Skipping ID\n");
		nado_loadid = 1;
	}
	
	rom_printk("ID loaded...\n");
	/* Load first page */
	e2k_read_data(page, 1);

	/* Check signature */
	if ((page[0] != 'e') || (page[1] != VERSION_NUMBER) || (page[2] != 'k')) {
		rom_printk("Memory will not be loaded. Invalid signature.\n");
		return;
	}
	/* Calculate variables region. It will be protected from write */
	vars_start = page[4] - 0x10000000000;
	vars_end = page[5] - 0x10000000000;

	bblock_start = (unsigned long)boot_info;
	bblock_end = (unsigned long)bootblock + sizeof(bootblock_struct_t);
	rom_printk("Boot block form 0x%X to 0x%X\n", bblock_start, bblock_end);
	
	mask_ptr = (int*)(page[6] - 0x10000000000);
	cached_irq_mask = mask_ptr[0];
	rom_printk("IRQ mask is %d - 0x%X\n", cached_irq_mask, (unsigned long)mask_ptr);
	switch_off = 1;
	nr_pages = page[7]; /* actually num_physpages */
	nr_block = 10; /* first block of the /dev/hdaN */ 
	page = (unsigned long*)0;
	rom_printk("Loading 0x%X pages, number of physical memory banks is %d\n", nr_pages, num_of_banks);

	while ((nr_pages > 0) && (io_error == 0)) {
		//if (nr_pages == 3*1024) {
		//	rom_printk("Starting real save\n");
			switch_off = 0;
		//}
		bank_info = &boot_info->bank;
		page_is_valid = 0;
		for (bank = 0; bank < num_of_banks; bank ++) {
			if ((bank_info->address <= (unsigned long)page) && 
					(bank_info->address + bank_info->size > (unsigned long)page)) {
				page_is_valid = 1;
				break;
			}
			bank_info++;
		}
		/* PSP stack */
		psp_hi = READ_PSP_HI_REG();
		psp_lo = READ_PSP_LO_REG();
		if (((unsigned long)page >= AS_STRUCT(psp_lo).base) &&
				((unsigned long)page < AS_STRUCT(psp_lo).base + AS_STRUCT(psp_hi).size)) {
			page_is_valid = 0;
			rom_printk("PSP stack zone\n");
		}

		/* Chain stack */
		pcsp_hi = READ_PCSP_HI_REG();
		pcsp_lo = READ_PCSP_LO_REG();
		if (((unsigned long)page >= AS_STRUCT(pcsp_lo).base) &&
				((unsigned long)page < AS_STRUCT(pcsp_lo).base + AS_STRUCT(pcsp_hi).size)) {
			page_is_valid = 0;
			rom_printk("PCSP stack zone\n");
		}

		/* C stack */
		if (((unsigned long)page >= READ_USBR_REG().USBR_base - E2K_BOOT_KERNEL_US_SIZE) &&
				((unsigned long)page < READ_USBR_REG().USBR_base)) {
			page_is_valid = 0;
			rom_printk("C stack zone\n");
		}

		if (page_is_valid) {
			e2k_read_data(page, nr_block);
		} else 
			rom_printk("Page 0x%X is invalid\n", (unsigned long)page);
		nr_pages--;
		nr_block++;
		page += (PAGE_SIZE)/sizeof(unsigned long);
	}
	mask_ptr[0] = cached_irq_mask;
	if (io_error)
		rom_printk("IO ERROR. Memory was not loaded\n");
}
