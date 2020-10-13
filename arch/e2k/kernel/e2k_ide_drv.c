/*
 *  linux/arch/e2k/kernel/e2k_ide_drv.c
 *
 */

#include <linux/config.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/ide.h>
#include <linux/errno.h>
#include <linux/delay.h>

#include <asm/io.h>

#define DebugIO1

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

#define E2K_GET_STAT()	inb(E2K_IDE_STATUS_REG)
#define E2K_GET_ERR()	inb(E2K_IDE_ERROR_REG)

struct hd_driveid drive_id;
struct hd_driveid* id = &drive_id;
byte io_32bit = 0;
byte status;

void report_error(void) {
	byte error;
	error = inb(E2K_IDE_ERROR_REG);
	if (error & E2K_ERR_BBK)
		printk("Bad block mark was detected\n");
	if (error & E2K_ERR_UNC)
		printk("Uncorrectable data error\n");
	if (error & E2K_ERR_MC)
		printk("Reserved for removable drives\n");
	if (error & E2K_ERR_IDNF)
		printk("Requested sector's ID was not found\n");
	if (error & E2K_ERR_MCR)
		printk("Reserved for removable drives\n");
	if (error & E2K_ERR_ABRT)
		printk("Requested command has beed aborted due to a drive status error\n");
	if (error & E2K_ERR_TK0NF)
		printk("Track 0 has not been found\n");
	if (error & E2K_ERR_AMNF)
		printk("Data address mark has not been found\n");
}

int inline wait_for_bsy0(void) {
	unsigned long timeout = E2K_IDE_TIMEOUT / 50000;
	unsigned long loc_timeout;
	do {
		if (!((status = inb(E2K_IDE_STATUS_REG)) & BUSY_STAT))
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
		if ((status = inb(E2K_IDE_STATUS_REG)) & DRQ_STAT)
			return 0;
		loc_timeout = 1000;
		while (loc_timeout--);
		timeout--;
	} while (timeout);
	return 1;
}

extern inline u16 e2k_fast_inw_p(unsigned long port)
{
	return inw_p(port);
}

extern inline void e2k_fast_outw_p(u16 halfword, unsigned long port)
{
	outw_p(halfword, port);
}

void e2k_ide_input_data_16bit(void *buffer, unsigned int wcount)
{
	u16 *hw_p = (u16 *)buffer;

	wcount = wcount << 1;

	//DebugIO1("insw entered.\n");

	//DebugIO1("port=%lx dst=%lx count=%lx\n", E2K_IDE_DATA_REG, buffer, wcount);

        if (((unsigned long)buffer) & 0x1) {
                panic("insw: memory address is not short aligned");
        }
        if (!wcount)
                return;

	while (wcount--) {
		*hw_p++ = e2k_fast_inw_p(E2K_IDE_DATA_REG);
	}

	//DebugIO1("insw exited.\n");
}

void e2k_ide_output_data_16bit(void *buffer, unsigned int wcount)
{
	u16 *hw_p = (u16 *)buffer;

	wcount = wcount << 1;

	//DebugIO1("outsw entered.\n");

	//DebugIO1("port=%lx src=%lx count=%lx\n", E2K_IDE_DATA_REG, buffer, wcount);

        if (((unsigned long)buffer) & 0x1) {
                panic("outsw: memory address is not short aligned");
        }
        if (!wcount)
                return;

	while (wcount--) {
		e2k_fast_outw_p(*hw_p++, E2K_IDE_DATA_REG);
	}

	//DebugIO1("outsw exited.\n");
}

void inline e2k_ide_drv_input_data(void *buffer, unsigned int wcount) {
	if (io_32bit)
		panic("32bit IO is not supported");
	else
		e2k_ide_input_data_16bit(buffer, wcount);
}

void inline e2k_ide_drv_output_data(void *buffer, unsigned int wcount) {
	if (io_32bit)
		panic("32bit IO is not supported");
	else
		e2k_ide_output_data_16bit(buffer, wcount);
}

int load_id(void) {
	outb(E2K_CMD_IDENTIFY, E2K_IDE_COMMAND_REG);
	if (wait_for_bsy0())
		return 1;
	if (wait_for_drq1())
		return 1;
	if (status & BAD_R_STAT) {
		printk("Drive has refused ID command\n");
		report_error();
		return 1;
	}
	e2k_ide_drv_input_data((void*)id, SECTOR_WORDS);
	return 0;
}

int inline select_drive(void) {
	/*  1, LBA or CHS, 1, 0=drive, 0, .. 0 */
	outb(0xE0, E2K_IDE_SELECT_REG);
	return wait_for_bsy0();
}

int read_data_lba(void* buffer, unsigned long block, int nsect) {
	int i;
	/* LBA */
	outb(8, E2K_IDE_NSECTOR_REG);
	
	outb(block,E2K_IDE_SECTOR_REG);
        outb(block>>=8,E2K_IDE_LCYL_REG);
        outb(block>>=8,E2K_IDE_HCYL_REG);
        outb(((block>>8)&0x0f)| 0xE0, E2K_IDE_SELECT_REG);

	outb(E2K_CMD_READ_SECTORS, E2K_IDE_COMMAND_REG);
	for (i = 0; i < nsect; i++) {
		if (wait_for_bsy0())
			return 1;
		if (wait_for_drq1())
			return 1;
		if (status & BAD_R_STAT) {
			printk("Drive has refused READ_SECTORS command\n");
			report_error();
			return 1;
		}
		e2k_ide_drv_input_data(buffer, SECTOR_WORDS);
		buffer += 512;
	}
	return 0;	
}

int read_data_chs(void* buffer, unsigned long block, int nsect) {
	unsigned int sect,head,cyl,track;
	int i;
	
	outb(8, E2K_IDE_NSECTOR_REG);

	track = block / id->sectors;
        sect  = block % id->sectors + 1;
        outb(sect,E2K_IDE_SECTOR_REG);
        head  = track % id->heads;
        cyl   = track / id->heads;
        outb(cyl, E2K_IDE_LCYL_REG);
        outb(cyl>>8, E2K_IDE_HCYL_REG);
        outb(head| 0xE0, E2K_IDE_SELECT_REG);
	printk("Block is 0x%lx, track - %d, sect - %d, head - %d, cyl - %d\n", block, track, sect, head, cyl);

	outb(E2K_CMD_READ_SECTORS, E2K_IDE_COMMAND_REG);
	for (i = 0; i < nsect; i++) {
		if (wait_for_bsy0())
			return 1;
		if (wait_for_drq1())
			return 1;
		if (status & BAD_R_STAT) {
			printk("Drive has refused READ_SECTORS command\n");
			report_error();
			return 1;
		}
		e2k_ide_drv_input_data(buffer, SECTOR_WORDS);
		buffer += 512;
	}
	return 0;
}

int inline read_page_lba(void* buffer, unsigned long block) {
	return read_data_lba(buffer, block, 8);
}

int inline read_page_chs(void* buffer, unsigned long block) {
	return read_data_chs(buffer, block, 8);
}

int write_data_lba(void* buffer, unsigned long block, int nsect) {
	int i;
	outb(8, E2K_IDE_NSECTOR_REG);
	
	outb(block,E2K_IDE_SECTOR_REG);
        outb(block>>=8,E2K_IDE_LCYL_REG);
        outb(block>>=8,E2K_IDE_HCYL_REG);
        outb(((block>>8)&0x0f)| 0xE0, E2K_IDE_SELECT_REG);
	
	outb(E2K_CMD_WRITE_SECTORS, E2K_IDE_COMMAND_REG);

	/* Wait for command */
	if (wait_for_bsy0())
		return 1;
	for (i = 0; i < nsect; i++) {
		if (wait_for_drq1())
			return 1;
		if (status & BAD_W_STAT) {
			report_error();
			return 1;
		}
		e2k_ide_drv_output_data(buffer, SECTOR_WORDS);
		buffer += 512;
		if (wait_for_bsy0())
			return 1;
	}
	status = inb(E2K_IDE_STATUS_REG);
	if (status & BAD_W_STAT) {
		report_error();
		return 1;
	}
	return 0;
}

int write_data_chs(void* buffer, unsigned long block, int nsect) {
	int i;
	unsigned int sect,head,cyl,track;

	outb(8, E2K_IDE_NSECTOR_REG);

	track = block / id->sectors;
        sect  = block % id->sectors + 1;
        outb(sect,E2K_IDE_SECTOR_REG);
        head  = track % id->heads;
        cyl   = track / id->heads;
        outb(cyl, E2K_IDE_LCYL_REG);
        outb(cyl>>8, E2K_IDE_HCYL_REG);
        outb(head| 0xE0, E2K_IDE_SELECT_REG);

	outb(E2K_CMD_WRITE_SECTORS, E2K_IDE_COMMAND_REG);

	/* Wait for command */
	if (wait_for_bsy0())
		return 1;
	for (i = 0; i < nsect; i++) {
		if (wait_for_drq1())
			return 1;
		if (status & BAD_W_STAT) {
			report_error();
			return 1;
		}
		e2k_ide_drv_output_data(buffer, SECTOR_WORDS);
		buffer += 512;
		if (wait_for_bsy0())
			return 1;
	}
	status = inb(E2K_IDE_STATUS_REG);
	if (status & BAD_W_STAT) {
		report_error();
		return 1;
	}
	return 0;
}

int inline write_page_chs(void* buffer, unsigned long block) {
	printk("Block is 0x%lx\n", block);
	return write_data_chs(buffer, block, 8);
}

void read_status(void) {
	status = inb(E2K_IDE_STATUS_REG);
	printk("Status is 0x%lx", (long)status);
	if (status & (BAD_R_STAT | BAD_W_STAT))
		report_error();	
}

void print_id(void) {
	int i;
	printk("Serial number: ");
	for (i = 0; i < 20; i++)
		printk("%c", id->serial_no[i]);
	printk("\n");
	printk("Firmware revision: ");
	for (i = 0; i < 8; i++)
		printk("%c", id->fw_rev[i]);
	printk("\n");
	printk("Model number: ");
	for (i = 0; i < 40; i++)
		printk("%c", id->model[i]);
	printk("\n");
	printk("Max multsect: %d\n", (int)id->max_multsect);
	printk("DMA is %s\n", (id->capability & 0x01) ? "supported" : "not supported");
	printk("LBA is %s\n", (id->capability & 0x02) ? "supported" : "not supported");
	printk("IORDY may %s disabled\n", (id->capability & 0x01) ? "be" : "not be");
	printk("IORDY %s supported\n", (id->capability & 0x01) ? "is" : "may be");
	printk("Multsectors option is %s\n", (id->multsect_valid & 0x01) ? "valid" : "not valid");
	printk("Current number of multsectors %d\n", (int)id->multsect);
	printk("Total number of addressable sectors %d\n", id->lba_capacity);
	if (id->dma_mword & 0x04)
		printk("Multiword DMA mode 2 and below is supported\n");
	else if (id->dma_mword & 0x02)
		printk("Multiword DMA mode 1 and below is supported\n");
	else if (id->dma_mword & 0x01)
		printk("Multiword DMA mode 0 is supported\n");
	else
		printk("Multiword DMA mode is not supported\n");
	if (id->dma_mword & 0x400)
		printk("Multiword DMA mode 2 is selected\n");
	else if (id->dma_mword & 0x200)
		printk("Multiword DMA mode 1 is selected\n");
	else if (id->dma_mword & 0x100)
		printk("Multiword DMA mode 0 is selected\n");
	else
		printk("Multiword DMA mode is not selected\n");
	printk("PIO mode 3 is %s\n", (id->eide_pio_modes & 0x01) ? "supported" : "not supported");
	printk("PIO mode 4 is %s\n", (id->eide_pio_modes & 0x02) ? "supported" : "not supported");
	printk("Device supports ATA-7: %s\n", (id->major_rev_num & 0x80) ? "yes" : "no");
	printk("Device supports ATA-6: %s\n", (id->major_rev_num & 0x40) ? "yes" : "no");
	printk("Device supports ATA-5: %s\n", (id->major_rev_num & 0x20) ? "yes" : "no");
	printk("Device supports ATA-4: %s\n", (id->major_rev_num & 0x10) ? "yes" : "no");
	printk("Device supports ATA-3: %s\n", (id->major_rev_num & 0x08) ? "yes" : "no");
	printk("NOP command supported: %s\n", (id->command_set_1 & 0x4000) ? "yes" : "no");
	printk("READ BUFFER command supported: %s\n", (id->command_set_1 & 0x2000) ? "yes" : "no");
	printk("WRITE BUFFER command supported: %s\n", (id->command_set_1 & 0x1000) ? "yes" : "no");
	printk("48bit address supported: %s\n", (id->command_set_2 & 0x400) ? "yes" : "no");
}

