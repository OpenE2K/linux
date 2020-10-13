
#include "bios.h"
#include <linux/pci_ids.h>
#include "pci.h"
#include "../Am85C30.h"

#if defined(CONFIG_LMS_CONSOLE)
extern void console_probe(void);
#endif

bios_hardware_t hardware = {0};

/*
 * First part of BIOS initialization
 * 
 * No any memory available yet. Minimum initializations for the moment.
 */

void bios_first(void)
{

#if defined(CONFIG_LMS_CONSOLE)
	console_probe();
#endif

#ifndef CONFIG_E2K_SIC
#if defined(CONFIG_ENABLE_SERIAL) || defined CONFIG_SERIAL_PRINTK \
		|| defined CONFIG_SERIAL_BOOT_PRINTK
	enable_serial_ports();
#endif
#endif

}

/*
 * Rest of BIOS initialization
 * 
 * Most of the job can be completed here. PCI should be inited before.
 */

#undef TEST_RDMA_REGS
#ifdef TEST_RDMA_REGS
static void test_rdma(void)
{
	struct bios_pci_dev *dev;
	unsigned int val = 0;
	rom_printk("test_rdma: scanning for RDMA device on PCI bus\n");
	dev = bios_pci_find_device(0x1544, 0x7112, 0);	/* 0x71918086 - e3m
							   0x71121544 - lms */
	if (dev) {
		rom_printk("found on bus %d device %d\n",
			dev->bus->number, PCI_SLOT(dev->devfn));
	}else{
		rom_printk("!!! NOT FOUND !!!\n");
		return;
	}
	rom_printk("test_rdma: check it's own bars\n");
	rom_printk("test_rdma: bar[0] = 0x%x\n",dev->base_address[0]);
	rom_printk("test_rdma: bar[1] = 0x%x\n",dev->base_address[1]);
	rom_printk("RDMA controler regs : \n");
	rom_printk("0	=	0x%x\n", *(u32*)(dev->base_address[0]));
	rom_printk("1	=	0x%x\n", *(u32*)(dev->base_address[0] + 0x4));
	rom_printk("2	=	0x%x\n", *(u32*)(dev->base_address[0] + 0x8));
	rom_printk("3	=	0x%x\n", *(u32*)(dev->base_address[0] + 0xc));
	pcibios_read_config_dword(dev->bus->number, dev->devfn, 0x00, &val);
	rom_printk("conf space:	0x00	=	0x%x\n", val);
	pcibios_read_config_dword(dev->bus->number, dev->devfn, 0x04, &val);
	rom_printk("conf space:	0x04	=	0x%x\n", val);
	pcibios_read_config_dword(dev->bus->number, dev->devfn, 0x08, &val);
	rom_printk("conf space:	0x08	=	0x%x\n", val);
	pcibios_read_config_dword(dev->bus->number, dev->devfn, 0x0c, &val);
	rom_printk("conf space:	0x0c	=	0x%x\n", val);
	pcibios_read_config_dword(dev->bus->number, dev->devfn, 0x10, &val);
	rom_printk("conf space:	0x10	=	0x%x\n", val);
	pcibios_read_config_dword(dev->bus->number, dev->devfn, 0x14, &val);
	rom_printk("conf space:	0x14	=	0x%x\n", val);
	pcibios_read_config_dword(dev->bus->number, dev->devfn, 0x18, &val);
	rom_printk("conf space:	0x18	=	0x%x\n", val);

}
#endif

#ifdef CONFIG_E2K_SIC
//#define TEST_FM33256
#ifdef TEST_FM33256

#include <asm/e2k_api.h>
#include <asm/mas.h>
#include <asm/e2k_debug.h>
#include <asm/e2k.h>
#include "printk.h"
#include "pci.h"

#define MAX_SPI_DEVICE_NR                                       3

#define SPI_CONTROL                                             0x00
#define SPI_STATUS                                              0x04
#define SPI_OPCODE                                              0x08
#define SPI_ADDRESS                                             0x0C
#define SPI_MODE                                                0x10

#define SPI_WREN_CMD                                            6
#define SPI_WRDI_CMD                                            4
#define SPI_WRSR_CMD                                            5
#define SPI_RDSR_CMD                                            1
#define SPI_READ_CMD                                            3
#define SPI_WRITE_CMD                                           2
#define SPI_RDPC_CMD                                            0x13
#define SPI_WRPC_CMD                                            0x12

#define SPI_STATUS_BUSY_SHIFT                           0
#define SPI_STATUS_INTR_SHIFT                           1
#define SPI_STATUS_FAIL_SHIFT                           2

#define SPI_STATUS_BUSY                                         (1 << SPI_STATUS_BUSY_SHIFT)
#define SPI_STATUS_INTR                                         (1 << SPI_STATUS_INTR_SHIFT)
#define SPI_STATUS_FAIL                                         (1 << SPI_STATUS_FAIL_SHIFT)

#define SPI_DEVICE_0                                            0
#define SPI_DEVICE_1                                            1
#define SPI_DEVICE_2                                            2
#define SPI_DEVICE_3                                            3

#define SPI_ADDRESS_SIZE_8                                      0
#define SPI_ADDRESS_SIZE_16                                     1
#define SPI_ADDRESS_SIZE_24                                     2
#define SPI_ADDRESS_SIZE_32                                     3

#define MAX_SPI_BYTES                                           64

#define SPI_DEVICE_SHIFT                                0

#define MAX_SPI_ADDRESS_SIZE_SHIFT                      3
#define SPI_ADDRESS_SIZE_SHIFT                          2

#define SPI_DATA_SIZE_SHIFT                             4
#define SPI_ADDRESS_PHASE_SHIFT                         11

#define SPI_ADDRESS_PHASE_ENABLE                        (1 << SPI_ADDRESS_PHASE_SHIFT)
#define SPI_ADDRESS_PHASE_DISABLE                       (0 << SPI_ADDRESS_PHASE_SHIFT)

#define SPI_DATA_PHASE_SHIFT                            12

#define SPI_DATA_PHASE_ENABLE                           (1 << SPI_DATA_PHASE_SHIFT)
#define SPI_DATA_PHASE_DISABLE                          (0 << SPI_DATA_PHASE_SHIFT)

#define SPI_TRANS_TYPE_SHIFT                            13

#define SPI_TRANS_READ                                          (0 << SPI_TRANS_TYPE_SHIFT)
#define SPI_TRANS_WRITE                                         (1 << SPI_TRANS_TYPE_SHIFT)

#define SPI_START_SHIFT                                         14

#define SPI_START                                                       (1 << SPI_START_SHIFT)

#define SPI_KILL_SHIFT                                          15

#define SPI_KILL                                                        (1 << SPI_KILL_SHIFT)

static void error(char *x)
{
        rom_puts("\n\n");
        rom_puts(x);
        rom_puts("\n\n -- System halted");

        E2K_LMS_HALT_ERROR(0xdead); /* Halt */
}

struct i2c_spi {
	unsigned long cntrl_base;
	unsigned long data_base;
	unsigned char dev_number;
};

struct i2c_spi i2c_spi;
/* cmos_addr - entire registers offset in 
*		Processor Companion case 
*		(SPI_RDPC_CMD or SPI_WRPC_CMD) or
*		entire flash offset in the case of
*		(SPI_READ_CMD or SPI_READ_CMD) 
* i2c_spi_cntrl.cntrl_base i2c/spi control bar = bar[0] for pci device 
* i2c_spi_cntrl.data_base i2c/spi memory buffer bar =  bar[1] for pci device */

int spi_read(unsigned int cmos_addr)
{
        unsigned long i2c_spi_cntrl = i2c_spi.cntrl_base;
	unsigned long i2c_spi_data = i2c_spi.data_base;
	unsigned char data;
	unsigned int cmd = 0;

        /* Set READ operation code */
	E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_OPCODE, SPI_RDPC_CMD, MAS_IOADDR);

        /* Set addr offset */
	E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_ADDRESS, cmos_addr, MAS_IOADDR);

        /* Set Device number, Address size, Data size offset */
	cmd = i2c_spi.dev_number << SPI_DEVICE_SHIFT |
		   SPI_ADDRESS_SIZE_16 << SPI_ADDRESS_SIZE_SHIFT |
		   		     1 << SPI_DATA_SIZE_SHIFT |
					SPI_ADDRESS_PHASE_ENABLE |
					SPI_DATA_PHASE_ENABLE |
					SPI_TRANS_READ |
					SPI_START;
				     				
	E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_CONTROL, cmd, MAS_IOADDR);

        while((E2K_READ_MAS_W(i2c_spi_cntrl + SPI_STATUS, MAS_IOADDR) & 
				(SPI_STATUS_INTR | SPI_STATUS_FAIL)) == 0)
        if (E2K_READ_MAS_W(i2c_spi_cntrl + SPI_STATUS, MAS_IOADDR) & SPI_STATUS_FAIL) {
                rom_printk("spi_read: Error - Transfer Failed");
                return -1;
        }
	data = E2K_READ_MAS_B(i2c_spi_data, MAS_IOADDR);
        return (int)data;
}

int spi_ops(unsigned int dev_number, unsigned char cmd_code)
{
	unsigned int cmd;
//unsigned long i2c_spi_data = i2c_spi.data_base;
//unsigned char status;
	unsigned long i2c_spi_cntrl = i2c_spi.cntrl_base;
        if (dev_number > MAX_SPI_DEVICE_NR) {
                rom_printk("spi_ops: Error - Device number is to large: %d (Max: %d)", dev_number, MAX_SPI_DEVICE_NR);
                return -1;
        }
        switch(cmd_code) {
                case SPI_READ_CMD:
                case SPI_WRITE_CMD:
		case SPI_RDPC_CMD:
                case SPI_WRPC_CMD:
                        rom_printk("spi_ops: Error - Wrong command code: %d", cmd_code);
                        return -1;
                default:
                        break;
        }

	E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_OPCODE, cmd_code, MAS_IOADDR);
//E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_OPCODE, SPI_RDSR_CMD, MAS_IOADDR);
//status = E2K_READ_MAS_B(i2c_spi_data, MAS_IOADDR);
//rom_printk("spi_ops: fm33256 status adter cmd %d is 0x%x", cmd_code, status);

	cmd = dev_number << SPI_DEVICE_SHIFT |
		SPI_ADDRESS_PHASE_DISABLE |
		SPI_DATA_PHASE_DISABLE |
		SPI_START;

	E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_CONTROL, cmd, MAS_IOADDR);
   
	while((E2K_READ_MAS_W(i2c_spi_cntrl + SPI_STATUS, MAS_IOADDR) & 
				(SPI_STATUS_INTR | SPI_STATUS_FAIL)) == 0)
        if (E2K_READ_MAS_W(i2c_spi_cntrl + SPI_STATUS, MAS_IOADDR) & SPI_STATUS_FAIL) {
                rom_printk("spi_ops: Error - Operation Failed");
                return -1;
        }
	return 1;
}

int spi_write(unsigned char val, unsigned int cmos_addr)
{

	unsigned int cmd;
	unsigned long i2c_spi_cntrl = i2c_spi.cntrl_base;
	unsigned long i2c_spi_data = i2c_spi.data_base;


        if(spi_ops(i2c_spi.dev_number, SPI_WREN_CMD) == -1) {
                rom_printk("%s: Error - Failed to enable write operation", __FUNCTION__);
                return -1;
        }

        E2K_WRITE_MAS_B(i2c_spi_data, val, MAS_IOADDR);

        /* Set WRITE operation code */
	E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_OPCODE, SPI_WRPC_CMD, MAS_IOADDR);

        /* Set addr offset */
	E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_ADDRESS, cmos_addr, MAS_IOADDR);

	/* Set Device number, Address size, Data size offset */
	cmd = i2c_spi.dev_number << SPI_DEVICE_SHIFT |
		   SPI_ADDRESS_SIZE_16 << SPI_ADDRESS_SIZE_SHIFT |
		   		     1 << SPI_DATA_SIZE_SHIFT |
					SPI_ADDRESS_PHASE_ENABLE |
					SPI_DATA_PHASE_ENABLE |
					SPI_TRANS_READ |
					SPI_START;

	E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_CONTROL, cmd, MAS_IOADDR);

	while((E2K_READ_MAS_W(i2c_spi_cntrl + SPI_STATUS, MAS_IOADDR) & 
				(SPI_STATUS_INTR | SPI_STATUS_FAIL)) == 0)
        if (E2K_READ_MAS_W(i2c_spi_cntrl + SPI_STATUS, MAS_IOADDR) & SPI_STATUS_FAIL) {
                rom_printk("spi_read: Error - Transfer Failed");
                return -1;
        }
        return 1;
}


int cmos_read(unsigned int cmos_addr)
{
	int data = spi_read(cmos_addr);
	
	if (data == -1) {
		rom_printk("%s: read operation failed", __FUNCTION__);
		return -1;
	}
	return data;
}

int cmos_write(unsigned char val, unsigned int cmos_addr)
{
	if (spi_write(val, cmos_addr) == -1) {
		rom_printk("%s: write operation failed", __FUNCTION__);
		return -1;
	}
        return 1;
}

void test_fm33256(void){
	int tmp;
	struct bios_pci_dev *dev;
	rom_printk("test_fm33256: Scanning PCI bus for ioapic/pic/timer i2c/spi controller ...");
	dev = bios_pci_find_device(E3M_MULTIFUNC_VENDOR, E3M_MULTIFUNC_DEVICE,
					0);
	if (dev) {
		rom_printk("found on bus %d device %d\n",
			dev->bus->number, PCI_SLOT(dev->devfn));
	}else{
		rom_printk("!!! NOT FOUND !!!\n");
//		error("Hardware failure!");
		return;
	}
		rom_printk("test_fm33256: control base addr = 0x%x, data base addr = 0x%x\n", 
			(unsigned int)dev->base_address[0], (unsigned int)dev->base_address[1]);
		i2c_spi.cntrl_base = dev->base_address[0];
		i2c_spi.data_base = dev->base_address[1];
		i2c_spi.dev_number = 1;
		tmp = cmos_read(0x18);
		rom_printk("test_fm33256: tmp = 0x%x\n", tmp);
#if 0
		tmp = cmos_read(0x10);
		rom_printk("test_fm33256: read 0x10 reg tmp = 0x%x\n", tmp);
		tmp = cmos_write(0x55, 0x10);
		tmp = cmos_read(0x10);
		rom_printk("test_fm33256: read after write 0x55 tmp = 0x%x\n", tmp);

       		{
		 	unsigned int mode = E2K_READ_MAS_W(i2c_spi.cntrl_base + SPI_MODE, MAS_IOADDR);
			rom_printk("test_fm33256: read mode 1 = 0x%x\n", mode);
		 	E2K_WRITE_MAS_W(i2c_spi.cntrl_base + SPI_MODE, mode | 0x10 , MAS_IOADDR);
		 	mode = E2K_READ_MAS_W(i2c_spi.cntrl_base + SPI_MODE, MAS_IOADDR);
			rom_printk("test_fm33256: read mode 2 = 0x%x\n", mode);
			
		 	mode = E2K_READ_MAS_W(i2c_spi.cntrl_base + SPI_STATUS, MAS_IOADDR);
			rom_printk("test_fm33256: read status 1 = 0x%x\n", mode);
			rom_printk("test_fm33256: write status 0x2\n");
			E2K_WRITE_MAS_W(i2c_spi.cntrl_base + SPI_STATUS, 0x02 , MAS_IOADDR);
		 	mode = E2K_READ_MAS_W(i2c_spi.cntrl_base + SPI_STATUS, MAS_IOADDR);
			rom_printk("test_fm33256: read status 2 = 0x%x\n", mode);

			mode = E2K_READ_MAS_W(i2c_spi.cntrl_base + SPI_MODE, MAS_IOADDR);
			mode &= (~(1 << 4));
			E2K_WRITE_MAS_W(i2c_spi.cntrl_base + SPI_MODE, mode, MAS_IOADDR);
		 	mode = E2K_READ_MAS_W(i2c_spi.cntrl_base + SPI_MODE, MAS_IOADDR);
			rom_printk("test_fm33256: read mode 3 = 0x%x\n", mode);
			
			rom_printk("test_fm33256: cmos_read\n");
			tmp = cmos_read(0x0);
		 	mode = E2K_READ_MAS_W(i2c_spi.cntrl_base + SPI_STATUS, MAS_IOADDR);
			rom_printk("test_fm33256: read status 3 = 0x%x\n", mode);


		}
		
//		asm volatile (".word \t0x00008001\n\t"
  //          	".word \t0x60000000");
#endif
}
#endif
#endif

void bios_rest(void)
{

#ifndef CONFIG_E2K_SIC
	sb_enable_itself();
#endif

#ifdef CONFIG_ENABLE_IOAPIC
#ifndef CONFIG_E2K_SIC
	sb_enable_ioapic();
#else
	configure_apic_system();
	configure_system_timer();
#ifdef CONFIG_SERIAL_AM85C30_BOOT_CONSOLE
	zilog_serial_init();
#endif
#endif
#endif
#ifdef TEST_RDMA_REGS
	test_rdma();
#endif
#ifdef CONFIG_E2K_SIC
#ifdef TEST_FM33256
	test_fm33256();
#endif
#endif
#ifdef CONFIG_ENABLE_IDE
#ifndef CONFIG_E2K_SIC
	sb_enable_ide();
#endif
#endif
	
#ifdef CONFIG_ENABLE_PARALLEL_PORT
#ifndef CONFIG_E2K_SIC
	enable_parallel_port();
#endif
#endif

#ifdef CONFIG_ENABLE_RTC
#ifndef CONFIG_E2K_SIC
	sb_enable_rtc();
#endif
#endif
	
#ifdef CONFIG_ENABLE_MOUSE
#ifndef CONFIG_E2K_SIC
	enable_mouse();
#endif
#endif

#ifdef CONFIG_ENABLE_KEYBOARD
#ifndef CONFIG_E2K_SIC
	enable_keyboard();
#endif
#endif

#ifdef CONFIG_ENABLE_FLOPPY
#ifndef CONFIG_E2K_SIC
	enable_floppy();
#endif
#endif

#ifdef	CONFIG_E2K_LEGACY_SIC
	enable_embeded_graphic();
#else	/* ! CONFIG_E2K_LEGACY_SIC */
#ifdef	CONFIG_ENABLE_MGA
	enable_mga();
#endif	/* CONFIG_ENABLE_MGA */
#endif	/* CONFIG_E2K_LEGACY_SIC */

}
