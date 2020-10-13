#include <linux/cpumask.h>
#include <asm/page.h>
#include <asm/mpspec.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>


#define E3M_MULTIFUNC_VENDOR    PCI_VENDOR_ID_INTEL
#define E3M_MULTIFUNC_DEVICE    0x0002

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

#define SPI_MODE_INTR_SHIFT                           4
#define SPI_MODE_INTR                                           (1 << SPI_MODE_INTR_SHIFT)

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

#define SPI_CMOS_CNTRL_AREA_SIZE                        0x40
#define SPI_CMOS_DATA_AREA_SIZE                         0x40

#define I2C_SPI_DEFAULT_IRQ                             23      

struct i2c_spi_t {
  void __iomem *cntrl_base;
  void __iomem *data_base;
  unsigned char dev_number;
};

struct proc_dir_entry *proc_dev;
struct gpio_regs_t {
 unsigned int ctrl_reg; 
 unsigned int data_reg;
 unsigned int inter_reg; 
 unsigned int inter_lvl_reg; 
 unsigned int enable_reg; 
 unsigned int inter_status_reg;
};

static struct gpio_t {
  void __iomem *gpio_base;
  struct i2c_spi_t i2c_spi;
  struct gpio_regs_t gpio_regs;
  struct pci_dev *dev_pcie;
  unsigned long ether_base;
} gpio;

void gpio_save(struct gpio_t gpio) 
{
  struct gpio_regs_t *gregs = &gpio.gpio_regs;
  
  gregs->ctrl_reg =  readl(gpio.gpio_base + 0x0);
  gregs->data_reg =  readl(gpio.gpio_base + 0x4);
  gregs->inter_reg =  readl(gpio.gpio_base + 0x8);
  gregs->inter_lvl_reg =  readl(gpio.gpio_base + 0xc);
  gregs->enable_reg =  readl(gpio.gpio_base + 0x10);
  writel(0x0, gpio.gpio_base + 0x10); // clean interrupt
  writel(0xff, gpio.gpio_base + 0x14); // clean interrupt
  //gregs-> inter_status_reg  =  readl(gpio.gpio_base + 0x0);
}

void gpio_restore(struct gpio_t gpio) 
{
  struct gpio_regs_t *gregs = &gpio.gpio_regs;

  writel(0x0, gpio.gpio_base + 0x10); // clean interrupt
  writel(0xff, gpio.gpio_base + 0x14); // clean interrupt
  writel(gregs->ctrl_reg, gpio.gpio_base + 0x0); 
  writel(gregs->data_reg, gpio.gpio_base + 0x4);     
  writel(gregs->inter_reg, gpio.gpio_base + 0x8); 
  writel(gregs->inter_lvl_reg, gpio.gpio_base + 0xc); 
  writel(gregs->enable_reg, gpio.gpio_base + 0x10);
  
}

#ifdef __e2k__
static int spi_read(struct i2c_spi_t *i2c_spi, unsigned int cmos_addr)
{
  void __iomem *i2c_spi_cntrl = i2c_spi->cntrl_base;
  void __iomem *i2c_spi_data = i2c_spi->data_base;
  unsigned char data;
  unsigned int cmd = 0;

  /* Set READ operation code */
  writel(SPI_RDPC_CMD, i2c_spi_cntrl + SPI_OPCODE);

  /* Set addr offset */
  writel(cmos_addr, i2c_spi_cntrl + SPI_ADDRESS);

  /* Set Device number, Address size, Data size offset */
  cmd = i2c_spi->dev_number << SPI_DEVICE_SHIFT |
      SPI_ADDRESS_SIZE_8 << SPI_ADDRESS_SIZE_SHIFT |
      1 << SPI_DATA_SIZE_SHIFT |
      SPI_ADDRESS_PHASE_ENABLE |
      SPI_DATA_PHASE_ENABLE |
      SPI_TRANS_READ |
      SPI_START;
                                                                
  writel(cmd, i2c_spi_cntrl + SPI_CONTROL);

  while((readl(i2c_spi_cntrl + SPI_STATUS) & 
         (SPI_STATUS_INTR | SPI_STATUS_FAIL)) == 0);

  if (readl(i2c_spi_cntrl + SPI_STATUS) & SPI_STATUS_FAIL) {
    printk("spi_read: Error - Transfer Failed");
    return -1;
  }
  data = readb(i2c_spi_data);
  return (int)data;
}
#endif /*__e2k__*/

static int proc_read_gpio_test(char *page, char **start,
                              off_t off, int count, 
                              int *eof, void *data)
{
  char tch[4096];
  struct i2c_spi_t i2c_spi = gpio.i2c_spi;
  void __iomem *g_base = gpio.gpio_base;
  unsigned int tmp;
#ifdef __e2k__
  int err = 0;
#else
  unsigned int tmp1;
#endif
  int p = 0;
  
  i2c_spi.dev_number = 0;
 
 memset(tch, 4096, 0);
 // i2c_spi
#ifdef __e2k__
 // init regs
   writel(0x0, g_base + 0x0); // 11- 8 bits output 7-0 bits input
   writel(0x0, g_base + 0x4); // 11- 8 bits output 7-0 bits input
   writel(0xffff, g_base + 0x8);
   writel(0x0, g_base + 0xc);
   writel(0x0, g_base + 0x10);  
   writel(0xffff, g_base + 0x14); // clear interrupt bits
   writel(0xffff, g_base + 0x10);
// end init
  
   i2c_spi.dev_number = 2;
   memset(tch, 4096, 0);
   spi_read(&i2c_spi, 0x10);
   i2c_spi.dev_number = 3;
   spi_read(&i2c_spi, 0x10);
   udelay(1000);
      
   if ((tmp = readl(g_base + 0x14)) != 0x3) {
	err += 1;
	p += sprintf(&tch[p], "SPI selftest ERROR\n");
	goto spi_err;
   }
   
// Test Ok.
p += sprintf(&tch[p], "SPI selftest OK\n");
spi_err:

  // i2c_spi

 // init regs
   writel(0x0, g_base + 0x0); // 11- 8 bits output 7-0 bits input
   writel(0x0, g_base + 0x4); // 11- 8 bits output 7-0 bits input
   writel(0xffff, g_base + 0x8);
   writel(0xffff, g_base + 0xc);
   writel(0x0, g_base + 0x10);  
   writel(0xffff, g_base + 0x14); // clear interrupt bits
   writel(0xffff, g_base + 0x10);
// end init

/*printk("GDB1: 0x%x  0x%x  0x%x  0x%x  0x%x  0x%x \n", readl(g_base + 0, MAS_IOADDR), E2K_READ_MAS_W(g_base + 4),\
      readl(g_base + 8, MAS_IOADDR), E2K_READ_MAS_W(g_base + 0xc, MAS_IOADDR), E2K_READ_MAS_W(g_base + 0x10),\
          readl(g_base + 0x14));
 */
  //GPIO in-out selftest

   writel(0x0f00, g_base + 0x0); // 11- 8 bits output 7-0 bits input
   writel(0x0, g_base + 0x4); // clear input bits 
   writel(0x0f00, g_base + 0x4); // clear input bits 
   writel(0x0, g_base + 0x4); // clear input bits 
 
   udelay(1000);
      
   if ((tmp = readl(g_base + 0x14)) != 0xf000) {
	p += sprintf(&tch[p], "GPIO in-out selftest read 0x%x\n", tmp);
   }
   
// Test Ok.
p += sprintf(&tch[p], "GPIO in-out selftest OK\n");

  if (err)
    p += sprintf(&tch[p], "GPIO  tests ERROR\n");
  else
    p += sprintf(&tch[p], "GPIO  tests OK\n");
#else
 writel(1<<9, g_base + 0x0);
 udelay(500);
 writel(1<<9, g_base + 0x4);
 udelay(500);
 tmp = readl(g_base + 0x4);
 //tmp1 = readl(g_base + 0x14);
 writel(0, g_base + 0x4);
 udelay(500);
 tmp1 = readl(g_base + 0x4);

 if((tmp & (1<<10)) && !(tmp1 & (1<<10))) {
 //Ok
    p += sprintf(&tch[p], "GPIO selftest OK\n");
 }
    else {
	p += sprintf(&tch[p], "GPIO selftest ERROR\n");
 }
#endif //sparc64
  memcpy(page, tch, strlen(tch));             
  return strlen(tch);

}
 

static struct pci_dev *dev, *dev_gpio, *dev_pcie, *dev_gether;
static int gpio_test_init_module(void)
{
  // int tmp;
  struct i2c_spi_t *i2c_spi = &gpio.i2c_spi;
 
  printk("test_gpio: Scanning PCI bus for ioapic/pic/timer i2c/spi controller ...");
  dev = pci_get_device(E3M_MULTIFUNC_VENDOR, E3M_MULTIFUNC_DEVICE, 0);
  if (dev) {
    printk("found on bus %d device %d\n",
               dev->bus->number, PCI_SLOT(dev->devfn));
  }else{
    printk("!!! NOT FOUND !!!\n");
//              error("Hardware failure!");
    return -1;
  }
  
  printk("test_gpio: Scanning PCI bus for ac97_gpio controller ...");
  dev_gpio = pci_get_device(0x1013, 0x6005, 0);
  if (dev_gpio) {
    printk("found on bus %d device %d\n",
           dev_gpio->bus->number, PCI_SLOT(dev_gpio->devfn));
  }else{
    printk("!!! NOT FOUND 0x1013, 0x6005 !!!\n");
//              error("Hardware failure!");
    return -1;
  }

  printk("test_gpio: Scanning PCI bus for GEthernet controller ...");
  dev_gether = pci_get_device(0x8086, 0x4d45, 0);
  if (dev_gether) {
    printk("found on bus %d device %d\n",
           dev_gether->bus->number, PCI_SLOT(dev_gether->devfn));
  }else{
    printk("!!! NOT FOUND 0x8086, 0x4d45 !!!\n");
//              error("Hardware failure!");
    return -1;
  }

  gpio.ether_base =  pci_resource_start( dev_gether, 0);

  printk("test_gpio: Scanning PCI bus for PCIe controller ...");
  dev_pcie = pci_get_device(0xe3e3, 0xabcd, 0);
  if (dev_pcie) {
    printk("found on bus %d device %d\n",
           dev_pcie->bus->number, PCI_SLOT(dev_pcie->devfn));
  }else{
    printk("!!! NOT FOUND 0x3e3e, 0xabcd !!!\n");
//              error("Hardware failure!");
//   return -1;
  }
  
  //niki gpio.dev_pcie = dev_pcie;
  
  gpio.gpio_base = pci_iomap(dev_gpio, 1, 0);
  printk("test_gpio: gpio base addr = %p\n", gpio.gpio_base);
  i2c_spi->cntrl_base = pci_iomap(dev, 0, 0);
  i2c_spi->data_base = pci_iomap(dev, 1, 0);
  i2c_spi->dev_number = 1;
  printk("test_gpio: spi control base addr = %p, data base addr = %p\n",
	 i2c_spi->cntrl_base, i2c_spi->data_base);
  
  proc_dev = create_proc_entry("gpio_test", 0444, NULL);
  if(proc_dev == NULL) 
    return -1;
  strcpy((char *)proc_dev->name, "gpio_test");
  //    strcpy(device->proc_dev->value, proc_name);
  proc_dev->data = NULL;
  proc_dev->read_proc = proc_read_gpio_test;
  proc_dev->write_proc = NULL;

  return 0;
}

static void gpio_test_exit_module(void)
{
	pci_iounmap(dev_gpio, gpio.gpio_base);
	pci_iounmap(dev, gpio.i2c_spi.cntrl_base);
	pci_iounmap(dev, gpio.i2c_spi.data_base);
	remove_proc_entry( "gpio_test", proc_dev );
}
module_init(gpio_test_init_module);
module_exit(gpio_test_exit_module);

MODULE_DESCRIPTION( "GPIO Test of e3s" );
MODULE_AUTHOR     ( "Aleksey Nikiforov" );
MODULE_LICENSE    ( "GPL" );


