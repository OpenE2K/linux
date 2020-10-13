#include <linux/cpumask.h>
#include <asm/mpspec.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>

static struct i2c_spi_t {
	void __iomem *cntrl_base;
	void __iomem *data_base;
  	unsigned char dev_number;
} i2c_spig;


char tch[1024];
struct proc_dir_entry *proc_dev;

#define E3M_MULTIFUNC_VENDOR	PCI_VENDOR_ID_INTEL
#define E3M_MULTIFUNC_DEVICE	0x0002

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
#define SPI_MODE_INTR                                       	(1 << SPI_MODE_INTR_SHIFT)

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

#define SPI_CMOS_CNTRL_AREA_SIZE			0x40
#define SPI_CMOS_DATA_AREA_SIZE				0x40

#define	I2C_SPI_DEFAULT_IRQ				23	

static int spi_ops(struct i2c_spi_t *i2c_spi, unsigned int dev_number, unsigned char cmd_code);
static int spi_read(struct i2c_spi_t *i2c_spi, unsigned int cmos_addr)
{
  void  *i2c_spi_cntrl = i2c_spi->cntrl_base;
  void  *i2c_spi_data = i2c_spi->data_base;
  unsigned char data;
  unsigned int cmd = 0;
  unsigned int tmp;

  /* Set READ operation code */
//niki  E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_OPCODE, SPI_RDPC_CMD, MAS_IOADDR);
    writel(SPI_RDPC_CMD, i2c_spi_cntrl + SPI_OPCODE);
    
  /* Set addr offset */
//niki  E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_ADDRESS, cmos_addr, MAS_IOADDR);
    writel(cmos_addr, i2c_spi_cntrl + SPI_ADDRESS);
    
  /* Clean int & fail bits */
//niki   E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_STATUS, 0x6, MAS_IOADDR);
    writel(0x6, i2c_spi_cntrl + SPI_STATUS);
    
  /* Set Device number, Address size, Data size offset */
  cmd = i2c_spi->dev_number << SPI_DEVICE_SHIFT |
      SPI_ADDRESS_SIZE_8 << SPI_ADDRESS_SIZE_SHIFT |
      1 << SPI_DATA_SIZE_SHIFT |
      SPI_ADDRESS_PHASE_ENABLE |
      SPI_DATA_PHASE_ENABLE |
      SPI_TRANS_READ |
      SPI_START;
                                                                
//niki  E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_CONTROL, cmd, MAS_IOADDR);
    writel(cmd, i2c_spi_cntrl + SPI_CONTROL);
    
  while((tmp = readl(i2c_spi_cntrl + SPI_STATUS)/*niki E2K_READ_MAS_W(i2c_spi_cntrl + SPI_STATUS, MAS_IOADDR)*/) & 
         (SPI_STATUS_BUSY)) 
	 {
	    if(tmp & SPI_STATUS_FAIL)
		break;
	 }

  if (readl(i2c_spi_cntrl + SPI_STATUS) /* niki E2K_READ_MAS_W(i2c_spi_cntrl + SPI_STATUS, MAS_IOADDR) */& SPI_STATUS_FAIL) {
    printk("spi_read: Error - Transfer Failed");
    return -1;
  }
  data = readb (i2c_spi_data);//niki E2K_READ_MAS_B(i2c_spi_data, MAS_IOADDR);
  return (int)data;
}

static int spi_write(struct i2c_spi_t *i2c_spi, unsigned char val, unsigned int cmos_addr)
{

  unsigned int cmd;
  void *i2c_spi_cntrl = i2c_spi->cntrl_base;
  void *i2c_spi_data = i2c_spi->data_base;
  unsigned int tmp;

  if(spi_ops(i2c_spi, i2c_spi->dev_number, SPI_WREN_CMD) == -1) {
    printk("%s: Error - Failed to enable write operation", __FUNCTION__);
    return -1;
  }

  //niki E2K_WRITE_MAS_B(i2c_spi_data, val, MAS_IOADDR);
    writeb(val, i2c_spi_data);
    
  /* Clean int & fail bits */
   //niki E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_STATUS, 0x6, MAS_IOADDR);
    writel(0x6, i2c_spi_cntrl + SPI_STATUS);
    
  /* Set WRITE operation code */
  //niki E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_OPCODE, SPI_WRPC_CMD, MAS_IOADDR);
  writel(SPI_WRPC_CMD, i2c_spi_cntrl + SPI_OPCODE);

  /* Set addr offset */
  //niki E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_ADDRESS, cmos_addr, MAS_IOADDR);
  writel(cmos_addr, i2c_spi_cntrl + SPI_ADDRESS);

  /* Set Device number, Address size, Data size offset */
  cmd = i2c_spi->dev_number << SPI_DEVICE_SHIFT |
      SPI_ADDRESS_SIZE_8 << SPI_ADDRESS_SIZE_SHIFT |
      1 << SPI_DATA_SIZE_SHIFT |
      SPI_ADDRESS_PHASE_ENABLE |
      SPI_DATA_PHASE_ENABLE |
      SPI_TRANS_WRITE |
      SPI_START;

  //niki E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_CONTROL, cmd, MAS_IOADDR);
  writel(cmd, i2c_spi_cntrl + SPI_CONTROL);

  while((tmp = readl(i2c_spi_cntrl + SPI_STATUS)/*niki E2K_READ_MAS_W(i2c_spi_cntrl + SPI_STATUS, MAS_IOADDR)*/) & 
         (SPI_STATUS_BUSY)) 
	 {
	    if(tmp & SPI_STATUS_FAIL)
		break;
	 }

  if (/*niki E2K_READ_MAS_W(i2c_spi_cntrl + SPI_STATUS, MAS_IOADDR)*/ readl(i2c_spi_cntrl + SPI_STATUS) & SPI_STATUS_FAIL) {
    printk("spi_write: Error - Transfer Failed");
    return -1;
  }
  return 1;
}


static int spi_interrupt_unlock(struct i2c_spi_t *i2c_spi, unsigned int mode)
{
//niki  E2K_WRITE_MAS_W(i2c_spi->cntrl_base + SPI_MODE, mode, MAS_IOADDR);
    writel(mode, i2c_spi->cntrl_base + SPI_MODE);
  return 1;
}

static unsigned int spi_interrupt_lock(struct i2c_spi_t *i2c_spi)
{
  unsigned int mode = readl(i2c_spi->cntrl_base + SPI_MODE);//E2K_READ_MAS_W(i2c_spi->cntrl_base + SPI_MODE, MAS_IOADDR);
  // mode &= (~SPI_MODE_INTR);
  //niki E2K_WRITE_MAS_W(i2c_spi->cntrl_base + SPI_MODE, mode & (~SPI_MODE_INTR), MAS_IOADDR);
  writel(mode & (~SPI_MODE_INTR),i2c_spi->cntrl_base + SPI_MODE);
  return mode;
}

static int spi_interrupt_reset(struct i2c_spi_t *i2c_spi)
{
  unsigned int status = readl(i2c_spi->cntrl_base + SPI_STATUS);//E2K_READ_MAS_W(i2c_spi->cntrl_base + SPI_STATUS, MAS_IOADDR);

  //niki E2K_WRITE_MAS_W(i2c_spi->cntrl_base + SPI_STATUS, status, MAS_IOADDR);
  writel(status, i2c_spi->cntrl_base + SPI_STATUS);
  return 1;
}

static int spi_ops(struct i2c_spi_t *i2c_spi, unsigned int dev_number, unsigned char cmd_code)
{
  unsigned int cmd;
  void *i2c_spi_cntrl = i2c_spi->cntrl_base;
  if (dev_number > MAX_SPI_DEVICE_NR) {
    printk("spi_ops: Error - Device number is to large: %d (Max: %d)", dev_number, MAX_SPI_DEVICE_NR);
    return -1;
  }
  switch(cmd_code) {
    case SPI_READ_CMD:
    case SPI_WRITE_CMD:
    case SPI_RDPC_CMD:
    case SPI_WRPC_CMD:
      printk("spi_ops: Error - Wrong command code: %d", cmd_code);
      return -1;
    default:
      break;
  }

  //niki E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_OPCODE, cmd_code, MAS_IOADDR);
  writel(cmd_code, i2c_spi_cntrl + SPI_OPCODE);

  cmd = dev_number << SPI_DEVICE_SHIFT |
      SPI_ADDRESS_PHASE_DISABLE |
      SPI_DATA_PHASE_DISABLE |
      SPI_START;
  //niki E2K_WRITE_MAS_W(i2c_spi_cntrl + SPI_CONTROL, cmd, MAS_IOADDR);
  writel(cmd, i2c_spi_cntrl + SPI_CONTROL);
   
  while((/* niki E2K_READ_MAS_W(i2c_spi_cntrl + SPI_STATUS, MAS_IOADDR)*/ readl(i2c_spi_cntrl + SPI_STATUS) & 
         (SPI_STATUS_INTR | SPI_STATUS_FAIL)) == 0);

  if (/*niki E2K_READ_MAS_W(i2c_spi_cntrl + SPI_STATUS, MAS_IOADDR)*/ readl(i2c_spi_cntrl + SPI_STATUS) & SPI_STATUS_FAIL) {
    printk("spi_ops: Error - Operation Failed");
    return -1;
  }
  return 1;
}

static void proc_read(char *ch);

static int proc_read_spi_test(char *page, char **start,
           off_t off, int count, 
	   int *eof, void *data)
{
    proc_read(&tch[0]);
    memcpy(page, tch, strlen(tch));		
    return strlen(tch);

}
 

static void proc_read(char *ch)
{
    int j, i = 0;
    int h, m, s, delta, r0;

  i += sprintf(&ch[i],"Ctrl %x\n",spi_read(&i2c_spig,  0x18));  

  i += sprintf(&ch[i],"S/N: ");
  for (j = 0; j < 8; j++) {
    i += sprintf(&ch[i],"%2.2x",spi_read(&i2c_spig,  0x10 + j));
  }
  
  
  r0 = spi_read(&i2c_spig,  0x0);
  r0 |= 1;
  spi_write(&i2c_spig, r0, 0x0);

  i += sprintf(&ch[i], "\n");
  s = spi_read(&i2c_spig,  0x2);
  s = (s >> 4) * 10 + (s & 0xf);
  m = spi_read(&i2c_spig,  0x3);
  m = (m >> 4) * 10 + (m & 0xf);
  h = spi_read(&i2c_spig,  0x4);
  h = (h >> 4) * 10 + (h & 0xf);
  
  r0 &= 0xfe;
  spi_write(&i2c_spig, r0, 0x0);
  
  i += sprintf(&ch[i],"RTC %.2dh %.2dm %.2ds\n",h, m, s);  

  msleep(2000);

  r0 = spi_read(&i2c_spig,  0x0);
  r0 |= 1;
  spi_write(&i2c_spig, r0, 0x0);

  delta = s;
  s = spi_read(&i2c_spig,  0x2);
  s = (s >> 4) * 10 + (s & 0xf);
  m = spi_read(&i2c_spig,  0x3);
  m = (m >> 4) * 10 + (m & 0xf);
  h = spi_read(&i2c_spig,  0x4);
  h = (h >> 4) * 10 + (h & 0xf);

  r0 &= 0xfe;
  spi_write(&i2c_spig, r0, 0x0);
  
  delta = ((delta = (s - delta)) >= 0)? (delta): (delta * -1);
  i += sprintf(&ch[i],"Time delay 2 sec %.2dh %.2dm %.2ds delta = %d\n",h, m, s, delta);  
  
  i += sprintf(&ch[i],"SPI TEST");
  if (delta < 1) {
    sprintf(&ch[i],"  ERROR\n");
  } else 
    i += sprintf(&ch[i],"  OK\n");
        
}

static int spi_test_init_module(void)
{
  char tmp;
 // int  j, i = 0;
  struct pci_dev *dev;
  unsigned int mode;
  
  printk("test_fm33256: Scanning PCI bus for ioapic/pic/timer i2c/spi controller ...");
  dev = pci_get_device(E3M_MULTIFUNC_VENDOR, E3M_MULTIFUNC_DEVICE, 0);
  if (dev) {
    printk("found on bus %d device %d\n",
               dev->bus->number, PCI_SLOT(dev->devfn));
  }else{
    printk("!!! NOT FOUND !!!\n");
    return -1;
  }
  printk("test_fm33256: control base addr = 0x%x, data base addr = 0x%x\n", 
             (unsigned int) pci_resource_start( dev, 0), (unsigned int) pci_resource_start( dev, 1));
  i2c_spig.cntrl_base = ioremap( pci_resource_start(dev, 0), pci_resource_len(dev, 0) ); // niki pci_resource_start( dev, 0);
  i2c_spig.data_base = ioremap( pci_resource_start(dev, 1), pci_resource_len(dev, 1) ); // niki pci_resource_start( dev, 1);
  i2c_spig.dev_number = 1;

  mode = spi_interrupt_lock(&i2c_spig);
  tmp = spi_read(&i2c_spig,  0x18);

  //proc_read(&tch[0]);
 
  proc_dev = create_proc_entry("spi_test", 0444, NULL);
  if(proc_dev == NULL) 
    return -1;
  strcpy((char *)proc_dev->name, "spi_test");
  //    strcpy(device->proc_dev->value, proc_name);
  proc_dev->data = NULL;
  proc_dev->read_proc = proc_read_spi_test;
  proc_dev->write_proc = NULL;
  
//  printk("%s \n", tch);
  spi_interrupt_reset(&i2c_spig);
  spi_interrupt_unlock(&i2c_spig, mode);
  
  
 return 0;
}

static void spi_test_exit_module(void)
{
  iounmap(i2c_spig.cntrl_base);
  iounmap(i2c_spig.data_base);
  remove_proc_entry( "spi_test", proc_dev );
}


module_init(spi_test_init_module);
module_exit(spi_test_exit_module);

MODULE_DESCRIPTION( "SPI Test of e3s" );
MODULE_AUTHOR     ( "Aleksey Nikiforov" );
MODULE_LICENSE    ( "GPL" );


