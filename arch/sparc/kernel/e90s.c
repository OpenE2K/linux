#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cpu.h>
#include <asm/io.h>
#include <asm/oplib.h>
#include <asm/bootinfo.h>
#include <asm/setup.h>
#include <asm/device.h>
#include <asm/prom.h>
#include <asm/machdep.h>
#include <asm/apic.h>

int this_is_starfire = 0;
int scons_pwroff = 1;
int sun4v_chip_type = SUN4V_CHIP_INVALID;

machdep_t	machine;
EXPORT_SYMBOL(machine);

static char command_line[COMMAND_LINE_SIZE];

char * __init prom_getbootargs(void)
{
#ifdef CONFIG_CMDLINE_BOOL
	return CONFIG_CMDLINE;
#endif
	if (bootblock != NULL &&
		bootblock->info.kernel_args_string != NULL) {
		char c = ' ', *from = command_line;
		int len = 0;

                if (strncmp(bootblock->info.kernel_args_string,
                                    KERNEL_ARGS_STRING_EX_SIGNATURE,
                                    KERNEL_ARGS_STRING_EX_SIGN_SIZE)) {
                       strncpy(command_line, bootblock->info.kernel_args_string,
                                            KSTRMAX_SIZE);
                } else {  // long cmd line 512 b
                       strncpy(command_line, bootblock->info.bios.kernel_args_string_ex,
                                            KSTRMAX_SIZE_EX);
                }
		command_line[COMMAND_LINE_SIZE-1] = '\0';	/* for safety */
		prom_printf("prom_getbootargs() command line 0x%p : %s\n",
			command_line, command_line);
		for (;;) {
			if (c != ' ')
				goto next_char;
#if defined(CONFIG_MCST) && defined(CONFIG_SERIAL_PRINTK)
			if (!memcmp(from, "boot_printk", 11)) {
				extern int use_boot_printk;
				use_boot_printk = 1;
			}
			if (!memcmp(from, "boot_printk_all", 15)) {
				extern int use_boot_printk_all;
				use_boot_printk_all = 1;
			}
#endif	/* CONFIG_MCST && CONFIG_SERIAL_PRINTK */

		next_char:
			c = *(from++);
			if (!c)
				break;
			if (COMMAND_LINE_SIZE <= ++len)
				break;
		}
		return (command_line);
	}

#ifdef CONFIG_PCI
#ifdef CONFIG_CMDLINE_BOOL
	return CONFIG_CMDLINE;
#else
	return "root=/dev/hda1 console=ttyS0";
#endif
#else
	return "root=/dev/nfs ip=bootp lpj=1000000000";
#endif
	return NULL;
}

void machine_restart(char * __unused)
{
	cpumask_var_t saved_mask;
	int cpu, i;
	unsigned node;

	if (!alloc_cpumask_var(&saved_mask, GFP_KERNEL))
		return;
	cpumask_copy(saved_mask, &current->cpus_allowed);

	/*
	 * Migrate to the bsp cpu.
	 */
	for_each_cpu(cpu, cpu_online_mask) {
		set_cpus_allowed_ptr(current, cpumask_of(cpu));
		if (BootStrap(apic_read(APIC_BSP)))
			break;
	}
	node = e90s_cpu_to_node(hard_smp_processor_id());
	for_each_online_node(i) {
		unsigned node_offset = i * NODE_OFF;
		unsigned v = __raw_readl(BASE_NODE0 + node_offset + NBSR_NODE_CFG);
		v &= ~NBSR_NODE_CFG_CPU_MASK;
		if(i == node)
			v |= 1 << (cpu % E90S_MAX_NR_NODE_CPUS);
		__raw_writel(v, BASE_NODE0 + node_offset + NBSR_NODE_CFG);
	}

	if (machine.arch_reset != NULL)
		machine.arch_reset();

	set_cpus_allowed_ptr(current, saved_mask);
	free_cpumask_var(saved_mask);
}

void machine_halt(void)
{
	if (machine.arch_halt != NULL)
		machine.arch_halt();
}

void machine_power_off(void)
{
	machine_halt();
}

void prom_halt(void)
{
	panic(__func__);
	for(;;);
}

/* This isn't actually used, it exists merely to satisfy the
 * reference in kernel/sys.c
 */
void (*pm_power_off)(void) = machine_power_off;
EXPORT_SYMBOL(pm_power_off);


#ifdef CONFIG_SYSCTL
static ctl_table *cpu_table;
static ctl_table *icjr_table;

struct rwreg_data {
	int cpu;
	unsigned long reg;
	unsigned long value;
	unsigned long mask;
};

static void writeq_reg(void *p)
{
	struct rwreg_data *d = p;
	if (d->cpu == smp_processor_id()) {
		writeq_asi((readq_asi(d->reg, ASI_IIU_INST_TRAP) & d->
			     mask) | d->value, d->reg, ASI_IIU_INST_TRAP);
	}
}

static void readq_reg(void *p)
{
	struct rwreg_data *d = p;
	if (d->cpu == smp_processor_id()) {
		d->value = readq_asi(d->reg, ASI_IIU_INST_TRAP);
	}

}

static int icjr_ghr_sysctl_handler(struct ctl_table *table, int write,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	unsigned long m;
	char buf[21];
	int i = (table - icjr_table) / 2;
	int cpu;
	struct rwreg_data d = {.reg = E90S_ICJR,
		.mask = ~(ICJR_GHR_MASK << ICJR_GHR_SHIFT)
	};
	sscanf(cpu_table[i].procname, "cpu%d", &cpu);
	d.cpu = cpu;

	if (!table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	if (write) {
		size_t len = *lenp;
		if (len > sizeof(buf) - 1)
			len = sizeof(buf) - 1;
		if (copy_from_user(buf, buffer, len))
			return -EFAULT;
		d.value = simple_strtoul(buf, NULL, 16);
		d.value = (d.value & ICJR_GHR_MASK) << ICJR_GHR_SHIFT;		
		smp_call_function_single(cpu, writeq_reg, &d, 1);
		*ppos += *lenp;
		return 0;
	}
	smp_call_function_single(cpu, readq_reg, &d, 1);

	m = (d.value >> ICJR_GHR_SHIFT) & ICJR_GHR_MASK;
	*lenp = sprintf(buf, "0x%03x\n", (unsigned)m);
	if (copy_to_user(buffer, buf, *lenp))
		return -EFAULT;
	*ppos += *lenp;

	return 0;
}

/* Make sure that /proc/sys/cpu is there */
static ctl_table cpu_root_table[] = {
	{
	 .procname = "cpu",
	 .maxlen = 0,
	 .mode = 0555,
	 },
	{}
};

static int __init cpu_sysctl_init(void)
{
	int n = num_online_cpus(), c, i = 0;
	char *name = kzalloc(sizeof("cpu00") * n, GFP_KERNEL);
	int *data = kzalloc(sizeof(int) * n, GFP_KERNEL);
	cpu_table = kzalloc(sizeof(ctl_table) * n + 1, GFP_KERNEL);
	icjr_table = kzalloc(sizeof(ctl_table) * n * 2, GFP_KERNEL);

	if (!cpu_table || !data || !icjr_table || !name)
		return -ENOMEM;

	cpu_root_table[0].child = cpu_table;
	for_each_online_cpu(c) {
		char *s = name + i * sizeof("cpu00");
		ctl_table *ct = icjr_table + i * 2;
		sprintf(s, "cpu%02d", c);

		cpu_table[i].procname = s;
		cpu_table[i].mode = 0555;
		cpu_table[i].child = ct;

		ct[0].procname = "icjr-ghr-mask";
		ct[0].mode = 0644;
		ct[0].proc_handler = &icjr_ghr_sysctl_handler;
		ct[0].maxlen = sizeof(int);
		i++;
	}
	register_sysctl_table(cpu_root_table);
	return 0;
}

module_init(cpu_sysctl_init);

#endif				/* CONFIG_SYSCTL */

#ifdef	CONFIG_E90S_SERIALIZE_IO
static DEFINE_RAW_SPINLOCK(e90s_io_lock);

#define membar_sync() do{__asm__ __volatile__("membar #Sync\n\t");}while(0)

#define io_delay()	do{	int i; membar_sync();		\
 				for(i = 0; i < 2000; i++)	\
					cpu_relax();		\
			}while(0)

/* Memory functions, same as I/O accesses on Ultra. */
u8 _readb(const volatile void __iomem *addr)
{
	u8 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("lduba\t[%1] %2, %0\t/* pci_readb */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
	return ret;
}

u16 _readw(const volatile void __iomem *addr)
{
	u16 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("lduha\t[%1] %2, %0\t/* pci_readw */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

u32 _readl(const volatile void __iomem *addr)
{
	u32 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("lduwa\t[%1] %2, %0\t/* pci_readl */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

u64 _readq(const volatile void __iomem *addr)
{
	u64 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("ldxa\t[%1] %2, %0\t/* pci_readq */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

void _writeb(u8 b, volatile void __iomem *addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stba\t%r0, [%1] %2\t/* pci_writeb */"
			     : /* no outputs */
			     : "Jr" (b), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

void _writew(u16 w, volatile void __iomem *addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stha\t%r0, [%1] %2\t/* pci_writew */"
			     : /* no outputs */
			     : "Jr" (w), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

void _writel(u32 l, volatile void __iomem *addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stwa\t%r0, [%1] %2\t/* pci_writel */"
			     : /* no outputs */
			     : "Jr" (l), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

void _writeq(u64 q, volatile void __iomem *addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stxa\t%r0, [%1] %2\t/* pci_writeq */"
			     : /* no outputs */
			     : "Jr" (q), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

u8 _inb(unsigned long addr)
{
	u8 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("lduba\t[%1] %2, %0\t/* pci_inb */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

u16 _inw(unsigned long addr)
{
	u16 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("lduha\t[%1] %2, %0\t/* pci_inw */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

u32 _inl(unsigned long addr)
{
	u32 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("lduwa\t[%1] %2, %0\t/* pci_inl */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

void _outb(u8 b, unsigned long addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stba\t%r0, [%1] %2\t/* pci_outb */"
			     : /* no outputs */
			     : "Jr" (b), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

void _outw(u16 w, unsigned long addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stha\t%r0, [%1] %2\t/* pci_outw */"
			     : /* no outputs */
			     : "Jr" (w), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

void _outl(u32 l, unsigned long addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stwa\t%r0, [%1] %2\t/* pci_outl */"
			     : /* no outputs */
			     : "Jr" (l), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

/* Now, SBUS variants, only difference from PCI is that we do
 * not use little-endian ASIs.
 */
u8 _sbus_readb(const volatile void __iomem *addr)
{
	u8 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("lduba\t[%1] %2, %0\t/* sbus_readb */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

u16 _sbus_readw(const volatile void __iomem *addr)
{
	u16 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("lduha\t[%1] %2, %0\t/* sbus_readw */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

u32 _sbus_readl(const volatile void __iomem *addr)
{
	u32 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("lduwa\t[%1] %2, %0\t/* sbus_readl */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

u64 _sbus_readq(const volatile void __iomem *addr)
{
	u64 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("ldxa\t[%1] %2, %0\t/* sbus_readq */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

void _sbus_writeb(u8 b, volatile void __iomem *addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stba\t%r0, [%1] %2\t/* sbus_writeb */"
			     : /* no outputs */
			     : "Jr" (b), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

void _sbus_writew(u16 w, volatile void __iomem *addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stha\t%r0, [%1] %2\t/* sbus_writew */"
			     : /* no outputs */
			     : "Jr" (w), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

void _sbus_writel(u32 l, volatile void __iomem *addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stwa\t%r0, [%1] %2\t/* sbus_writel */"
			     : /* no outputs */
			     : "Jr" (l), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

void _sbus_writeq(u64 l, volatile void __iomem *addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stxa\t%r0, [%1] %2\t/* sbus_writeq */"
			     : /* no outputs */
			     : "Jr" (l), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

u8 _raw_readb(unsigned long addr)
{	u8 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("lduba\t[%1] %2, %0\t/* pci_raw_readb */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
	return ret;
}

u16 _raw_readw(unsigned long addr)
{	u16 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("lduha\t[%1] %2, %0\t/* pci_raw_readw */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

u32 _raw_readl(unsigned long addr)
{	u32 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("lduwa\t[%1] %2, %0\t/* pci_raw_readl */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

u64 _raw_readq(unsigned long addr)
{	u64 ret;
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);

	__asm__ __volatile__("ldxa\t[%1] %2, %0\t/* pci_raw_readq */"
			     : "=r" (ret)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);

	return ret;
}

void _raw_writeb(u8 b, unsigned long addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stba\t%r0, [%1] %2\t/* pci_raw_writeb */"
			     : /* no outputs */
			     : "Jr" (b), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

void _raw_writew(u16 w, unsigned long addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stha\t%r0, [%1] %2\t/* pci_raw_writew */"
			     : /* no outputs */
			     : "Jr" (w), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

void _raw_writel(u32 l, unsigned long addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stwa\t%r0, [%1] %2\t/* pci_raw_writel */"
			     : /* no outputs */
			     : "Jr" (l), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

void _raw_writeq(u64 q, unsigned long addr)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&e90s_io_lock, flags);
	__asm__ __volatile__("stxa\t%r0, [%1] %2\t/* pci_raw_writeq */"
			     : /* no outputs */
			     : "Jr" (q), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E));
	io_delay();
	raw_spin_unlock_irqrestore(&e90s_io_lock, flags);
}

EXPORT_SYMBOL(_readb);
EXPORT_SYMBOL(_readw);
EXPORT_SYMBOL(_readl);
EXPORT_SYMBOL(_readq);
EXPORT_SYMBOL(_writeb);
EXPORT_SYMBOL(_writew);
EXPORT_SYMBOL(_writel);
EXPORT_SYMBOL(_writeq);
EXPORT_SYMBOL(_inb);
EXPORT_SYMBOL(_inw);
EXPORT_SYMBOL(_inl);
EXPORT_SYMBOL(_outb);
EXPORT_SYMBOL(_outw);
EXPORT_SYMBOL(_outl);
EXPORT_SYMBOL(_sbus_readb);
EXPORT_SYMBOL(_sbus_readw);
EXPORT_SYMBOL(_sbus_readl);
EXPORT_SYMBOL(_sbus_readq);
EXPORT_SYMBOL(_sbus_writeb);
EXPORT_SYMBOL(_sbus_writew);
EXPORT_SYMBOL(_sbus_writel);
EXPORT_SYMBOL(_sbus_writeq);
EXPORT_SYMBOL(_raw_readb);
EXPORT_SYMBOL(_raw_readw);
EXPORT_SYMBOL(_raw_readl);
EXPORT_SYMBOL(_raw_readq);
EXPORT_SYMBOL(_raw_writeb);
EXPORT_SYMBOL(_raw_writew);
EXPORT_SYMBOL(_raw_writel);
EXPORT_SYMBOL(_raw_writeq);

#endif	/*CONFIG_E90S_SERIALIZE_IO*/

#ifdef	CONFIG_PROC_FS
static unsigned long bist_regs[] = {
	0x0200000500,
	0x0200000700,
	0x0200000800,
	0x0200000900,
	0x0200000a00,
	0x0200000b00,
	0x0200000c00,
	0x0200000d00,
	0x0200000e00,
	0x0200000f00
};

static void readq_reg_asi60(void *p)
{
	struct rwreg_data *d = p;
	d->value = readq_asi(d->reg, 0x60);
}

static void readq_reg_asi45(void *p)
{
	struct rwreg_data *d = p;
	d->value = readq_asi(d->reg, 0x45);
}

static void readq_reg_asi69(void *p)
{
	struct rwreg_data *d = p;
	d->value = readq_asi(d->reg, 0x69);
}

static int show_bist_info(struct seq_file *m, void *__unused)
{
	int i;
	int err = 0;
	for_each_online_cpu(i) {
		struct rwreg_data d = { .cpu = i, .reg = 0x20, .value = 0xbad };
		smp_call_function_single(d.cpu, readq_reg_asi60, &d, 1);
		seq_printf(m, "cpu%d:	%p (asi %x):	%016lx\n",
			 d.cpu, (void *)d.reg, 0x60,  d.value);
		err |= d.value;
	}
	seq_printf(m, "\n");

	for_each_online_cpu(i) {
		struct rwreg_data d = { .cpu = i, .reg = 0x28, .value = 0xbad };
		smp_call_function_single(d.cpu, readq_reg_asi45, &d, 1);
		seq_printf(m, "cpu%d:	%p (asi %x):	%016lx\n",
			 d.cpu, (void *)d.reg, 0x45,  d.value);
		err |= d.value;
	}
	seq_printf(m, "\n");

	for_each_online_cpu(i) {
		int j;
		if(i % E90S_MAX_NR_NODE_CPUS)
			continue;
		for(j = 0; j < ARRAY_SIZE(bist_regs); j++) {
			struct rwreg_data d = { .cpu = i, .reg = bist_regs[j],
				.value = 0xbad };
			smp_call_function_single(d.cpu, readq_reg_asi69, &d, 1);
			seq_printf(m, "cpu%d:	%p (asi %x):	%016lx\n",
				d.cpu, (void *)d.reg, 0x69,  d.value);
			err |= d.value;
		}
		seq_printf(m, "\n");
	}
	seq_printf(m, "BIST %s\n", err ? "FAILED" : "PASSED");
	
	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	/* The pointer we are returning is arbitrary,
	 * it just has to be non-NULL and not IS_ERR
	 * in the success case.
	 */
	return *pos == 0 ? &c_start : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

struct seq_operations bist_info_op = {
	.start =c_start,
	.next =	c_next,
	.stop =	c_stop,
	.show =	show_bist_info,
};

static int bist_info_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &bist_info_op);
}

static const struct file_operations proc_bist_info_operations = {
	.open		= bist_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init bist_init(void)
{
	proc_create_data("bist", S_IFREG | S_IRUGO,
			  NULL, &proc_bist_info_operations, NULL);
	return 0;
}

module_init(bist_init);

#endif /*CONFIG_PROC_FS*/

static DEFINE_PER_CPU(struct cpu, cpu_devices);

static int __init topology_init(void)
{
	int i;
	for_each_online_node(i)
		register_one_node(i);
	for_each_present_cpu(i)
		register_cpu(&per_cpu(cpu_devices, i), i);

	return 0;
}

subsys_initcall(topology_init);
