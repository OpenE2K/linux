#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <linux/vgaarb.h>
#include <asm/io.h>
#include <asm/oplib.h>
#include <asm/bootinfo.h>
#include <asm/setup.h>
#include <asm/device.h>
#include <asm/prom.h>
#include <asm/machdep.h>
#include <asm/apic.h>
#include <asm/adi.h>

int this_is_starfire = 0;
int scons_pwroff = 1;
int sun4v_chip_type = SUN4V_CHIP_INVALID;
EXPORT_SYMBOL(sun4v_chip_type);

machdep_t	machine;
EXPORT_SYMBOL(machine);

static char command_line[COMMAND_LINE_SIZE];
struct adi_config adi_state;
EXPORT_SYMBOL(adi_state);

char * __init prom_getbootargs(void)
{
#ifdef CONFIG_CMDLINE_BOOL
	return CONFIG_CMDLINE;
#endif
	if (bootblock != NULL &&
		bootblock->info.kernel_args_string != NULL) {

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

void machine_restart(char *cmd)
{
	if (machine.arch_reset != NULL)
		machine.arch_reset(cmd);
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


#define	L2_CTRL	((2UL << 32) | (0 << 8))
# define CMD_FLUSH_L2	(1 << 8)

static void e90s_local_flush_l2_cache(void)
{
	u64 v = readq_asi(L2_CTRL, ASI_CONFIG);
	writeq_asi(v | CMD_FLUSH_L2, L2_CTRL, ASI_CONFIG);
}

void e90s_flush_l2_cache(void)
{
	if (e90s_get_cpu_type() < E90S_CPU_R2000) /* unsupported */
		return;
	WARN_ONCE(e90s_get_cpu_type() != E90S_CPU_R2000P,
				"FIXME: add smp flush_cache_all()\n");
	e90s_local_flush_l2_cache();
}
EXPORT_SYMBOL(e90s_flush_l2_cache);

u8 inb(unsigned long addr)
{
	/*we have to OR BASE_PCIIO because vga drivers ignore it*/
	return readb((void __iomem *)(addr | BASE_PCIIO));
}
EXPORT_SYMBOL(inb);

u16 inw(unsigned long addr)
{
	return readw((void __iomem *)(addr | BASE_PCIIO));
}
EXPORT_SYMBOL(inw);

u32 inl(unsigned long addr)
{
	return readl((void __iomem *)(addr | BASE_PCIIO));
}
EXPORT_SYMBOL(inl);

void outb(u8 b, unsigned long addr)
{
	writeb(b, (void __iomem *)(addr | BASE_PCIIO));
}
EXPORT_SYMBOL(outb);

void outw(u16 w, unsigned long addr)
{
	writew(w, (void __iomem *)(addr | BASE_PCIIO));
}
EXPORT_SYMBOL(outw);

void outl(u32 l, unsigned long addr)
{
	writel(l, (void __iomem *)(addr | BASE_PCIIO));
}
EXPORT_SYMBOL(outl);

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
