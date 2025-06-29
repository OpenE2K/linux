/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 *	Intel Multiprocessor Specificiation 1.1 and 1.4
 *	compliant MP-table parsing routines.
 *
 *	Given from i386 architecture mpparse.c implementation.
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/irq.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/kernel_stat.h>
#include <linux/mc146818rtc.h>
#include <linux/cpumask.h>

#ifdef CONFIG_E2K
#include <asm/p2v/boot_smp.h>
#include <asm/e2k_sic.h>
#endif
#include <asm/pic.h>
#include <asm/unaligned.h>
#include <asm/smp.h>
#include <asm/mpspec.h>
#include <asm/pgalloc.h>
#include <asm/console.h>


#undef	DEBUG_MPT_MODE
#undef	DebugMPT
#define	DEBUG_MPT_MODE		0	/* MP-table parsing */
#define	DebugMPT		if (DEBUG_MPT_MODE) printk

static struct intel_mp_floating *mpf_found = NULL;
unsigned int __initdata maxcpus = NR_CPUS;
int __initdata max_iolinks = MAX_NUMIOLINKS;
int __initdata max_node_iolinks = 1;

#ifdef CONFIG_E2K
# define boot_mpf_found	boot_get_vo_value(mpf_found)
#else
# define boot_mpf_found	mpf_found
#endif

/*
 * Various Linux-internal data structures created from the
 * MP-table.
 */
static mpc_config_iolink_t mp_iolinks[MAX_NUMIOLINKS];
static int mp_iolinks_num = 0;
int mp_iohubs_num = 0;
static int mp_rdmas_num = 0;

mpc_config_timer_t mp_timers[MAX_MP_TIMERS];
int rtc_model = 0;
int rtc_syncintr = 0;
int nr_timers = 0;

int IOHUB_revision = 0;
EXPORT_SYMBOL(IOHUB_revision);
						/* CPU present map (passed by */
						/* BIOS thru MP table) */
int		phys_cpu_present_num = 0;	/* number of present CPUs */
						/* (passed by BIOS thru */
						/* MP table) */

/* Processor count in MP configuration table */
unsigned int mp_num_processors;

/*
 * Checksum an MP configuration block.
 */

static int __init
mpf_checksum(unsigned char *mp, int len)
{
	int sum = 0;

	while (len--)
		sum += *mp++;

	return sum & 0xFF;
}

static void __init
MP_processor_info(struct mpc_config_processor *m)
{
	if (!(m->mpc_cpuflag & CPU_ENABLED))
		return;

	printk("Processor %s ID #%d version %d\n",
		cpu_has_epic() ? "EPIC" : "APIC",
		m->mpc_apicid,
		m->mpc_apicver);

	if (m->mpc_cpuflag & CPU_BOOTPROCESSOR) {
		DebugMPT("    Bootup CPU\n");
		boot_cpu_physical_apicid = m->mpc_apicid;
	}

	if (mp_num_processors >= NR_CPUS) {
		printk(KERN_WARNING "WARNING: NR_CPUS limit of %i reached."
			"  Processor ignored.\n", NR_CPUS);
		return;
	}

	if (mp_num_processors >= maxcpus) {
		printk(KERN_WARNING "WARNING: maxcpus limit of %i reached."
			" Processor ignored.\n", maxcpus);
		return;
	}
	mp_num_processors++;

	if (m->mpc_apicid > MAX_APICS) {
		printk("Processor #%d INVALID. (Max ID: %d).\n",
			m->mpc_apicid, MAX_APICS);
		return;
	}

	pic_processor_info(m->mpc_apicid, m->mpc_apicver,
					m->mpc_cepictimerfreq);
}

static void __init
MP_iolink_info(struct mpc_config_iolink *m)
{
	printk("IO link #%d on node %d, version 0x%02x,",
		m->link, m->node, m->mpc_iolink_ver);
	if (m->mpc_iolink_type == MP_IOLINK_IOHUB) {
		printk(" connected to IOHUB: min bus #%d max bus #%d IO %s "
			"ID %d\n", m->bus_min, m->bus_max,
			cpu_has_epic() ? "EPIC" : "APIC", m->apicid);
	} else {
		printk(" is RDMA controller\n");
	}
	if (mp_iolinks_num >= max_iolinks) {
		printk(KERN_WARNING "WARNING: IO links limit of %i reached."
			"  IO link ignored.\n", max_iolinks);
		return;
	}
#if defined(CONFIG_E90S) && !defined(CONFIG_NUMA)
	if (m->node >= MAX_NUMIOLINKS) {
#else	/* E2K or NUMA */
	if (m->node >= MAX_NUMNODES) {
#endif	/* CONFIG_E90S && ! CONFIG_NUMA */
		printk(KERN_WARNING "WARNING: invalid node #%d (>= max %d)."
			"  IO link ignored.\n", m->node, MAX_NUMNODES);
		if (nr_ioapics > mp_iolinks_num)
			nr_ioapics = mp_iolinks_num;
		return;
	}

	if (m->link >= NODE_NUMIOLINKS) {
		printk(KERN_WARNING "WARNING: invalid local link #%d "
			"(>= max %d). IO link ignored.\n",
			m->link, NODE_NUMIOLINKS);
		return;
	}
	memcpy(&mp_iolinks[mp_iolinks_num], m, sizeof(*m));
	mp_iolinks_num ++;
	if (m->mpc_iolink_type == MP_IOLINK_IOHUB)
		mp_iohubs_num ++;
	else
		mp_rdmas_num ++;
}

static void __init MP_ioapic_info(struct mpc_ioapic *m)
{
	if (!(m->flags & MPC_APIC_USABLE))
		return;

#ifdef 	CONFIG_L_IO_APIC
	if (nr_ioapics >= max_iolinks) {
		pr_warn("Max # of I/O APICs (IO links) "
			"(%d) limit reached. IO APIC ignored.\n",
			max_iolinks);
		return;
	}
#endif
}

#ifdef	CONFIG_EPIC
static void __init MP_ioepic_info(struct mpc_ioepic *m)
{
}

/*
 * Find an mpc_iolink structure with matching IO-EPIC id. Get PCI bus of EIOHub / IOEPIC
 * from bus_min field.
 * This requires boot to pass all mpc_iolinks before mpc_ioepics.
 */
int __init mp_ioepic_find_bus(int ioepic_id)
{
	mpc_config_iolink_t *iolink;
	int i;

	for (i = 0; i < mp_iolinks_num; i++) {
		iolink = &mp_iolinks[i];
		if (iolink->apicid == ioepic_id)
			return iolink->bus_min;
	}

	pr_warn("%s(): failed to find PCI bus of IOEPIC id %d\n", __func__, ioepic_id);
	return 1;
}
#else
static void __init MP_ioepic_info(struct mpc_ioepic *m)
{
	pr_warn("Received MP_IOEPIC from boot on kernel without EPIC support\n");
}
#endif

static void __init
MP_timer_info(mpc_config_timer_t *m)
{
	unsigned long timeraddr = get_unaligned(&m->mpc_timeraddr);
	printk(KERN_INFO "System timer type %d Version %d at 0x%lX.\n",
		m->mpc_timertype, m->mpc_timerver, timeraddr);
	/* try to find out explicit definition of RTC*/
	if (m->mpc_timertype == MP_RTC_TYPE) {
		rtc_model = m->mpc_timerver;
		rtc_syncintr = m->mpc_timerflags & MP_RTC_FLAG_SYNCINTR;
	}
	if (nr_timers >= MAX_MP_TIMERS) {
		printk(KERN_CRIT "Max # of System timers (%d) exceeded "
			"(found %d).\n",
			MAX_MP_TIMERS, nr_timers);
		panic("Recompile kernel with bigger MAX_MP_TIMERS!.\n");
	}
	if (!timeraddr) {
		printk(KERN_ERR "WARNING: bogus zero System timer address"
			" found in MP table, skipping!\n");
		return;
	}
	memcpy(&mp_timers[nr_timers], m, sizeof(*m));
	nr_timers++;
}

static void MP_i2c_spi_info(struct mpc_config_i2c *mpc)
{
	void *i2ccntrladdr = (void *)get_unaligned(&mpc->mpc_i2ccntrladdr);
	void *i2cdataaddr = (void *)get_unaligned(&mpc->mpc_i2cdataaddr);
	IOHUB_revision = mpc->mpc_revision;
	printk("i2c_spi_info: control base addr = %px, data base addr = "
		"%px, IRQ %d IOHUB revision %02x\n",
		i2ccntrladdr, i2cdataaddr,
		mpc->mpc_i2c_irq,
		IOHUB_revision);
}


static void __init MP_intsrc_info(struct mpc_intsrc *m)
{
#ifdef CONFIG_KVM
	mp_irqs[mp_irq_entries] = *m;
	DebugMPT("Int: type %d, pol %d, trig %d, bus %d, IRQ %02x, APIC ID %x, APIC INT %02x\n",
			m->irqtype, m->irqflag & 3,
			(m->irqflag >> 2) & 3, m->srcbus,
			m->srcbusirq, m->dstapic, m->dstirq);
	if (++mp_irq_entries == MAX_IRQ_SOURCES)
		panic("Max # of irq sources exceeded!!\n");
#endif
}

static void __init MP_lintsrc_info(struct mpc_config_lintsrc *m)
{
	DebugMPT("Lint: type %d, pol %d, trig %d, bus %d,"
		" IRQ %02x, APIC ID %x, APIC LINT %02x\n",
			m->mpc_irqtype, m->mpc_irqflag & 3,
			(m->mpc_irqflag >> 2) &3, m->mpc_srcbusid,
			m->mpc_srcbusirq, m->mpc_destapic, m->mpc_destapiclint);
	/*
	 * Well it seems all SMP boards in existence
	 * use ExtINT/LVT1 == LINT0 and
	 * NMI/LVT2 == LINT1 - the following check
	 * will show us if this assumptions is false.
	 * Until then we do not have to add baggage.
	 */
	if ((m->mpc_irqtype == mp_ExtINT) &&
		(m->mpc_destapiclint != 0))
			BUG();
	if ((m->mpc_irqtype == mp_NMI) &&
		(m->mpc_destapiclint != 1))
			BUG();
}

/*
 * Read/parse the MPC
 */

static int __init smp_read_mpc(struct mpc_table *mpc)
{
	char str[16];
	int count = MP_SIZE_ALIGN(sizeof(*mpc));
	unsigned char *mpt= MP_ADDR_ALIGN(((unsigned char *)mpc) + count);

	if (memcmp(mpc->mpc_signature,MPC_SIGNATURE,4))
	{
		panic("SMP mptable: bad signature [%c%c%c%c]!\n",
			mpc->mpc_signature[0],
			mpc->mpc_signature[1],
			mpc->mpc_signature[2],
			mpc->mpc_signature[3]);
		return 1;
	}
	if (mpf_checksum((unsigned char *)mpc,mpc->mpc_length))
	{
		panic("SMP mptable: checksum error!\n");
		return 1;
	}
	if (mpc->mpc_spec!=0x01 && mpc->mpc_spec!=0x04 && mpc->mpc_spec!=0x08)
	{
		printk("Bad Config Table version (%d)!!\n",mpc->mpc_spec);
		return 1;
	}
	memcpy(str,mpc->mpc_oem,8);
	str[8]=0;
	printk("OEM ID: %s ",str);

	memcpy(str,mpc->mpc_productid,12);
	str[12]=0;
	printk("Product ID: %s ",str);

	printk("%s at: 0x%X\n", cpu_has_epic() ? "EPIC" : "APIC",
		mpc->mpc_lapic);

	/* save the local APIC address, it might be non-default */
	mp_lapic_addr = mpc->mpc_lapic;

	/*
	 *	Now process the configuration blocks.
	 */
	count = MP_SIZE_ALIGN(count);
	while (count < MP_SIZE_ALIGN(mpc->mpc_length)) {
		switch(*mpt) {
			case MP_PROCESSOR:
			{
				struct mpc_config_processor *m=
					(struct mpc_config_processor *)mpt;
				MP_processor_info(m);
				mpt += MP_SIZE_ALIGN(sizeof(*m));
				count += MP_SIZE_ALIGN(sizeof(*m));
				break;
			}
			case MP_IOLINK:
			{
				struct mpc_config_iolink *m=
					(struct mpc_config_iolink *)mpt;
				MP_iolink_info(m);
				mpt += MP_SIZE_ALIGN(sizeof(*m));
				count += MP_SIZE_ALIGN(sizeof(*m));
				break;
			}
			case MP_BUS:
			{
				struct mpc_config_bus *m=
					(struct mpc_config_bus *)mpt;
				mpt += MP_SIZE_ALIGN(sizeof(*m));
				count += MP_SIZE_ALIGN(sizeof(*m));
				break;
			}
			case MP_IOAPIC:
			{
				struct mpc_ioapic *m=
					(struct mpc_ioapic *)mpt;
				MP_ioapic_info(m);
				mpt += MP_SIZE_ALIGN(sizeof(*m));
				count += MP_SIZE_ALIGN(sizeof(*m));
				break;
			}
			case MP_IOEPIC:
			{
				struct mpc_ioepic *m =
					(struct mpc_ioepic *)mpt;
				MP_ioepic_info(m);
				mpt += MP_SIZE_ALIGN(sizeof(*m));
				count += MP_SIZE_ALIGN(sizeof(*m));
				break;
			}
			case MP_INTSRC:
			{
				struct mpc_intsrc *m =
						(struct mpc_intsrc *) mpt;
				MP_intsrc_info(m);
				mpt += MP_SIZE_ALIGN( sizeof(*m));
				count += MP_SIZE_ALIGN(sizeof(*m));
				break;
			}
			case MP_LINTSRC:
			{
				struct mpc_config_lintsrc *m=
					(struct mpc_config_lintsrc *)mpt;
				MP_lintsrc_info(m);
				mpt += MP_SIZE_ALIGN( sizeof(*m));
				count += MP_SIZE_ALIGN( sizeof(*m));
				break;
			}
			case MP_I2C_SPI:
			{
				struct mpc_config_i2c *m=
					(struct mpc_config_i2c *)mpt;
				MP_i2c_spi_info(m);
				mpt += MP_SIZE_ALIGN(sizeof(*m));
				count += MP_SIZE_ALIGN(sizeof(*m));
				break;
			}
			case MP_TIMER:
			{
				mpc_config_timer_t *m=
					(mpc_config_timer_t *)mpt;
				MP_timer_info(m);
				mpt += MP_SIZE_ALIGN(sizeof(*m));
				count += MP_SIZE_ALIGN(sizeof(*m));
				break;
			}
			case MP_PMC:
			{
				mpc_config_pmc_t *m =
					(mpc_config_pmc_t *)mpt;
				/* Do nothing: as pmc is a pci host bridge */
				mpt += MP_SIZE_ALIGN(sizeof(*m));
				count += MP_SIZE_ALIGN(sizeof(*m));
				break;
			}
			default :
			{
				printk("smp_read_mpc() undefined MP table "
					"item type %d\n", *mpt);
			}
		}
	}
	return mp_num_processors;
}

#ifdef CONFIG_IOHUB_DOMAINS
static int
mp_fix_iolinks_io_apicid(unsigned int src_apicid, unsigned int new_apicid)
{
	mpc_config_iolink_t *iolink;
	int i;

	if (mp_iolinks_num <= 0)
		return 0;
	for (i = 0; i < mp_iolinks_num; i++) {
		iolink = &mp_iolinks[i];
		if (iolink->mpc_iolink_type != MP_IOLINK_IOHUB)
			continue;
		if (iolink->apicid == src_apicid) {
			iolink->apicid = new_apicid;
			pr_err("... IOLINK node #%d link #%d IO-APIC ID "
				"fixing up to %d\n",
				iolink->node, iolink->link, new_apicid);
			return 0;
		}
	}
	pr_err("BIOS MP table bug: could not find IOLINK this IO-APIC ID %d\n",
		src_apicid);
	return -1;
}

int mp_fix_io_apicid(unsigned int src_apicid, unsigned int new_apicid)
{
	int ret = 0;

	if (mp_iolinks_num > 0)
		ret += mp_fix_iolinks_io_apicid(src_apicid, new_apicid);
/*	ret += mp_fix_intsrc_io_apicid(src_apicid, new_apicid); */
	return ret;
}

int mp_find_iolink_root_busnum(int node, int link)
{
	mpc_config_iolink_t *iolink;
	int i;

	for (i = 0; i < mp_iolinks_num; i ++) {
		iolink = &mp_iolinks[i];
		if (iolink->mpc_iolink_type != MP_IOLINK_IOHUB)
			continue;
		if (iolink->node == node && iolink->link == link)
			return (iolink->bus_min);
	}
	return (-1);
}

int mp_find_iolink_io_apicid(int node, int link)
{
	mpc_config_iolink_t *iolink;
	int i;

	for (i = 0; i < mp_iolinks_num; i ++) {
		iolink = &mp_iolinks[i];
		if (iolink->mpc_iolink_type != MP_IOLINK_IOHUB)
			continue;
		if (iolink->node == node && iolink->link == link)
			return (iolink->apicid);
	}
	return (-1);
}
#else  /* ! CONFIG_IOHUB_DOMAINS */
#define	MP_construct_default_iolinks()
#endif /* CONFIG_IOHUB_DOMAINS */

void mp_pci_add_resources(struct list_head *resources, struct iohub_sysdata *sd)
{
	mpc_config_iolink_t *iolink = NULL;
	struct resource	*mem;

#ifdef	CONFIG_IOHUB_DOMAINS
	int i;

	for (i = 0; i < mp_iolinks_num; i++) {
		iolink = &mp_iolinks[i];
		if (iolink->mpc_iolink_type != MP_IOLINK_IOHUB)
			continue;
		if (iolink->node == sd->node && iolink->link == sd->link)
			break;
	}
	BUG_ON(i == mp_iolinks_num);
#else
	iolink = &mp_iolinks[0];
#endif
	sd->mem_space.name	= "PCI mem";
	sd->mem_space.flags	= IORESOURCE_MEM;
	if (iolink->pci_mem_end) {
		sd->mem_space.start	= iolink->pci_mem_start;
		sd->mem_space.end	= iolink->pci_mem_end - 1;
		WARN_ON(request_resource(&iomem_resource, &sd->mem_space));
		mem = &sd->mem_space;
	} else {
		mem = &iomem_resource;
	}
	pci_add_resource_offset(resources, &ioport_resource,
					L_IOPORT_RESOURCE_OFFSET);
	pci_add_resource_offset(resources, mem,
					L_IOMEM_RESOURCE_OFFSET);
}

static inline void __init
MP_construct_default_timer(void)
{
	mpc_config_timer_t mp_timer;

#ifdef CONFIG_E2K
	return;
#endif
	mp_timer.mpc_type = MP_TIMER;
	mp_timer.mpc_timertype = MP_LT_TYPE;
	mp_timer.mpc_timerver = MP_LT_VERSION;
	mp_timer.mpc_timerflags = MP_LT_FLAGS;
	mp_timer.mpc_timeraddr = 0;
	MP_timer_info(&mp_timer);
}

/*
 * Scan the memory blocks for an SMP configuration block.
 */
void __init
get_smp_config(void)
{
	struct intel_mp_floating *mpf = mpf_found;
	if (!smp_found_config || mpf == NULL) {
		printk("MultiProcessor Specification could not find\n");
		return;
	}
	printk("MultiProcessor Specification v1.%d\n", mpf->mpf_specification);
	if (mpf->mpf_feature2 & (1<<7)) {
		printk("    IMCR and PIC compatibility mode.\n");
		panic("PIC cannot be used by this kernel\n");
	} else {
		printk("    Virtual Wire compatibility mode.\n");
	}

	/*
	 * Now see if we need to read further.
	 */
	if (mpf->mpf_feature1 != 0) {
		panic("Default MP configuration #%d\n", mpf->mpf_feature1);

	} else if (mpf->mpf_physptr) {
		/*
		 * Read the physical hardware table.  Anything here will
		 * override the defaults.
		 */
		smp_read_mpc(mpc_addr_to_virt(mpf->mpf_physptr));

		if (mp_iolinks_num <= 0)
			panic("mp_iolinks_num <= 0\n");
	} else
		BUG();

	printk("Processors: %d\n", mp_num_processors);
	/*
	 * Only use the first configuration found.
	 */
}

void __init
find_smp_config(void)
{
	u32 *bp;
	struct intel_mp_floating *mpf;
	boot_info_t *boot_info = &bootblock_virt->info;

	if (boot_info->mp_table_base == 0)
		return;

	mpf = (struct intel_mp_floating *)mpc_addr_to_virt(boot_info->mp_table_base);

	bp = (u32 *)mpf;
	DebugMPT("mpf->mpf_signature = 0x%x SMP_MAGIC_IDENT = 0x%x\n",
		*bp, SMP_MAGIC_IDENT);
	DebugMPT("mpf->mpf_length = %d should be 1\n",
		mpf->mpf_length);
	DebugMPT("mpf->mpf_checksum = 0x%x mpf_checksum() = 0x%x\n",
		mpf->mpf_checksum,
		mpf_checksum((unsigned char *)bp, sizeof(*mpf)));
	DebugMPT("mpf->mpf_specification = %d should be 1/4 or 8\n",
		mpf->mpf_specification);
	if ((*bp == SMP_MAGIC_IDENT) &&
		(mpf->mpf_length == 1) &&
		!mpf_checksum((unsigned char *)bp, sizeof(*mpf)) &&
		((mpf->mpf_specification == 1) ||
			(mpf->mpf_specification == 4) ||
			(mpf->mpf_specification == 8)) ) {

		smp_found_config = 1;
		printk("found SMP MP-table\n");
		mpf_found = mpf;
	}
}

#define APIC_ADD_MASK 0x000000FFFFFFFFFF /* as physical address */

#if 0
static void __init_kexec print_lintsrc_info(struct mpc_config_lintsrc *m)
{
	dump_printk("------- Lintsrc info entry\n");
	dump_printk("lintsrc entry: word 1 (32 bit) 0x%x\n", *(int *)m);
	dump_printk("lintsrc entry: word 2 (32 bit) 0x%x\n", *(int *)(m + 1));
	dump_printk("Lint: type %d, pol %d, trig %d, bus %d,"
		" IRQ %02x,\n\t\t\t APIC ID %x, APIC LINT %02x\n",
		m->mpc_irqtype, m->mpc_irqflag & 3,
		(m->mpc_irqflag >> 2) &3, m->mpc_srcbusid,
		m->mpc_srcbusirq, m->mpc_destapic, m->mpc_destapiclint);
}

static void __init_kexec print_intsrc_info(struct mpc_intsrc *m)
{
	dump_printk("------- Intsrc info entry\n");
	dump_printk("intsrc entry: word 1 (32 bit) 0x%x\n", *(int *)m);
	dump_printk("intsrc entry: word 2 (32 bit) 0x%x\n", *(int *)(m + 1));

	dump_printk("Int: type %d, pol %d, trig %d, bus %d,"
		" IRQ %02x,\n\t\t\t APIC ID %x, APIC INT %02x\n",
			m->irqtype, m->irqflag & 3,
			(m->irqflag >> 2) & 3, m->srcbus,
			m->srcbusirq, m->dstapic, m->dstirq);
}

static void __init_kexec print_iolink_info(struct mpc_config_iolink *m)
{
	dump_printk("------- I/O link entry\n");
	dump_printk("io apic entry: word 1 (32 bit) 0x%x\n", *(int *)m);
	dump_printk("io apic entry: word 2 (32 bit) 0x%x\n", *(int *)(m + 1));
	dump_printk("io apic entry: word 3 (32 bit) 0x%x\n", *(int *)(m + 2));
	dump_printk("io apic entry: word 4 (32 bit) 0x%x\n", *(int *)(m + 3));
	dump_printk("io apic entry: word 5 (32 bit) 0x%x\n", *(int *)(m + 4));
	dump_printk("io apic entry: word 6 (32 bit) 0x%x\n", *(int *)(m + 5));

	dump_printk("IO link #%d on node %d, version 0x%02x,",
		m->link, m->node, m->mpc_iolink_ver);
	if (m->mpc_iolink_type == MP_IOLINK_IOHUB) {
		dump_printk(" connected to IOHUB: min bus #%d max bus #%d "
			"IO APIC ID %d\n",
			m->bus_min, m->bus_max, m->apicid);
	} else {
		dump_printk(" is RDMA controller\n");
	}
}

static void __init_kexec print_ioapic_info(struct mpc_ioapic *m)
{
	dump_printk("------- I/O apic entry\n");
	dump_printk("io apic entry: word 1 (32 bit) 0x%x\n", *(int *)m);
	dump_printk("io apic entry: word 2 (32 bit) 0x%x\n", *(int *)(m + 1));

	if (!(m->flags & MPC_APIC_USABLE)) {
		dump_printk("i/o apic is unusable\n");
		return;
	}
	dump_printk("I/O APIC ID #%d Version %d at 0x%x.\n", m->apicid,
			m->apicver, m->apicaddr & APIC_ADD_MASK);
}

static void __init_kexec
print_timer_info(mpc_config_timer_t *m)
{

	dump_printk("------- System timer entry\n");
	dump_printk("timer type %d Version %d at 0x%lX.\n",
		m->mpc_timertype, m->mpc_timerver, m->mpc_timeraddr);
}

static void __init_kexec
print_i2c_spi_info(struct mpc_config_i2c *m){
	dump_printk("------- i2c/spi controller\n");
	dump_printk("device %d revision %02x control base addr = 0x%lx, "
		"data base addr = 0x%lx, IRQ = %d\n",
		m->mpc_max_channel, m->mpc_revision,
		m->mpc_i2ccntrladdr, m->mpc_i2cdataaddr,
		m->mpc_i2c_irq);
}

static void __init_kexec print_bus_info(struct mpc_config_bus *m)
{
	char str[7];

	dump_printk("------- Bus entry\n");
	memcpy(str, m->mpc_bustype, 6);

	dump_printk("bus entry: word 1 (32 bit) 0x%x\n", *(int *)m);
	dump_printk("bus entry: word 2 (32 bit) 0x%x\n", *(int *)(m + 1));
	dump_printk("Bus #%d is %s\n", m->mpc_busid, str);

}

static void __init_kexec print_processor_info(struct mpc_config_processor *m)
{
	dump_printk("------- Processor entry\n");
	dump_printk("processor entry: word 1 (32 bit) 0x%x\n", *(int *)m);
	dump_printk("processor entry: word 2 (32 bit) 0x%x\n",
							m->mpc_cpufeature);
	dump_printk("processor entry: word 3 (32 bit) 0x%x\n",
							m->mpc_featureflag);

	dump_printk("Proc: lapic id %d, lapic version %d,\n"
	"\t cpuflags(bit 1 - cpu enable, bit 2 - bootstrap) 0x%x\n"
	"\t\t signature 0x%x flags 0x%x\n", m->mpc_apicid, m->mpc_apicver,
		m->mpc_cpuflag & 0x3, m->mpc_cpufeature, m->mpc_featureflag);
}

static void __init_kexec print_entries(char type, char *mpt)
{
	if (type == MP_BUS) {
		struct mpc_config_bus *m = (struct mpc_config_bus *)mpt;
		print_bus_info(m);
	} else if (type == MP_IOLINK) {
		struct mpc_config_iolink *m = (struct mpc_config_iolink *)mpt;
		print_iolink_info(m);
	} else if (type == MP_IOAPIC) {
		struct mpc_ioapic *m = (struct mpc_ioapic *)mpt;
		print_ioapic_info(m);
	} else if (type == MP_INTSRC) {
		struct mpc_intsrc *m = (struct mpc_intsrc *)mpt;
			print_intsrc_info(m);
	} else if (type == MP_LINTSRC) {
		struct mpc_config_lintsrc *m = (struct mpc_config_lintsrc *)mpt;
		print_lintsrc_info(m);
	} else if (type == MP_TIMER) {
		mpc_config_timer_t *m = (mpc_config_timer_t *)mpt;
		print_timer_info(m);
	} else if (type == MP_I2C_SPI) {
		struct mpc_config_i2c *m = (struct mpc_config_i2c *)mpt;
		print_i2c_spi_info(m);
	} else {
		dump_printk("print_entries() invalid MP table entry type "
			"%d\n", type);
	}
}

static void __init_kexec print_mptable(struct intel_mp_floating *mpf)
{
	char str[16];
	struct mpc_table *mpc = (struct mpc_table *)
					mpc_addr(mpf->mpf_physptr);
	int count = MP_SIZE_ALIGN(sizeof(*mpc));
	unsigned char *mpt = MP_ADDR_ALIGN(((unsigned char *)mpc) + count);

	dump_printk("\n\nMP CONFIGURATION TABLE HEADER:\n\n");
	dump_printk("mpf->mpf_feature1 = %d\n", mpf->mpf_feature1);

	if (mpf->mpf_feature1 != 0) {
		dump_printk(".......construct_default_ISA_mptable\n");
		return;
	}

	if (!mpf->mpf_physptr) {
		dump_printk("null mptable address pointer\n");
		return;
	}

	dump_printk("SMP mptable: signature [%c%c%c%c]!\n",
				mpc->mpc_signature[0],
				mpc->mpc_signature[1],
				mpc->mpc_signature[2],
				mpc->mpc_signature[3]);

	dump_printk("SMP mptable: mpc->mpc_length %d\n", mpc->mpc_length);
	if (mpf_checksum((unsigned char *)mpc,mpc->mpc_length))
	{
		dump_printk("SMP mptable: checksum error!\n");
		return;
	}
	if (mpc->mpc_spec!=0x01 && mpc->mpc_spec!=0x04 && mpc->mpc_spec!=0x08)
	{
		dump_printk("Bad Config Table version (%d)!!\n", mpc->mpc_spec);
		return;
	}
	memcpy(str,mpc->mpc_oem,8);
	str[8]=0;
	dump_printk("OEM ID: %s\n", str);

	memcpy(str, mpc->mpc_productid, 12);
	str[12]=0;
	dump_printk("Product ID: %s\n", str);

	dump_printk("APIC at: 0x%lx\n", mpc->mpc_lapic & APIC_ADD_MASK);

	dump_printk("\n\nMP TABLE CONFIGURATION ENTRIES:\n\n");

	while (count < MP_SIZE_ALIGN(mpc->mpc_length)) {
		if (*mpt == MP_PROCESSOR) {
			struct mpc_config_processor *m=
				(struct mpc_config_processor *)mpt;
			print_processor_info(m);
			mpt += MP_SIZE_ALIGN(sizeof(*m));
			count += MP_SIZE_ALIGN(sizeof(*m));
		} else if (*mpt == MP_IOLINK) {
			struct mpc_config_iolink *m=
				(struct mpc_config_iolink *)mpt;
			print_iolink_info(m);
			mpt += MP_SIZE_ALIGN(sizeof(*m));
			count += MP_SIZE_ALIGN(sizeof(*m));
		} else if ((*mpt == MP_BUS) || (*mpt == MP_INTSRC) ||
			(*mpt == MP_LINTSRC)) {
			print_entries(*mpt, (char *) mpt);
			mpt += MP_SIZE_ALIGN(8);
			count += MP_SIZE_ALIGN(8);
		} else if (*mpt == MP_IOAPIC) {
			struct mpc_ioapic *m =
				(struct mpc_ioapic *)mpt;
			print_ioapic_info(m);
			mpt += MP_SIZE_ALIGN(sizeof(*m));
			count += MP_SIZE_ALIGN(sizeof(*m));
		} else if (*mpt == MP_TIMER) {
			print_timer_info((mpc_config_timer_t *)mpt);
			mpt += MP_SIZE_ALIGN(sizeof(mpc_config_timer_t));
			count += MP_SIZE_ALIGN(sizeof(mpc_config_timer_t));
		} else if (*mpt == MP_I2C_SPI) {
			struct mpc_config_i2c *m =
				(struct mpc_config_i2c *)mpt;
			print_i2c_spi_info(m);
			mpt += MP_SIZE_ALIGN(sizeof(*m));
			count += MP_SIZE_ALIGN(sizeof(*m));
		} else {
			dump_printk("unrecognized entry: %c ", *mpt);
			mpt += 8; count += 8;
		}
	}
	return;

}

static void __init_kexec print_floating_point(struct intel_mp_floating *mpf)
{
	u32 *bp;

	bp = (u32 *)mpf;

	dump_printk("\n\nFLOATING POINT STRUCTURE:\n\n");
	dump_printk("floating point: word 1 (32 bit) 0x%08x\n", *bp);
	dump_printk("floating point: word 2 (32 bit) 0x%08x\n", *(bp+1));
	dump_printk("floating point: word 3 (32 bit) 0x%08x\n", *(bp+2));
	dump_printk("floating point: word 4 (32 bit) 0x%08x\n\n", *(bp+3));

	dump_printk("mpf->mpf_signature = [%c%c%c%c]\n",
			mpf->mpf_signature[0], mpf->mpf_signature[1],
			mpf->mpf_signature[2], mpf->mpf_signature[3]);
	dump_printk("mpf->mpf_signature = 0x%x SMP_MAGIC_IDENT = 0x%x\n",
		*bp, SMP_MAGIC_IDENT);
	dump_printk("mpf->mpf_length = %d should be 1\n",
		mpf->mpf_length);
	dump_printk("mpf->mpf_checksum = 0x%x check sum() = 0x%x\n",
		mpf->mpf_checksum,
		mpf_checksum((unsigned char *)bp, sizeof(*mpf)));
	dump_printk("mpf->mpf_specification = %d should be 1/4 or 8\n",
		mpf->mpf_specification);

	if ((*bp == SMP_MAGIC_IDENT) &&
		(mpf->mpf_length == 1) &&
		!mpf_checksum((unsigned char *)bp, sizeof(*mpf)) &&
		((mpf->mpf_specification == 1) ||
			(mpf->mpf_specification == 4) ||
			(mpf->mpf_specification == 8)) ) {
		dump_printk("found floating pointer structure at 0x%lx\n",
			mpf);
		print_mptable(mpf);
	} else {
		dump_printk("error floating pointer structur at 0x%lx\n",
			mpf);

	}
}

static void __init_kexec print_boot_info(boot_info_t *boot_info)
{
	int node;
	int bank;
	int total_banks = 0;

	dump_printk("signature 0x%x\n", boot_info->signature);
	dump_printk("vga_mode %d\n", boot_info->vga_mode);
	dump_printk("num_of_banks %d\n", boot_info->num_of_banks);
	dump_printk("num_of_busy areas %d\n", boot_info->num_of_busy);
	dump_printk("kernel_base 0x%lx\n", boot_info->kernel_base);
	dump_printk("kernel_size 0x%lx\n", boot_info->kernel_size);

	dump_printk("ramdisk_base 0x%lx\n", boot_info->ramdisk_base);
	dump_printk("ramdisk_size 0x%lx\n", boot_info->ramdisk_size);
	dump_printk("num_of_cpus %d\n", boot_info->num_of_cpus);
	dump_printk("machine flags 0x%04x\n", boot_info->mach_flags);
	dump_printk("mp_table_base 0x%lx\n", boot_info->mp_table_base);
	dump_printk("serial base 0x%x\n", boot_info->serial_base);

	if (boot_info->kernel_args_string_pnt)
		dump_printk("kernel string %s\n", boot_info->kernel_args_string_pnt);
	else if (!strncmp(boot_info->kernel_args_string, KERNEL_ARGS_STRING_EX_SIGNATURE,
		     KERNEL_ARGS_STRING_EX_SIGN_SIZE))
		dump_printk("kernel string %s\n", boot_info->kernel_args_string_ex);
	else
		dump_printk("kernel string %s\n", boot_info->kernel_args_string);

	dump_printk("mach_serialn 0x%lx\n", boot_info->mach_serialn);
	dump_printk("kernel_csum 0x%lx\n", boot_info->kernel_csum);

	dump_printk("num_of_nodes %d\n", boot_info->num_of_nodes);
	dump_printk("nodes_map %d\n", boot_info->nodes_map);

	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		bank_info_t *cur_bank;

		cur_bank = boot_info->nodes_mem[node].banks;
		if (cur_bank->size == 0) {
			if (boot_info->nodes_map & (1 << node)) {
				dump_printk("Node #%d has not physical "
					"memory\n", node);
			} else {
				dump_printk("Node #%d is not online\n", node);
			}
			continue;	/* node has not memory */
		} else if (!(boot_info->nodes_map & (1 << node))) {
			dump_printk("BUG : Node #%d is not online, but has "
				"physical memory\n", node);
		}

		dump_printk("Node #%d physical memory banks: ", node);
		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
			if (cur_bank->size) {
				dump_printk("     [%d] : address 0x%x, "
					"size 0x%x\n",
					bank, cur_bank->address,
					cur_bank->size);
			} else
				break;	/* no more memory on node */
			cur_bank ++;
			total_banks ++;
		}
	}
	if (boot_info->num_of_banks &&
				(boot_info->num_of_banks != total_banks)) {
		dump_printk("BUG : boot_info->num_of_banks %d != "
			"number of banks at boot_info->nodes_mem %d\n",
			boot_info->num_of_banks, total_banks);
	}
	for (bank = 0; bank < boot_info->num_of_busy; bank ++) {
		dump_printk("boot_info->busy[%d].address 0x%x\n",
				bank, boot_info->busy[bank].address);
		dump_printk("boot_info->busy[%d].size 0x%x\n",
				bank, boot_info->busy[bank].size);
	}

	if (boot_info->mp_table_base)
		print_floating_point((struct intel_mp_floating *)
				mpc_addr(boot_info->mp_table_base));
	else
		dump_printk("null mp floating structure pointer\n");
}

void __init_kexec print_bootblock(bootblock_struct_t *bootblock)
{
	boot_info_t *boot_info = &bootblock->info;

	dump_printk("BOOT_INFO *******************************************:\n");
	print_boot_info(boot_info);
	dump_printk("BOOT_INFO *******************************************:\n");
}
#endif
