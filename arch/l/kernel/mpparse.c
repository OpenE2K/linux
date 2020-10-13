/*
 *	Intel Multiprocessor Specificiation 1.1 and 1.4
 *	compliant MP-table parsing routines.
 *	
 *	Given from i386 architecture mpparse.c implementation.
 */

#include <linux/mm.h>
#include <linux/irq.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/bootmem.h>
#include <linux/kernel_stat.h>
#include <linux/mc146818rtc.h>
#include <linux/cpumask.h>

#ifdef __e2k__
#include <asm/boot_smp.h>
#include <asm/e2k_sic.h>
#endif
#include <asm/smp.h>
#include <asm/mtrr.h>
#include <asm/mpspec.h>
#include <asm/pgalloc.h>
#include <asm/console.h>
#include <asm/io_apic.h>

#include <asm-l/i2c-spi.h>
#include <asm-l/l_pmc.h>

#undef	DEBUG_MPT_MODE
#undef	DebugMPT
#define	DEBUG_MPT_MODE		0	/* MP-table parsing */
#define	DebugMPT		if (DEBUG_MPT_MODE) printk

static struct intel_mp_floating *mpf_found = NULL;
static boot_info_t *mpf_boot_info = NULL;
unsigned int __initdata maxcpus = NR_CPUS;
int __initdata max_iolinks = MAX_NUMIOLINKS;
int __initdata max_node_iolinks = 1;

/* Define l_boot_printk() here as it is not used anywhere else. */
#ifdef CONFIG_E2K
# define l_boot_printk	do_boot_printk
# define boot_mpf_found	boot_get_vo_value(mpf_found)
#else
# define l_boot_printk	dump_printk
# define boot_mpf_found	mpf_found
#endif

/*
 * Various Linux-internal data structures created from the
 * MP-table.
 */
static mpc_config_iolink_t mp_iolinks[MAX_NUMIOLINKS];
static int mp_iolinks_num = 0;
static int mp_iohubs_num = 0;
static int mp_rdmas_num = 0;

mpc_config_timer_t mp_timers[MAX_MP_TIMERS];
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

#ifdef CONFIG_IOHUB_DOMAINS
static int src_irq_entries;
#endif /* CONFIG_IOHUB_DOMAINS */

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
MP_processor_info (struct mpc_config_processor *m)
{
	if (!(m->mpc_cpuflag & CPU_ENABLED))
		return;
#ifdef	CONFIG_E2K
	if (!IS_VIRT_CPU_ENABLED(m->mpc_apicid)) {
			return;
	}
#endif	/* CONFIG_E2K */

	printk("Processor APIC ID #%d version %d\n",
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

	generic_processor_info(m->mpc_apicid, m->mpc_apicver);
}

static void __init
MP_iolink_info (struct mpc_config_iolink *m)
{
	printk("IO link #%d on node %d, version 0x%02x,",
		m->link, m->node, m->mpc_iolink_ver);
	if (m->mpc_iolink_type == MP_IOLINK_IOHUB) {
		printk(" connected to IOHUB: min bus #%d max bus #%d IO APIC "
			"ID %d\n",
			m->bus_min, m->bus_max, m->apicid);
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
	mp_iolinks[mp_iolinks_num] = *m;
	mp_iolinks_num ++;
	if (m->mpc_iolink_type == MP_IOLINK_IOHUB)
		mp_iohubs_num ++;
	else
		mp_rdmas_num ++;
}

static void __init MP_bus_info (struct mpc_config_bus *m)
{
	char str[7];
#if MAX_MP_BUSSES < 256
	if (m->mpc_busid >= MAX_MP_BUSSES) {
		WARN(1, "MP table busid value (%d) for bustype %s  is too large, max. supported is %d\n",
		       m->mpc_busid, str, MAX_MP_BUSSES - 1);
		return;
	}
#endif
	memcpy(str, m->mpc_bustype, 6);
	str[6] = 0;
	DebugMPT("Bus #%d is %s\n", m->mpc_busid, str);

	if (strncmp(str, BUSTYPE_ISA, sizeof(BUSTYPE_ISA)-1) == 0) {
		set_bit(m->mpc_busid, mp_bus_not_pci);
#if defined(CONFIG_EISA) || defined(CONFIG_MCA)
		mp_bus_id_to_type[m->mpc_busid] = MP_BUS_ISA;
#endif
	} else if (strncmp(str, BUSTYPE_PCI, sizeof(BUSTYPE_PCI)-1) == 0) {
		clear_bit(m->mpc_busid, mp_bus_not_pci);
#if defined(CONFIG_EISA) || defined(CONFIG_MCA)
		mp_bus_id_to_type[m->mpc_busid] = MP_BUS_PCI;
	} else if (strncmp(str, BUSTYPE_EISA, sizeof(BUSTYPE_EISA)-1) == 0) {
		mp_bus_id_to_type[m->mpc_busid] = MP_BUS_EISA;
	} else if (strncmp(str, BUSTYPE_MCA, sizeof(BUSTYPE_MCA)-1) == 0) {
		mp_bus_id_to_type[m->mpc_busid] = MP_BUS_MCA;
#endif
	} else
		printk(KERN_WARNING "Unknown bustype %s - ignoring\n", str);
}

static void __init MP_ioapic_info (struct mpc_ioapic *m)
{
	if (!(m->flags & MPC_APIC_USABLE))
		return;

#ifdef 	CONFIG_L_IO_APIC
	if (nr_ioapics >= max_iolinks) {
		pr_warning("Max # of I/O APICs (IO links) "
			"(%d) limit reached. IO APIC ignored.\n",
			max_iolinks);
		return;
	}

	mp_register_ioapic(m->apicid, m->apicaddr, gsi_top);
#endif
}

static void __init
MP_timer_info(mpc_config_timer_t *m)
{

	printk(KERN_INFO "System timer type %d Version %d at 0x%lX.\n",
		m->mpc_timertype, m->mpc_timerver, m->mpc_timeraddr);
	if (nr_timers >= MAX_MP_TIMERS) {
		printk(KERN_CRIT "Max # of System timers (%d) exceeded "
			"(found %d).\n",
			MAX_MP_TIMERS, nr_timers);
		panic("Recompile kernel with bigger MAX_MP_TIMERS!.\n");
	}
	if (!m->mpc_timeraddr) {
		printk(KERN_ERR "WARNING: bogus zero System timer address"
			" found in MP table, skipping!\n");
		return;
	}
	mp_timers[nr_timers] = *m;
	nr_timers++;
}

static void MP_i2c_spi_info(struct mpc_config_i2c *mpc)
{
#ifdef CONFIG_I2C_SPI_RESET_CONTROLLER
	i2c_spi[0].cntrl_base = (void __iomem *)mpc->mpc_i2ccntrladdr;
	i2c_spi[0].data_base = (void __iomem *)mpc->mpc_i2cdataaddr;
	i2c_spi[0].dev_number = mpc->mpc_max_channel;
	i2c_spi[0].IRQ = mpc->mpc_i2c_irq;
	if (i2c_spi[0].IRQ == 0) {
		i2c_spi[0].IRQ = I2C_SPI_DEFAULT_IRQ;
	}
	IOHUB_revision = mpc->mpc_revision;
	printk("i2c_spi_info: control base addr = %p, data base addr = "
		"%p, IRQ %d IOHUB revision %02x\n",
		i2c_spi[0].cntrl_base, i2c_spi[0].data_base, i2c_spi[0].IRQ,
		IOHUB_revision);
#endif
}

static void MP_pmc_info(struct mpc_config_pmc *mpc)
{
#ifdef	CONFIG_L_PMC
	unsigned long val;

	l_pmc.type = mpc->mpc_pmc_type; /* Izumrud or Processor-2 */
	l_pmc.version = mpc->mpc_pmc_version;
	l_pmc.cntrl_base = (void __iomem *)mpc->mpc_pmc_cntrl_addr;
	l_pmc.data_base = (void __iomem *)mpc->mpc_pmc_data_addr;

	val = (unsigned  long)mpc->mpc_pmc_vmax;
	val <<= PMC_L_COVFID_STATUS_VMAX_SHIFT;
	l_pmc.vrange = val;
	val = (unsigned long)mpc->mpc_pmc_vmin;
	val <<= PMC_L_COVFID_STATUS_VMIN_SHIFT;
	l_pmc.vrange += val;
	val = (unsigned long)mpc->mpc_pmc_fmax;
	val <<= PMC_L_COVFID_STATUS_FMAX_SHIFT;
	l_pmc.vrange += val;

	l_pmc.data_size = mpc->mpc_pmc_data_size;

	memcpy(l_pmc.p_state, mpc->mpc_pmc_p_state,
				PMC_L_MAX_PSTATES * sizeof(unsigned int));
	l_pmc.freq = mpc->mpc_pmc_freq;

	printk(KERN_NOTICE "pmc_info: control base addr = %p, data base addr = "
		"%p, data_size = %d, type = %d, version = %d, freq = %d\n",
		l_pmc.cntrl_base, l_pmc.data_base, l_pmc.data_size,
		l_pmc.type, l_pmc.version, l_pmc.freq);
#endif
}

static void __init MP_intsrc_info (struct mpc_intsrc *m)
{
#ifdef 	CONFIG_L_IO_APIC
	mp_irqs [mp_irq_entries] = *m;
	DebugMPT("Int: type %d, pol %d, trig %d, bus %d,"
		" IRQ %02x, APIC ID %x, APIC INT %02x\n",
			m->irqtype, m->irqflag & 3,
			(m->irqflag >> 2) & 3, m->srcbus,
			m->srcbusirq, m->dstapic, m->dstirq);
	if (++mp_irq_entries == MAX_IRQ_SOURCES)
		panic("Max # of irq sources exceeded!!\n");
#endif
}

static void __init construct_default_ioirq_mptable(int mpc_default_type)
{
	struct mpc_intsrc intsrc;
	int i;

	intsrc.type = MP_INTSRC;
	intsrc.irqflag = 0;			/* conforming */
	intsrc.srcbus = 0;
#ifdef 	CONFIG_L_IO_APIC
	intsrc.dstapic = mpc_ioapic_id(0);
#else
	intsrc.dstapic = 0;
#endif

	intsrc.irqtype = mp_INT;
	for (i = 0; i < 16; i++) {
		switch (mpc_default_type) {
		case 2:
			if (i == 0 || i == 13)
				continue;	/* IRQ0 & IRQ13 not connected */
			/* fall through */
		default:
			if (i == 2)
				continue;	/* IRQ2 is never connected */
		}

		intsrc.srcbusirq = i;
		intsrc.dstirq = i ? i : 2;		/* IRQ0 to INTIN2 */
//		intsrc.dstirq = i;			/* */
		MP_intsrc_info(&intsrc);
	}

	intsrc.irqtype = mp_ExtINT;
	intsrc.srcbusirq = 0;
	intsrc.dstirq = 0;				/* 8259A to INTIN0 */
	MP_intsrc_info(&intsrc);
}

static void __init MP_lintsrc_info (struct mpc_config_lintsrc *m)
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

	printk("APIC at: 0x%X\n",mpc->mpc_lapic);

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
				MP_bus_info(m);
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
				MP_pmc_info(m);
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

#ifdef	__e2k__
static int __init
MP_construct_dup_ioapic(int node, int link)
{
	struct mpc_ioapic ioapic;

	pr_info("BOOT did not pass IO-APIC info for node %d link %d, "
		"construct duplicated table\n", node, link);

	ioapic.type = MP_IOAPIC;
	ioapic.flags = MPC_APIC_USABLE;
	ioapic.apicver = 0x11;

	if (nr_ioapics <= link) {
		ioapic.apicid = NR_CPUS + link;
		ioapic.apicaddr = 0xfec00000 + link * 0x1000;
	} else {
		ioapic.apicid = mpc_ioapic_id(link) + (nr_ioapics - link);
		ioapic.apicaddr = mpc_ioapic_addr(link) +
				  (node * NODE_NUMIOLINKS) * 0x1000;
	}

	MP_ioapic_info(&ioapic);

	return ioapic.apicid;
}

static void __init
MP_construct_dup_intsrc(int apicid, int node, int link)
{
	struct mpc_intsrc intsrc;
	int src_apicid;
	int ent;

	if (nr_ioapics <= link)
		panic("MP_construct_dup_intsrc() nothing IO APICs detected in "
			"MP table\n");
	src_apicid = mpc_ioapic_id(link);
	for (ent = 0; ent < src_irq_entries; ent ++) {
		if (mp_irqs[ent].dstapic != src_apicid)
			continue;
		intsrc = mp_irqs[ent];
		intsrc.dstapic = apicid;
		MP_intsrc_info(&intsrc);
	}
}
#endif	/* __e2k__ */

static void __init
MP_construct_default_iolinks(void)
{
	mpc_config_iolink_t mp_iolink;
	boot_info_t *boot_info = mpf_boot_info;
	unsigned long node_mask;
	int node;
	int iolinks_count;
	unsigned int apicid;

	early_sic_init();

	printk("BOOT did not pass IOLINKs info, construct default table\n");
#ifdef	__e2k__
	if ((IS_MACHINE_E3M) || boot_info == NULL) {
		/* only one IO controller (south bridge) PIIX4 */
		/* on single node # 0 */
		mp_iolink.mpc_type = MP_IOLINK;
		mp_iolink.mpc_iolink_type = MP_IOLINK_IOHUB;
		if (!HAS_MACHINE_E2K_IOHUB)
			mp_iolink.mpc_iolink_ver = MP_IOHUB_E3M_VER;
		else
			mp_iolink.mpc_iolink_ver = MP_IOHUB_FPGA_VER;
		mp_iolink.node = 0;
		mp_iolink.link = 0;
		mp_iolink.bus_min = 0;
		mp_iolink.bus_max = 7;
		if (nr_ioapics < 1)
			mp_iolink.apicid = -1;
		else
			mp_iolink.apicid = mpc_ioapic_id(0);
		MP_iolink_info(&mp_iolink);
		return;
	}
#endif	/* __e2k__ */
	node_mask = boot_info->nodes_map;
	iolinks_count = 0;
	src_irq_entries = mp_irq_entries;
	mp_iolink.mpc_type = MP_IOLINK;

#if defined(CONFIG_E90S) && !defined(CONFIG_NUMA)
	for (node = 0; node < MAX_NUMIOLINKS; node++) {
#else	/* E2K or NUMA */
	for (node = 0; node < MAX_NUMNODES; node++) {
		if (!(node_mask & (1 << node)))
			continue;
#endif	/* CONFIG_E90S && ! CONFIG_NUMA */
		if (!early_iohub_online(node, 0))
			continue;
		if (iolinks_count >= max_iolinks)
			break;

		mp_iolink.mpc_iolink_type = MP_IOLINK_IOHUB;
		mp_iolink.mpc_iolink_ver = MP_IOHUB_FPGA_VER;
		mp_iolink.node = node;
		mp_iolink.link = 0;
		mp_iolink.bus_min = 1;
		mp_iolink.bus_max = 3;
		if (nr_ioapics <= iolinks_count) {
#ifdef	__e2k__
			apicid = MP_construct_dup_ioapic(node, 0);
			MP_construct_dup_intsrc(apicid, node, 0);
#else	/* e90s */
			pr_info("BOOT did not pass IO-APIC info for IOLINK #%d "
				"on node #%d, ignore IO link\n",
				iolinks_count, node);
			break;
#endif	/* __e2k__ */
		} else {
			apicid = mpc_ioapic_id(iolinks_count);
		}
		mp_iolink.apicid = apicid;
		iolinks_count ++;
		MP_iolink_info(&mp_iolink);
#ifdef	__e2k__
		if (IS_MACHINE_ES2) {
			/* there is second IO link on each node */
			if (!early_iohub_online(node, 1))
				continue;
			if (iolinks_count >= max_iolinks)
				break;
			if (max_node_iolinks <= 1)
				continue;
			mp_iolink.link = 1;
			mp_iolink.bus_min = 1;
			mp_iolink.bus_max = 1;
			if (nr_ioapics <= iolinks_count) {
				apicid = MP_construct_dup_ioapic(node, 1);
				MP_construct_dup_intsrc(apicid, node, 1);
			} else {
				apicid = mpc_ioapic_id(iolinks_count);
			}
			mp_iolink.apicid = apicid;
			iolinks_count ++;
			MP_iolink_info(&mp_iolink);
		}
#endif	/* __e2k__ */
	}
}

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

int mp_fix_intsrc_io_apicid(unsigned int src_apicid, unsigned int new_apicid)
{
	struct mpc_intsrc *m;
	int count = 0;
	int i;

	for (i = 0; i < mp_irq_entries; i++) {
		m = &mp_irqs[i];
		if (m->dstapic == src_apicid) {
			m->dstapic = new_apicid;
			count++;
			pr_err("... BUS #%d IRQ %d IO-APIC ID "
				"fixing up to %d\n",
				m->srcbus, m->srcbusirq, new_apicid);
		}
	}
	if (count <= 0) {
		pr_err("BIOS MP table bug: none IRQ entry for IO-APIC ID %d\n",
			src_apicid);
		return -1;
	}
	return 0;
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

static int mp_find_srcbus_io_apicid(int busnum)
{
	int i;

	for (i = 0; i < mp_irq_entries; i++) {
		int lbus = mp_irqs[i].srcbus;

		if (busnum == lbus)
			return mp_irqs[i].dstapic;
	}
	return -1;
}

int get_bus_to_io_apicid(int busnum)
{
	mpc_config_iolink_t *iolink;
	int i;

	if (mp_iolinks_num <= 0) {
		printk(KERN_WARNING "Bogus boot: none IO links info "
			"in MP table\n");
		return mp_find_srcbus_io_apicid(busnum);
	}
	for (i = 0; i < mp_iolinks_num; i++) {
		iolink = &mp_iolinks[i];
		if (iolink->mpc_iolink_type != MP_IOLINK_IOHUB)
			continue;
		if (busnum >= iolink->bus_min && busnum <= iolink->bus_max)
			return iolink->apicid;
	}
	return -1;
}

static inline void __init
MP_construct_default_timer(void)
{
	mpc_config_timer_t mp_timer;
#ifdef __e2k__
	if (machine_id != MACHINE_ID_E3S_LMS &&
		machine_id != MACHINE_ID_ES2_DSP_LMS &&
		machine_id != MACHINE_ID_ES2_RU_LMS)
		return;
#endif
	mp_timer.mpc_type = MP_TIMER;
	mp_timer.mpc_timertype = MP_LT_TYPE;
	mp_timer.mpc_timerver = MP_LT_VERSION;
	mp_timer.mpc_timerflags = MP_LT_FLAGS;
	mp_timer.mpc_timeraddr = 0;
	MP_timer_info(&mp_timer);
}

static inline void __init construct_default_ISA_mptable(int mpc_default_type)
{
	struct mpc_config_processor processor;
	struct mpc_config_bus bus;
	struct mpc_ioapic ioapic;
	struct mpc_config_lintsrc lintsrc;
	int linttypes[2] = { mp_ExtINT, mp_NMI };
	int i;

	/*
	 * local APIC has default address
	 */
	mp_lapic_addr = APIC_DEFAULT_PHYS_BASE;

	/*
	 * 2 CPUs, numbered 0 & 1.
	 */
	processor.mpc_type = MP_PROCESSOR;
	/* Either an integrated APIC or a discrete 82489DX. */
	processor.mpc_apicver = mpc_default_type > 4 ? 0x10 : 0x01;
	processor.mpc_cpuflag = CPU_ENABLED;

	/* 
	 * 111 Indicates a processor that is not a Intel architecture-
	 * compatible processor.
	 */
	processor.mpc_cpufeature = 0x0f;
	processor.mpc_featureflag = 0x0;
	processor.mpc_reserved[0] = 0;
	processor.mpc_reserved[1] = 0;

	/* 
	 * Default configuration must be set for all live processors.
	 */
	for (i = 0; i < phys_cpu_present_num; i++) {
		processor.mpc_apicid = i;
		MP_processor_info(&processor);
	}
	if (mp_num_processors != phys_cpu_present_num) {
		printk("BIOS bug, Number of processors from BIOS is %d "
			"!= %d (number of processors in MP table)\n",
			phys_cpu_present_num, mp_num_processors);
	}

	MP_construct_default_iolinks();

	bus.mpc_type = MP_BUS;
	bus.mpc_busid = 0;
	switch (mpc_default_type) {
		default:
			printk("???\nUnknown standard configuration %d\n",
				mpc_default_type);
			/* fall through */
		case 1:
		case 5:
			memcpy(bus.mpc_bustype, "ISA   ", 6);
			break;
		case 2:
		case 6:
		case 3:
			memcpy(bus.mpc_bustype, "EISA  ", 6);
			break;
		case 4:
		case 7:
			memcpy(bus.mpc_bustype, "MCA   ", 6);
	}
	MP_bus_info(&bus);
	if (mpc_default_type > 4) {
		bus.mpc_busid = 1;
		memcpy(bus.mpc_bustype, "PCI   ", 6);
		MP_bus_info(&bus);
	}

	ioapic.type = MP_IOAPIC;
	ioapic.apicid = 2;
	ioapic.apicver = mpc_default_type > 4 ? 0x10 : 0x01;
	ioapic.flags = MPC_APIC_USABLE;
	ioapic.apicaddr = 0xFEC00000;
	MP_ioapic_info(&ioapic);

	/*
	 * We set up most of the low 16 IO-APIC pins according to MPS rules.
	 */
	construct_default_ioirq_mptable(mpc_default_type);

	lintsrc.mpc_type = MP_LINTSRC;
	lintsrc.mpc_irqflag = 0;		/* conforming */
	lintsrc.mpc_srcbusid = 0;
	lintsrc.mpc_srcbusirq = 0;
	lintsrc.mpc_destapic = MP_APIC_ALL;
	for (i = 0; i < 2; i++) {
		lintsrc.mpc_irqtype = linttypes[i];
		lintsrc.mpc_destapiclint = i;
		MP_lintsrc_info(&lintsrc);
	}
	MP_construct_default_timer();
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
		pic_mode = 0;
	}

	/*
	 * Now see if we need to read further.
	 */
	if (mpf->mpf_feature1 != 0) {

		printk("Default MP configuration #%d\n", mpf->mpf_feature1);
		construct_default_ISA_mptable(mpf->mpf_feature1);

	} else if (mpf->mpf_physptr) {
		/*
		 * Read the physical hardware table.  Anything here will
		 * override the defaults.
		 */
		smp_read_mpc(mpc_addr_to_virt(mpf->mpf_physptr));

		/*
		 * If there are no explicit MP IRQ entries, then we are
		 * broken.  We set up most of the low 16 IO-APIC pins to
		 * ISA defaults and hope it will work.
		 */
		if (!mp_irq_entries) {
			struct mpc_config_bus bus;

			printk("BIOS bug, no explicit IRQ entries, "
				"using default mptable. "
				"(tell your hw vendor)\n");

			bus.mpc_type = MP_BUS;
			bus.mpc_busid = 0;
			memcpy(bus.mpc_bustype, "ISA   ", 6);
			MP_bus_info(&bus);

			construct_default_ioirq_mptable(0);
		}
		if (mp_iolinks_num <= 0)
			MP_construct_default_iolinks();
	} else
		BUG();

	printk("Processors: %d\n", mp_num_processors);
	/*
	 * Only use the first configuration found.
	 */
}

void __init
find_smp_config(boot_info_t *bblock)
{
	u32 *bp;
	struct intel_mp_floating *mpf;

	mpf_boot_info = bblock;
	mpf = (struct intel_mp_floating *)
			mpc_addr_to_virt(bblock->mp_table_base);

	if (mpf == NULL)
		return;

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
		printk("found SMP MP-table at 0x%p \n", mpf);
		mpf_found = mpf;
	}
}

#define APIC_ADD_MASK 0x000000FFFFFFFFFF /* as physical address */

static void __init print_lintsrc_info(struct mpc_config_lintsrc *m)
{
	l_boot_printk("------- Lintsrc info entry\n");
	l_boot_printk("lintsrc entry: word 1 (32 bit) 0x%x\n", *(int *)m);
	l_boot_printk("lintsrc entry: word 2 (32 bit) 0x%x\n", *(int *)(m + 1));
	l_boot_printk("Lint: type %d, pol %d, trig %d, bus %d,"
		" IRQ %02x,\n\t\t\t APIC ID %x, APIC LINT %02x\n",
		m->mpc_irqtype, m->mpc_irqflag & 3,
		(m->mpc_irqflag >> 2) &3, m->mpc_srcbusid,
		m->mpc_srcbusirq, m->mpc_destapic, m->mpc_destapiclint);
}

static void __init print_intsrc_info(struct mpc_intsrc *m)
{
	l_boot_printk("------- Intsrc info entry\n");
	l_boot_printk("intsrc entry: word 1 (32 bit) 0x%x\n", *(int *)m);
	l_boot_printk("intsrc entry: word 2 (32 bit) 0x%x\n", *(int *)(m + 1));
	
	l_boot_printk("Int: type %d, pol %d, trig %d, bus %d,"
		" IRQ %02x,\n\t\t\t APIC ID %x, APIC INT %02x\n",
			m->irqtype, m->irqflag & 3,
			(m->irqflag >> 2) & 3, m->srcbus,
			m->srcbusirq, m->dstapic, m->dstirq);
}

static void print_iolink_info(struct mpc_config_iolink *m)
{
	l_boot_printk("------- I/O link entry\n");
	l_boot_printk("io apic entry: word 1 (32 bit) 0x%x\n", *(int *)m);
	l_boot_printk("io apic entry: word 2 (32 bit) 0x%x\n", *(int *)(m + 1));
	l_boot_printk("io apic entry: word 3 (32 bit) 0x%x\n", *(int *)(m + 2));
	l_boot_printk("io apic entry: word 4 (32 bit) 0x%x\n", *(int *)(m + 3));
	l_boot_printk("io apic entry: word 5 (32 bit) 0x%x\n", *(int *)(m + 4));
	l_boot_printk("io apic entry: word 6 (32 bit) 0x%x\n", *(int *)(m + 5));

	l_boot_printk("IO link #%d on node %d, version 0x%02x,",
		m->link, m->node, m->mpc_iolink_ver);
	if (m->mpc_iolink_type == MP_IOLINK_IOHUB) {
		l_boot_printk(" connected to IOHUB: min bus #%d max bus #%d "
			"IO APIC ID %d\n",
			m->bus_min, m->bus_max, m->apicid);
	} else {
		l_boot_printk(" is RDMA controller\n");
	}
}

static void __init print_ioapic_info(struct mpc_ioapic *m)
{
	l_boot_printk("------- I/O apic entry\n");
	l_boot_printk("io apic entry: word 1 (32 bit) 0x%x\n", *(int *)m);
	l_boot_printk("io apic entry: word 2 (32 bit) 0x%x\n", *(int *)(m + 1));
	
	if (!(m->flags & MPC_APIC_USABLE)) {
		l_boot_printk("i/o apic is unusable\n");
		return;
	}
	l_boot_printk("I/O APIC ID #%d Version %d at 0x%x.\n", m->apicid,
			m->apicver, m->apicaddr & APIC_ADD_MASK);
}

static void __init
print_timer_info(mpc_config_timer_t *m)
{

	l_boot_printk("------- System timer entry\n");
	l_boot_printk("timer type %d Version %d at 0x%lX.\n",
		m->mpc_timertype, m->mpc_timerver, m->mpc_timeraddr);
}

static void __init
print_i2c_spi_info(struct mpc_config_i2c *m){
	l_boot_printk("------- i2c/spi controller\n");
	l_boot_printk("device %d revision %02x control base addr = 0x%lx, "
		"data base addr = 0x%lx, IRQ = %d\n",
		m->mpc_max_channel, m->mpc_revision,
		m->mpc_i2ccntrladdr, m->mpc_i2cdataaddr,
		m->mpc_i2c_irq);
}

static void __init print_bus_info(struct mpc_config_bus *m)
{
	char str[7];

	l_boot_printk("------- Bus entry\n");
	memcpy(str, m->mpc_bustype, 6);

	l_boot_printk("bus entry: word 1 (32 bit) 0x%x\n", *(int *)m);
	l_boot_printk("bus entry: word 2 (32 bit) 0x%x\n", *(int *)(m + 1));
	l_boot_printk("Bus #%d is %s\n", m->mpc_busid, str);

}

static void __init print_processor_info(struct mpc_config_processor *m)
{
	l_boot_printk("------- Processor entry\n");
	l_boot_printk("processor entry: word 1 (32 bit) 0x%x\n", *(int *)m);
	l_boot_printk("processor entry: word 2 (32 bit) 0x%x\n",
							m->mpc_cpufeature);
	l_boot_printk("processor entry: word 3 (32 bit) 0x%x\n",
							m->mpc_featureflag);
	
	l_boot_printk("Proc: lapic id %d, lapic version %d,\n" 
	"\t cpuflags(bit 1 - cpu enable, bit 2 - bootstrap) 0x%x\n"
	"\t\t signature 0x%x flags 0x%x\n", m->mpc_apicid, m->mpc_apicver,
		m->mpc_cpuflag & 0x3, m->mpc_cpufeature, m->mpc_featureflag);
}

static void __init print_entries(char type, char *mpt)
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
		l_boot_printk("print_entries() invalid MP table entry type "
			"%d\n", type);
	}
}

static void __init print_mptable(struct intel_mp_floating *mpf)
{
	char str[16];
	struct mpc_table *mpc = (struct mpc_table *)
					mpc_addr_to_phys(mpf->mpf_physptr);
	int count = MP_SIZE_ALIGN(sizeof(*mpc));
	unsigned char *mpt = MP_ADDR_ALIGN(((unsigned char *)mpc) + count);
	
	l_boot_printk("\n\nMP CONFIGURATION TABLE HEADER:\n\n");
	l_boot_printk("mpf->mpf_feature1 = %d\n", mpf->mpf_feature1);

	if (mpf->mpf_feature1 != 0) {
		l_boot_printk(".......construct_default_ISA_mptable\n");
		return;
	}
	
	if (!mpf->mpf_physptr) {
		l_boot_printk("null mptable address pointer\n");
		return;
	}
	
	l_boot_printk("SMP mptable: signature [%c%c%c%c]!\n",
				mpc->mpc_signature[0],
				mpc->mpc_signature[1],
				mpc->mpc_signature[2],
				mpc->mpc_signature[3]);

	l_boot_printk("SMP mptable: mpc->mpc_length %d\n", mpc->mpc_length);
	if (mpf_checksum((unsigned char *)mpc,mpc->mpc_length))
	{
		l_boot_printk("SMP mptable: checksum error!\n");
		return;
	}
	if (mpc->mpc_spec!=0x01 && mpc->mpc_spec!=0x04 && mpc->mpc_spec!=0x08)
	{
		l_boot_printk("Bad Config Table version (%d)!!\n",mpc->mpc_spec);
		return;
	}
	memcpy(str,mpc->mpc_oem,8);
	str[8]=0;
	l_boot_printk("OEM ID: %s\n",str);

	memcpy(str,mpc->mpc_productid,12);
	str[12]=0;
	l_boot_printk("Product ID: %s\n",str);

	l_boot_printk("APIC at: 0x%lx\n", mpc->mpc_lapic & APIC_ADD_MASK);

	l_boot_printk("\n\nMP TABLE CONFIGURATION ENTRIES:\n\n");

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
			l_boot_printk("unrecognized entry: %c ", *mpt);
			mpt += 8; count += 8;
		}
	}
	return;

}

void __init print_floating_point(struct intel_mp_floating *mpf)
{
	u32 *bp;
	
	bp = (u32 *)mpf;
	
	l_boot_printk("\n\nFLOATING POINT STRUCTURE:\n\n");
	l_boot_printk("floating point: word 1 (32 bit) 0x%08x\n", *bp);
	l_boot_printk("floating point: word 2 (32 bit) 0x%08x\n", *(bp+1));
	l_boot_printk("floating point: word 3 (32 bit) 0x%08x\n", *(bp+2));
	l_boot_printk("floating point: word 4 (32 bit) 0x%08x\n\n", *(bp+3));
	
	l_boot_printk("mpf->mpf_signature = [%c%c%c%c]\n",
			mpf->mpf_signature[0], mpf->mpf_signature[1],
			mpf->mpf_signature[2], mpf->mpf_signature[3]);
	l_boot_printk("mpf->mpf_signature = 0x%x SMP_MAGIC_IDENT = 0x%x\n",
		*bp, SMP_MAGIC_IDENT);
	l_boot_printk("mpf->mpf_length = %d should be 1\n",
		mpf->mpf_length);
	l_boot_printk("mpf->mpf_checksum = 0x%x check sum() = 0x%x\n",
		mpf->mpf_checksum,
		mpf_checksum((unsigned char *)bp, sizeof(*mpf)));
	l_boot_printk("mpf->mpf_specification = %d should be 1/4 or 8\n",
		mpf->mpf_specification);
	
	if ((*bp == SMP_MAGIC_IDENT) &&
		(mpf->mpf_length == 1) &&
		!mpf_checksum((unsigned char *)bp, sizeof(*mpf)) &&
		((mpf->mpf_specification == 1) ||
			(mpf->mpf_specification == 4) ||
			(mpf->mpf_specification == 8)) ) {
		l_boot_printk("found floating pointer structure at 0x%lx\n",
			mpf);
		print_mptable(mpf);
	} else {
		l_boot_printk("error floating pointer structur at 0x%lx\n",
			mpf);
		
	}
}

void __init print_boot_info(boot_info_t *boot_info)
{
	int node;
	int bank;
	int total_banks = 0;

	l_boot_printk("signature 0x%x\n", boot_info->signature);
	l_boot_printk("cylinders %d\n", boot_info->cylinders);
	l_boot_printk("heads %d\n", boot_info->heads);
	l_boot_printk("sectors %d\n", boot_info->sectors);
	l_boot_printk("vga_mode %d\n", boot_info->vga_mode);
	l_boot_printk("num_of_banks %d\n", boot_info->num_of_banks);
	l_boot_printk("num_of_busy areas %d\n", boot_info->num_of_busy);
	l_boot_printk("kernel_base 0x%lx\n", boot_info->kernel_base);
	l_boot_printk("kernel_size 0x%lx\n", boot_info->kernel_size);
	
	l_boot_printk("ramdisk_base 0x%lx\n", boot_info->ramdisk_base);
	l_boot_printk("ramdisk_size 0x%lx\n", boot_info->ramdisk_size);
	l_boot_printk("num_of_cpus %d\n", boot_info->num_of_cpus);
	l_boot_printk("machine flags 0x%04x\n", boot_info->mach_flags);
	l_boot_printk("mp_table_base 0x%lx\n", boot_info->mp_table_base);
	l_boot_printk("serial base 0x%x\n", boot_info->serial_base);

	if (!strncmp(boot_info->kernel_args_string,
			KERNEL_ARGS_STRING_EX_SIGNATURE,
			KERNEL_ARGS_STRING_EX_SIGN_SIZE))
		l_boot_printk("kernel string %s\n",
			boot_info->bios.kernel_args_string_ex);
	else
		l_boot_printk("kernel string %s\n",
			boot_info->kernel_args_string);

	l_boot_printk("mach_serialn 0x%lx\n", boot_info->mach_serialn);
	l_boot_printk("kernel_csum 0x%lx\n", boot_info->kernel_csum);
	
	l_boot_printk("num_of_nodes %d\n", boot_info->num_of_nodes);
	l_boot_printk("nodes_map %d\n", boot_info->nodes_map);

	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		bank_info_t *cur_bank;

		cur_bank = boot_info->nodes_mem[node].banks;
		if (cur_bank->size == 0) {
			if (boot_info->nodes_map & (1 << node)) {
				l_boot_printk("Node #%d has not physical "
					"memory\n", node);
			} else {
				l_boot_printk("Node #%d is not online\n", node);
			}
			continue;	/* node has not memory */
		} else if (!(boot_info->nodes_map & (1 << node))) {
			l_boot_printk("BUG : Node #%d is not online, but has "
				"physical memory\n", node);
		}

		l_boot_printk("Node #%d physical memory banks: ", node);
		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
			if (cur_bank->size) {
				l_boot_printk("     [%d] : address 0x%x, "
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
		l_boot_printk("BUG : boot_info->num_of_banks %d != "
			"number of banks at boot_info->nodes_mem %d\n",
			boot_info->num_of_banks, total_banks);
	}
	for (bank = 0; bank < boot_info->num_of_busy; bank ++) {
		l_boot_printk("boot_info->busy[%d].address 0x%x\n",
				bank, boot_info->busy[bank].address);
		l_boot_printk("boot_info->busy[%d].size 0x%x\n",
				bank, boot_info->busy[bank].size);
	}

	if (boot_info->mp_table_base)
		print_floating_point((struct intel_mp_floating *)
				mpc_addr_to_phys(boot_info->mp_table_base));
	else
		l_boot_printk("null mp floating structure pointer\n");	
}

void __init
print_bootblock(bootblock_struct_t *bootblock)
{
	boot_info_t *boot_info = &bootblock->info;

	l_boot_printk("BOOT_INFO *******************************************:\n");
	print_boot_info(boot_info);
	l_boot_printk("BOOT_INFO *******************************************:\n");
}
