/*
 * $Id: mpspec.c,v 1.8 2009/02/24 15:13:21 atic Exp $
 * From linuxbios.org
 */

#include <linux/threads.h>
#include <linux/cpumask.h>

#include <asm/mpspec.h>
#include <asm/apic.h>
#include "pci.h"

#undef BIOS_DEBUG
#define MPSPEC_DEBUG 0
#define BIOS_DEBUG MPSPEC_DEBUG

#define	CONFIG_DEBUG_MPTABLE	0

#include "printk.h"

unsigned char smp_compute_checksum(void *v, int len)
{
	unsigned char *bytes;
	unsigned char checksum;
	int i;
	bytes = v;
	checksum = 0;
	for(i = 0; i < len; i++) {
		checksum -= bytes[i];
	}
	return checksum;
}

static int
mpf_do_checksum(unsigned char *mp, int len)
{
	int sum = 0;

	while (len--)
		sum += *mp++;

	return 0x100 - (sum & 0xFF);
}

void smp_write_floating_table(struct intel_mp_floating *mpf)
{
	mpf->mpf_signature[0] = '_';
	mpf->mpf_signature[1] = 'M';
	mpf->mpf_signature[2] = 'P';
	mpf->mpf_signature[3] = '_';
	mpf->mpf_physptr = (unsigned long)(((char *)mpf) + SMP_FLOATING_TABLE_LEN);
	mpf->mpf_length = 1;
	mpf->mpf_specification = 4;
	mpf->mpf_checksum = 0;
	mpf->mpf_feature1 = 0;
	mpf->mpf_feature2 = 0;
	mpf->mpf_feature3 = 0;
	mpf->mpf_feature4 = 0;
	mpf->mpf_feature5 = 0;
///	mpf->mpf_checksum = smp_compute_checksum(mpf, mpf->mpf_length*16);
	mpf->mpf_checksum = mpf_do_checksum((unsigned char *)mpf, sizeof (*mpf));
}

void *smp_next_mpc_entry(struct mpc_table *mc)
{
	void *v;
	v = (void *)(((char *)mc) + mc->mpc_length);
	return v;
}
static void smp_add_mpc_entry(struct mpc_table *mc, unsigned length)
{
	mc->mpc_length += length;
	mc->mpc_oemcount++;
}

void *smp_next_mpe_entry(struct mpc_table *mc)
{
	void *v;
	v = (void *)(((char *)mc) + mc->mpc_length + mc->mpe_length);
	return v;
}
static void smp_add_mpe_entry(struct mpc_table *mc, mpe_t mpe)
{
	mc->mpe_length += mpe->mpe_length;
}

void smp_write_processor(struct mpc_table *mc,
	unsigned char apicid, unsigned char apicver,
	unsigned char cpuflag, unsigned int cpufeature,
	unsigned int featureflag)
{
	struct mpc_config_processor *mpc;
	mpc = smp_next_mpc_entry(mc);
	memset(mpc, '\0', sizeof(*mpc));
	mpc->mpc_type = MP_PROCESSOR;
	mpc->mpc_apicid = apicid;
	mpc->mpc_apicver = apicver;
	mpc->mpc_cpuflag = cpuflag;
	mpc->mpc_cpufeature = cpufeature;
	mpc->mpc_featureflag = featureflag;
	smp_add_mpc_entry(mc, sizeof(*mpc));
}

#ifdef	CONFIG_SMP
extern unsigned int all_apic_ids[NR_CPUS];
#endif	/* CONFIG_SMP */

//unsigned int initial_apicid[MAX_CPUS] =
//{
//	0, 1, [2 ... MAX_CPUS - 1] = -1
//};

/* If we assume a symmetric processor configuration we can
 * get all of the information we need to write the processor
 * entry from the bootstrap processor.
 * Plus I don't think linux really even cares.
 * Having the proper apicid's in the table so the non-bootstrap
 *  processors can be woken up should be enough.
 */
void smp_write_processors(struct mpc_table *mc, 
			unsigned int phys_cpu_num)
{
	int i;
	int processor_id;
	unsigned apic_version;
	unsigned cpu_flags;
	unsigned cpu_features;
	unsigned cpu_feature_flags;
	processor_id = arch_apic_read(APIC_ID) >> 24;
	apic_version = arch_apic_read(APIC_LVR) & 0xff;
	cpu_features = 0x0f;
	cpu_feature_flags = 1 << 9;
	for(i = 0; i < NR_CPUS; i++) {
#ifdef	CONFIG_SMP
		unsigned int cpu_apicid = all_apic_ids[i];
#else	/* ! CONFIG_SMP */
		unsigned int cpu_apicid = processor_id;
#endif	/* CONFIG_SMP */
///		if(initial_apicid[i]==-1)
///			continue;
		if((i+1) > phys_cpu_num)
			continue;
#ifdef	CONFIG_SMP
		if (processor_id == all_apic_ids[i])
#endif	/* CONFIG_SMP */
			cpu_flags = CPU_BOOTPROCESSOR | CPU_ENABLED;
#ifdef	CONFIG_SMP
		else
			cpu_flags = CPU_ENABLED;
#endif	/* CONFIG_SMP */
		smp_write_processor(mc, cpu_apicid, apic_version,
			cpu_flags,
			cpu_features, cpu_feature_flags
		);
	
	}
}

void smp_write_bus(struct mpc_table *mc,
	unsigned char id, unsigned char *bustype)
{
	struct mpc_config_bus *mpc;
	mpc = smp_next_mpc_entry(mc);
	memset(mpc, '\0', sizeof(*mpc));
	mpc->mpc_type = MP_BUS;
	mpc->mpc_busid = id;
	memcpy(mpc->mpc_bustype, bustype, sizeof(mpc->mpc_bustype));
	smp_add_mpc_entry(mc, sizeof(*mpc));
}

void smp_write_ioapic(struct mpc_table *mc,
	unsigned char id, unsigned char ver, 
	unsigned long apicaddr)
{
	struct mpc_ioapic *mpc;
	mpc = smp_next_mpc_entry(mc);
	memset(mpc, '\0', sizeof(*mpc));
	mpc->type = MP_IOAPIC;
	mpc->apicid = id;
	mpc->apicver = ver;
	mpc->flags = MPC_APIC_USABLE;
	mpc->apicaddr = apicaddr;
	smp_add_mpc_entry(mc, sizeof(*mpc));
}

void smp_write_intsrc(struct mpc_table *mc,
	unsigned char irqtype, unsigned short irqflag,
	unsigned char srcbus, unsigned char srcbusirq,
	unsigned char dstapic, unsigned char dstirq)
{
	struct mpc_intsrc *mpc;
	mpc = smp_next_mpc_entry(mc);
	memset(mpc, '\0', sizeof(*mpc));
	mpc->type = MP_INTSRC;
	mpc->irqtype = irqtype;
	mpc->irqflag = irqflag;
	mpc->srcbus = srcbus;
	mpc->srcbusirq = srcbusirq;
	mpc->dstapic = dstapic;
	mpc->dstirq = dstirq;
	smp_add_mpc_entry(mc, sizeof(*mpc));
#if CONFIG_DEBUG_MPTABLE
	printk_info("add intsrc srcbus 0x%x srcbusirq 0x%x, dstapic 0x%x, dstirq 0x%x\n",
				srcbus, srcbusirq, dstapic, dstirq);
	hexdump(__FUNCTION__, mpc, sizeof(*mpc));
#endif
}

void smp_i2c_spi_timer(struct mpc_table *mc,
			unsigned char timertype, unsigned char timerver,
			unsigned char timerflags, unsigned long timeraddr)
{
	struct mpc_config_timer *mpc;
	mpc = smp_next_mpc_entry(mc);
	memset(mpc, '\0', sizeof(*mpc));
	mpc->mpc_type = MP_TIMER;
	mpc->mpc_timertype = timertype;
	mpc->mpc_timerver = timerver;
	mpc->mpc_timerflags = timerflags;
	mpc->mpc_timeraddr = timeraddr;
	smp_add_mpc_entry(mc, sizeof(*mpc));
}

void smp_i2c_spi_dev(struct mpc_table *mc, unsigned char max_channel, 
			unsigned char irq, unsigned long pcidevaddr)
{
	struct mpc_config_i2c *mpc;
	mpc = smp_next_mpc_entry(mc);
	memset(mpc, '\0', sizeof(*mpc));
	mpc->mpc_type = MP_I2C_SPI;
	mpc->mpc_i2ccntrladdr =
		((struct bios_pci_dev *)pcidevaddr)->base_address[0];
	mpc->mpc_i2cdataaddr =
		((struct bios_pci_dev *)pcidevaddr)->base_address[1];
	mpc->mpc_max_channel = max_channel;
	mpc->mpc_i2c_irq = irq;
#if CONFIG_DEBUG_MPTABLE
	rom_printk("add i2c/spi dev addr to mptable, "
		   " base[0] = 0x%x, base[1] = 0x%x. IRQ %d\n",
		((struct bios_pci_dev *)pcidevaddr)->base_address[0],
		((struct bios_pci_dev *)pcidevaddr)->base_address[1],
		irq);
#endif
	smp_add_mpc_entry(mc, sizeof(*mpc));
}

void smp_write_lintsrc(struct mpc_table *mc,
	unsigned char irqtype, unsigned short irqflag,
	unsigned char srcbusid, unsigned char srcbusirq,
	unsigned char destapic, unsigned char destapiclint)
{
	struct mpc_config_lintsrc *mpc;
	mpc = smp_next_mpc_entry(mc);
	memset(mpc, '\0', sizeof(*mpc));
	mpc->mpc_type = MP_LINTSRC;
	mpc->mpc_irqtype = irqtype;
	mpc->mpc_irqflag = irqflag;
	mpc->mpc_srcbusid = srcbusid;
	mpc->mpc_srcbusirq = srcbusirq;
	mpc->mpc_destapic = destapic;
	mpc->mpc_destapiclint = destapiclint;
	smp_add_mpc_entry(mc, sizeof(*mpc));
}

void smp_write_address_space(struct mpc_table *mc,
	unsigned char busid, unsigned char address_type,
	unsigned int address_base_low, unsigned int address_base_high,
	unsigned int address_length_low, unsigned int address_length_high)
{
	struct mp_exten_system_address_space *mpe;
	mpe = smp_next_mpe_entry(mc);
	memset(mpe, '\0', sizeof(*mpe));
	mpe->mpe_type = MPE_SYSTEM_ADDRESS_SPACE;
	mpe->mpe_length = sizeof(*mpe);
	mpe->mpe_busid = busid;
	mpe->mpe_address_type = address_type;
	mpe->mpe_address_base_low  = address_base_low;
	mpe->mpe_address_base_high = address_base_high;
	mpe->mpe_address_length_low  = address_length_low;
	mpe->mpe_address_length_high = address_length_high;
	smp_add_mpe_entry(mc, (mpe_t)mpe);
}


void smp_write_bus_hierarchy(struct mpc_table *mc,
	unsigned char busid, unsigned char bus_info,
	unsigned char parent_busid)
{
	struct mp_exten_bus_hierarchy *mpe;
	mpe = smp_next_mpe_entry(mc);
	memset(mpe, '\0', sizeof(*mpe));
	mpe->mpe_type = MPE_BUS_HIERARCHY;
	mpe->mpe_length = sizeof(*mpe);
	mpe->mpe_busid = busid;
	mpe->mpe_bus_info = bus_info;
	mpe->mpe_parent_busid = parent_busid;
	smp_add_mpe_entry(mc, (mpe_t)mpe);
}

void smp_write_compatibility_address_space(struct mpc_table *mc,
	unsigned char busid, unsigned char address_modifier,
	unsigned int range_list)
{
	struct mp_exten_compatibility_address_space *mpe;
	mpe = smp_next_mpe_entry(mc);
	memset(mpe, '\0', sizeof(*mpe));
	mpe->mpe_type = MPE_COMPATIBILITY_ADDRESS_SPACE;
	mpe->mpe_length = sizeof(*mpe);
	mpe->mpe_busid = busid;
	mpe->mpe_address_modifier = address_modifier;
	mpe->mpe_range_list = range_list;
	smp_add_mpe_entry(mc, (mpe_t)mpe);
}

#if 0 
/* memcpy standard block */
const static char smpblock[] =
{0x5F, 0x4D, 0x50, 0x5F, 0x00, 0x00, 0x00,
 0x00, 0x01, 0x04, 0x9B, 0x05, 0x00, 0x00, 0x00, 0x00
};
void write_smp_table(void *v)
{
	memcpy(v, smpblock, sizeof(smpblock));
}
#endif /* 0 */

