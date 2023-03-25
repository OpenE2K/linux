
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <asm/sbus.h> 
#include <asm-l/tree_entry.h>


#undef DEBUG
#define DEBUG
#undef DEBUG

#ifdef DEBUG
#define  dbg(fmt, args...)      printk( fmt "\n", ## args)
#else
#define  dbg(fmt, args...)
#endif
#define  info(fmt, args...)     printk(KERN_ALERT fmt "\n", ## args)


#ifdef CONFIG_E90
extern void * prom_early_alloc(unsigned long size);
#define kmalloc(sz, how) prom_early_alloc(sz)
#endif


#define SBUS_BRIDGE1_STEP       0x01000000
#define SBUS_BRIDGE0_SLOT_NUM 4
#define SBUS_BRIDGE1_SLOT_NUM 7
#define SBUS_BRIDGE2_SLOT_NUM 7

#define MAX_DEVICES	256
static struct tree_entry  *te_table[MAX_DEVICES];
static int last_used_node = 0;

static int assign_node(struct tree_entry *te)
{
	last_used_node++;
	if (last_used_node >= MAX_DEVICES) {
		return -ENOMEM;
	}
	dbg("assign node %d to te %p  %s",
		last_used_node, te, (char *)te->prop[ATTRIB_NAME].value);
	te_table[last_used_node] = te;
	te->node = last_used_node;
	return last_used_node;
}

struct tree_entry *get_te_by_node(int node)
{
	if (node < 0 || node >= MAX_DEVICES) {
		return NULL;
	}
	if (te_table[node] == NULL) {
		panic("get_te_by_node: no tree_entry for node %d. last used node = %d\n",
				node, last_used_node);
	} 
	return te_table[node];
}
EXPORT_SYMBOL(get_te_by_node);

static void assign_tree(struct tree_entry *te)
{
        while (te) {
                assign_node(te);
                assign_tree(te->child);
                te = te->sibling;
        }
}


void init_known_nodes(struct tree_entry *te)
{
	if (last_used_node == 0) {
		assign_tree(te);
	}
}
EXPORT_SYMBOL(init_known_nodes);

static struct linux_prom_registers bridge_reg[] = {
	{0, 0, 0x40000},
};
static unsigned long bridge_intr[] = { 5 };

static struct linux_prom_registers mmr_reg[] = {
	{0, 0x10000, 0x00000100},
	{0, 0x40000, 0x00020000}
};
static u32 mmr_interrupts[] = { 4 };
static u32 mmr_intr[] = { 0x37, 0 };

static struct linux_prom_registers mop_reg[] = {
	{0, 0x00000000, 0x00010000},
	{0, 0x00010000, 0x00000100},
	{0, 0x00040000, 0x00010000}
};
static u32 mop_interrupts[] = { 0x03, 0x07 };
static u32 mop_intr[] = { 0x00000035, 0x0000003d };


static struct linux_prom_registers mbk3_reg[] = {
	{0, 0x10000, 0x00000080},
};
static u32 mbk3_interrupts[] = { 0x03 };
static u32 mbk3_slave_burst_sizes[] = { 0x20 };


static struct linux_prom_registers mbkp1_reg[] = {
	{0, 0x00010000, 0x00000090},
	{0, 0, 0x00000100}
};
static u32 mbkp1_interrupts[] = { 0x03 };
static u32 mbkp1_intr[] = { 0x00000035, 0 };


/// MVP fcode properties
static struct linux_prom_registers mvp_reg[] = {
	{0, 0x00010000, 0x00000080},
};
static u32 mvp_interrupts[] = { 0x3 };

/// MPV fcode properties
/*
ok cd /iommu/sbus/MCST,mpv
<#0> ok .attributes
intr                    00000032  00000033
			00000035  00000037
			00000039  0000003b
			0000003d  00000000
interrupts              00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04
reg                     00000001  00010000  000000dc
name                    MCST,mpv
*/
static struct linux_prom_registers mpv_reg[] = {
	{1, 0x00010000, 0x000000dc}, }; /* which_io, phys_addr, reg_size */
static u32 mpv_interrupts[] = { 0x1, 0x2, 0x3, 0x4 };
static u32 mpv_intr[] = { /* pri, vector_unused */
			0x00000032, 0, 0x00000033, 0,
			0x00000035, 0, 0x00000037, 0,
			0x00000039, 0, 0x0000003b, 0,
			0x0000003d, 0 };

/// MPK
static struct linux_prom_registers mpk_reg[] = {
	{0x00000000, 0x00040000, 0x00000020},
	{0x00000000, 0x00050000, 0x00000100},
};

static u32 mpk_interrupts[] = { 0x3 };
#if 0
static u32 mpk_intr[] = { 0x00000035, 0x00000000 };
#endif

static struct linux_prom_registers mbkp2_reg[] = {
	{0, 0x00010000, 0x00000090},
	{0, 0x00000000, 0x00000100}
};
static u32 mbkp2_interrupts[] = { 0x003 };
static u32 mbkp2_intr[] = { 0x00000035, 0x000000 };

static struct linux_prom_registers mcap_reg[] = {
	{0, 0x00010000, 0x00000024},
	{0, 0x00040000, 0x00020000}
};
static u32 mcap_interrupts[] = { 0x003 };
static u32 mcap_intr[] = { 0x00000035, 0x0000000 };

static struct linux_prom_registers mckk_reg[] = {
	{0, 0x00010000, 0x00000024},
	{0, 0x00040000, 0x00020000}
};
static u32 mckk_interrupts[] = { 0x001 };
static u32 mckk_intr[] = { 0x00000032, 0x000000 };


static struct linux_prom_registers mcka_reg[] = {
	{0, 0x00010000, 0x00000024},
	{0, 0x00040000, 0x00020000}
};
static u32 mcka_interrupts[] = { 0x003 };
static u32 mcka_intr[] = { 0x00000035, 0x000000 };

static struct linux_prom_registers mcpm_reg[] = {
	{0, 0x00010000, 0x00000024},
	{0, 0x00040000, 0x00020000}
};

static struct linux_prom_registers mppk_reg[] = {
	{0, 0x00040000, 0x00000020},
	{0, 0x00480000, 0x00000020}
};
static u32 mppk_interrupts[] = { 0x03, 0x02 };
static u32 mppk_intr[] =
    { 0x00000035, 0x000000, 0x00000033, 0x00000000 };

static u32 mcpm_interrupts[] = { 0x004 };
static u32 mcpm_intr[] = { 0x00000037, 0x000000 };

static struct linux_prom_registers mzs8_reg[] = {
	{0, 0x00040000, 0x00000020}
};
static u32 mzs8_interrupts[] = { 0x003 };
static u32 mzs8_intr[] = { 0x00000035, 0x000000 };

static struct linux_prom_registers mpp_reg[] = {
	{0, 0x00480000, 0x00000020}
};
static u32 mpp_interrupts[] = { 0x002 };
static u32 mpp_intr[] = { 0x00000033, 0x000000 };

static struct linux_prom_registers spif_reg[] = {
	{0, 0x00000000, 0x00001000},
};
static u32 spif_intr[] =
    { 0x0000003d, 0x000000, 0x00000037, 0x00000000 };
static u32 spif_verosc[] = { 0x00000001 };
static u32 spif_revlev[] = { 0x00000005 };

/*
MFE attributes:
<#0> ok cd /iommu/sbus/ledma@1,430010/le
<#0> ok .attributes
intr                     00000035  00000000
interrupts               00000003
local-mac-address        08 00 20 00 01 13
reg                      00000001  00c30000  00000004
name                     le
*/
static u32 mfe_le_intr[] = { 0x0000035, 0x0000000 };
static unsigned char mfe_le_local_mac_address[] =
    { 0x08, 0x00, 0x20, 0x00, 0x01, 0x10 };
static u32 mfe_le_interrupts[] = { 0x0000003 };
static struct linux_prom_registers mfe_le_reg[] = {
	{0x00000000, 0x00c00000, 0x00000004},
};

static struct tree_entry mfe_le = {
	.prop = {
		 {"name", "le", sizeof("le")}
		 ,
		 {"intr", mfe_le_intr, sizeof(mfe_le_intr)}
		 ,
		 {"interrupts", mfe_le_interrupts,
		  sizeof(mfe_le_interrupts)}
		 ,
		 {"reg", mfe_le_reg, sizeof(mfe_le_reg)}
		 ,
		 {"local-mac-address", mfe_le_local_mac_address,
		  sizeof(mfe_le_local_mac_address)}
		 ,
		 }
	,
};

static struct linux_prom_registers mfe_reg[] = {
	{0, 0x00400010, 0x00000020}
};

static struct linux_prom_registers mga_reg[] = {
	{0, 0x00000000, 0x00008000},
	{0, 0x00400000, 0x00002000},
	{0, 0x00600000, 0x00001000},
	{0, 0x00800000, 0x00800000},
};

static struct tree_entry mppk = {
	.prop = {
		 {"name", "MCST,mppk", sizeof("MCST,mppk")}
		 ,
		 {"intr", mppk_intr, sizeof(mppk_intr)}
		 ,
		 {"interrupts", mppk_interrupts, sizeof(mppk_interrupts)}
		 ,
		 {"reg", mppk_reg, sizeof(mppk_reg)}
		 ,
		 }
	,
};
static struct tree_entry mzs8 = {
	.prop = {
		 {"name", "MCST,mzs8", sizeof("MCST,mzs8")}
		 ,
		 {"intr", mzs8_intr, sizeof(mzs8_intr)}
		 ,
		 {"interrupts", mzs8_interrupts, sizeof(mzs8_interrupts)}
		 ,
		 {"reg", mzs8_reg, sizeof(mzs8_reg)}
		 ,
		 }
	,
};

static struct linux_prom_registers cgsix_reg[] = {
        {0x00000000, 0x0, 0x01000000},
};
static unsigned long cgsix_intr[] = { 0x00000039, 0 };


static struct tree_entry known_sbus_dev[] = {
	{
	 .prop = {
		  {"name", "cgsix", sizeof("cgsix")}
		  ,
		  {"intr", cgsix_intr, sizeof(cgsix_intr)}
		  ,
		  {"reg", cgsix_reg, sizeof(cgsix_reg)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "bridge", sizeof("bridge")}
		  ,
		  {"interrupts", bridge_intr, sizeof(bridge_intr)}
		  ,
		  {"reg", bridge_reg, sizeof(bridge_reg)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mmr", sizeof("mmr")}
		  ,
		  {"intr", mmr_intr, sizeof(mmr_intr)}
		  ,
		  {"interrupts", mmr_interrupts, sizeof(mmr_interrupts)}
		  ,
		  {"reg", mmr_reg, sizeof(mmr_reg)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mop", sizeof("mop")}
		  ,
		  {"intr", mop_intr, sizeof(mop_intr)}
		  ,
		  {"interrupts", mop_interrupts, sizeof(mop_interrupts)}
		  ,
		  {"reg", mop_reg, sizeof(mop_reg)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mbk3", sizeof("mbk3")}
		  ,
		  {"interrupts", mbk3_interrupts, sizeof(mbk3_interrupts)}
		  ,
		  {"reg", mbk3_reg, sizeof(mbk3_reg)}
		  ,
		  {"slave-burst-sizes", mbk3_slave_burst_sizes,
		   sizeof(mbk3_slave_burst_sizes)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mbkp1", sizeof("mbkp1")}
		  ,
		  {"intr", mbkp1_intr, sizeof(mbkp1_intr)}
		  ,
		  {"interrupts", mbkp1_interrupts, sizeof(mbkp1_interrupts)}
		  ,
		  {"reg", mbkp1_reg, sizeof(mbkp1_reg)}
		  ,
		  {"alias", "mbkp1", sizeof("mbkp1")}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mvp", sizeof("mvp")}
		  ,
		  {"interrupts", mvp_interrupts, sizeof(mvp_interrupts)}
		  ,
		  {"reg", mvp_reg, sizeof(mvp_reg)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mpv", sizeof("mpv")}
		  ,
		  {"interrupts", mpv_interrupts, sizeof(mpv_interrupts)}
		  ,
		  {"intr", mpv_intr, sizeof(mpv_intr)}
		  ,
		  {"reg", mpv_reg, sizeof(mpv_reg)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mpk", sizeof("mpk")}
		  ,
		  {"interrupts", mpk_interrupts, sizeof(mpk_interrupts)}
		  ,
#if 0
		  {"intr", mpk_intr, sizeof(mpk_intr)}
		  ,
#endif
		  {"reg", mpk_reg, sizeof(mpk_reg)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mbkp2", sizeof("mbkp2")}
		  ,
		  {"intr", mbkp2_intr, sizeof(mbkp2_intr)}
		  ,
		  {"interrupts", mbkp2_interrupts, sizeof(mbkp2_interrupts)}
		  ,
		  {"reg", mbkp2_reg, sizeof(mbkp2_reg)}
		  ,
		  {"alias", "mbkp2", sizeof("mbkp2")}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mcap", sizeof("mcap")}
		  ,
		  {"intr", mcap_intr, sizeof(mcap_intr)}
		  ,
		  {"interrupts", mcap_interrupts, sizeof(mcap_interrupts)}
		  ,
		  {"reg", mcap_reg, sizeof(mcap_reg)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mckk", sizeof("mckk")}
		  ,
		  {"intr", mckk_intr, sizeof(mckk_intr)}
		  ,
		  {"interrupts", mckk_interrupts, sizeof(mckk_interrupts)}
		  ,
		  {"reg", mckk_reg, sizeof(mckk_reg)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mcka", sizeof("mcka")}
		  ,
		  {"intr", mcka_intr, sizeof(mcka_intr)}
		  ,
		  {"interrupts", mcka_interrupts, sizeof(mcka_interrupts)}
		  ,
		  {"reg", mcka_reg, sizeof(mcka_reg)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mcpm", sizeof("mcpm")}
		  ,
		  {"intr", mcpm_intr, sizeof(mcpm_intr)}
		  ,
		  {"interrupts", mcpm_interrupts, sizeof(mcpm_interrupts)}
		  ,
		  {"reg", mcpm_reg, sizeof(mcpm_reg)}
		  ,
		  }
	 ,
	 }
	,
	{			/*MCST,mpp2 DOLVNO STOQTX RANX[E MCST,mpp */
	 .prop = {
		  {"name", "mpp2", sizeof("mpp2")}
		  ,
		  {"intr", mpp_intr, sizeof(mpp_intr)}
		  ,
		  {"interrupts", mpp_interrupts, sizeof(mpp_interrupts)}
		  ,
		  {"reg", mpp_reg, sizeof(mpp_reg)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "mpp", sizeof("mpp")}
		  ,
		  {"intr", mpp_intr, sizeof(mpp_intr)}
		  ,
		  {"interrupts", mpp_interrupts, sizeof(mpp_interrupts)}
		  ,
		  {"reg", mpp_reg, sizeof(mpp_reg)}
		  ,
		  }
	 ,
	 }
	,
	{
	 .prop = {
		  {"name", "SUNW,spif", sizeof("SUNW,spif")}
		  ,
		  {"intr", spif_intr, sizeof(spif_intr)}
		  ,
		  {"reg", spif_reg, sizeof(spif_reg)}
		  ,
		  {"verosc", spif_verosc, sizeof(spif_verosc)}
		  ,
		  {"revlev", spif_revlev, sizeof(spif_revlev)}
		  ,
		  }
	 ,

	 }
	,
	{
	 .prop = {
		  {"name", "ledma", sizeof("ledma")}
		  ,
		  {"reg", mfe_reg, sizeof(mfe_reg)}
		  ,
		  }
	 ,
	 .child = &mfe_le,
	 }
	,
	{
	 .prop = {
		  {"name", "mga", sizeof ("mga")},
		  {"reg", mga_reg, sizeof (mga_reg)},
                  {"device_type", "display", sizeof ("display")},
                 },
	 },
	{
	 .prop = {
		  {"name", " MGA/M", sizeof (" MGA/M")},
		  {"reg", mga_reg, sizeof (mga_reg)},
                  {"device_type", "display", sizeof ("display")},
                 },
	 },
};






//Here goes SBUS scanning

#undef  EOF
#define  EOF -1
#define  EOL -2
#define  PARSE_ERR -3
#define  EOT 4

#define FCODE_VERSION1 0xfd
#define FCODE_VERSION2or3 0xf1
    struct fcode_header {
	unsigned char version;	/*0xfd ILI 0xf1 */
	unsigned char reserved[3];	/* reserved bytes */
	unsigned int  length;
};
/**************************************************************
		MEHANIZM SKANIROWANIQ sbus-USTROJSTW.
		
	sNA^ALA W fcode'AH I]UTSQ IMENA Q^EJKEK NAHODQ]IHSQ 
W SPISKE IZWESTNYH. pRI OTSUTSTWII IZWESTNOGO IMENI PROIZWODITSQ
POISK TEKSTOWOJ INFOMACII O Q^EJKE.

	iNFORMACIQ DOLVNA BYTX ZAPISANA W Q^EJKU SRAZU 
POSLE fcode'OW ILI WMESTOW SLEDU@]EM TEKSTOWOM FORMATE:

	kAVDYJ ATRIBUT ZAPISYWAETSQ W STRO^KU, SNA^ALA IDET IMQ,
ZATEM DANNYE; ESLI DANNYE NA^INA@TSQ CIFROJ, TO S^ITAETSQ
^TO DANNYE - ^ISLENNYE, W INOM SLU^AE - SIMWOLXNYE.
~ISLENNYE DANNYE ZAPISYWA@TSQ ^EREZ PROBELY W 16-RI^NOM FORMATE.
kAVDOE ^ISLO POME]AETSQ W 4-RE BAJTA.

kONEC FAJLA - EOT (0x4);
'#' - KOMMENTARIJ;
'\' - SIMWOL IGNORIROWANIQ POSLEDU@]EGO KONCA STROKI;


pRIMER FORMIROWANIQ FAJLA PRO[IWKI:

cat mppk.data >> mppk.fcode
echo -ne "\004" >> mppk.fcode

pRIMER INFORMACIONNOGO FAJLA:

#mppk card

name            MCST,mpp
intr            00000033 000000
interrupts      02
reg             0 00480000 00000020

name            MCST,mzs8 
intr            00000035 000000
interrupts      003
reg             0 00040000 00000020

name            MCST,mppk 
intr            00000035 000000 00000033 00000000
interrupts      03 02
reg             0 00040000 00000020  \
                0 00480000 00000020

*		
******************************************************************************/

struct tree_entry *copy_sbus_dev(struct tree_entry *dev)
{
	struct tree_entry *new
	    = kmalloc(sizeof(struct tree_entry), GFP_KERNEL);
	int i;
	if (!new)
		return NULL;

	memcpy(new, dev, sizeof(struct tree_entry));
	for (i = 0; i < MAX_PROPERTY && dev->prop[i].name; i++) {
		/* FIXME: copy name too? */
		new->prop[i].value =
		    kmalloc(dev->prop[i].size, GFP_KERNEL);
		if (!new->prop[i].value)
			goto err_free_prop;
		memcpy(new->prop[i].value, dev->prop[i].value,
					dev->prop[i].size);
	}

	if (assign_node(new) < 0)
		goto err_free_prop;
	/* Success */
	return new;

err_free_prop:
	while (--i >= 0)
		kfree(new->prop[i].value);
	kfree(new);
	return NULL;
}
EXPORT_SYMBOL(copy_sbus_dev);

/*
 * Simple free and detach dev from te_table[] if it's last_used_node
 */
void free_sbus_dev(struct tree_entry *dev)
{
	int i;
	if (te_table[last_used_node] != dev)
		return;
		
	te_table[last_used_node --] = NULL;

	for (i = 0; i < MAX_PROPERTY && dev->prop[i].value; i++)
		kfree(dev->prop[i].value);
	kfree(dev);
}
EXPORT_SYMBOL(free_sbus_dev);

static struct tree_entry *fix_sbus_dev(struct tree_entry *dev,
				       unsigned long regs_offset, int slot)
{
	int i;
	for (i = 0; i < MAX_PROPERTY && dev->prop[i].name; i++) {
		if (!strcmp(dev->prop[i].name, "reg")) {
			struct linux_prom_registers *regs =
			    dev->prop[i].value;
			int size =
			    dev->prop[i].size /
			    sizeof(struct linux_prom_registers);
			int j;
			for (j = 0; j < size; j++) {
				regs[j].phys_addr += regs_offset;
				regs[j].which_io = slot;
			}
		}
	}
	return dev;
}




static struct tree_entry *new_sbus_dev(struct tree_entry *dev,
				       unsigned long regs_offset, int slot)
{
	struct tree_entry *new = copy_sbus_dev(dev);
	if(new) {
		fix_sbus_dev(new, regs_offset, slot);
	} else {
		dbg("new_sbus_dev could not copy_sbus_dev\n");
	}
	return new;
}



static struct tree_entry *add_sbus_dev(struct tree_entry *bus, struct tree_entry *dev,
			 unsigned long regs_offset, int slot)
{
	struct tree_entry *te = bus;
	for (; te->sibling; te = te->sibling);
	if (!strcmp(dev->prop[ATTRIB_NAME].value, "MCST,mpp2")
	    || !strcmp(dev->prop[ATTRIB_NAME].value, "MCST,mpp")) {
		te->sibling = new_sbus_dev(dev, regs_offset, slot);
		if(te->sibling)
			te = te->sibling;
		te->sibling =
			new_sbus_dev(&mzs8, regs_offset, slot);
		if(te->sibling)
			te = te->sibling;
		te->sibling =
		    new_sbus_dev(&mppk, regs_offset, slot);
		return te->sibling;
	}
	if (!strcmp(dev->prop[ATTRIB_NAME].value, "ledma")) {
		int i, j;
#ifdef CONFIG_E90
		for (i = 0; i < 4; i++) {
                        unsigned long regs;
                        // MVC has MFE with only 2 sunlance chips.
                        // So we must touch sunlance regs to detemine
                        // it's existance
                        regs = (slot << 28) |
                                   (regs_offset + i * 0x10000 +  0x00400010);
                        if (!sbus_laddr_is_valid(regs)) {
                                continue;
                        }
#else  /* CONFIG_PCI2SBUS: we have to support compatibility with 2.6.14 */
		for (i = 3; i >= 0; i--) {
#endif
			te->sibling =
			    new_sbus_dev(dev, regs_offset + i * 0x10000, slot);
			if(te->sibling)
				te = te->sibling;
			else 
				return NULL;
			te->child =
			    new_sbus_dev(dev->child,
					 regs_offset + i * 0x10000, slot);
			if(!te->child)
				return NULL;
			for (j = 0;
			     te->child->prop[j].name && j < MAX_PROPERTY;
			     j++) {
				if (!strcmp
				    (dev->child->prop[j].name,
				     "local-mac-address")) {
					unsigned char *mac =
					    (unsigned char *)
					    te->child->prop[j].value;
					mac[5] += i;
					break;
				}
			}
		}
		return te;
	}
	dbg("add_sbus_dev calls new_sbus_dev\n");
	return (te->sibling = new_sbus_dev(dev, regs_offset, slot));
}

#define FCODE_MAX_NAME_LEN 64
char* fcode_get_short_name ( unsigned long addr, unsigned long length )
{
	int i, j;
	char* short_name = NULL;
	unsigned char name[FCODE_MAX_NAME_LEN] = { '\0', };

	int max_name_size = 0;
	int sdev_num = sizeof(known_sbus_dev) / sizeof(known_sbus_dev[0]);

	for (i = 0; i < sdev_num; i++)
		max_name_size = max(max_name_size, known_sbus_dev[i].prop[ATTRIB_NAME].size);

	BUG_ON(FCODE_MAX_NAME_LEN < max_name_size);

	for (j = 0, i = 0; i < length;) {
		/* FIXME: external loop not needed,
		 * this is hindu code are awesome */
		int k;
		for (; j < max_name_size && i < length; i++, j++)
#ifdef CONFIG_E90
			name[j] = readb_asi((void *)addr + i, ASI_M_SBUS);
#else
			name[j] = sbus_readb((void *)addr + i);
#endif

		if (j == max_name_size - 1)
			break;

		for (k = 0; k < sdev_num; k++) {
			struct prom_property *p = &known_sbus_dev[k].prop[ATTRIB_NAME];
			if (p->size-1 > j)
				continue;
			if (strnstr(name, p->value, p->size - 1) != NULL) {
				short_name = kmalloc(p->size, GFP_KERNEL);
				strcpy(short_name, p->value);
				goto out;
			}
		}

		for (k = 1; k < max_name_size; k++) {
			name[k - 1] = name[k];
		}

		j = max_name_size - 1;
	}
out:
        dbg("%s: got short_name = %s\n", __func__, short_name);
	mdelay(1);	/* Without this bug-fix function always returns NULL */
	return short_name;
}

static struct tree_entry *get_dev_from_fcode(struct tree_entry *bus, unsigned long ba,
					unsigned int length, unsigned long regs_offset,
					int slot)
{
	int i, sdev_num =
			sizeof(known_sbus_dev) / sizeof(known_sbus_dev[0]);
	struct tree_entry *dev = NULL;
	char *short_name = fcode_get_short_name(ba, length);

	for (i = 0; i < sdev_num; i++) {
		struct prom_property *p = &known_sbus_dev[i].prop[ATTRIB_NAME];

                if ( short_name ) {
                        dbg("%s: trying to found name <%s> in given table, comparing with <%s> \n", __func__,
				short_name, (char *)p->value);

		        if ( (strcmp(short_name, p->value) == 0) || 
                                ((strcmp(short_name, "mfe") == 0) && (strcmp(p->value, "ledma") == 0)) ) {

			        dev = &known_sbus_dev[i];
				dbg("Device matched\n");
			        goto out;
                        }        
		}
	}
out:
	if(dev)
		add_sbus_dev(bus, dev, regs_offset, slot);
	return dev;
}

static struct tree_entry *scan_sbus_slot(struct tree_entry *bus, unsigned long ba,
					 unsigned long regs_offset, int slot)
{
	struct tree_entry *dev = NULL;
	struct fcode_header fh;

#ifdef CONFIG_E90
	fh.version = readb_asi(ba, ASI_M_SBUS);
	fh.length = readl_asi(ba + 4, ASI_M_SBUS);
#else
	fh.version = sbus_readb(ba);
	fh.length = sbus_readl(ba + 4);
#endif

        dbg("scan_sbus_slot [%d]: addr = 0x%lx, fcode version = 0x%x, bin_length = 0x%x, sizeof(fh) = %d\n", 
               slot, ba, fh.version, fh.length, sizeof(fh) );
	if (fh.version == FCODE_VERSION1
		|| fh.version == FCODE_VERSION2or3) {
                printk("scan_sbus_slot %d: Binary FCode length: 0x%08lx\n", slot, (unsigned long)fh.length);
		dev = get_dev_from_fcode(bus, ba + sizeof(fh), fh.length, regs_offset, slot);
	} 
	if (dev) {
		printk("Device %s found in slot %d",
			(char *)dev->prop[ATTRIB_NAME].value, slot);
	} else {
                printk("Nothing has been found in slot %d\n", slot);
        }
	return dev;
}
static void scan_sbus_brige2(struct tree_entry *bus, unsigned long ba)
{
	int i;
	const unsigned long reg_off[] = { 0, 0x400000, 0x800000, 0xc00000,
		0x8000000, 0x8400000, 0x8800000
	};
	struct tree_entry *dev;
	for (i = 1; i < SBUS_BRIDGE2_SLOT_NUM; i++) {
		if (!sbus_addr_is_valid(ba + reg_off[i]))
			continue;
		if ((dev = scan_sbus_slot(bus, ba + reg_off[i], ba + reg_off[i], 0))) {
			info("    bridge 2 slot %d: %s", i, (char *) dev->prop[ATTRIB_NAME].value);
		} else {
			info("    bridge 2 slot %d: unknown card", i);
			continue;
		}
	}
}
static void scan_sbus_brige1(struct tree_entry *bus, unsigned long ba, int slot)
{
	int i;
	struct tree_entry *dev;
	for (i = 1; i < SBUS_BRIDGE1_SLOT_NUM; i++) {
		if (!sbus_addr_is_valid(ba + SBUS_BRIDGE1_STEP * i))
			continue;
		if ((dev = scan_sbus_slot(bus, ba + SBUS_BRIDGE1_STEP * i, SBUS_BRIDGE1_STEP * i, slot))) {
			info("  bridge 1 slot %d: %s", i, (char *) dev->prop[ATTRIB_NAME].value);
			if (!strcmp
			    (dev->prop[ATTRIB_NAME].value, "bridge"))
				scan_sbus_brige2(bus, ba +
						 SBUS_BRIDGE1_STEP * i);
		} else {
			info("  bridge 1 slot %d: unknown card", i);
		}
	}
}


void scan_sbus(struct tree_entry *bus, unsigned long slot0_ba,
			 int slot_len, int slot_num)
{
	int i;
	struct tree_entry *dev;

	for (i = 0; i < slot_num; i++) {
		unsigned long ba = slot0_ba + slot_len * i;

		if (!sbus_addr_is_valid(ba)) {
			info("bridge 0 slot %d: addr 0x%lx not valid", i, ba);
			continue;
		}

		if ((dev = scan_sbus_slot(bus, ba, 0, i))) {
			info("bridge 0 slot %d: %s", i, (char *) dev->prop[ATTRIB_NAME].value);
			if (!strcmp(dev->prop[ATTRIB_NAME].value, "bridge"))
				scan_sbus_brige1(bus, ba, i);
		} else {
			info("bridge 0 slot %d: unknown card", i);
			continue;
		}
	}
}
EXPORT_SYMBOL(scan_sbus);
