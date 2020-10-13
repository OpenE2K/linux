/*
 *  linux/arch/e2k/kernel/state_save.c
 *
 */

#include <linux/config.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/ide.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/reboot.h>

#include <asm/io.h>
#include <asm/state_save.h>

//#define CHECK_MODE
#define CHECK_TABLE_SIZE 20
#define WAKEUP(drive)	((drive)->service_start + 2 * (drive)->service_time)
#define NUM_PHYS_PAGES (end_of_phys_memory >> PAGE_SHIFT) - (start_of_phys_memory >> PAGE_SHIFT)
#define virtual_to_kernel(addr) virt_to_phys(addr) + KERNEL_BASE - kernel_phys_base
#define kernel_to_virtual(addr) (unsigned long)phys_to_virt(kernel_va_to_pa(addr))

typedef struct check_struct {
	unsigned long start;
	unsigned long end;
	int (*action)(struct check_struct*, unsigned long);
} check_struct_t;

typedef struct local_vars {
	atomic_t block_schedule;
	atomic_t block_io;
	atomic_t request_started;
	unsigned long time_left;
	long is_kstate_inited;
	long kstate_error;
	long load_counter;
	long can_save;
	ide_hwif_t* hwif;
	ide_drive_t* drive;
	ide_hwgroup_t* hwgroup;
	long rw_buffer[PAGE_SIZE/sizeof(long)];
	long nr_pages;
	long nr_block;
	struct page* page;
	unsigned long *to;
	unsigned long *from;
	long flags;
	long flags2;
	long count;
	check_struct_t check_table[CHECK_TABLE_SIZE];
	unsigned long stacks[(PAGE_SIZE*8)/sizeof(unsigned long)];
	unsigned long sbr;
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;
	unsigned long k_sbr;
	e2k_usd_lo_t k_usd_lo; 
	e2k_usd_hi_t k_usd_hi;
	e2k_psp_lo_t k_psp_lo;
	e2k_psp_hi_t k_psp_hi;
	e2k_pcsp_lo_t k_pcsp_lo;
	e2k_pcsp_hi_t k_pcsp_hi;
	unsigned long jiffies;
#ifdef CHECK_MODE
	long diff_count;
#endif
	long temp;
	unsigned long nid;
} variables_t;

variables_t variables;

#define VARS(field) variables.field

/* Possible values are
 * 0 - no block
 * 1 - block new IO requests
 * 2 - report about new IO requests (it's an error) and redirect timer and 
 * interrupt handlers to e2k functions
 */

/* Constants */

int device_major = 3;
int device_minor = 2;
int minor;
unsigned long device_block_size = 0x10000a6a1a0L;
unsigned long device_block_size_minor = 0x40f8;

long check_size;
long check_wp_size;

int kstate_redirect(void) {
	if (atomic_read(&VARS(block_io)) == 2) {
		printk("interrupt from IDE\n");
		return 1;
	}
	return 0;
}

int kstate_block(void) {
	if (atomic_read(&VARS(block_io)) == 1)
		return 1;
	return 0;
}

void kstate_dec(void) {
        if (VARS(time_left) > 1)
                VARS(time_left)--;
}
void open_device(char* dev_name);

void block_io_and_sched(void) {
	unsigned long	flags;
	long i = 0;
	atomic_inc(&VARS(block_io));
	/* Block scheduling */
	atomic_inc(&VARS(block_schedule));

	/* Wait while last IO operation complete */
	if (VARS(hwgroup) == NULL) {
		open_device("/dev/hda2");
	}
	if (VARS(hwgroup) != NULL) {
again:
		while (VARS(hwgroup)->busy) {
			i++;
			if (i > 100000) {
				printk("Disk is busy\n");
				i = 0;
			}
		}
		spin_lock_irqsave(&ide_lock, flags);
		if (VARS(hwgroup)->busy) {
			spin_unlock(&ide_lock);
			local_irq_enable();
			goto again;
		} else {
			VARS(hwgroup)->busy = 1;
			spin_unlock_irqrestore(&ide_lock, flags);
		}
	} else {
		printk("HWGROUP is NULL\n");
	}

	/* Redirect all new interrupts */
	atomic_inc(&VARS(block_io));
}

void unblock_io_and_sched(void) {
	atomic_set(&VARS(block_io), 0);
	atomic_dec(&VARS(block_schedule));
}

void unblock_ide(void) {
	VARS(hwgroup)->busy = 0;
}

/* Extracted from swapoff */
void check_device(char* dev_name) {
        int error;
        struct block_device *bdev = NULL;
	struct file *swap_file = NULL;

	printk("check_device() Opening device for kstatesaved\n");
	
	swap_file = filp_open(dev_name, O_RDWR, 0);
	error = PTR_ERR(swap_file);
	if (IS_ERR(swap_file)) {
		swap_file = NULL;
		goto bad_dev;
	}
	if (S_ISBLK(swap_file->f_mapping->host->i_mode)) {
		bdev = I_BDEV(swap_file->f_mapping->host);
		if (bdev != bdev->bd_contains) {
			struct hd_struct *p = bdev->bd_part;
			printk("Device %s, starts from the sector 0x%lx\n", dev_name, p->start_sect);
		} else
			printk("Device %s, starts from 0\n", dev_name);
	} else {
		printk("check_device() Only block devices may be used\n");
	}
	filp_close(swap_file, NULL);
	return;
bad_dev:
	printk("check_device() has FAILED\n");
	return;
}

void init_variables(void) {
	unsigned long stack;
	
	atomic_set(&VARS(block_schedule), 0);
	atomic_set(&VARS(block_io), 0);
	atomic_set(&VARS(request_started), 0);
	VARS(time_left) = 0;
	VARS(hwgroup) = NULL;
	VARS(load_counter) = 0;
	VARS(can_save) = 1;
	stack = (unsigned long)VARS(stacks);
	if (stack & (PAGE_SIZE - 1))
		stack = PAGE_ALIGN(stack);
	/* First will be ustack  - 2 PAGES */
	AS_WORD(VARS(k_usd_lo)) = stack + 2*PAGE_SIZE;
	AS_STRUCT(VARS(k_usd_lo)).unused = 0;
	AS_STRUCT(VARS(k_usd_lo)).rw = 3;

	AS_AP_STRUCT(VARS(k_usd_hi)).curptr = 0;
	AS_STRUCT(VARS(k_usd_hi)).size = 2*PAGE_SIZE;
	VARS(k_sbr) = stack + 2*PAGE_SIZE;

	stack += 3*PAGE_SIZE;
	/* p stack */
	AS_WORD(VARS(k_psp_lo)) = stack;
	AS_STRUCT(VARS(k_psp_lo)).rw = 3;

	AS_STRUCT(VARS(k_psp_hi)).ind = 0;
	AS_STRUCT(VARS(k_psp_hi)).size = 2*PAGE_SIZE;

	stack += 2*PAGE_SIZE;
	/* pc stack */
	AS_WORD(VARS(k_pcsp_lo)) = stack;
	AS_STRUCT(VARS(k_pcsp_lo)).rw = 3;

	AS_STRUCT(VARS(k_pcsp_hi)).ind = 0;
	AS_STRUCT(VARS(k_pcsp_hi)).size = 2*PAGE_SIZE;	
}

void open_device(char* dev_name) {
	int i, name_len;
	char last_letter;
	
	/* Search for the hwgroup, hwif & drive for the device.
	 * Hwif table must be already initialized */
	printk("open_device() Search for the hwif for the device\n");
	/* We use the last letter of the dev_name. It would be a, b, c or d
	 * Also dev_name may have digits at the end. So we search for the first
	 * letter from the end of the string */
	for (name_len = 0; dev_name[name_len] != 0; name_len++);

	last_letter = 0;
	for (i = name_len - 1; i >= 0; i--)
		if ((dev_name[i] >= 'a') && (dev_name[i] <= 'z')) {
			last_letter = dev_name[i];
			break;
		}
	if (!last_letter) {
		printk("open_device() Cant get a drive letter from the device name\n");
		goto bad_dev;
	}
	for (i = 0; i < MAX_HWIFS; i++) {
		int unit;
		
		VARS(hwif) = &ide_hwifs[i];
		for (unit = 0; unit < MAX_DRIVES; ++unit) {
			VARS(drive) = &VARS(hwif)->drives[unit];
			if (VARS(drive)->name[2] == last_letter) {
				VARS(hwgroup) = HWGROUP(VARS(drive));
				if (VARS(hwgroup) == NULL) {
					printk("open_device() disk %s is not "
						"yet initialized\n",
						dev_name);
				}
				return;
			}
		}
	}
	printk("open_device() Cant find appropriate hwif and drive\n");
	return;
bad_dev:
	printk("open_device() has FAILED\n");
	VARS(kstate_error) = 1;
}

#define DECLARE_INTERVAL_BY_VALUE(var_name, var_type, var_action) \
	addr = kernel_to_virtual((unsigned long)(&var_name)); \
	VARS(check_table)[i].start = addr; \
	VARS(check_table)[i].end = addr + sizeof(var_type) - 1; \
	VARS(check_table)[i].action = var_action; \
	i++;

void init_check_table(void) {
	int i = 0;
	unsigned long addr;
	/* Write protected */
	DECLARE_INTERVAL_BY_VALUE(variables, variables_t, NULL);
	check_wp_size = i;
	check_size = i;
}

static inline void copy_data_saveirq(void * _to, void * _from, unsigned long count)
{
	VARS(to) = (unsigned long *)_to;
	VARS(from) = (unsigned long *)_from;

	count /= (sizeof(unsigned long));
	raw_local_irq_save(VARS(flags));
	do {
		//printk("Copy from 0x%lx to 0x%lx\n", from, to);
		VARS(to)[0] = VARS(from)[0];
		count--;
		VARS(from) += 1;
		VARS(to) += 1;
	} while (count);
	raw_local_irq_restore(VARS(flags));
}

static inline void copy_page_saveirq(void * _to, void * _from) {
	copy_data_saveirq(_to, _from, PAGE_SIZE);
}

/****************************************************************************************************
 *
 * ....
 * 
 ****************************************************************************************************/

int kstate_block_schedule(void) {
	if (atomic_read(&VARS(block_schedule)) > 0)
		return 1;
	else
		return 0;
}

#define SAVE_STACK_REGISTERS(reg) \
({								\
	raw_all_irq_save(VARS(flags));				\
	E2K_FLUSHCPU;						\
	VARS(sbr) = READ_SBR_REG_VALUE();			\
	VARS(usd_hi) = READ_USD_HI_REG();			\
	VARS(usd_lo) = READ_USD_LO_REG();			\
	VARS(psp_hi) = READ_PSP_HI_REG();			\
	VARS(psp_lo) = READ_PSP_LO_REG();			\
	VARS(pcsp_hi) = READ_PCSP_HI_REG();			\
	VARS(pcsp_lo) = READ_PCSP_LO_REG();			\
	WRITE_SBR_REG_VALUE(reg->k_sbr);			\
	WRITE_USD_REG(reg->k_usd_hi, reg->k_usd_lo);		\
	WRITE_PSP_REG(reg->k_psp_hi, reg->k_psp_lo);		\
	WRITE_PCSP_REG(reg->k_pcsp_hi, reg->k_pcsp_lo);		\
	raw_all_irq_restore(VARS(flags)); 			\
})

#define RESTORE_STACK_REGISTERS(reg)				\
({								\
	raw_all_irq_save(VARS(flags));				\
	E2K_FLUSHCPU;						\
	WRITE_SBR_REG_VALUE(reg->sbr);				\
	WRITE_USD_REG(reg->usd_hi, reg->usd_lo);		\
	WRITE_PSP_REG(reg->psp_hi, reg->psp_lo);		\
	WRITE_PCSP_REG(reg->pcsp_hi, reg->pcsp_lo);		\
	raw_all_irq_restore(VARS(flags));			\
})

long log_14 = 0;

extern int load_id(void);
extern void print_id(void);
extern int inline write_page_chs(void* buffer, unsigned long block);
extern int inline read_page_chs(void* buffer, unsigned long block);
extern struct hd_driveid drive_id;
extern struct hd_driveid* id;
#define BLOCK_SHIFT 0x81f0
#define VERSION_NUMBER '4'
#define CHECK_SYMB '6'

void e2k_rw_data_new(void * data, int blocknr, int cmd) {	
	printk("kstate() writing or reading page from 0x%p to 0x%p\n", VARS(from), VARS(to));
	
	if (cmd == WRITE) {
		if (write_page_chs(data, BLOCK_SHIFT + blocknr*8)) {
			printk("Write failed\n");
			VARS(kstate_error) = 1;
		}
	} else {
		if (read_page_chs(data, BLOCK_SHIFT + blocknr*8)) {
			printk("Read failed\n");
			VARS(kstate_error) = 1;
		}
	}

	if (VARS(kstate_error) == 1) {
		panic("IO error");
	}
}

extern unsigned int cached_irq_mask;

static inline void save_machine_state_new(void) {

	/* save system information in the 1st sector */
	VARS(rw_buffer)[0] = 'e';
	VARS(rw_buffer)[1] = VERSION_NUMBER;
	VARS(rw_buffer)[2] = 'k';
	VARS(rw_buffer)[3] = VARS(load_counter) + 1;
	VARS(rw_buffer)[4] = VARS(check_table)[0].start;
	VARS(rw_buffer)[5] = VARS(check_table)[0].end;
	VARS(rw_buffer)[6] = kernel_to_virtual((unsigned long)(&cached_irq_mask));
	VARS(nr_pages) = 0;
	VARS(rw_buffer)[10] = num_online_nodes();
	for_each_online_node(VARS(nid)) {
		VARS(rw_buffer)[11 + VARS(nid)] = node_spanned_pages(VARS(nid));
		VARS(nr_pages) = VARS(nr_pages) + node_spanned_pages(VARS(nid));
	}
	VARS(load_counter)++;
	e2k_rw_data_new(VARS(rw_buffer), 1, WRITE);
	printk("Saving %lx pages on %d node(s)\n",
		VARS(nr_pages), num_online_nodes());
	printk("Memory image number is 0x%lx\n", VARS(rw_buffer)[3]);
	VARS(nr_block) = 10; /* first block of the /dev/hdaN */
	for_each_online_node(VARS(nid)) {
		VARS(page) = nid_page_nr(VARS(nid), 0);
		VARS(nr_pages) = node_spanned_pages(VARS(nid));
		while ((VARS(nr_pages) > 0) && (VARS(kstate_error) == 0)) {
			if (page_valid(VARS(page))) {
				copy_page_saveirq(&VARS(rw_buffer)[0], page_address(VARS(page)));
				e2k_rw_data_new(VARS(rw_buffer), VARS(nr_block), WRITE);
			} else
				printk("Page %p is invalid, flags are 0x%lx, count is %d\n",
						page_address(VARS(page)), VARS(page)->flags,
						page_count(VARS(page)));
			VARS(nr_pages)--;
			VARS(nr_block)++;
			VARS(page)++;
		}
	}
}

static inline void load_machine_state_new(void) {
	VARS(nr_pages) = 0;
	for_each_online_node(VARS(nid)) {
		VARS(nr_pages) = VARS(nr_pages) + node_spanned_pages(VARS(nid));
	}
	printk("Loading %lx pages on %d nodes\n",
		VARS(nr_pages), num_online_nodes());
	VARS(nr_block) = 10; /* first block of the /dev/hdaN */
	for_each_online_node(VARS(nid)) {
		VARS(page) = nid_page_nr(VARS(nid), 0);
		VARS(nr_pages) = node_spanned_pages(VARS(nid));
		while ((VARS(nr_pages) > 0) && (VARS(kstate_error) == 0)) {
			if (page_valid(VARS(page))) {
				e2k_rw_data_new(VARS(rw_buffer), VARS(nr_block), READ);

				/* We must be very careful to not overwrite
				 * local variables
				 */
			
				VARS(count) = PAGE_SIZE/sizeof(unsigned long);
				VARS(from) = (unsigned long*)VARS(rw_buffer);
				VARS(to) = (unsigned long*)page_address(VARS(page));
				do {
					/* Dont overwrite variables structure */
					if ((VARS(check_table)[0].start > (unsigned long)VARS(to)) ||
						(VARS(check_table)[0].end < (unsigned long)VARS(to))) {
						if (((unsigned long)VARS(to) < (unsigned long)phys_to_virt(kernel_boot_stack_phys_base(0))) ||
							((unsigned long)VARS(to) >= (unsigned long)phys_to_virt(kernel_boot_stack_phys_base(0)) +
							 kernel_boot_stack_size(0))) {
							if ((unsigned long)VARS(to) >= 0x10000122000)
								VARS(to)[0] = VARS(from)[0];
						}
						else
							printk("+");
					}
					VARS(count)--;
					VARS(from)++;
					VARS(to)++;
				} while (VARS(count));
			} else
				printk("Page %p is invalid, flags are 0x%lx, count is %d\n",
					page_address(VARS(page)), VARS(page)->flags, 
					page_count(VARS(page)));
		
			VARS(nr_pages)--;
			VARS(nr_block)++;
			VARS(page)++;
		}
	}
}

static inline void check_state(void) {
	VARS(nr_pages) = 0;
	for_each_online_node(VARS(nid)) {
		VARS(nr_pages) = VARS(nr_pages) + node_spanned_pages(VARS(nid));
	}
	printk("Loading %lx pages on %d nodes\n",
		VARS(nr_pages), num_online_nodes());
	VARS(nr_block) = 10; /* first block of the /dev/hdaN */
	for_each_online_node(VARS(nid)) {
		VARS(page) = nid_page_nr(VARS(nid), 0);
		VARS(nr_pages) = node_spanned_pages(VARS(nid));
		while ((VARS(nr_pages) > 0) && (VARS(kstate_error) == 0)) {
			if (page_valid(VARS(page))) {
				e2k_rw_data_new(VARS(rw_buffer), VARS(nr_block), READ);
			/* We must be very careful to not overwrite
			 * local variables
			 */
				VARS(count) = PAGE_SIZE/sizeof(unsigned long);
				VARS(from) = (unsigned long*)VARS(rw_buffer);
				VARS(to) = (unsigned long*)page_address(VARS(page));
				do {
					/* Dont overwrite variables structure */
					if ((VARS(check_table)[0].start > (unsigned long)VARS(to)) ||
						(VARS(check_table)[0].end < (unsigned long)VARS(to))) {
//						if (((unsigned long)VARS(to) < (unsigned long)phys_to_virt(kernel_boot_stack_phys_base(0))) ||
//							((unsigned long)VARS(to) >= (unsigned long)phys_to_virt(kernel_boot_stack_phys_base(0)) +
//							 kernel_boot_stack_size(0))) {
						if (VARS(to)[0] != VARS(from)[0])
							printk("Difference on 0x%p (kernel_address 0x%lx), expected  0x%lx, \
								found 0x%lx\n", VARS(to), virtual_to_kernel(VARS(to)),
								VARS(from)[0], VARS(to)[0]);
//						} else
//							printk("+");
					} else
						printk("-");
					VARS(count)--;
					VARS(from)++;
					VARS(to)++;
				} while (VARS(count));
			} else
				printk("Page %p is invalid, flags are 0x%lx, count is %d\n",
					page_address(VARS(page)), VARS(page)->flags, 
					page_count(VARS(page)));
			VARS(nr_pages)--;
			VARS(nr_block)++;
			VARS(page)++;
		}
	}

}

#define mask_irq(irq)           ({if (irq_to_desc(irq) && \
				irq_to_desc(irq)->chip && \
			        irq_to_desc(irq)->chip->disable) \
				irq_to_desc(irq)->chip->disable(irq);})

#define unmask_irq(irq)         ({if (irq_to_desc(irq) && \
				irq_to_desc(irq)->chip && \
			        irq_to_desc(irq)->chip->enable) \
				irq_to_desc(irq)->chip->enable(irq);})

static void enable_irq_14(int i) {
	if (i)
		unmask_irq(14);
	else
		mask_irq(14);
}

extern void print_tasks(void);

void e2k_save_state(void) {
	if (VARS(hwgroup) == NULL) {
		open_device("/dev/hda2");
		if (VARS(hwgroup) == NULL) {
			VARS(kstate_error) = 1;
			return;
		} else {
			VARS(kstate_error) = 0;
		}
	}
	printk("hwgroup->busy is %d\n", VARS(hwgroup)->busy);
//printk("ADDR - 0x%lx\n", kernel_to_virtual((unsigned long)(0xe200044e6c0)));
	/* Check errors */
	//print_tasks();
//	if (!VARS(can_save)) {
		VARS(can_save) = 1;
		unblock_io_and_sched();
		return;
//	}
	//if (VARS(can_save) >= 2){
	//	VARS(can_save) = 2;
	//	unblock_io_and_sched();
	//	return;
	//}
	//VARS(can_save) = 2;
	if (VARS(kstate_error) == 0) {
		register variables_t* reg = &variables;
		enable_irq_14(0);
		/* First time load special page */
		if (VARS(load_counter) == 0) {
			e2k_rw_data_new(VARS(rw_buffer), 1, READ);
			if (VARS(kstate_error)) {
				unblock_io_and_sched();
				enable_irq_14(1);
				return;
			}
			/* if the signature is right skip saving */
			if ((VARS(rw_buffer)[0] == 'e') && (VARS(rw_buffer)[1] == VERSION_NUMBER) &&
                                (VARS(rw_buffer)[2] == 'k')) {
				VARS(can_save) = 1;
				unblock_io_and_sched();
				enable_irq_14(1);
				return;
			}
		}
		SAVE_STACK_REGISTERS(reg);
		E2K_SET_USER_STACK(1);
		printk("State will be saved and the computer will be restarted\n");
		save_machine_state_new();
		RESTORE_STACK_REGISTERS(reg);
		enable_irq_14(1);
	}
	unblock_io_and_sched();
}

void e2k_load_state(void) {
	unblock_ide();
	if (VARS(can_save))
		return;
	return;
	raw_local_irq_save(VARS(flags2));
	if (VARS(kstate_error) == 0) {
		register variables_t* reg = &variables;
		SAVE_STACK_REGISTERS(reg);
		E2K_SET_USER_STACK(1);
		printk("State will be loaded\n");
		//load_machine_state_new();
		check_state();
		//load_machine_state_new();
		VARS(can_save) = 1;
		VARS(load_counter) = 1;
		RESTORE_STACK_REGISTERS(reg);
	}
	raw_local_irq_restore(VARS(flags2));
}

static inline void check_machine_state(void) {
	VARS(nr_pages) = 0;
	for_each_online_node(VARS(nid)) {
		VARS(nr_pages) = VARS(nr_pages) + node_spanned_pages(VARS(nid));
	}
	printk("Checking %lx pages on %d nodes\n",
		VARS(nr_pages), num_online_nodes());
	VARS(nr_block) = 10; /* first block of the /dev/hdaN */
	for_each_online_node(VARS(nid)) {
		VARS(page) = nid_page_nr(VARS(nid), 0);
		VARS(nr_pages) = node_spanned_pages(VARS(nid));
		while ((VARS(nr_pages) > 0) && (VARS(kstate_error) == 0)) {
			e2k_rw_data_new(VARS(rw_buffer), VARS(nr_block), READ);
			/* We must be very careful to not overwrite
			 * local variables
			 */
			VARS(count) = PAGE_SIZE/sizeof(unsigned long);
			VARS(from) = (unsigned long*)VARS(rw_buffer);
			VARS(to) = (unsigned long*)page_address(VARS(page));
			do {
				/* Dont overwrite variables structure */
				if ((VARS(check_table)[0].start > (unsigned long)VARS(to)) ||
					(VARS(check_table)[0].end < (unsigned long)VARS(to))) {
					if (VARS(to)[0] != VARS(from)[0])
						printk("Difference on 0x%p (kernel_address 0x%lx), expected  0x%lx, \
							found 0x%lx\n", VARS(to), virtual_to_kernel(VARS(to)),
							VARS(from)[0], VARS(to)[0]);
				}
				VARS(count)--;
				VARS(from)++;
				VARS(to)++;
			} while (VARS(count));

			VARS(nr_pages)--;
			VARS(nr_block)++;
			VARS(page)++;
		}
	}
}

void init_state_save(void) {
	int i;
	if (VARS(is_kstate_inited) != 1) {
		VARS(is_kstate_inited) = 0;
		VARS(kstate_error) = 0;
		VARS(time_left) = 0;
		init_variables();
		init_check_table();
		//if (load_id()) {
		//	printk("Disk ID cannot be loaded\n");
		//	VARS(kstate_error) = 1;
		//} else {
		//	printk("Loaded id -----------------------\n");
		//	print_id();
		//	printk("End of ID -----------------------\n");
		//}
		//check_device("/dev/hda2");
		open_device("/dev/hda2");
		id = VARS(drive)->id;
		VARS(is_kstate_inited) = 1;
		for (i = 0; i < check_size; i++) {
			printk("check_table[0x%d] is 0x%lx, 0x%lx\n", i, variables.check_table[i].start,
				variables.check_table[i].end);
		}
		if (VARS(kstate_error) == 1) {
			printk("Kstatesave is not initialized\n");
			VARS(kstate_error) = 1;
			panic("Look above");
		}
	}
}
