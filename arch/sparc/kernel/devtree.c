#include <asm-l/devtree.h>
#include <linux/of_fdt.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/memblock.h>
#include <linux/types.h>
#include <asm/io.h>
#include <asm/bootinfo.h>

int devtree_detected = 1;

void __init early_init_dt_add_memory_arch(u64 base, u64 size)
{
	memblock_add(base, size);
}

void __init *early_init_dt_alloc_memory_arch(u64 size, u64 align)
{
	return memblock_alloc(size, align);
}

/*
 * This function will create device nodes in sysfs coresponding to nodes
 * described in dtb.
 */
int __init sparc_publish_devices(void)
{
	if (!of_have_populated_dt()) {
		return 0;
	}
	return of_platform_populate(NULL, of_default_bus_match_table,
					NULL, NULL);
}
device_initcall(sparc_publish_devices);

static u64 get_device_tree_addr(void)
{
	/*
	 * Atention! Hack!
	 * Old versions of boot (2019 year include), have a bug.
	 * Boot writes virtual memory address in ....bios.devtree field.
	 * But we need phys memory address.
	 * Boot-writers claim that phys address high bits
	 * are same as in ....kernel_base field.
	 * So, for fix it, we need to change this high bytes.
	 */
	if ((bootblock->info.bios.devtree & 0xf0000000) ==
	    (bootblock->info.kernel_base & 0xf0000000))
		return bootblock->info.bios.devtree;
	return (bootblock->info.bios.devtree & 0xffffff) | 0x81000000;
}

u32 get_dtb_size(void)
{
	u32 *blob_addr = (u32 *)get_device_tree_addr();
	u32 dtb_data = __raw_readl(blob_addr);
	u32 magic = OF_DT_HEADER;

	/* left for possible debugging */
	/*
	printk(KERN_ERR "DevTree: %llx ==> %llx\n",
			bootblock->info.bios.devtree, get_device_tree_addr());
	printk(KERN_ERR "DevTree[0] DevTree[1]: %x %x\n",
			__raw_readl(blob_addr), __raw_readl(blob_addr + 1));
	printk(KERN_ERR "Kern phys: 0x%llx\n", bootblock->info.kernel_base);
	printk(KERN_ERR "BootLog addr: %x\n",
			bootblock->info.bios.bootlog_addr);
	*/
	if (be32_to_cpu(dtb_data) != magic) {
		printk(KERN_ERR "DevTree: disabled (incorrect magic): %x\n",
				dtb_data);
		return 0;
	}
	dtb_data = __raw_readl(blob_addr+1);

	return __be32_to_cpu(dtb_data);
}

void get_dtb_from_boot(u8 *blob, u32 len)
{
	u32 *blob_addr = (u32 *)get_device_tree_addr();
	u8 *dtb_ptr = (u8 *)blob_addr;
	int i;

	for (i = 0; i < len; i++) {
		u8 dt = __raw_readb(dtb_ptr);
		blob[i] = dt;
		dtb_ptr++;
	}

	return;
}

int __init device_tree_init(void)
{
	u8 *dt;
#ifdef CONFIG_DTB_L_TEST
	initial_boot_params = (struct boot_param_header *)test_blob;
#else
	u32 sz = get_dtb_size();
	if (sz == 0) {
		printk(KERN_ERR "DevTree: device tree size is 0\n");
		devtree_detected = 0;
		return -1;
	} else {
		printk(KERN_INFO "DevTree: device tree size is %d\n", sz);
	}

	dt = memblock_alloc(sz, SMP_CACHE_BYTES);
	if (dt == NULL) {
		printk(KERN_ERR "DevTree: not enough memory\n");
		devtree_detected = 0;
		return -2;
	}

	get_dtb_from_boot(dt, sz);

	initial_boot_params = (struct boot_param_header *)dt;
#endif
	unflatten_device_tree();
	return 0;
}
