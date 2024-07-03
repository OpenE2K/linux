/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Extract CPU cache information and expose it via sysfs.
 */

#include <linux/cpu.h>
#include <linux/cacheinfo.h>
#include <linux/seq_file.h>

struct e2k_cache_info {
	u32 cpu_mdl : 8;
	u32 level : 3;
	u32 type : 3;
	u32 private : 1;
	u32 associativity : 8;
	u32 physical_line_partition : 8;
	unsigned int cache_size;
	unsigned int line_size;
	unsigned int attributes;
};

static const struct e2k_cache_info e2k_caches[] = {
	{ IDR_E2S_MDL, 1, CACHE_TYPE_INST, 1, 4, 1, 128 * 1024, 256,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E2S_MDL, 1, CACHE_TYPE_DATA, 1, 4, 1, 64 * 1024, 32,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E2S_MDL, 2, CACHE_TYPE_UNIFIED, 1, 4, 4, 2 * 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E8C_MDL, 1, CACHE_TYPE_INST, 1, 4, 1, 128 * 1024, 256,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E8C_MDL, 1, CACHE_TYPE_DATA, 1, 4, 1, 64 * 1024, 32,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E8C_MDL, 2, CACHE_TYPE_UNIFIED, 1, 4, 4, 512 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E8C_MDL, 3, CACHE_TYPE_UNIFIED, 0, 16, 8, 16 * 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E1CP_MDL, 1, CACHE_TYPE_INST, 1, 4, 1, 128 * 1024, 256,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E1CP_MDL, 1, CACHE_TYPE_DATA, 1, 4, 1, 64 * 1024, 32,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E1CP_MDL, 2, CACHE_TYPE_UNIFIED, 1, 4, 4, 2 * 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E8C2_MDL, 1, CACHE_TYPE_INST, 1, 4, 1, 128 * 1024, 256,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E8C2_MDL, 1, CACHE_TYPE_DATA, 1, 4, 1, 64 * 1024, 32,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E8C2_MDL, 2, CACHE_TYPE_UNIFIED, 1, 4, 4, 512 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E8C2_MDL, 3, CACHE_TYPE_UNIFIED, 0, 16, 8, 16 * 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E12C_MDL, 1, CACHE_TYPE_INST, 1, 4, 1, 128 * 1024, 256,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E12C_MDL, 1, CACHE_TYPE_DATA, 1, 4, 1, 64 * 1024, 32,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E12C_MDL, 2, CACHE_TYPE_UNIFIED, 1, 4, 4, 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E12C_MDL, 3, CACHE_TYPE_UNIFIED, 1, 16, 16, 24 * 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E16C_MDL, 1, CACHE_TYPE_INST, 1, 4, 1, 128 * 1024, 256,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E16C_MDL, 1, CACHE_TYPE_DATA, 1, 4, 1, 64 * 1024, 32,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E16C_MDL, 2, CACHE_TYPE_UNIFIED, 1, 4, 4, 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E16C_MDL, 3, CACHE_TYPE_UNIFIED, 0, 16, 16, 32 * 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E2C3_MDL, 1, CACHE_TYPE_INST, 1, 4, 1, 128 * 1024, 256,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E2C3_MDL, 1, CACHE_TYPE_DATA, 1, 4, 1, 64 * 1024, 32,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E2C3_MDL, 2, CACHE_TYPE_UNIFIED, 1, 4, 4, 2 * 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E48C_MDL, 1, CACHE_TYPE_INST, 1, 4, 1, 128 * 1024, 256,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E48C_MDL, 1, CACHE_TYPE_DATA, 1, 4, 1, 64 * 1024, 48,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E48C_MDL, 2, CACHE_TYPE_UNIFIED, 1, 4, 4, 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E48C_MDL, 3, CACHE_TYPE_UNIFIED, 0, 16, 16, 48 * 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E8V7_MDL, 1, CACHE_TYPE_INST, 1, 4, 1, 128 * 1024, 256,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E8V7_MDL, 1, CACHE_TYPE_DATA, 1, 4, 1, 64 * 1024, 48,
		CACHE_READ_ALLOCATE | CACHE_WRITE_THROUGH },
	{ IDR_E8V7_MDL, 2, CACHE_TYPE_UNIFIED, 1, 4, 4, 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_E8V7_MDL, 3, CACHE_TYPE_UNIFIED, 0, 16, 16, 48 * 1024 * 1024, 64,
		CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE | CACHE_WRITE_BACK },
	{ IDR_NONE, 0, 0, 0, 0, 0, 0, 0, 0 }
};

static void ci_leaf_init(struct cacheinfo *this_leaf,
			 const struct e2k_cache_info *ci, int cpu)
{
	int num_sets;

	this_leaf->level = ci->level;
	this_leaf->type = ci->type;
	this_leaf->coherency_line_size = ci->line_size;
	this_leaf->ways_of_associativity = ci->associativity;
	this_leaf->size = ci->cache_size;
	this_leaf->physical_line_partition = ci->physical_line_partition;
	this_leaf->attributes = ci->attributes;

	num_sets = this_leaf->size / this_leaf->coherency_line_size;
	num_sets /= this_leaf->ways_of_associativity;
	this_leaf->number_of_sets = num_sets;

	if (ci->private)
		cpumask_set_cpu(cpu, &this_leaf->shared_cpu_map);
	else
		cpumask_copy(&this_leaf->shared_cpu_map, cpu_cpu_mask(cpu));

	/* Unlike s390, we do not disable sysfs for shared caches */
	this_leaf->disable_sysfs = false;
	this_leaf->priv = (void *)ci;
}

int init_cache_level(unsigned int cpu)
{
	int cpu_mdl = machine.native_id & MACHINE_ID_CPU_TYPE_MASK;
	struct cpu_cacheinfo *this_cpu_ci = get_cpu_cacheinfo(cpu);
	unsigned int max_level = 0, leaves = 0;
	const struct e2k_cache_info *ci;

	if (!this_cpu_ci)
		return -EINVAL;

	for (ci = e2k_caches; ci->cpu_mdl != IDR_NONE; ci++) {
		if (ci->cpu_mdl != cpu_mdl)
			continue;

		++leaves;
		if (ci->level > max_level)
			max_level = ci->level;
	}

	if (WARN_ONCE(!leaves, "Provide cache info for the new processor\n"))
		return -EINVAL;

	this_cpu_ci->num_levels = max_level;
	this_cpu_ci->num_leaves = leaves;

	return 0;
}

int populate_cache_leaves(unsigned int cpu)
{
	int cpu_mdl = machine.native_id & MACHINE_ID_CPU_TYPE_MASK;
	struct cpu_cacheinfo *this_cpu_ci = get_cpu_cacheinfo(cpu);
	struct cacheinfo *this_leaf = this_cpu_ci->info_list;
	const struct e2k_cache_info *ci;

	if (!this_leaf)
		return -EINVAL;

	for (ci = e2k_caches; ci->cpu_mdl != IDR_NONE; ci++) {
		if (ci->cpu_mdl != cpu_mdl)
			continue;

		ci_leaf_init(this_leaf, ci, cpu);
		++this_leaf;
	}

	this_cpu_ci->cpu_map_populated = true;

	return 0;
}


static const char * const cache_type_string[] = {
	"",
	"Instruction",
	"Data",
	"",
	"Unified",
};

u64 cacheinfo_get_l1d_line_size()
{
	struct cpu_cacheinfo *this_cpu_ci;
	struct cacheinfo *cache;
	int idx;

	this_cpu_ci = get_cpu_cacheinfo(cpumask_any(cpu_online_mask));
	for (idx = 0; idx < this_cpu_ci->num_leaves; idx++) {
		cache = this_cpu_ci->info_list + idx;
		if (cache->level != 1 ||
				cache->type != CACHE_TYPE_DATA &&
				cache->type != CACHE_TYPE_UNIFIED)
			continue;

		return cache->coherency_line_size;
	}

	WARN_ON_ONCE(system_state == SYSTEM_RUNNING);

	return 32;
}

void show_cacheinfo(struct seq_file *m)
{
	struct cpu_cacheinfo *this_cpu_ci;
	struct cacheinfo *cache;
	const struct e2k_cache_info *ci;
	int idx;

	this_cpu_ci = get_cpu_cacheinfo(cpumask_any(cpu_online_mask));
	for (idx = 0; idx < this_cpu_ci->num_leaves; idx++) {
		cache = this_cpu_ci->info_list + idx;
		ci = cache->priv;
		seq_printf(m, "cache%-11d: ", idx);
		seq_printf(m, "level=%d ", cache->level);
		seq_printf(m, "type=%s ", cache_type_string[cache->type]);
		seq_printf(m, "scope=%s ", ci->private ? "Private" : "Shared");
		seq_printf(m, "size=%dK ", cache->size >> 10);
		seq_printf(m, "line_size=%u ", cache->coherency_line_size);
		seq_printf(m, "associativity=%d", cache->ways_of_associativity);
		seq_puts(m, "\n");
	}
}
