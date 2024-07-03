/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/hash.h>
#include <linux/ktime.h>
#include <linux/log2.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include <asm/kvm/gva_cache.h>
#include <asm/mmu_types.h>
#include <asm-generic/bug.h>

/* Interfaces for working with cache cell  */
static void gva_cache_cell_set_translation(gva_cache_cell_t *cell,
					gva_translation_t *translation)
{
	cell->GVA_ADDR = (translation->gva >> PAGE_SHIFT);
	cell->GVA_FLAGS = ADDR_VALID_MASK;
	cell->gfn = translation->gpa >> PAGE_SHIFT;
	cell->pte_access = translation->pte_access;
	cell->level = translation->level;
}

static bool gva_cache_is_cell_valid(gva_cache_cell_t *cell)
{
	return cell->GVA_FLAGS & ADDR_VALID_MASK;
}

static bool gva_cache_is_cell_gva_hit(gva_cache_cell_t *cell,
					gva_t gva)
{
	return cell->GVA_ADDR == (gva >> PAGE_SHIFT);
}

static bool gva_cache_is_cell_access_ok(gva_cache_cell_t *cell,
					u32 access)
{
	if ((access & (PFERR_WRITE_MASK | PFERR_WAIT_LOCK_MASK)) &&
			!(cell->pte_access & ACC_WRITE_MASK))
		/* try write to write protected page (by pte) */
		return false;
	if ((access & PFERR_USER_MASK) && !(access & PFERR_FAPB_MASK) &&
			!(cell->pte_access & ACC_WRITE_MASK))
		/* try access from user to privileged page */
		return false;
	if ((access & PFERR_FETCH_MASK) &&
			!(cell->pte_access & ACC_EXEC_MASK))
		/* Try to execute non-executable page */
		return false;

	return true;
}

static bool gva_cache_is_cell_hit(gva_cache_cell_t *cell,
				gva_cache_query_t *query)
{
	return gva_cache_is_cell_valid(cell) &&
		gva_cache_is_cell_gva_hit(cell, query->gva) &&
		gva_cache_is_cell_access_ok(cell, query->access);
}


/* Interfaces for choosing cache cell for replacement */
static gva_cache_cell_t *gva_cache_find_cell_to_replace_lru(
						gva_cache_cell_t *bucket,
						bool *is_conflict)
{
	gva_cache_cell_t *cell, *res_cell = bucket;
	bool conflict = true;

	for (cell = bucket; cell < bucket + KVM_GVA_CACHE_BUCKET_LEN; cell++) {
		/* If cell is free, choose it for replacement */
		if (!gva_cache_is_cell_valid(cell)) {
			res_cell = cell;
			conflict = false;
			break;
		}

		/*
		 * If access time for curr cell is earlier, choose it
		 * for replacement.
		 */
		if (cell->replace_data < res_cell->replace_data) {
			res_cell = cell;
			break;
		}
	}

	gva_cache_stat_replace_conflict(is_conflict, conflict);

	return res_cell;
}

static gva_cache_cell_t *gva_cache_find_cell_to_replace_rand(
					gva_cache_cell_t *bucket)
{
	/* TODO: Now not implemented */
	BUG_ON(true);
	return NULL;
}

static gva_cache_cell_t *gva_cache_find_cell_to_replace(gva_cache_t *cache,
						gva_cache_cell_t *bucket,
						bool *is_conflict)
{
	switch (cache->replace_policy) {
	case LRU:
		return gva_cache_find_cell_to_replace_lru(bucket, is_conflict);
	case RAND:
		return gva_cache_find_cell_to_replace_rand(bucket);
	default:
		BUG_ON(true);
		return NULL;
	}
}


/* Interfaces for updating of replacement information in cache cell */
static void gva_cache_cell_update_replace_data_lru(gva_cache_cell_t *cell)
{
	cell->replace_data = ktime_get_ns();
}

static void gva_cache_cell_update_replace_data_rand(gva_cache_cell_t *cell)
{
	/* Do not need additional replace data for random replacement policy */
}

static void gva_cache_cell_update_replace_data(gva_cache_t *cache,
						gva_cache_cell_t *cell)
{
	switch (cache->replace_policy) {
	case LRU:
		gva_cache_cell_update_replace_data_lru(cell);
		break;
	case RAND:
		gva_cache_cell_update_replace_data_rand(cell);
		break;
	default:
		BUG_ON(true);
		break;
	}
}


/* Interface for replacement of cache cell */
static void gva_cache_replace_cell(gva_cache_t *cache, gva_cache_cell_t *cell,
				gva_translation_t *translation)
{
	gva_cache_cell_set_translation(cell, translation);
	gva_cache_cell_update_replace_data(cache, cell);
}


/* Interface for initialization of cache cell */
static void gva_cache_cell_init(gva_cache_cell_t *cell)
{
	cell->GVA_WHOLE = 0;
	cell->gfn = 0;
	cell->replace_data = 0;
	cell->pte_access = 0;
	cell->level = 0;
}


/* Interfaces for lookup of gva in cache */
static gva_cache_cell_t *gva_cache_bucket_lookup(gva_cache_cell_t *bucket,
						gva_cache_query_t *query)
{
	gva_cache_cell_t *cell;

	for (cell = bucket; cell < bucket + KVM_GVA_CACHE_BUCKET_LEN;
			cell++) {
		if (gva_cache_is_cell_hit(cell, query))
			return cell;
	}

	return NULL;
}

static gva_cache_cell_t *gva_cache_bucket_find_gva(gva_cache_cell_t *bucket,
						gva_t gva)
{
	gva_cache_cell_t *cell;

	for (cell = bucket; cell < bucket + KVM_GVA_CACHE_BUCKET_LEN;
			cell++) {
		if (gva_cache_is_cell_gva_hit(cell, gva))
			return cell;
	}

	return NULL;
}

static gpa_t gva_cache_lookup(gva_cache_t *cache, gva_cache_query_t *query,
			struct kvm_vcpu *vcpu, kvm_arch_exception_t *exc,
			gva_translator_t gva_translate)
{
	gva_cache_cell_t *hit_cell, *replace_cell, *bucket;
	u64 bucket_n;
	gw_attr_t gw_res;
	gpa_t gpa = UNMAPPED_GVA;
	bool is_conflict_miss = false;

	DbgGvaCache("cache 0x%lx gva 0x%lx access 0x%x\n", cache,
			query->gva, query->access);

	gva_cache_stat_lookup_start();

	/* Get cache bucket pointer */
	bucket_n = hash_64(query->gva >> PAGE_SHIFT,
				KVM_GVA_CACHE_BUCKET_BITS);
	bucket = &cache->data[bucket_n*KVM_GVA_CACHE_BUCKET_LEN];

	/* Acquire lock to access cache bucket */
	spin_lock(&cache->cache_lock);

	/* Lookup for gva to gpa translation in cache bucket */
	hit_cell = gva_cache_bucket_lookup(bucket, query);

	if (hit_cell)
		gva_cache_cell_update_replace_data(cache, hit_cell);

	/* Release cache lock */
	spin_unlock(&cache->cache_lock);

	if (hit_cell) {
		/* Cache hit */
		gpa = hit_cell->gfn << PAGE_SHIFT;
		gpa |= query->gva & ~PAGE_MASK;

		gva_cache_stat_lookup_hit_end();

		DbgGvaCache("hit gpa = 0x%llx\n", gpa);
	} else {
		gva_cache_stat_lookup_miss_start();

		/* Cache miss, translate gva->gpa through gpt */
		gpa = gva_translate(vcpu, query->gva, query->access,
				exc, &gw_res);

		gva_cache_stat_lookup_miss_stop();

		if (!arch_is_error_gpa(gpa) &&
				gw_res.level == E2K_PTE_LEVEL_NUM) {
			/* If translation successful, replace another cell */
			gva_translation_t new_trans = {
				.gva = query->gva,
				.gpa = gpa,
				.pte_access = gw_res.access
			};

			spin_lock(&cache->cache_lock);
			replace_cell = gva_cache_find_cell_to_replace(cache,
						bucket, &is_conflict_miss);
			gva_cache_replace_cell(cache, replace_cell,
						&new_trans);
			spin_unlock(&cache->cache_lock);
		}

		DbgGvaCache("miss gpa = 0x%llx\n", gpa);

		gva_cache_stat_lookup_miss_conflict(is_conflict_miss);
	}

	return gpa;
}


/* Interfaces for fluashing gva in cache */
static void gva_cache_bucket_flush_addr(gva_cache_cell_t *bucket, gva_t gva)
{
	gva_cache_cell_t *cell;

	/* Search for this gva in cache bucket and flush it if found */
	for (cell = bucket; cell < bucket + KVM_GVA_CACHE_BUCKET_LEN; cell++) {
		if (cell->GVA_ADDR == (gva >> PAGE_SHIFT))
			gva_cache_cell_init(cell);
	}
}

static void gva_cache_flush_all(gva_cache_t *cache)
{
	gva_cache_cell_t *cell, *bucket;
	u64 bucket_n;

	gva_cache_stat_flush_all_start();

	spin_lock(&cache->cache_lock);

	for (bucket_n = 0; bucket_n < KVM_GVA_CACHE_BUCKETS; bucket_n++) {
		bucket = &cache->data[bucket_n*KVM_GVA_CACHE_BUCKET_LEN];

		for (cell = bucket; cell < bucket + KVM_GVA_CACHE_BUCKET_LEN;
				cell++)
			gva_cache_cell_init(cell);
	}

	spin_unlock(&cache->cache_lock);

	gva_cache_stat_flush_all_end();
}


/* External interfaces */
gva_cache_t *gva_cache_init(void)
{
	gva_cache_cell_t *cell, *cache_data;
	gva_cache_t *gva_cache;
	struct page *cache_pages;

	/* Alloc new cache descriptor */
	gva_cache = kmalloc(GFP_KERNEL, sizeof(gva_cache_t));
	if (!gva_cache)
		return NULL;

	/* Initialize cache lock */
	spin_lock_init(&gva_cache->cache_lock);

	/* Alloc memory pages for new gva cache */
	cache_pages = alloc_pages(GFP_KERNEL,
				ilog2(KVM_GVA_CACHE_SZ >> PAGE_SHIFT));
	if (!cache_pages)
		return NULL;
	cache_data = (gva_cache_cell_t *) page_address(cache_pages);

	/* Init cache content */
	for (cell = cache_data; cell < cache_data + KVM_GVA_CACHE_LEN;
			cell++)
		gva_cache_cell_init(cell);

	gva_cache->data = cache_data;
	gva_cache->replace_policy = LRU;

	return gva_cache;
}

void gva_cache_erase(gva_cache_t *cache)
{
	BUG_ON(!cache);

	if (cache->data) {
		free_pages((unsigned long)cache->data,
				ilog2(KVM_GVA_CACHE_SZ >> PAGE_SHIFT));
		cache->data = NULL;
	}

	kfree(cache);
}

gpa_t gva_cache_translate(gva_cache_t *cache, gva_t gva, u32 access,
			struct kvm_vcpu *vcpu, kvm_arch_exception_t *exc,
			gva_translator_t gva_translate)
{
	BUG_ON(!vcpu);
	BUG_ON(!cache);

	gva_cache_query_t cache_query = {
		.gva = gva,
		.access = access
	};

	return gva_cache_lookup(cache, &cache_query, vcpu, exc, gva_translate);
}

void gva_cache_fetch_addr(gva_cache_t *cache, gva_t gva, gpa_t gpa,
			u32 access)
{
	BUG_ON(!cache);

	gva_cache_cell_t *hit_cell, *replace_cell, *bucket;
	u64 bucket_n;
	bool conflict;
	gva_translation_t new_trans = {
		.gva = gva,
		.gpa = gpa,
		.pte_access = access
	};

	gva_cache_stat_fetch_start();

	/* Get cache bucket pointer */
	bucket_n = hash_64(gva >> PAGE_SHIFT, KVM_GVA_CACHE_BUCKET_BITS);
	bucket = &cache->data[bucket_n*KVM_GVA_CACHE_BUCKET_LEN];

	/* Acquire lock to access cache bucket */
	spin_lock(&cache->cache_lock);

	/* Lookup for this gva in cache bucket */
	hit_cell = gva_cache_bucket_find_gva(bucket, gva);

	if (hit_cell) {
		/* gva is already cached, update translation for it */
		gva_cache_cell_set_translation(hit_cell, &new_trans);
		gva_cache_cell_update_replace_data(cache, hit_cell);

		gva_cache_stat_fetch_update();

		DbgGvaCache("cache 0x%lx replace gva 0x%lx gpa 0x%llx "
			"access 0x%x\n", cache, gva, gpa, access);
	} else {
		/* gva is not cached, replace another cell and cache it now */
		replace_cell = gva_cache_find_cell_to_replace(cache, bucket,
								&conflict);
		gva_cache_replace_cell(cache, replace_cell, &new_trans);

		gva_cache_stat_fetch_replace(conflict);

		DbgGvaCache("cache 0x%lx new gva 0x%lx gpa 0x%llx "
			"access 0x%x\n", cache, gva, gpa, access);
	}

	/* Release cache lock */
	spin_unlock(&cache->cache_lock);

	gva_cache_stat_fetch_end();
}

void gva_cache_flush_addr(gva_cache_t *cache, gva_t gva)
{
	BUG_ON(!cache);

	u64 bucket_n;
	gva_cache_cell_t *bucket;

	DbgGvaCache("cache 0x%lx gva 0x%lx\n", cache, gva);

	gva_cache_stat_flush_gva_start();

	/* Get cache bucket pointer */
	bucket_n = hash_64(gva >> PAGE_SHIFT, KVM_GVA_CACHE_BUCKET_BITS);
	bucket = &cache->data[bucket_n*KVM_GVA_CACHE_BUCKET_LEN];

	/* Acquire lock to access cache bucket */
	spin_lock(&cache->cache_lock);

	gva_cache_bucket_flush_addr(bucket, gva);

	/* Release cache lock */
	spin_unlock(&cache->cache_lock);

	gva_cache_stat_flush_gva_end();
}

void gva_cache_flush_addr_range(gva_cache_t *cache, gva_t start_gva,
				gva_t end_gva)
{
	BUG_ON(!cache);

	gva_t gva;

	DbgGvaCache("cache 0x%lx gva range [0x%lx-0x%lx]\n", cache,
			start_gva, end_gva);

	/* Round gva range down to PAGE_SIZE */
	start_gva &= PAGE_MASK;
	end_gva &= PAGE_MASK;

	/*
	 * If gva range for flushing is too large, then flush
	 * all the cache, else flush only gvas.
	 */
	if (end_gva - start_gva >= KVM_GVA_CACHE_FLUSH_THRESHOLD * PAGE_SIZE)
		gva_cache_flush_all(cache);
	else
		for (gva = start_gva; gva <= end_gva; gva += PAGE_SIZE)
			gva_cache_flush_addr(cache, gva);
}
