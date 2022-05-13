#ifndef GVA_CACHE_E2K_H
#define GVA_CACHE_E2K_H


#include <linux/kvm_types.h>

#include <asm/page.h>
#include <asm/kvm/mmu_exc.h>
#include <asm/kvm/mmu_pte.h>

/* Format of address record in gva cache */
typedef union {
	struct {
		u64 addr : 64 - PAGE_SHIFT;
		u64 flags : PAGE_SHIFT;
	} fields;
	u64 word;
} cache_addr_t;

#define ADDR_VALID_MASK		(1 << 0)

#define GVA_ADDR		gva.fields.addr
#define GVA_FLAGS		gva.fields.flags
#define GVA_WHOLE		gva.word

/* Cache "cell" with gva -> gpa,hva translation */
typedef struct gva_cache_cell {
	cache_addr_t gva;
	gfn_t gfn;
	u32 pte_access;
	u32 level;
	u64 replace_data;
} gva_cache_cell_t;

/* gva -> gpa cache size */
#define KVM_GVA_CACHE_SZ		PAGE_SIZE
/* 2 ^ KVM_GVA_CACHE_BUCKET_BITS buckets in cache */
#define KVM_GVA_CACHE_BUCKET_BITS	6
#define KVM_GVA_CACHE_BUCKETS		(1 << KVM_GVA_CACHE_BUCKET_BITS)
#define KVM_GVA_CACHE_BUCKET_SZ		\
		(KVM_GVA_CACHE_SZ / KVM_GVA_CACHE_BUCKETS)
#define KVM_GVA_CACHE_BUCKET_LEN	\
	(KVM_GVA_CACHE_BUCKET_SZ / sizeof(gva_cache_cell_t))
#define KVM_GVA_CACHE_LEN		\
	(KVM_GVA_CACHE_SZ / sizeof(gva_cache_cell_t))
/* maximum gva range len for partial flush  */
#define KVM_GVA_CACHE_FLUSH_THRESHOLD	6

typedef enum REPLACE_POLICY {
	LRU = 0,
	RAND = 1
} replace_policy_t;

/*
 * gva cache stores translations from gva to gpa and hva to avoid
 * guest page table and kvm memory slots lookup.
 */
typedef struct gva_cache {
	spinlock_t cache_lock;
	gva_cache_cell_t *data;
	replace_policy_t replace_policy;
} gva_cache_t;

typedef struct gva_translation {
	gva_t gva;
	gpa_t gpa;
	u32 pte_access;
	u32 level;
} gva_translation_t;

typedef struct gva_cache_query {
	gva_t gva;
	u32 access;
} gva_cache_query_t;


typedef gpa_t (*gva_translator_t)(struct kvm_vcpu *, gva_t,
			u32, struct kvm_arch_exception*, gw_attr_t *);

gpa_t gva_cache_translate(gva_cache_t *cache, gva_t gva, u32 access,
			struct kvm_vcpu *vcpu, kvm_arch_exception_t *exc,
			gva_translator_t gva_translate);
void gva_cache_fetch_addr(gva_cache_t *cache, gva_t gva, gpa_t gpa,
			u32 access);
void gva_cache_flush_addr(gva_cache_t *cache, gva_t gva);
void gva_cache_flush_addr_range(gva_cache_t *cache, gva_t start_gva,
				gva_t end_gva);
gva_cache_t *gva_cache_init(void);
void gva_cache_erase(gva_cache_t *cache);


#ifdef CONFIG_KVM_GVA_CACHE_STAT

int gva_cache_stat_dev_init(void);

/* Statistics of access to gva->gpa cache */
typedef struct gva_caches_stat {
	u64 accesses;
	u64 hits;
	u64 misses;

	u64 sum_hit_time;
	u64 sum_miss_pen;
	u64 conflict_misses;
	u64 cold_misses;

	u64 flushes_gva;
	u64 flushes_all;
	u64 sum_flush_gva_time;
	u64 sum_flush_all_time;

	u64 fetches;
	u64 update_fetches;
	u64 conflict_fetches;
	u64 cold_fetches;
	u64 sum_fetch_time;
} gva_caches_stat_t;

extern gva_caches_stat_t caches_stat;

#define gva_cache_stat_lookup_start()				\
	caches_stat.accesses++;					\
	u64 stop, start = ktime_get_ns()

#define gva_cache_stat_lookup_hit_end()				\
({								\
	stop = ktime_get_ns();					\
	caches_stat.hits++;					\
	caches_stat.sum_hit_time += (stop - start);		\
})

#define gva_cache_stat_lookup_miss_start()			\
({								\
	caches_stat.misses++;					\
	start = ktime_get_ns();					\
})

#define gva_cache_stat_lookup_miss_stop()			\
({								\
	stop = ktime_get_ns();					\
	caches_stat.sum_miss_pen += (stop - start);		\
})

#define gva_cache_stat_lookup_miss_conflict(is_conflict)	\
({								\
	if (is_conflict)					\
		caches_stat.conflict_misses++;			\
	else							\
		caches_stat.cold_misses++;			\
})

#define gva_cache_stat_replace_conflict(is_conflict, conflict)	\
({								\
	if (is_conflict)					\
		*is_conflict = conflict;			\
})

#define gva_cache_stat_fetch_start()				\
	caches_stat.accesses++;					\
	caches_stat.fetches++;					\
	u64 stop, start = ktime_get_ns()

#define gva_cache_stat_fetch_end()				\
({								\
	stop = ktime_get_ns();					\
	caches_stat.sum_fetch_time += (stop - start);		\
})

#define gva_cache_stat_fetch_replace(conflict)			\
({								\
	if (conflict)						\
		caches_stat.conflict_fetches++;			\
	else							\
		caches_stat.cold_fetches++;			\
})

#define gva_cache_stat_fetch_update()				\
({								\
	caches_stat.update_fetches++;				\
})

#define gva_cache_stat_flush_gva_start()			\
	caches_stat.accesses++;					\
	caches_stat.flushes_gva++;				\
	u64 stop, start = ktime_get_ns()

#define gva_cache_stat_flush_gva_end()				\
({								\
	stop = ktime_get_ns();					\
	caches_stat.sum_flush_gva_time += (stop - start);	\
})

#define gva_cache_stat_flush_all_start()			\
	caches_stat.accesses++;					\
	caches_stat.flushes_all++;				\
	u64 stop, start = ktime_get_ns()

#define gva_cache_stat_flush_all_end()				\
({								\
	stop = ktime_get_ns();					\
	caches_stat.sum_flush_all_time += (stop - start);	\
})


#else /* !CONFIG_KVM_GVA_CACHE_STAT */

#define gva_cache_stat_lookup_start()
#define gva_cache_stat_lookup_hit_end()
#define gva_cache_stat_lookup_miss_start()
#define gva_cache_stat_lookup_miss_stop()
#define gva_cache_stat_lookup_miss_stop()
#define gva_cache_stat_lookup_miss_conflict(is_conflict)
#define gva_cache_stat_replace_conflict(is_conflict, conflict)
#define gva_cache_stat_fetch_start()
#define gva_cache_stat_fetch_end()
#define gva_cache_stat_fetch_replace(conflict)
#define gva_cache_stat_fetch_update()
#define gva_cache_stat_flush_gva_start()
#define gva_cache_stat_flush_gva_end()
#define gva_cache_stat_flush_all_start()
#define gva_cache_stat_flush_all_end()

#endif /* !CONFIG_KVM_GVA_CACHE_STAT */


#ifdef CONFIG_KVM_GVA_CACHE_DEBUG

#define DbgGvaCache(fmt, args...)					\
({									\
	pr_info("%s(): " fmt, __func__, ##args);			\
})

#else /* !CONFIG_KVM_GVA_CACHE_DEBUG */
#define DbgGvaCache(fmt, args...)
#endif /* !CONFIG_KVM_GVA_CACHE_DEBUG */


#endif /* GVA_CACHE_H */
