#if !defined(_TRACE_KVMMMU_E2K_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVMMMU_E2K_H

#include <linux/tracepoint.h>
#include <linux/trace_events.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvmmmu

#define KVM_MMU_PAGE_FIELDS			\
	__field(unsigned long, mmu_valid_gen)	\
	__field(__u64, gfn)			\
	__field(__u64, gva)			\
	__field(__u64, gpt_gpa)			\
	__field(__u32, role)			\
	__field(__u32, root_count)		\
	__field(bool, unsync)

#define KVM_MMU_PAGE_ASSIGN(sp)				\
	__entry->mmu_valid_gen = sp->mmu_valid_gen;	\
	__entry->gfn = sp->gfn;				\
	__entry->gpt_gpa = sp->huge_gpt_gpa;		\
	__entry->gva = sp->gva;				\
	__entry->role = sp->role.word;			\
	__entry->root_count = sp->root_count;		\
	__entry->unsync = sp->unsync;

#define KVM_MMU_PAGE_PRINTK() ({					\
	const char *saved_ptr = trace_seq_buffer_ptr(p);		\
	static const char *access_str[] = {				\
		"---", "--x", "w--", "w-x", "-u-", "-ux", "wu-", "wux"	\
	};								\
	union kvm_mmu_page_role role;					\
									\
	role.word = __entry->role;					\
									\
	trace_seq_printf(p, "sp gen %lx gfn %llx gpt gpa %llx "		\
			"gva %llx %u %s %s %s"				\
			 " %snxe root %u %s%c",	__entry->mmu_valid_gen,	\
			 __entry->gfn, __entry->gpt_gpa,		\
			 __entry->gva, role.level,			\
			 role.direct ? " direct" : "",			\
			 access_str[role.access],			\
			 role.invalid ? " invalid" : "",		\
			 role.nxe ? "" : "!",				\
			 __entry->root_count,				\
			 __entry->unsync ? "unsync" : "sync", 0);	\
	saved_ptr;							\
		})

#define	KVM_MMU_PT_LEVEL_NAME(__level)					\
	(((__level) == E2K_PGD_LEVEL_NUM) ? "pgd" : \
		(((__level) == E2K_PUD_LEVEL_NUM) ? "pud" : \
			(((__level) == E2K_PMD_LEVEL_NUM) ? "pmd" : \
				(((__level) == E2K_PTE_LEVEL_NUM) ? \
							"pte" : "???"))))

#define kvm_mmu_trace_pferr_flags		\
	{ PFERR_PRESENT_MASK, "P" },		\
	{ PFERR_WRITE_MASK, "W" },		\
	{ PFERR_USER_MASK, "U" },		\
	{ PFERR_RSVD_MASK, "RSVD" },		\
	{ PFERR_NOT_PRESENT_MASK, "NotP" },	\
	{ PFERR_PT_FAULT_MASK, "PF" },		\
	{ PFERR_INSTR_FAULT_MASK, "IF" },	\
	{ PFERR_INSTR_PROT_MASK, "IP" },	\
	{ PFERR_FORCED_MASK, "Empty" },		\
	{ PFERR_WAIT_LOCK_MASK, "WLock" },	\
	{ PFERR_GPTE_CHANGED_MASK, "GpteCH" },	\
	{ PFERR_MMIO_MASK, "MMIO" },		\
	{ PFERR_ONLY_VALID_MASK, "OValid" },	\
	{ PFERR_READ_PROT_MASK, "RProt" },	\
	{ PFERR_IS_UNMAPPED_MASK, "UNMap" },	\
	{ PFERR_FAPB_MASK, "UNMap" },		\
	{ PFERR_FETCH_MASK, "F" }

/*
 * A pagetable walk has started
 */
TRACE_EVENT(
	kvm_mmu_pagetable_walk,
	TP_PROTO(u64 addr, u32 pferr),
	TP_ARGS(addr, pferr),

	TP_STRUCT__entry(
		__field(__u64, addr)
		__field(__u32, pferr)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->pferr = pferr;
	),

	TP_printk("addr %llx pferr %x %s size %d", __entry->addr, __entry->pferr,
		  __print_flags(__entry->pferr, "|", kvm_mmu_trace_pferr_flags),
		  PFRES_GET_ACCESS_SIZE(__entry->pferr))
);

/* We just walked a paging element */
TRACE_EVENT(
	kvm_mmu_paging_element,
	TP_PROTO(pgprot_t pte, int level),
	TP_ARGS(pte, level),

	TP_STRUCT__entry(
		__field(pgprotval_t, pte)
		__field(__u32, level)
		),

	TP_fast_assign(
		__entry->pte = pgprot_val(pte);
		__entry->level = level;
		),

	TP_printk("level #%u %s : %lx",
		__entry->level,
		KVM_MMU_PT_LEVEL_NAME(__entry->level),
		__entry->pte)
);

DECLARE_EVENT_CLASS(kvm_mmu_set_bit_class,

	TP_PROTO(unsigned long table_gfn, unsigned index, unsigned size),

	TP_ARGS(table_gfn, index, size),

	TP_STRUCT__entry(
		__field(__u64, gpa)
	),

	TP_fast_assign(
		__entry->gpa = ((u64)table_gfn << PAGE_SHIFT)
				+ index * size;
		),

	TP_printk("gpa %llx", __entry->gpa)
);

/* We set a pte accessed bit */
DEFINE_EVENT(kvm_mmu_set_bit_class, kvm_mmu_set_accessed_bit,

	TP_PROTO(unsigned long table_gfn, unsigned index, unsigned size),

	TP_ARGS(table_gfn, index, size)
);

/* We set a pte dirty bit */
DEFINE_EVENT(kvm_mmu_set_bit_class, kvm_mmu_set_dirty_bit,

	TP_PROTO(unsigned long table_gfn, unsigned index, unsigned size),

	TP_ARGS(table_gfn, index, size)
);

TRACE_EVENT(
	kvm_mmu_walker_error,
	TP_PROTO(u32 pferr),
	TP_ARGS(pferr),

	TP_STRUCT__entry(
		__field(__u32, pferr)
		),

	TP_fast_assign(
		__entry->pferr = pferr;
		),

	TP_printk("pferr %x %s size %d", __entry->pferr,
		  __print_flags(__entry->pferr, "|", kvm_mmu_trace_pferr_flags),
		  PFRES_GET_ACCESS_SIZE(__entry->pferr))
);

TRACE_EVENT(
	mmu_topup_memory_cache,

	TP_PROTO(const char *name, int cur_nobjs, int min_nobjs, int added_nobjs),

	TP_ARGS(name, cur_nobjs, min_nobjs, added_nobjs),

	TP_STRUCT__entry(
		__field(const char *,		name		)
		__field(int,			cur		)
		__field(int,			min		)
		__field(int,			add		)
	),

	TP_fast_assign(
		__entry->name = name;
		__entry->cur = cur_nobjs;
		__entry->min = min_nobjs;
		__entry->add = added_nobjs;
	),

	TP_printk("\nadd new objects to %s cache was %d min %d added %d\n",
		__entry->name, __entry->cur, __entry->min, __entry->add)
);

TRACE_EVENT(
	mmu_free_memory_cache,

	TP_PROTO(const char *name, int cur_nobjs),

	TP_ARGS(name, cur_nobjs),

	TP_STRUCT__entry(
		__field(const char *,		name		)
		__field(int,			cur		)
	),

	TP_fast_assign(
		__entry->name = name;
		__entry->cur = cur_nobjs;
	),

	TP_printk("\nfree all %d objects from %s cache\n",
		__entry->cur, __entry->name)
);

TRACE_EVENT(
	mmu_memory_cache_alloc_obj,

	TP_PROTO(const char *name, int cur_nobjs),

	TP_ARGS(name, cur_nobjs),

	TP_STRUCT__entry(
		__field(const char *,		name		)
		__field(int,			cur		)
	),

	TP_fast_assign(
		__entry->name = name;
		__entry->cur = cur_nobjs;
	),

	TP_printk("\nalloc new object outside %s cache, at cache now %d objects\n",
		__entry->name, __entry->cur)
);

TRACE_EVENT(
	mmu_memory_cache_alloc,

	TP_PROTO(const char *name, int cur_nobjs),

	TP_ARGS(name, cur_nobjs),

	TP_STRUCT__entry(
		__field(const char *,		name		)
		__field(int,			cur		)
	),

	TP_fast_assign(
		__entry->name = name;
		__entry->cur = cur_nobjs;
	),

	TP_printk("\nget object from %s cache, at cache was %d objects\n",
		__entry->name, __entry->cur)
);

DECLARE_EVENT_CLASS(
	kvm_gmm_get_put_class,
	TP_PROTO(const char *from_or_to, struct kvm_vcpu *vcpu,
		 gthread_info_t *gti, gmm_struct_t *gmm),
	TP_ARGS(from_or_to, vcpu, gti, gmm),

	TP_STRUCT__entry(
		__field(const char *, comment)
		__field(int, vcpu_id)
		__field(int, gti_id)
		__field(int, gmm_id)
		__field(int, count)
		),

	TP_fast_assign(
		__entry->comment = from_or_to;
		__entry->vcpu_id = (vcpu != NULL) ? vcpu->vcpu_id : -1;
		__entry->gti_id = (gti != NULL) ? gti->gpid->nid.nr : -1;
		__entry->gmm_id = (gmm != NULL) ? gmm->id : -1;
		__entry->count = (gmm != NULL) ? atomic_read(&gmm->mm_count) : -1;
		),

	TP_printk("vcpu #%d\n"
		  "       %s\n"
		  "       gti #%d, gmm #%d, mm count is now %d\n",
		__entry->vcpu_id, __entry->comment,
		__entry->gti_id, __entry->gmm_id, __entry->count)
);

DEFINE_EVENT(kvm_gmm_get_put_class, kvm_gmm_get,
	TP_PROTO(const char *from_or_to, struct kvm_vcpu *vcpu,
		 gthread_info_t *gti, gmm_struct_t *gmm),
	TP_ARGS(from_or_to, vcpu, gti, gmm)
);

DEFINE_EVENT(kvm_gmm_get_put_class, kvm_gmm_put,
	TP_PROTO(const char *from_or_to, struct kvm_vcpu *vcpu,
		 gthread_info_t *gti, gmm_struct_t *gmm),
	TP_ARGS(from_or_to, vcpu, gti, gmm)
);

TRACE_EVENT(
	kvm_mmu_get_page,
	TP_PROTO(struct kvm_mmu_page *sp, bool created),
	TP_ARGS(sp, created),

	TP_STRUCT__entry(
		KVM_MMU_PAGE_FIELDS
		__field(bool, created)
		),

	TP_fast_assign(
		KVM_MMU_PAGE_ASSIGN(sp)
		__entry->created = created;
		),

	TP_printk("%s %s", KVM_MMU_PAGE_PRINTK(),
		  __entry->created ? "new" : "existing")
);

DECLARE_EVENT_CLASS(kvm_mmu_page_class,

	TP_PROTO(struct kvm_mmu_page *sp),
	TP_ARGS(sp),

	TP_STRUCT__entry(
		KVM_MMU_PAGE_FIELDS
	),

	TP_fast_assign(
		KVM_MMU_PAGE_ASSIGN(sp)
	),

	TP_printk("%s", KVM_MMU_PAGE_PRINTK())
);

DEFINE_EVENT(kvm_mmu_page_class, kvm_mmu_sync_page,
	TP_PROTO(struct kvm_mmu_page *sp),

	TP_ARGS(sp)
);

DEFINE_EVENT(kvm_mmu_page_class, kvm_mmu_unsync_page,
	TP_PROTO(struct kvm_mmu_page *sp),

	TP_ARGS(sp)
);

DEFINE_EVENT(kvm_mmu_page_class, kvm_mmu_prepare_zap_page,
	TP_PROTO(struct kvm_mmu_page *sp),

	TP_ARGS(sp)
);

TRACE_EVENT(
	kvm_sync_shadow_pt_range,
	TP_PROTO(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
		 hpa_t spt_root, gpa_t guest_root,
		 gva_t start, gva_t end),
	TP_ARGS(vcpu, gmm, spt_root, guest_root, start, end),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(int, gmm_id)
		__field(hpa_t, spt_root)
		__field(gpa_t, guest_root)
		__field(gva_t, start)
		__field(gva_t, end)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->gmm_id = gmm->nid.nr;
		__entry->spt_root = spt_root;
		__entry->guest_root = guest_root;
		__entry->start = start;
		__entry->end = end;
	),

	TP_printk("\n"
		"vcpu #%d gmm id #%d sync range from %lx to %lx root: spt %llx "
		"guest %llx",
		__entry->vcpu_id, __entry->gmm_id, __entry->start, __entry->end,
		__entry->spt_root, __entry->guest_root
	)
);

/*
 * A pagetable walk has started
 */
TRACE_EVENT(
	kvm_sync_shadow_gva,
	TP_PROTO(gva_t gva, int level),
	TP_ARGS(gva, level),

	TP_STRUCT__entry(
		__field(gva_t, gva)
		__field(int, level)
	),

	TP_fast_assign(
		__entry->gva = gva;
		__entry->level = level;
	),

	TP_printk("guest addr %lx level #%d",
		__entry->gva, __entry->level)
);

TRACE_EVENT(
	kvm_sync_gpte,
	TP_PROTO(gva_t gva, pgprot_t *sptep, gpa_t gpte, pgprotval_t pte,
		 int level),
	TP_ARGS(gva, sptep, gpte, pte, level),

	TP_STRUCT__entry(
		__field(gva_t, gva)
		__field(pgprot_t *, sptep)
		__field(gpa_t, gpte)
		__field(pgprotval_t, spte)
		__field(pgprotval_t, pte)
		__field(int, level)
		),

	TP_fast_assign(
		__entry->gva = gva,
		__entry->sptep = sptep;
		__entry->gpte = gpte,
		__entry->spte = pgprot_val(*sptep);
		__entry->pte = pte;
		__entry->level = level;
		),

	TP_printk("guest addr %lx level #%u\n"
		" %s shadow %016lx : %016lx guest %016llx : %016lx",
		__entry->gva, __entry->level,
		KVM_MMU_PT_LEVEL_NAME(__entry->level),
		(unsigned long)__entry->sptep, __entry->spte,
		__entry->gpte, __entry->pte)
);

TRACE_EVENT(
	kvm_sync_only_valid,
	TP_PROTO(pgprot_t *sptep, int level),
	TP_ARGS(sptep, level),

	TP_STRUCT__entry(
		__field(pgprot_t *, sptep)
		__field(pgprotval_t, spte)
		__field(int, level)
		),

	TP_fast_assign(
		__entry->sptep = sptep;
		__entry->spte = pgprot_val(*sptep);
		__entry->level = level;
		),

	TP_printk("level #%u\n"
		" %s shadow %016lx : %016lx",
		__entry->level,
		KVM_MMU_PT_LEVEL_NAME(__entry->level),
		(unsigned long)__entry->sptep, __entry->spte)
);

TRACE_EVENT(
	kvm_sync_spte,
	TP_PROTO(pgprot_t *sptep, pgprot_t old_spte, int level),
	TP_ARGS(sptep, old_spte, level),

	TP_STRUCT__entry(
		__field(pgprot_t *, sptep)
		__field(pgprotval_t, old_spte)
		__field(pgprotval_t, new_spte)
		__field(int, level)
		),

	TP_fast_assign(
		__entry->sptep = sptep;
		__entry->old_spte = pgprot_val(old_spte);
		__entry->new_spte = pgprot_val(*sptep);
		__entry->level = level;
		),

	TP_printk("level #%u\n"
		" %s shadow %016lx : old %016lx new %016lx",
		__entry->level,
		KVM_MMU_PT_LEVEL_NAME(__entry->level),
		(unsigned long)__entry->sptep,
		__entry->old_spte, __entry->new_spte)
);

TRACE_EVENT(
	kvm_sync_drop_pfn_spte,
	TP_PROTO(pgprot_t *sptep, gfn_t old_pfn, int level),
	TP_ARGS(sptep, old_pfn, level),

	TP_STRUCT__entry(
		__field(pgprot_t *, sptep)
		__field(gfn_t, old_pfn)
		__field(pgprotval_t, spte)
		__field(int, level)
		),

	TP_fast_assign(
		__entry->sptep = sptep;
		__entry->old_pfn = old_pfn;
		__entry->spte = pgprot_val(*sptep);
		__entry->level = level;
		),

	TP_printk("level #%u\n"
		" %s shadow %016lx : %016lx old pfn %llx",
		__entry->level,
		KVM_MMU_PT_LEVEL_NAME(__entry->level),
		(unsigned long)__entry->sptep,
		__entry->spte, __entry->old_pfn)
);

TRACE_EVENT(
	kvm_sync_spt_level,
	TP_PROTO(pgprot_t *sptep, pgprot_t old_spte, int level),
	TP_ARGS(sptep, old_spte, level),

	TP_STRUCT__entry(
		__field(pgprot_t *, sptep)
		__field(pgprotval_t, old_spte)
		__field(pgprotval_t, new_spte)
		__field(int, level)
		),

	TP_fast_assign(
		__entry->sptep = sptep;
		__entry->old_spte = pgprot_val(old_spte);
		__entry->new_spte = pgprot_val(*sptep);
		__entry->level = level;
		),

	TP_printk("level #%u\n"
		" %s shadow %016lx : old %016lx new %016lx",
		__entry->level,
		KVM_MMU_PT_LEVEL_NAME(__entry->level),
		(unsigned long)__entry->sptep,
		__entry->old_spte, __entry->new_spte)
);

TRACE_EVENT(
	mark_mmio_spte,
	TP_PROTO(pgprot_t *sptep, gfn_t gfn, unsigned access, unsigned int gen),
	TP_ARGS(sptep, gfn, access, gen),

	TP_STRUCT__entry(
		__field(void *, sptep)
		__field(gfn_t, gfn)
		__field(unsigned, access)
		__field(unsigned int, gen)
	),

	TP_fast_assign(
		__entry->sptep = sptep;
		__entry->gfn = gfn;
		__entry->access = access;
		__entry->gen = gen;
	),

	TP_printk("sptep:%px gfn %llx access %x gen %x", __entry->sptep,
		  __entry->gfn, __entry->access, __entry->gen)
);

TRACE_EVENT(
	handle_mmio_page_fault,
	TP_PROTO(u64 addr, gfn_t gfn, unsigned access),
	TP_ARGS(addr, gfn, access),

	TP_STRUCT__entry(
		__field(u64, addr)
		__field(gfn_t, gfn)
		__field(unsigned, access)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->gfn = gfn;
		__entry->access = access;
	),

	TP_printk("addr:%llx gfn %llx access %x", __entry->addr, __entry->gfn,
		  __entry->access)
);

TRACE_EVENT(
	kvm_gva_to_gpa,
	TP_PROTO(struct kvm_vcpu *vcpu, gva_t gva, u32 access),
	TP_ARGS(vcpu, gva, access),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(gva_t, gva)
		__field(__u32, access)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->gva = gva;
		__entry->access = access;
	),

	TP_printk("vcpu #%d guest addr %lx access %x %s",
		__entry->vcpu_id, __entry->gva,
		__entry->access,
		__print_flags(__entry->access, "|", kvm_mmu_trace_pferr_flags)
	)
);

TRACE_EVENT(
	kvm_spt_page_fault,
	TP_PROTO(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
		 gva_t gva, u32 error_code),
	TP_ARGS(vcpu, gmm, gva, error_code),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(int, gmm_id)
		__field(gva_t, gva)
		__field(u32, error_code)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->gmm_id = gmm->nid.nr;
		__entry->gva = gva;
		__entry->error_code = error_code;
	),

	TP_printk("vcpu #%d gmm id #%d addr %lx error_code %s size %d",
		  __entry->vcpu_id, __entry->gmm_id,
		  __entry->gva,
		  __print_flags(__entry->error_code, "|", kvm_mmu_trace_pferr_flags),
		  PFRES_GET_ACCESS_SIZE(__entry->error_code)
	)
);

TRACE_EVENT(
	spt_ptotection_fault,
	TP_PROTO(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
		 struct kvm_mmu_page *sp, gva_t pt_addr,
		 gva_t map_start, gva_t map_end,
		 hpa_t spt_root, gpa_t guest_root),
	TP_ARGS(vcpu, gmm, sp, pt_addr, map_start, map_end, spt_root, guest_root),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(int, gmm_id)
		__field(hpa_t, spt_root)
		__field(gpa_t, guest_root)
		__field(gva_t, pt_addr)
		__field(gva_t, map_start)
		__field(gva_t, map_end)
		__field(int, level)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->gmm_id = gmm->nid.nr;
		__entry->spt_root = spt_root;
		__entry->guest_root = guest_root;
		__entry->pt_addr = pt_addr;
		__entry->map_start = map_start;
		__entry->map_end = map_end;
		__entry->level = sp->role.level;
	),

	TP_printk("\n"
		"vcpu #%d gmm id #%d protected guest PT level #%d at %lx "
		"map range from %lx to %lx root: spt %llx guest %llx",
		__entry->vcpu_id, __entry->gmm_id,
		__entry->level, __entry->pt_addr,
		__entry->map_start, __entry->map_end,
		__entry->spt_root, __entry->guest_root
	)
);

TRACE_EVENT(
	kvm_prefetch_gpte,
	TP_PROTO(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
		 pgprot_t *sptep, pgprotval_t gpte),
	TP_ARGS(vcpu, sp, sptep, gpte),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(int, gmm_id)
		__field(gva_t, gva)
		__field(gfn_t, gfn)
		__field(pgprot_t *, sptep)
		__field(pgprotval_t, spte)
		__field(pgprotval_t, gpte)
		__field(bool, direct)
		__field(int, level)
		),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->gmm_id = kvm_get_sp_gmm(sp)->nid.nr;
		__entry->gva = sp->gva;
		__entry->gfn = sp->gfn;
		__entry->sptep = sptep;
		__entry->spte = pgprot_val(*sptep);
		__entry->gpte = gpte;
		__entry->level = sp->role.level;
		__entry->direct = sp->role.direct;
		),

	TP_printk("guest addr %lx %s gfn %llx\n"
		"vcpu #%d gmm id #%d level #%u %s shadow %016lx : %016lx "
		"guest %016lx",
		__entry->gva, (__entry->direct) ? "direct page" : "shadow pt",
		__entry->gfn,
		__entry->vcpu_id, __entry->gmm_id, __entry->level,
		KVM_MMU_PT_LEVEL_NAME(__entry->level),
		(unsigned long)__entry->sptep, __entry->spte,
		__entry->gpte)
);

#define __spte_satisfied(__spte)	\
		(__entry->retry && is_writable_pte(__pgprot(__entry->__spte)))

TRACE_EVENT(
	fast_page_fault,
	TP_PROTO(struct kvm_vcpu *vcpu, gva_t gva, u32 error_code,
		 pgprot_t *sptep, pgprot_t old_spte, bool retry),
	TP_ARGS(vcpu, gva, error_code, sptep, old_spte, retry),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(gva_t, gva)
		__field(u32, error_code)
		__field(pgprot_t *, sptep)
		__field(pgprotval_t, old_spte)
		__field(pgprotval_t, new_spte)
		__field(bool, retry)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->gva = gva;
		__entry->error_code = error_code;
		__entry->sptep = sptep;
		__entry->old_spte = pgprot_val(old_spte);
		__entry->new_spte = pgprot_val(*sptep);
		__entry->retry = retry;
	),

	TP_printk("vcpu %d gva %lx error_code %s sptep %px old %#lx"
		  " new %lx spurious %d fixed %d", __entry->vcpu_id,
		  __entry->gva, __print_flags(__entry->error_code, "|",
		  kvm_mmu_trace_pferr_flags), __entry->sptep,
		  __entry->old_spte, __entry->new_spte,
		  __spte_satisfied(old_spte), __spte_satisfied(new_spte)
	)
);

TRACE_EVENT(
	kvm_mmu_invalidate_zap_all_pages,
	TP_PROTO(struct kvm *kvm),
	TP_ARGS(kvm),

	TP_STRUCT__entry(
		__field(unsigned long, mmu_valid_gen)
		__field(unsigned int, mmu_used_pages)
	),

	TP_fast_assign(
		__entry->mmu_valid_gen = kvm->arch.mmu_valid_gen;
		__entry->mmu_used_pages = kvm->arch.n_used_mmu_pages;
	),

	TP_printk("kvm-mmu-valid-gen %lx used_pages %x",
		  __entry->mmu_valid_gen, __entry->mmu_used_pages
	)
);


TRACE_EVENT(
	check_mmio_spte,
	TP_PROTO(pgprot_t spte, unsigned int kvm_gen, unsigned int spte_gen),
	TP_ARGS(spte, kvm_gen, spte_gen),

	TP_STRUCT__entry(
		__field(unsigned int, kvm_gen)
		__field(unsigned int, spte_gen)
		__field(pgprotval_t, spte)
	),

	TP_fast_assign(
		__entry->kvm_gen = kvm_gen;
		__entry->spte_gen = spte_gen;
		__entry->spte = pgprot_val(spte);
	),

	TP_printk("spte %lx kvm_gen %x spte-gen %x valid %d", __entry->spte,
		  __entry->kvm_gen, __entry->spte_gen,
		  __entry->kvm_gen == __entry->spte_gen
	)
);
#endif /* _TRACE_KVMMMU_E2K_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/kvm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE mmutrace-e2k

/* This part must be outside protection */
#include <trace/define_trace.h>
