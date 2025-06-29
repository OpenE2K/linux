/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#if !defined(_TRACE_HOST_GMM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOST_GMM_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM gmm

TRACE_EVENT(host_gmm_root_hpa,

	TP_PROTO(gmm_struct_t *gmm, hpa_t root, hpa_t gk_root,
		 unsigned long ip),

	TP_ARGS(gmm, root, gk_root, ip),

	TP_STRUCT__entry(
		__field(void *,	gmm)
		__field(unsigned long, ip)
		__field(int, id)
		__field(hpa_t, root)
		__field(hpa_t, gk_root)
	),

	TP_fast_assign(
		__entry->gmm = (void *)gmm;
		__entry->id = gmm->id;
		__entry->ip = ip;
		__entry->root = root;
		__entry->gk_root = gk_root;
	),

	TP_printk("gmm #%d %px at %psx\n"
		"   root: user 0x%012llx, gk 0x%012llx\n",
		__entry->id, __entry->gmm, (void *)__entry->ip,
		__entry->root, __entry->gk_root)
);

TRACE_EVENT(
	host_get_gmm_root_hpa,

	TP_PROTO(gmm_struct_t *gmm, unsigned long ip),

	TP_ARGS(gmm, ip),

	TP_STRUCT__entry(
		__field(void *,	gmm)
		__field(unsigned long, ip)
		__field(int, id)
		__field(hpa_t, root)
		__field(hpa_t, gk_root)
	),

	TP_fast_assign(
		__entry->gmm = (void *)gmm;
		__entry->id = gmm->id;
		__entry->ip = ip;
		__entry->root = gmm->root_hpa;
		__entry->gk_root = gmm->gk_root_hpa;
	),

	TP_printk("gmm #%d %px at %psx\n"
		"   root: user 0x%012llx, gk 0x%012llx\n",
		__entry->id, __entry->gmm, (void *)__entry->ip,
		__entry->root, __entry->gk_root)
);

TRACE_EVENT(
	host_set_gmm_root_hpa,

	TP_PROTO(gmm_struct_t *gmm, hpa_t old_root, hpa_t old_gk_root,
		 unsigned long ip),

	TP_ARGS(gmm, old_root, old_gk_root, ip),

	TP_STRUCT__entry(
		__field(void *,	gmm)
		__field(unsigned long, ip)
		__field(int, id)
		__field(hpa_t, old_root)
		__field(hpa_t, old_gk_root)
		__field(hpa_t, root)
		__field(hpa_t, gk_root)
	),

	TP_fast_assign(
		__entry->gmm = (void *)gmm;
		__entry->id = gmm->id;
		__entry->ip = ip;
		__entry->old_root = old_root;
		__entry->old_gk_root = old_gk_root;
		__entry->root = gmm->root_hpa;
		__entry->gk_root = gmm->gk_root_hpa;
	),

	TP_printk("gmm #%d %px at %psx\n"
		"   root old: user 0x%012llx, gk 0x%012llx\n"
		"        new:      0x%012llx,    0x%012llx\n",
		__entry->id, __entry->gmm, (void *)__entry->ip,
		__entry->old_root, __entry->old_gk_root,
		__entry->root, __entry->gk_root)
);

#endif /* _TRACE_HOST_GMM_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/kvm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace-gmm

/* This part must be outside protection */
#include <trace/define_trace.h>
