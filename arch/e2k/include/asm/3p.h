/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_3P_H_ 
#define _E2K_3P_H_

#ifdef __KERNEL__

#include <asm/mmu_types.h>
#include <asm/tags.h>
#include <asm/prot_loader.h>

struct vm_area_struct;
struct pt_regs;
struct file;
extern int do_global_sp(struct pt_regs *regs, trap_cellar_t *tcellar);
#ifdef CONFIG_PROTECTED_MODE
extern int lw_global_sp(struct pt_regs *regs);
#else
static inline int lw_global_sp(struct pt_regs *regs) { return 0; }
#endif
extern void free_global_sp(void);
extern int delete_records(unsigned int psl_from);
extern void mark_all_global_sp(struct pt_regs *regs, pid_t pid);
extern int interpreted_ap_code(struct pt_regs *regs,
		struct vm_area_struct **vma, e2k_addr_t *address);

/*
 * List of protected mode system calls supported.
 * For the moment it covers all the calls implemented in plib library.
 */

#define __NR_P_get_mem          500
#define __NR_P_free_mem         501
#define __NR_P_dump_umem	507


/*
 * Here are some stuff that belongs to LOCAL->GLOBAL operation support
 */

typedef struct global_store_trace_record global_store_t;

typedef enum {
    TYPE_GLOBAL = 0,
    TYPE_BOUND,
    TYPE_INIT,
} type_global_type_t;

struct global_store_trace_record {
	global_store_t	*prev;  /*that is  struct list_head list; */
	global_store_t	*next;
	type_global_type_t type;
	unsigned int	lcl_psl;
	unsigned int	orig_psr_lw;   /* to keep track */
	e2k_addr_t	global_p;
	pid_t	        pid;          
	e2k_addr_t	new_address;
	e2k_addr_t	old_address;
	unsigned long	word1;         /*the first word of SAP */
	unsigned long	word2;         /*the second word of SAP */
        e2k_addr_t      sbr;
	/* 
	 * just to care about perhaps I need to store the LOCAL here
	 * as a backup.
	 */
};

#define	IS_SAP_LO(addr)						\
({								\
	e2k_rwsap_lo_struct_t *sap_lo;				\
	sap_lo = (e2k_rwsap_lo_struct_t *) addr; 		\
	(AS_SAP_STRUCT((*sap_lo)).itag == E2K_SAP_ITAG ?	\
	(NATIVE_LOAD_TAGD(addr) == E2K_SAP_LO_ETAG ? 1 : 0) : 0); \
})

#define	IS_SAP_HI(addr)                                  	\
({                                                              \
	(NATIVE_LOAD_TAGD(addr) == E2K_SAP_HI_ETAG ? 1 : 0);	\
})

#define	IS_AP_LO(addr)						\
({								\
	e2k_rwap_lo_struct_t *ap_lo;				\
	ap_lo = (e2k_rwap_lo_struct_t *) addr; 		        \
	(AS_AP_STRUCT((*ap_lo)).itag == E2K_AP_ITAG ?	        \
	(NATIVE_LOAD_TAGD(addr) == E2K_AP_LO_ETAG ? 1 : 0) : 0); \
})

#define	IS_AP_HI(addr)                                  	\
({                                                              \
	(NATIVE_LOAD_TAGD(addr) == E2K_AP_HI_ETAG ? 1 : 0);	\
})

#endif /* __KERNEL__ */

#endif /* _E2K_3P_H_ */
