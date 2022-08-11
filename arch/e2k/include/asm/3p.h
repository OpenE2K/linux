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
extern int lw_global_sp(struct pt_regs *regs);
extern void free_global_sp(void);
extern int delete_records(unsigned int psl_from);
extern void mark_all_global_sp(struct pt_regs *regs, pid_t pid);
extern int interpreted_ap_code(struct pt_regs *regs,
		struct vm_area_struct **vma, e2k_addr_t *address);

struct syscall_attrs {
	u32  mask; /* for coding specs see systable.c */
	/* The next 6 fields specify minimum allowed argument size
	 *                          in case of argument-descriptor.
	 * If negative value, this means size is defined by corresponding arg.
	 *             F.e. value (-3) means size is specified by argument #3.
	 */
	short size1; /* min allowed size of arg1 of particular system call */
	short size2; /* minimum allowed size of arg2  */
	short size3; /* minimum allowed size of arg3  */
	short size4; /* minimum allowed size of arg4  */
	u16 size5; /* minimum allowed size of arg5  */
	u16 size6; /* minimum allowed size of arg6  */
} __aligned(16) /* For faster address calculation */;
extern const struct syscall_attrs sys_protcall_args[];
extern const char *sys_call_ID_to_name[];

/*
 * Definition of ttable entry number used for protected system calls.
 * This is under agreement with protected mode compiler/plib team.
 */
#define	PMODE_NEW_SYSCALL_TRAPNUM	10

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
