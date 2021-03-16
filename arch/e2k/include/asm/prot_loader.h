#ifndef _E2K_PROT_LOADER_H_
#define _E2K_PROT_LOADER_H_

#include <asm/e2k_ptypes.h>

#define USE_ELF64 0

#define	ARGS_AS_ONE_ARRAY

#define	E2k_ELF_ARGV_IND	0
#define	E2k_ELF_ENVP_IND	1
#define	E2k_ELF_AUX_IND		2
#define	E2k_ELF_ARG_NUM_AP	3

#define DT_PLTGOTSZ		0x7000101b
#define DT_INIT_GOT		0x7000101c

#ifdef CONFIG_HAVE_FUTEX_CMPXCHG
#define futex_cmpxchg_enabled 1
#else
extern int  __read_mostly futex_cmpxchg_enabled;
#endif

typedef struct {
	e2k_pl_t	mdd_init_got;
	e2k_ptr_t	mdd_got;
} umdd_t;
#define MDD_PROT_SIZE	((sizeof(umdd_t) + 15) & ~15)

typedef struct {
	e2k_pl_lo_t	mdd_init_got;
	e2k_pl_lo_t	mdd_init;
	e2k_pl_lo_t	mdd_fini;
	e2k_pl_lo_t	mdd_start;
	e2k_ptr_t	mdd_got;
	/* By a call descriptors of the areas of memory containing preparations
	 * are located here (without external tags) for formation of the tagged
	 * values placed in sections .gott (OT), .gctt (CT) and .gompt (OMP)
	 * of the loaded module. */
	e2k_ptr_t	mdd_gtt[3];
} umdd_old_t;
#define MDD_OLD_PROT_SIZE	((sizeof(umdd_old_t) + 15) & ~15)

typedef struct {
	u64		got_addr;
	u64		got_len;
	u32		cui;
	u64		init_got_point;
	u64		entry_point;
	u64		init_point;
	u64		fini_point;
} kmdd_t;

	/* It's here for compatibility with old loader    */

typedef enum {
	RTL_FT_NONE,   /* The type isn't defined */
	RTL_FT_EXE,    /* Loading file */
	RTL_FT_LIB,    /* Dynamic library */
	RTL_FT_DRV     /* System driver */
} rtl_FileType_t;

typedef struct rtl_Unit_s rtl_Unit_t;

struct rtl_Unit_s {
	char *u_code;               /* The pointer on code sector */
	char *u_data;               /* The pointer on data sector */
	char *u_name;               /* Module name */
	char *u_fullname;           /* Module full name */
	char *u_type_map;
	char *u_type_structs;       /* The pointer on the array of structures
				     * for construction of templates */
	char *u_type_structs_end;   /* The pionter for the end of the array
				     * of structures */
	rtl_Unit_t *u_next;         /* The pointer on the following module */
	rtl_Unit_t *u_prev;         /* The pointer on the previous module */
	char *u_init;               /* The pointer on function of initialization
				     * of the module */
	char *u_fini;               /* The pointer on function of a finalization
				     * of the module */
	unsigned long long u_entry; /* Entry point */
	rtl_FileType_t u_mtype;     /* Module type */
	unsigned int u_num;         /* Number of the module */
	unsigned int u_tnum;        /* Number of the first class of the
				     * module */
	unsigned int u_tcount;      /* Quantity of classes in the module */

	struct {
	unsigned long long ub_code; /* Base address of a code */
	unsigned long long ub_data; /* Base address of data */
	unsigned long long ub_bss;
	unsigned long long ub_brk;  /* Address brk */
	} base;

	struct {
	unsigned long long uc_start;    /* Code start address */
	unsigned long long uc_dataend;  /* End address data file */
	unsigned long long uc_allocend; /* End address all data */
	unsigned long long uc_mapend;   /* End address mapped memory */
	unsigned long long uc_mapoff;   /* Initial offset of a code in the
					 * file */
	unsigned int uc_prot;           /* Flags of protection of code pages */
	} code;

	struct {
	unsigned long long ud_start;    /* Initial address of data */
	unsigned long long ud_dataend;  /* End address of file data */
	unsigned long long ud_allocend; /* End address of all data */
	unsigned long long ud_mapend;   /* End address of mapped memory */
	unsigned long long ud_mapoff;   /* Initial offset of data on the file */
	unsigned int ud_prot;           /* Pprtection data data pages */
	} data;

/* ELF file */
	char *u_eheader;      /* The pointer on file title */
	char *u_pheader;      /* The pointer on program title */
	char *u_symtab;       /* The pointer on the dynamic character table */
	char *u_symtab_st;    /* The pointer on the static character table */
	char *u_strtab;       /* The pointer on the dynamic strings table */
	char *u_strtab_st;    /* The pointer on the static strings table */
	unsigned int *u_hash; /* The pointer on hash the table of symbolic
			       * names */
	char *u_got;          /* The pointer on the global table of offsets */
	char *u_gtt;          /* The pointer on global tables of types */
	char *u_type;         /* The pointer on the table of types for Xi ++ */
	char *u_dynrel;       /* The pointer on the table of dynamic
			       * relocation */
	char *u_gttrel;       /* The pointer on the table of relocation for
			       * GTT */
	char *u_typerel;      /* The pointer on the table of relocation for
			       * types */
	char *u_dyn;          /* The pointer on dynamic section */
	char *u_tobj;         /* The pointer on section of the description of
			       * classes */
	char *u_tcast;        /* The pointer on section of coercions */
	char *u_typed;        /* The pointer on section of descriptors of
			       * types */
struct {
	unsigned long long ul_code;      /* Code segment size */
	unsigned long long ul_data;      /* Data segment size */
	unsigned long long ul_strtab;    /* Size of the strings table */
	unsigned long long ul_strtab_st; /* Size of the strings table */
	unsigned long long ul_type;      /* The size of the table of types
					  * for Xi ++ */
	unsigned long long ul_dynrel;    /* Size of the table of dynamic
					  * relocation */
	unsigned long long ul_gttrel;    /* The size of the table of
					  * relocation for GTT */
	unsigned long long ul_typerel;   /* The size of the table of relocation
					  * for types */
	unsigned int ul_symtab;          /* Quantity of elements of the dynamic
					  * character table */
	unsigned int ul_symtab_st;       /* Quantity of elements of the static
					  * character table */
	unsigned int ul_hash;            /* Size table hash */
	unsigned int ul_gtt;             /* Size of the global table of types */
	unsigned int ul_tobj;            /* Size of section of member data */
	unsigned int ul_typed;           /* Size of section of types */
	unsigned int ul_tcast;           /* Size of section of reductions */
} len;

};

/*    Global Type Table (GTT) correction. C++ stuff hadling. */
extern void rtl32_CorrectionType( rtl_Unit_t *unit_p );

extern	long sys_load_cu_elf32_3P(char *name, kmdd_t *mdd);
extern	long sys_load_cu_elf64_3P(char *name, kmdd_t *mdd);

extern  long sys_unload_cu_elf32_3P(unsigned long glob_base,
						size_t glob_size);
extern  long sys_unload_cu_elf64_3P(unsigned long glob_base,
						size_t glob_size);

#endif	/* _E2K_PROT_LOADER_H_ */
	
