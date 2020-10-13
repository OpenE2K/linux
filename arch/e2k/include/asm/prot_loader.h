#ifndef _E2K_PROT_LOADER_H_
#define _E2K_PROT_LOADER_H_

#include <asm/e2k_ptypes.h>


#define USE_ELF64 0


#define	ARGS_AS_ONE_ARRAY

#define	E2k_ELF_ARGV_IND		0
#define	E2k_ELF_ENVP_IND		1
#define	E2k_ELF_AUX_IND			2
#define	E2k_ELF_ARG_NUM_AP	3


#define DT_TCT                          0x70001005
#define DT_GOTT                         0x7000100c
#define DT_GCTT                         0x7000100d
#define DT_GOMPT                        0x7000100e
#define DT_GOTTSZ                       0x7000100f
#define DT_GCTTSZ                       0x70001010
#define DT_GOMPTSZ                      0x70001011
#define DT_PLTGOTSZ                     0x7000101b
#define DT_INIT_GOT                     0x7000101c


typedef struct {
	e2k_pl_t			mdd_init_got;
	e2k_pl_t			mdd_init;
	e2k_pl_t			mdd_fini;
	e2k_pl_t			mdd_start;
	e2k_ptr_t                       mdd_got;
        /* При вызове сюда помещаются дескрипторы областей памяти, содержащих заготовки
           (без внешних тэгов) для формирования тэгированных значений, размещаемых в секциях
           .gott (OT), .gctt (CT) и .gompt (OMP) загружаемого модуля. */
        e2k_ptr_t                       mdd_gtt[3];
} umdd_t;
#define MDD_PROT_SIZE	((sizeof (umdd_t) + 15) & ~15)


typedef struct {
	u64		got_addr;
	u64		got_len;
        char            *src_gtt_addr[3];
        u64             src_gtt_len[3];
	u64		init_got_point;
	u64		entry_point;
	u64		init_point;
	u64		fini_point;
}	kmdd_t;



	/* It's here for compatibility with old loader    */

typedef enum
{
    RTL_FT_NONE,   /**< О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫*/
    RTL_FT_EXE,    /**< О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ */
    RTL_FT_LIB,    /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ */
    RTL_FT_DRV     /**< О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫*/
} rtl_FileType_t;

typedef struct rtl_Unit_s rtl_Unit_t;

struct rtl_Unit_s
{
    char *u_code;                        /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ О©╫О©╫ */
    char *u_data;                        /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ О©╫О©╫О©╫ */
    char *u_name;                        /**< О©╫О©╫О©╫О©╫О©╫ */
    char *u_fullname;                    /**< О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ */
    char *u_type_map;
    char *u_type_structs;                /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫
                                          * О©╫О©╫О©╫О©╫ */
    char *u_type_structs_end;            /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
    rtl_Unit_t *u_next;                  /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
    rtl_Unit_t *u_prev;                  /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ */
    char *u_init;                        /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
    char *u_fini;                        /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
    unsigned long long u_entry;          /**< О©╫О©╫О©╫О©╫О©╫О©╫*/
    rtl_FileType_t u_mtype;              /**< О©╫О©╫О©╫О©╫О©╫ */
    unsigned int u_num;                  /**< О©╫О©╫О©╫О©╫О©╫О©╫ */
    unsigned int u_tnum;                 /**< О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ */
    unsigned int u_tcount;               /**< О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */

    struct
    {
        unsigned long long ub_code;      /**< О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
        unsigned long long ub_data;      /**< О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
        unsigned long long ub_bss;
        unsigned long long ub_brk;       /**< О©╫О©╫О©╫brk */
    } base;

    struct
    {
        unsigned long long uc_start;         /**< О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
        unsigned long long uc_dataend;       /**< О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ */
        unsigned long long uc_allocend;      /**< О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ */
        unsigned long long uc_mapend;        /**< О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ */
        unsigned long long uc_mapoff;        /**< О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ О©╫ О©╫О©╫О©╫*/
        unsigned int uc_prot;                /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫ */
    } code;

    struct
    {
        unsigned long long ud_start;         /**< О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
        unsigned long long ud_dataend;       /**< О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ */
        unsigned long long ud_allocend;      /**< О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ */
        unsigned long long ud_mapend;        /**< О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ */
        unsigned long long ud_mapoff;        /**< О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ О©╫ О©╫О©╫О©╫*/
        unsigned int ud_prot;                /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
    } data;

    /* ELF О©╫О©╫ */
    char *u_eheader;                     /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫*/
    char *u_pheader;                     /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫*/
    char *u_symtab;                      /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫*/
    char *u_symtab_st;                   /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫*/
    char *u_strtab;                      /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫*/
    char *u_strtab_st;                   /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫*/
    unsigned int *u_hash;                /**< О©╫О©╫О©╫О©╫О©╫О©╫ hash О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ */
    char *u_got;                         /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
    char *u_gtt;                         /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫*/
    char *u_type;                        /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫++ */
    char *u_dynrel;                      /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫*/
    char *u_gttrel;                      /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫GTT */
    char *u_typerel;                     /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫*/
    char *u_dyn;                         /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ */
    char *u_tobj;                        /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫*/
    char *u_tcast;                       /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫ */
    char *u_typed;                       /**< О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫*/

    struct
    {
        unsigned long long ul_code;      /**< О©╫О©╫О©╫ О©╫О©╫О©╫О©╫ О©╫О©╫ */
        unsigned long long ul_data;      /**< О©╫О©╫О©╫ О©╫О©╫О©╫О©╫ О©╫О©╫О©╫ */
        unsigned long long ul_strtab;    /**< О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫*/
        unsigned long long ul_strtab_st; /**< О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫*/
        unsigned long long ul_type;      /**< О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫++ */
        unsigned long long ul_dynrel;    /**< О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫*/
        unsigned long long ul_gttrel;    /**< О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫GTT */
        unsigned long long ul_typerel;   /**< О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫*/
        unsigned int ul_symtab;          /**< О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫╫*/
        unsigned int ul_symtab_st;       /**< О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫*/
        unsigned int ul_hash;            /**< О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫*/
        unsigned int ul_gtt;			/* 		*/
        unsigned int ul_tobj;			/* 		 */
        unsigned int ul_typed;		/*		*/
        unsigned int ul_tcast;			/*		 */
    } len;

};

/*    Global Type Table (GTT) correction. C++ stuff hadling. */
extern void rtl32_CorrectionType( rtl_Unit_t *unit_p );

extern	long sys_load_cu_elf32_3P(char *name, kmdd_t *mdd);
extern	long sys_load_cu_elf64_3P(char *name, kmdd_t *mdd);

#endif	/* _E2K_PROT_LOADER_H_ */
	
