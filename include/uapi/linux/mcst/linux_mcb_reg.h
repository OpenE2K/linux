/*
 * Copyright (c) 1998 by MCST.
 */

#ifndef	_UAPI__LINUX_MCB_REG_H__
#define	_UAPI__LINUX_MCB_REG_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <linux/mcst/linux_me90_reg.h>
#include <linux/mcst/linux_me90_io.h>

/*
 * Register sets of boards
 */

/* ================================================================ EPROMS : */

#define	MCB_EPROM_REG_SET_OFFSET	ME90_EPROM_REG_SET_OFFSET

typedef	me90_eprom_t			mcb_eprom_t;	/* EPROM memory */
							/* structure */
#define  MCB_EPROM_char                 ME90_EPROM_char
#define  MCB_EPROM_u_char               ME90_EPROM_u_char
#define  MCB_EPROM_long                 ME90_EPROM_long
#define  MCB_EPROM_u_long               ME90_EPROM_u_long
#define  MCB_EPROM_caddr                ME90_EPROM_caddr
#define  MCB_MAX_EPROM_REG_SET_LEN      ME90_MAX_EPROM_REG_SET_LEN
#define  MCB_EPROM_REG_SET_LEN          ME90_EPROM_REG_SET_LEN

/* =================================== MC group : MCKK/MCKA/MC19/MC53/MCPM : */

#define  MC_EPROM_REG_SET_OFFSET        MCB_EPROM_REG_SET_OFFSET
typedef  mcb_eprom_t     mc_eprom_t;   /* EPROM memory structure */
#define  MC_EPROM_char                  MCB_EPROM_char
#define  MC_EPROM_u_char                MCB_EPROM_u_char
#define  MC_EPROM_long                  MCB_EPROM_long
#define  MC_EPROM_u_long                MCB_EPROM_u_long
#define  MC_EPROM_caddr                 MCB_EPROM_caddr
#define  MC_MAX_EPROM_REG_SET_LEN       MCB_MAX_EPROM_REG_SET_LEN
#define  MC_EPROM_REG_SET_LEN           MCB_EPROM_REG_SET_LEN

#define  MC_CNTR_ST_REG_SET_OFFSET      0x00010000 /* Control-state regs     */
#ifdef __e2k__
typedef  u_int         mc_reg_t;      /* entire MC register like as long    */
#else 
typedef	 u_long        mc_reg_t;      /* entire MC register like as long    */
#endif

#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct mc_rd_reg_bits          /* all register bits as to read */
{
   mc_reg_t  _unused_0       :  3;     /* [31:29] unused bits */
   mc_reg_t  _rnc            :  5;     /* [28:24] channel number of SBus */
   mc_reg_t  _unused_1       :  3;     /* [23:21] unused bits */
   mc_reg_t  _rerr           :  5;     /* [20:16] error register */
   mc_reg_t  _unused_2       :  3;     /* [15:13] unused bits */
   mc_reg_t  _rtm            :  5;     /* [12: 8] module type */
   mc_reg_t  _unused_3       :  1;     /*    [ 7] unused bits */
   mc_reg_t  _tpsb           :  1;     /*    [ 6] parity of SBus flag */
   mc_reg_t  _tsb            :  1;     /*    [ 5] request to SBus from MP */
   mc_reg_t  _tisb           :  1;     /*    [ 4] interrupt SBus from MP */
   mc_reg_t  _tlrm           :  1;     /*    [ 3] lock of reset module */
   mc_reg_t  _trm            :  1;     /*    [ 2] reset module */
   mc_reg_t  _tmi            :  1;     /*    [ 1] mask of interrupt to MP from
                                                  SPARC */
   mc_reg_t  _ti             :  1;     /*    [ 0] interrupt to MP from SPARC */
} mc_rd_reg_bits_t;
#else 
typedef struct mc_rd_reg_bits          /* all register bits as to read */
{
   mc_reg_t  _ti             :  1;     /*    [ 0] interrupt to MP from SPARC */
   mc_reg_t  _tmi            :  1;     /*    [ 1] mask of interrupt to MP from
                                                  SPARC */
   mc_reg_t  _trm            :  1;     /*    [ 2] reset module */
   mc_reg_t  _tlrm           :  1;     /*    [ 3] lock of reset module */
   mc_reg_t  _tisb           :  1;     /*    [ 4] interrupt SBus from MP */
   mc_reg_t  _tsb            :  1;     /*    [ 5] request to SBus from MP */
   mc_reg_t  _tpsb           :  1;     /*    [ 6] parity of SBus flag */
   mc_reg_t  _unused_3       :  1;     /*    [ 7] unused bits */
   mc_reg_t  _rtm            :  5;     /* [12: 8] module type */
   mc_reg_t  _unused_2       :  3;     /* [15:13] unused bits */
   mc_reg_t  _rerr           :  5;     /* [20:16] error register */
   mc_reg_t  _unused_1       :  3;     /* [23:21] unused bits */
   mc_reg_t  _rnc            :  5;     /* [28:24] channel number of SBus */
   mc_reg_t  _unused_0       :  3;     /* [31:29] unused bits */
} mc_rd_reg_bits_t;
#endif

#ifdef MY_DRIVER_BIG_ENDIAN
typedef union  mc_wr_reg_bits          /* all register bits as to write */
{
   mc_rd_reg_bits_t          tlrm_wr_reg_bits;   /* to write TLRM */
   struct trm_trcwd_wr_reg                       /* to write TRM + TRCWD */
   {
      mc_reg_t  _unused_0    :  3;     /* [31:29] unused bits */
      mc_reg_t  _rnc         :  5;     /* [28:24] channel number of SBus */
      mc_reg_t  _unused_1    :  3;     /* [23:21] unused bits */
      mc_reg_t  _rerr        :  5;     /* [20:16] error register */
      mc_reg_t  _unused_2    :  3;     /* [15:13] unused bits */
      mc_reg_t  _rtm         :  5;     /* [12: 8] module type */
      mc_reg_t  _unused_3    :  1;     /*    [ 7] unused bits */
      mc_reg_t  _tpsb        :  1;     /*    [ 6] parity of SBus flag */
      mc_reg_t  _tsb         :  1;     /*    [ 5] request to SBus from MP */
      mc_reg_t  _tisb        :  1;     /*    [ 4] interrupt SBus from MP */
      mc_reg_t  _trcwd       :  1;     /*    [ 3] reset of channel control word
                                                  register valid bit */
      mc_reg_t  _trm         :  1;     /*    [ 2] reset module */
      mc_reg_t  _tmi         :  1;     /*    [ 1] mask of interrupt to MP from
                                               SPARC */
      mc_reg_t  _ti          :  1;     /*    [ 0] interrupt to MP from SPARC */
   }                         trm_trcwd_wr_reg_bits;
} mc_wr_reg_bits_t;
#else
typedef union  mc_wr_reg_bits          /* all register bits as to write */
{
   mc_rd_reg_bits_t          tlrm_wr_reg_bits;   /* to write TLRM */
   struct trm_trcwd_wr_reg                       /* to write TRM + TRCWD */
   {
      mc_reg_t  _ti          :  1;     /*    [ 0] interrupt to MP from SPARC */
      mc_reg_t  _tmi         :  1;     /*    [ 1] mask of interrupt to MP from
                                               SPARC */
      mc_reg_t  _trm         :  1;     /*    [ 2] reset module */
      mc_reg_t  _trcwd       :  1;     /*    [ 3] reset of channel control word
                                                  register valid bit */
      mc_reg_t  _tisb        :  1;     /*    [ 4] interrupt SBus from MP */
      mc_reg_t  _tsb         :  1;     /*    [ 5] request to SBus from MP */
      mc_reg_t  _tpsb        :  1;     /*    [ 6] parity of SBus flag */
      mc_reg_t  _unused_3    :  1;     /*    [ 7] unused bits */
      mc_reg_t  _rtm         :  5;     /* [12: 8] module type */
      mc_reg_t  _unused_2    :  3;     /* [15:13] unused bits */
      mc_reg_t  _rerr        :  5;     /* [20:16] error register */
      mc_reg_t  _unused_1    :  3;     /* [23:21] unused bits */
      mc_reg_t  _rnc         :  5;     /* [28:24] channel number of SBus */
      mc_reg_t  _unused_0    :  3;     /* [31:29] unused bits */
   }                         trm_trcwd_wr_reg_bits;
} mc_wr_reg_bits_t;
#endif

typedef enum rtm_encode_t_             /* list of rigiser of module type value
                                          encoding */
{
   undefined_rtm_encode = 0,
   mckk_rtm_encode      = 4,
   mcka_rtm_encode      = 1,
   mcap_rtm_encode      = 5,
   mckp_rtm_encode      = 6,
   mcpm_rtm_encode      = 3,
   mctc_rtm_encode      = 7
} rtm_encode_t;

typedef union mc_rd_reg                /* entire register as to read */
{
   mc_rd_reg_bits_t        as_bits;    /* as set of bits */
   mc_reg_t                whole;      /* as entire register */
} mc_rd_reg_t;
#define TI_read         as_bits._ti
#define TMI_read        as_bits._tmi
#define TRM_read        as_bits._trm
#define TLRM_read       as_bits._tlrm
#define TISB_read       as_bits._tisb
#define TSB_read        as_bits._tsb
#define TPSB_read       as_bits._tpsb
#define RTM_read        as_bits._rtm
#define RERR_read       as_bits._rerr
#define RNC_read        as_bits._rnc
#define RGEN_read       whole

typedef union mc_wr_reg                /* entire register as to write */
{
   mc_wr_reg_bits_t        as_bits;    /* as set of bits */
   mc_reg_t                whole;      /* as entire register */
} mc_wr_reg_t;
#define _tlrm_wr_reg_bits_        as_bits.tlrm_wr_reg_bits
#define _trm_trcwd_wr_reg_bits_   as_bits.trm_trcwd_wr_reg_bits
#define TI_write                  _tlrm_wr_reg_bits_._ti
#define TMI_write                 _tlrm_wr_reg_bits_._tmi
#define TRM_write                 _trm_trcwd_wr_reg_bits_._trm
#define TRCWD_write               _trm_trcwd_wr_reg_bits_._trcwd
#define TLRM_write                _tlrm_wr_reg_bits_._tlrm
#define TISB_write                _tlrm_wr_reg_bits_._tisb
#define TSB_write                 _tlrm_wr_reg_bits_._tsb
#define TPSB_write                _tlrm_wr_reg_bits_._tpsb
#define RTM_write                 _tlrm_wr_reg_bits_._rtm
#define RERR_write                _tlrm_wr_reg_bits_._rerr
#define RNC_write                 _tlrm_wr_reg_bits_._rnc
#define RGEN_write                whole

typedef union MC_reg_t                 /* entire register to read & to write */
{
   mc_rd_reg_t             to_read;    /* as to read */
   mc_wr_reg_t             to_write;   /* as to write */
   mc_reg_t                whole;      /* as entire register */
} MC_reg_t;
#define _RGEN_read_        to_read
#define _RGEN_write_       to_write
#define RGEN_TI            _RGEN_read_.TI_read
#define RGEN_TMI           _RGEN_read_.TMI_read
#define RGEN_TRM           _RGEN_write_.TRM_write
#define RGEN_TRCWD         _RGEN_write_.TRCWD_write
#define RGEN_TLRM          _RGEN_read_.TLRM_read
#define RGEN_TISB          _RGEN_read_.TISB_read
#define RGEN_TSB           _RGEN_read_.TSB_read
#define RGEN_TPSB          _RGEN_read_.TPSB_read
#define RGEN_RTM           _RGEN_read_.RTM_read
#define RGEN_RERR          _RGEN_read_.RERR_read
#define RGEN_RNC           _RGEN_read_.RNC_read
#define RGEN_entire        whole

//#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct mc_cntr_st_reg_rd       /* control-state registers structure
                                          to read */
{
   mc_rd_reg_t TI       ;  /*  0  0x00  interrupt to MP from SPARC */
   mc_rd_reg_t TMI      ;  /*  1  0x04  mask of interrupt to MP from
                                        SPARC */
   mc_rd_reg_t TRM      ;  /*  2  0x08  reset module */
   mc_rd_reg_t TLRM     ;  /*  3  0x0c  lock of reset module */
   mc_rd_reg_t TISB     ;  /*  4  0x10  interrupt SBus from MP */
   mc_rd_reg_t TSB      ;  /*  5  0x14  request to SBus from MP */
   mc_rd_reg_t TPSB     ;  /*  6  0x18  parity of SBus flag */
   mc_rd_reg_t RERR_RNC ;  /*  7  0x1c  error register & channel number
                                         of SBus */
#define        RGEN_READ    TI       /* raad always as whole register */
#define        RTM_READ     TI       /* module type */
} mc_cntr_st_reg_rd_t;

//#else
#if 0
typedef struct mc_cntr_st_reg_rd       /* control-state registers structure
                                          to read */
{
   mc_rd_reg_t RERR_RNC ;  /*  7  0x1c  error register & channel number
                                         of SBus */
   mc_rd_reg_t TPSB     ;  /*  6  0x18  parity of SBus flag */
   mc_rd_reg_t TSB      ;  /*  5  0x14  request to SBus from MP */
   mc_rd_reg_t TISB     ;  /*  4  0x10  interrupt SBus from MP */
   mc_rd_reg_t TLRM     ;  /*  3  0x0c  lock of reset module */
   mc_rd_reg_t TRM      ;  /*  2  0x08  reset module */
   mc_rd_reg_t TMI      ;  /*  1  0x04  mask of interrupt to MP from */
   mc_rd_reg_t TI       ;  /*  0  0x00  interrupt to MP from SPARC */
#define        RGEN_READ    TI       /* raad always as whole register */
#define        RTM_READ     TI       /* module type */
} mc_cntr_st_reg_rd_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

//#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct mc_cntr_st_reg_wr       /* control-state registers structure
                                          to write */
{
   mc_wr_reg_t TI       ;  /*  0  0x00  interrupt to MP from SPARC */
   mc_wr_reg_t TMI      ;  /*  1  0x04  mask of interrupt to MP from
                                        SPARC */
   mc_wr_reg_t TRM_TRCWD;  /*  2  0x08  reset module */
   mc_wr_reg_t TLRM     ;  /*  3  0x0c  lock of reset module */
   mc_wr_reg_t TISB     ;  /*  4  0x10  interrupt SBus from MP */
   mc_wr_reg_t TSB      ;  /*  5  0x14  request to SBus from MP */
   mc_wr_reg_t TPSB     ;  /*  6  0x18  parity of SBus flag */
   mc_wr_reg_t RERR_RNC ;  /*  7  0x1c  error register & channel number
                                        of SBus */
   mc_wr_reg_t TGRM     ;  /*  8  0x20  trigger of general reset of module */
} mc_cntr_st_reg_wr_t;
//#else
#if 0
typedef struct mc_cntr_st_reg_wr       /* control-state registers structure
                                          to write */
{
   mc_wr_reg_t TGRM     ;  /*  8  0x20  trigger of general reset of module */
   mc_wr_reg_t RERR_RNC ;  /*  7  0x1c  error register & channel number
                                        of SBus */
   mc_wr_reg_t TPSB     ;  /*  6  0x18  parity of SBus flag */
   mc_wr_reg_t TSB      ;  /*  5  0x14  request to SBus from MP */
   mc_wr_reg_t TISB     ;  /*  4  0x10  interrupt SBus from MP */
   mc_wr_reg_t TLRM     ;  /*  3  0x0c  lock of reset module */
   mc_wr_reg_t TRM_TRCWD;  /*  2  0x08  reset module */
   mc_wr_reg_t TMI      ;  /*  1  0x04  mask of interrupt to MP from
                                        SPARC */
   mc_wr_reg_t TI       ;  /*  0  0x00  interrupt to MP from SPARC */
} mc_cntr_st_reg_wr_t;
#endif /* MY_DRIVER_BIG_ENDIAN */

typedef union  mc_cntr_st_reg          /* control-state registers structure
                                          to read & to write */
{
   mc_cntr_st_reg_rd_t         to_read;   /* control-state registers structure
                                             to read */
   mc_cntr_st_reg_wr_t         to_write;  /* control-state registers structure
                                             to write */
} mc_cntr_st_reg_t;
#define MC_RGEN_read       to_read
#define MC_RGEN_write      to_write

#define MC_TI_read         MC_RGEN_read.TI.RGEN_read
#define MC_TMI_read        MC_RGEN_read.TMI.RGEN_read
#define MC_TRM_read        MC_RGEN_read.TRM.RGEN_read
#define MC_TLRM_read       MC_RGEN_read.TLRM.RGEN_read
#define MC_TISB_read       MC_RGEN_read.TISB.RGEN_read
#define MC_TSB_read        MC_RGEN_read.TSB.RGEN_read
#define MC_TPSB_read       MC_RGEN_read.TPSB.RGEN_read
#define MC_RTM_read        MC_RGEN_read.RTM_READ.RGEN_read
#define MC_RERR_RNC_read   MC_RGEN_read.RERR_RNC.RGEN_read
#define MC_RGENS_read      MC_RGEN_read.RGEN_READ.RGEN_read

#define MC_TI_write        MC_RGEN_write.TI.RGEN_write
#define MC_TMI_write       MC_RGEN_write.TMI.RGEN_write
#define MC_TRM_TRCWD_write MC_RGEN_write.TRM_TRCWD.RGEN_write
#define MC_TLRM_write      MC_RGEN_write.TLRM.RGEN_write
#define MC_TISB_write      MC_RGEN_write.TISB.RGEN_write
#define MC_TSB_write       MC_RGEN_write.TSB.RGEN_write
#define MC_TPSB_write      MC_RGEN_write.TPSB.RGEN_write
#define MC_RERR_RNC_write  MC_RGEN_write.RERR_RNC.RGEN_write
#define MC_TGRM_write      MC_RGEN_write.TGRM.RGEN_write

#define	MC_CNTR_ST_REG_SET_LEN		sizeof(mc_cntr_st_reg_t)

/* =========================================================== BASE MEMORY : */

#define	MC_BMEM_REG_SET_OFFSET		0x00040000 /* Base Memory offset */

#define	MC_BMEM_REG_SET_LEN		0x00020000 /* base memory length */

#define	MC_MAX_REG_SETS_NUM		3  /* EPROM + control-state regs + */
					   /* BMEM */
#define	MC_MIN_REG_SETS_NUM		2  /* only control-state regs + BMEM */

/*
 * General registers types
 */

typedef  u_int      mc_reg_type_t;  /* MC boards general register types as
                                       bits of mask */

#define   TI_mc_reg_type     0x00000001  /* interrupt to MP from SPARC */
#define   TMI_mc_reg_type    0x00000002  /* mask of interrupt to MP from SPARC*/
#define   TRM_mc_reg_type    0x00000004  /* reset module */
#define   TRCWD_mc_reg_type  0x00000008  /* reset of channel control word reg */
#define   TLRM_mc_reg_type   0x00000010  /* lock of reset module */
#define   TISB_mc_reg_type   0x00000020  /* interrupt SBus from MP */
#define   TSB_mc_reg_type    0x00000040  /* request to SBus from MP */
#define   TPSB_mc_reg_type   0x00000080  /* parity of SBus flag */
#define   RTM_mc_reg_type    0x00000100  /* module type */
#define   RERR_mc_reg_type   0x00000200  /* error register */
#define   RNC_mc_reg_type    0x00000400  /* channel number of SBus */
#define   TGRM_mc_reg_type   0x00000800  /* general reset of module */
#define   set_by_reset_mc_reg_type  /* mask of registers, which sets by */    \
                                    /* reset of module */		      \
      TI_mc_reg_type     |  TMI_mc_reg_type    |  TRM_mc_reg_type    |        \
                                                  TISB_mc_reg_type   |        \
      TSB_mc_reg_type    |  TPSB_mc_reg_type   |  RTM_mc_reg_type
      
#define   all_readable_mc_reg_type  /* all readable general register mask */  \
      TI_mc_reg_type     |  TMI_mc_reg_type    |  TRM_mc_reg_type    |        \
                            TLRM_mc_reg_type   |  TISB_mc_reg_type   |        \
      TSB_mc_reg_type    |  TPSB_mc_reg_type /*|  RTM_mc_reg_type*/ /* Not actual in new version */    |        \
      RERR_mc_reg_type   |  RNC_mc_reg_type
#define   all_writable_mc_reg_type  /* all writable general register mask */  \
      TI_mc_reg_type     |  TMI_mc_reg_type    |  TRM_mc_reg_type    |        \
      TRCWD_mc_reg_type  |  TLRM_mc_reg_type   |  TISB_mc_reg_type   |        \
      TSB_mc_reg_type    |  TPSB_mc_reg_type   |                              \
      RERR_mc_reg_type   |  RNC_mc_reg_type
#define   all_RGEN_mc_reg_type      /* all general register mask */           \
      all_readable_mc_reg_type | all_writable_mc_reg_type

/*
 * Device transfer control words structures
 */

typedef u_int			dev_word_t;

#ifdef MY_DRIVER_BIG_ENDIAN
#ifdef	__OLD_DCW_STRICTIRE__

typedef struct dcw_bits1               /* device control word bits */
{
   dev_word_t  _ecf          :  1;     /*    [31] empty code flag */
   dev_word_t  _unused30     :  1;     /*    [30] unused */
   dev_word_t  _read_op      :  1;     /*    [29] read memory operation flag */
   dev_word_t  _size         :  3;     /* [28:26] block size */
   dev_word_t  _unused25_24  :  2;     /* [25:24] unused */
   dev_word_t  _rcb          :  1;     /*    [23] bit of reverse counter */
   dev_word_t  _btf          :  1;     /*    [22] byte transfer flag */
   dev_word_t  _mpf          :  1;     /*    [21] MP flag */
   dev_word_t  _buf_num      :  5;     /* [20:16] MP buffer number */
   dev_word_t  _unused15_13  :  3;     /* [15:13] unused */
   dev_word_t  _brf          :  1;     /*    [12] block remainder flag */
   dev_word_t  _unused11     :  1;     /*    [11] unused */
   dev_word_t  _wf           :  1;     /*    [10] waiting flag */
   dev_word_t  _ae           :  1;     /*    [ 9] end of array */
   dev_word_t  _sbn          :  1;     /*    [ 8] semibuffer number */
   dev_word_t  _bs1          :  1;     /*    [ 7] buffer 1 state */
   dev_word_t  _bs2          :  1;     /*    [ 6] buffer 2 state */
   dev_word_t  _bac          :  6;     /* [ 5: 0] counter of byte address */
} dcw_bits1_t;

typedef struct dcw_bits2               /* device control word bits */
{
   dev_word_t  _ecf          :  1;     /*    [31] empty code flag */
   dev_word_t  _unused30     :  1;     /*    [30] unused */
   dev_word_t  _read_op      :  1;     /*    [29] read memory operation flag */
   dev_word_t  _size         :  3;     /* [28:26] block size */
   dev_word_t  _unused25_24  :  2;     /* [25:24] unused */
   dev_word_t  _rcb          :  1;     /*    [23] bit of reverse counter */
   dev_word_t  _btf          :  1;     /*    [22] byte transfer flag */
   dev_word_t  _br_size      :  6;     /* [21:16] block remainder size */
   dev_word_t  _unused15_13  :  3;     /* [15:13] unused */
   dev_word_t  _brf          :  1;     /*    [12] block remainder flag */
   dev_word_t  _unused11     :  1;     /*    [11] unused */
   dev_word_t  _wf           :  1;     /*    [10] waiting flag */
   dev_word_t  _ae           :  1;     /*    [ 9] end of array */
   dev_word_t  _sbn          :  1;     /*    [ 8] semibuffer number */
   dev_word_t  _bs1          :  1;     /*    [ 7] buffer 1 state */
   dev_word_t  _bs2          :  1;     /*    [ 6] buffer 2 state */
   dev_word_t  _bac          :  6;     /* [ 5: 0] counter of byte address */
} dcw_bits2_t;
#else
typedef struct dcw_bits1               /* device control word bits */
{
   dev_word_t  _ecf          :  1;     /*    [31] empty code flag */
   dev_word_t  _unused30     :  1;     /*    [30] unused */
   dev_word_t  _read_op      :  1;     /*    [29] read memory operation flag */
   dev_word_t  _size         :  3;     /* [28:26] block size */
   dev_word_t  _wf           :  1;     /*    [25] waiting flag */
   dev_word_t  _brf          :  1;     /*    [24] block remainder flag */
   dev_word_t  _rcb          :  1;     /*    [23] bit of reverse counter */
   dev_word_t  _btf          :  1;     /*    [22] byte transfer flag */
   dev_word_t  _mpf          :  1;     /*    [21] MP flag */
   dev_word_t  _buf_num      :  5;     /* [20:16] MP buffer number */
   dev_word_t  _unused15_10  :  6;     /* [15:10] unused */
   dev_word_t  _ae           :  1;     /*    [ 9] end of array */
   dev_word_t  _unused8      :  1;     /*    [ 8] unused */
   dev_word_t  _tef          :  1;     /*    [ 7] end of transfer flag */
   dev_word_t  _sbn          :  1;     /*    [ 6] semibuffer number */
   dev_word_t  _bac          :  6;     /* [ 5: 0] counter of byte address */
} dcw_bits1_t;

typedef struct dcw_bits2               /* device control word bits */
{
   dev_word_t  _ecf          :  1;     /*    [31] empty code flag */
   dev_word_t  _unused30     :  1;     /*    [30] unused */
   dev_word_t  _read_op      :  1;     /*    [29] read memory operation flag */
   dev_word_t  _size         :  3;     /* [28:26] block size */
   dev_word_t  _wf           :  1;     /*    [25] waiting flag */
   dev_word_t  _brf          :  1;     /*    [24] block remainder flag */
   dev_word_t  _rcb          :  1;     /*    [23] bit of reverse counter */
   dev_word_t  _btf          :  1;     /*    [22] byte transfer flag */
   dev_word_t  _br_size      :  6;     /* [21:16] block remainder size */
   dev_word_t  _unused15_10  :  6;     /* [15:10] unused */
   dev_word_t  _ae           :  1;     /*    [ 9] end of array */
   dev_word_t  _unused8      :  1;     /*    [ 8] unused */
   dev_word_t  _tef          :  1;     /*    [ 7] end of transfer flag */
   dev_word_t  _sbn          :  1;     /*    [ 6] semibuffer number */
   dev_word_t  _bac          :  6;     /* [ 5: 0] counter of byte address */
} dcw_bits2_t;

#endif	/* __OLD_DCW_STRICTIRE__ */
#else
#ifdef	__OLD_DCW_STRICTIRE__

typedef struct dcw_bits1               /* device control word bits */
{
   dev_word_t  _bac          :  6;     /* [ 5: 0] counter of byte address */
   dev_word_t  _bs2          :  1;     /*    [ 6] buffer 2 state */
   dev_word_t  _bs1          :  1;     /*    [ 7] buffer 1 state */
   dev_word_t  _sbn          :  1;     /*    [ 8] semibuffer number */
   dev_word_t  _ae           :  1;     /*    [ 9] end of array */
   dev_word_t  _wf           :  1;     /*    [10] waiting flag */
   dev_word_t  _unused11     :  1;     /*    [11] unused */
   dev_word_t  _brf          :  1;     /*    [12] block remainder flag */
   dev_word_t  _unused15_13  :  3;     /* [15:13] unused */
   dev_word_t  _buf_num      :  5;     /* [20:16] MP buffer number */
   dev_word_t  _mpf          :  1;     /*    [21] MP flag */
   dev_word_t  _btf          :  1;     /*    [22] byte transfer flag */
   dev_word_t  _rcb          :  1;     /*    [23] bit of reverse counter */
   dev_word_t  _unused25_24  :  2;     /* [25:24] unused */
   dev_word_t  _size         :  3;     /* [28:26] block size */
   dev_word_t  _read_op      :  1;     /*    [29] read memory operation flag */
   dev_word_t  _unused30     :  1;     /*    [30] unused */
   dev_word_t  _ecf          :  1;     /*    [31] empty code flag */
} dcw_bits1_t;

typedef struct dcw_bits2               /* device control word bits */
{
   dev_word_t  _bac          :  6;     /* [ 5: 0] counter of byte address */
   dev_word_t  _bs2          :  1;     /*    [ 6] buffer 2 state */
   dev_word_t  _bs1          :  1;     /*    [ 7] buffer 1 state */
   dev_word_t  _sbn          :  1;     /*    [ 8] semibuffer number */
   dev_word_t  _ae           :  1;     /*    [ 9] end of array */
   dev_word_t  _wf           :  1;     /*    [10] waiting flag */
   dev_word_t  _unused11     :  1;     /*    [11] unused */
   dev_word_t  _brf          :  1;     /*    [12] block remainder flag */
   dev_word_t  _unused15_13  :  3;     /* [15:13] unused */
   dev_word_t  _br_size      :  6;     /* [21:16] block remainder size */
   dev_word_t  _btf          :  1;     /*    [22] byte transfer flag */
   dev_word_t  _rcb          :  1;     /*    [23] bit of reverse counter */
   dev_word_t  _unused25_24  :  2;     /* [25:24] unused */
   dev_word_t  _size         :  3;     /* [28:26] block size */
   dev_word_t  _read_op      :  1;     /*    [29] read memory operation flag */
   dev_word_t  _unused30     :  1;     /*    [30] unused */
   dev_word_t  _ecf          :  1;     /*    [31] empty code flag */
} dcw_bits2_t;
#else
typedef struct dcw_bits1               /* device control word bits */
{
   dev_word_t  _bac          :  6;     /* [ 5: 0] counter of byte address */
   dev_word_t  _sbn          :  1;     /*    [ 6] semibuffer number */
   dev_word_t  _tef          :  1;     /*    [ 7] end of transfer flag */
   dev_word_t  _unused8      :  1;     /*    [ 8] unused */
   dev_word_t  _ae           :  1;     /*    [ 9] end of array */
   dev_word_t  _unused15_10  :  6;     /* [15:10] unused */
   dev_word_t  _buf_num      :  5;     /* [20:16] MP buffer number */
   dev_word_t  _mpf          :  1;     /*    [21] MP flag */
   dev_word_t  _btf          :  1;     /*    [22] byte transfer flag */
   dev_word_t  _rcb          :  1;     /*    [23] bit of reverse counter */
   dev_word_t  _brf          :  1;     /*    [24] block remainder flag */
   dev_word_t  _wf           :  1;     /*    [25] waiting flag */
   dev_word_t  _size         :  3;     /* [28:26] block size */
   dev_word_t  _read_op      :  1;     /*    [29] read memory operation flag */
   dev_word_t  _unused30     :  1;     /*    [30] unused */
   dev_word_t  _ecf          :  1;     /*    [31] empty code flag */
} dcw_bits1_t;

typedef struct dcw_bits2               /* device control word bits */
{
   dev_word_t  _bac          :  6;     /* [ 5: 0] counter of byte address */
   dev_word_t  _sbn          :  1;     /*    [ 6] semibuffer number */
   dev_word_t  _tef          :  1;     /*    [ 7] end of transfer flag */
   dev_word_t  _unused8      :  1;     /*    [ 8] unused */
   dev_word_t  _ae           :  1;     /*    [ 9] end of array */
   dev_word_t  _unused15_10  :  6;     /* [15:10] unused */
   dev_word_t  _br_size      :  6;     /* [21:16] block remainder size */
   dev_word_t  _btf          :  1;     /*    [22] byte transfer flag */
   dev_word_t  _rcb          :  1;     /*    [23] bit of reverse counter */
   dev_word_t  _brf          :  1;     /*    [24] block remainder flag */
   dev_word_t  _wf           :  1;     /*    [25] waiting flag */
   dev_word_t  _size         :  3;     /* [28:26] block size */
   dev_word_t  _read_op      :  1;     /*    [29] read memory operation flag */
   dev_word_t  _unused30     :  1;     /*    [30] unused */
   dev_word_t  _ecf          :  1;     /*    [31] empty code flag */
} dcw_bits2_t;

#endif	/* __OLD_DCW_STRICTIRE__ */
#endif /* MY_DRIVER_BIG_ENDIAN */
typedef union   dcw_bits               /* device control word bits */
{
   dcw_bits1_t         reg_bits1;
   dcw_bits2_t         reg_bits2;
} dcw_bits_t;

typedef union  dev_cntr_word            /* device control word */
{
   dcw_bits_t		reg_bits;	/* as bites fields */
   dev_word_t		whole_reg;	/* whole register */
} dev_cntr_word_t;

#define DCW_ECF         reg_bits.reg_bits1._ecf
#define DCW_READ_op     reg_bits.reg_bits1._read_op
#define DCW_SIZE        reg_bits.reg_bits1._size
#define DCW_WF          reg_bits.reg_bits1._wf
#define DCW_BRF         reg_bits.reg_bits1._brf
#define DCW_RCB         reg_bits.reg_bits1._rcb
#define DCW_BTF         reg_bits.reg_bits1._btf
#define DCW_MPF         reg_bits.reg_bits1._mpf
#define DCW_BUF_NUM     reg_bits.reg_bits1._buf_num
#define DCW_BR_SIZE     reg_bits.reg_bits2._br_size
#define DCW_AE          reg_bits.reg_bits1._ae
#define DCW_TEF         reg_bits.reg_bits1._tef
#define DCW_SBN         reg_bits.reg_bits1._sbn
#define DCW_BS1         reg_bits.reg_bits1._bs1
#define DCW_BS2         reg_bits.reg_bits1._bs2
#define DCW_BAC         reg_bits.reg_bits1._bac
#define DCW_reg         whole_reg

typedef struct	dev_trans_words		/* device transfer control words */
{
	dev_cntr_word_t	dcw;		/* device control word */
	u_long		dma_addr;	/* Sparc memory DMA address */
	size_t		block_size;	/* transfer block size */
	size_t		word_size;	/* transfer size in words */
} dev_trans_words_t;

/*
 * MC boards Mapped registers sets structures
 */

typedef struct mcb_reg_sets_t			/* MC group boards register */
						/* sets */
{
	mc_eprom_t		eprom;		/* EPROM memory */
	mc_cntr_st_reg_t	*cntr_st_regs;	/* control-state registers */
	mc_base_mem_t		base_memory;	/* base memory */
} mcb_reg_sets_t;

#define	MC_EPROM_regs		eprom
#define	MC_EPROM_regs_char	MC_EPROM_regs.MC_EPROM_char
#define	MC_EPROM_regs_u_char	MC_EPROM_regs.MC_EPROM_u_char
#define	MC_EPROM_regs_long	MC_EPROM_regs.MC_EPROM_long
#define	MC_EPROM_regs_u_long	MC_EPROM_regs.MC_EPROM_u_long
#define	MC_EPROM_regs_caddr	MC_EPROM_regs.MC_EPROM_caddr
#define	MC_CNTR_ST_regs		cntr_st_regs
#define	MC_BMEM_regs		base_memory

#define MNI MAX_NUMBER_INTR

/*
 * Base memory mapping
 */

#define TRAP_TABLE_BMEM_ADDR	ME90_TRAP_TABLE_BMEM_ADDR /* trap taable */
#define TRAP_TABLE_BMEM_SIZE	ME90_TRAP_TABLE_BMEM_SIZE

#define ALL_DEV_BUF_BMEM_ADDR	0x01000		/* buffers of all devices */
#define ALL_DEV_BUF_BMEM_SIZE	DEV_FULL_BUF_BMEM_SIZE * MC_BOARD_DEVICE_NUM
#define DEV_BUF1_BMEM_ADDR(dev) (ALL_DEV_BUF_BMEM_ADDR       +		\
                                 DEV_FULL_BUF_BMEM_SIZE*dev)
#define DEV_BUF2_BMEM_ADDR(dev) (DEV_BUF1_BMEM_ADDR(dev) + 		\
                                 DEV_HALF_BUF_BMEM_SIZE)
#define DEV_0_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(0)	/* device  0 buf 1 */
#define DEV_0_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(0)	/* device  0 buf 2 */
#define DEV_1_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(1)	/* device  1 buf 1 */
#define DEV_1_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(1)	/* device  1 buf 2 */
#define DEV_2_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(2)	/* device  2 buf 1 */
#define DEV_2_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(2)	/* device  2 buf 2 */
#define DEV_3_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(3)	/* device  3 buf 1 */
#define DEV_3_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(3)	/* device  3 buf 2 */
#define DEV_4_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(4)	/* device  4 buf 1 */
#define DEV_4_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(4)	/* device  4 buf 2 */
#define DEV_5_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(5)	/* device  5 buf 1 */
#define DEV_5_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(5)	/* device  5 buf 2 */
#define DEV_6_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(6)	/* device  6 buf 1 */
#define DEV_6_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(6)	/* device  6 buf 2 */
#define DEV_7_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(7)	/* device  7 buf 1 */
#define DEV_7_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(7)	/* device  7 buf 2 */
#define DEV_8_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(8)	/* device  8 buf 1 */
#define DEV_8_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(8)	/* device  8 buf 2 */
#define DEV_9_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(9)	/* device  9 buf 1 */
#define DEV_9_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(9)	/* device  9 buf 2 */
#define DEV_10_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(10)	/* device 10 buf 1 */
#define DEV_10_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(10)	/* device 10 buf 2 */
#define DEV_11_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(11)	/* device 11 buf 1 */
#define DEV_11_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(11)	/* device 11 buf 2 */
#define DEV_12_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(12)	/* device 12 buf 1 */
#define DEV_12_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(12)	/* device 12 buf 2 */
#define DEV_13_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(13)	/* device 13 buf 1 */
#define DEV_13_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(13)	/* device 13 buf 2 */
#define DEV_14_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(14)	/* device 14 buf 1 */
#define DEV_14_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(14)	/* device 14 buf 2 */
#define DEV_15_BUF1_BMEM_ADDR	DEV_BUF1_BMEM_ADDR(15)	/* device 15 buf 1 */
#define DEV_15_BUF2_BMEM_ADDR	DEV_BUF2_BMEM_ADDR(15)	/* device 15 buf 2 */

#define ALL_DEV_CNTR_BMEM_ADDR	0x01800		/* all device control words */
#define ALL_DEV_CNTR_BMEM_SIZE	DEV_CNTR_BMEM_SIZE * MC_BOARD_DEVICE_NUM
#define DEV_CNTR_BMEM_ADDR(dev) (ALL_DEV_CNTR_BMEM_ADDR       +		\
                                 DEV_CNTR_BMEM_SIZE * dev)
#define DEV_0_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(0)	/* device  0 control */
#define DEV_1_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(1)	/* device  1 control */
#define DEV_2_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(2)	/* device  2 control */
#define DEV_3_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(3)	/* device  3 control */
#define DEV_4_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(4)	/* device  4 control */
#define DEV_5_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(5)	/* device  5 control */
#define DEV_6_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(6)	/* device  6 control */
#define DEV_7_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(7)	/* device  7 control */
#define DEV_8_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(8)	/* device  8 control */
#define DEV_9_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(9)	/* device  9 control */
#define DEV_10_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(10)	/* device 10 control */
#define DEV_11_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(11)	/* device 11 control */
#define DEV_12_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(12)	/* device 12 control */
#define DEV_13_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(13)	/* device 13 control */
#define DEV_14_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(14)	/* device 14 control */
#define DEV_15_CNTR_BMEM_ADDR	DEV_CNTR_BMEM_ADDR(15)	/* device 15 control */

#define MP_BUF_BMEM_ADDR		0x01900		/* buffers of MP */
#define MP_BUF1_BMEM_ADDR	MP_BUF_BMEM_ADDR	/* buffer # 1 of MP */
#define MP_BUF2_BMEM_ADDR	MP_BUF_BMEM_ADDR + MP_HALF_BUF_BMEM_SIZE

#define MP_CNTR_BMEM_ADDR		0x01980	/* MP control words */

#define MCPM_DRV_CMN_AREA_BMEM_ADDR	0x1c8c0	/* MCPM interdriver */
						/* communication area */
#define MCPM_DRV_CMN_AREA_BMEM_SIZE	0xb0	/* size of MCPM interdriver */
						/* communication area */
#define MCTC_DRV_CMN_AREA_BMEM_ADDR	0x01990	/* MCTC interdriver */
											/* communication area */
#define MCTC_DRV_CMN_AREA_BMEM_SIZE	0xb0	/* size of MCTC interdriver */
											/* communication area */
#define TR_CNTR_BUF_BMEM_ADDR		0x01990	/* transfer control word buf */
#define TR_CNTR_BUF_BMEM_SIZE		sizeof(drv_intercom_t)

#define MP_CODE_AREA_BMEM_ADDR		ME90_MP_CODE_AREA_BMEM_ADDR

#define FREE_AREA1_BMEM_ADDR	TRAP_TABLE_BMEM_ADDR + TRAP_TABLE_BMEM_SIZE
#define FREE_AREA1_BMEM_SIZE	ALL_DEV_BUF_BMEM_ADDR - FREE_AREA1_BMEM_ADDR

#define FREE_AREA2_BMEM_ADDR	TR_CNTR_BUF_BMEM_ADDR + TR_CNTR_BUF_BMEM_SIZE
#define FREE_AREA2_BMEM_SIZE	MP_INIT_AREA_BMEM_ADDR - FREE_AREA2_BMEM_ADDR

#ifdef	__cplusplus
}
#endif

#endif /* _UAPI__LINUX_MCB_REG_H__ */
