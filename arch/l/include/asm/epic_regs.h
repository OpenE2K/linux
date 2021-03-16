#ifndef	__ASM_L_EPIC_REGS_H
#define	__ASM_L_EPIC_REGS_H

#include <asm/types.h>

#ifndef	__ASSEMBLY__
#ifdef __LITTLE_ENDIAN
union cepic_ctrl {
	u32	raw;
	struct	{
		u32	__reserved1	:  8,
			bsp_core	:  1,
			__reserved2	:  1,
			soft_en		:  1,
			__reserved3	: 21;
	} __packed bits;
};

/* Ignore 4 bits of CEPIC (core) ID so that physical core ID is <= 64 */
union cepic_id {
	u32	raw;
	struct	{
		u32	cepicn		:  4,
			cepicn_reserved	:  4,
			prepicn		:  2,
			__reserved2	: 22;
	} __packed bits;
};

union cepic_ctrl2 {
	u32	raw;
	struct	{
		u32	mi_gst_blk	:  1,
			nmi_gst_blk	:  1,
			int_hv		:  1,
			__reserved1	:  1,
			clear_gst	:  1,
			__reserved2	:  3,
			timer_stop	:  1,
			__reserved3	: 23;
	} __packed bits;
};

union cepic_dat {
	u64	raw;
	struct	{
		u64	__reserved1	:  6,
			dat_cop		:  2,
			__reserved2	:  4,
			stat		:  1,
			__reserved3	:  7,
			index		: 10,
			__reserved4	:  2,
			__reserved5	:  8,
			gst_dst		: 10,
			__reserved6	:  2,
			gst_id		: 12;
	} __packed bits;
};

union cepic_epic_int {
	u32	raw;
	struct	{
		u32	vect		: 10,
			__reserved1	:  2,
			stat		:  1,
			__reserved2	:  3,
			mask		:  1,
			__reserved3	: 15;
	} __packed bits;
};

union cepic_epic_int2 {
	u64	raw;
	struct	{
		u64	vect		: 10,
			dst_sh		:  2,
			__reserved1	:  1,
			dlvm		:  3,
			__reserved2	:  4,
			gst_id		: 12,
			__reserved3	: 12,
			gst_dst		: 10,
			__reserved4	: 10;
	} __packed bits;
};

union cepic_cpr {
	u32	raw;
	struct	{
		u32	__reserved1	:  8,
			cpr		:  3,
			__reserved2	: 21;
	} __packed bits;
};

union cepic_esr {
	u32	raw;
	struct	{
		u32	__reserved1	:  5,
			rq_addr_err	:  1,
			rq_virt_err	:  1,
			rq_cop_err	:  1,
			ms_gstid_err	:  1,
			ms_virt_err	:  1,
			ms_err		:  1,
			ms_icr_err	:  1,
			__reserved2	: 20;
	} __packed bits;
};

union cepic_esr2 {
	u32	raw;
	struct	{
		u32	vect		: 10,
			__reserved1	:  2,
			stat		:  1,
			__reserved2	:  3,
			mask		:  1,
			__reserved3	: 15;
	} __packed bits;
};

union cepic_eoi {
	u32	raw;
	struct	{
		u32	__reserved1	: 16,
			rcpr		:  3,
			__reserved2	: 13;
	} __packed bits;
};

union cepic_cir {
	u32	raw;
	struct	{
		u32	vect		: 10,
			__reserved1	:  2,
			stat		:  1,
			__reserved2	: 19;
	} __packed bits;
};

union cepic_gstbase_hi {
	u32	raw;
	struct	{
		u32	gstbase_hi	: 4,
			__reserved	: 28;
	} __packed bits;
};

union cepic_gstid {
	u32	raw;
	struct	{
		u32	gstid		: 12,
			__reserved	: 20;
	} __packed bits;
};

union cepic_pnmirr {
	u32	raw;
	struct	{
		u32	startup_entry	:  8,
			__reserved1	:  1,
			smi		:  1,
			nmi		:  1,
			init		:  1,
			startup		:  1,
			int_violat	:  1,
			__reserved2	:  2,
			nm_timer	:  1,
			nm_special	:  1,
			__reserved3	: 14;
	} __packed bits;
};

union cepic_icr {
	u64	raw;
	struct	{
		u64	vect		: 10,
			dst_sh		:  2,
			stat		:  1,
			dlvm		:  3,
			__reserved1	:  4,
			gst_id		: 12,
			__reserved2	:  8,
			dst		: 10,
			__reserved3	: 14;
	} __packed bits;
};

union cepic_timer_lvtt {
	u32	raw;
	struct	{
		u32	vect		: 10,
			__reserved1	:  2,
			stat		:  1,
			__reserved2	:  3,
			mask		:  1,
			mode		:  1,
			__reserved3	: 14;
	} __packed bits;
};

union cepic_timer_div {
	u32	raw;
	struct	{
		u32	divider		:  4,
			__reserved1	: 28;
	} __packed bits;
};

union cepic_nm_timer_lvtt {
	u32	raw;
	struct	{
		u32	__reserved1	: 17,
			mode		:  1,
			__reserved2	: 14;
	} __packed bits;
};

union cepic_nm_timer_div {
	u32	raw;
	struct	{
		u32	divider		:  4,
			__reserved1	: 28;
	} __packed bits;
};

union cepic_svr {
	u32	raw;
	struct	{
		u32	vect		: 10,
			__reserved1	: 22;
	} __packed bits;
};

union cepic_pnmirr_mask {
	u32	raw;
	struct	{
		u32	__reserved1	:  9,
			smi		:  1,
			nmi		:  1,
			__reserved2	:  2,
			int_violat	:  1,
			__reserved3	:  2,
			nm_timer	:  1,
			nm_special	:  1,
			__reserved4	: 14;
	} __packed bits;
};

union cepic_vect_inta {
	u32	raw;
	struct	{
		u32	vect		:  10,
			__reserved1	:   6,
			cpr		:   3,
			__reserved2	:  13;
	} __packed bits;
};

union prepic_ctrl {
	u32	raw;
	struct	{
		u32	__reserved1	:  8,
			bsp		:  1,
			__reserved2	:  2,
			epic_en		:  1,
			__reserved3	: 20;
	} __packed bits;
};

union prepic_id {
	u32	raw;
	struct	{
		u32	__reserved1	:  8,
			prepicn		:  2,
			__reserved2	: 22;
	} __packed bits;
};

union prepic_ctrl2 {
	u32	raw;
	struct	{
		u32	__reserved1	:  9,
			bgi_mode	:  1,
			__reserved2	:  2,
			virt_en		:  1,
			__reserved3	: 19;
	} __packed bits;
};

union prepic_err_int {
	u32	raw;
	struct	{
		u32	vect		: 10,
			__reserved1	:  2,
			stat		:  1,
			dlvm		:  3,
			mask		:  1,
			__reserved2	:  3,
			dst		: 10,
			__reserved3	:  2;
	} __packed bits;
};

union prepic_linpn {
	u32	raw;
	struct	{
		u32	vect		: 10,
			__reserved1	:  2,
			stat		:  1,
			dlvm		:  3,
			mask		:  1,
			__reserved2	:  3,
			dst		: 10,
			__reserved3	:  2;
	} __packed bits;
};

typedef struct kvm_epic_page {
/*000*/	u32		ctrl;
	u32		id;
	u32		cpr;
	u32		esr;
	u32		esr2;
	u32		cir;
	atomic_t	esr_new;
	u32		svr;
	u64		icr;
	u32		timer_lvtt;
	u32		timer_init;
	u32		timer_cur;
	u32		timer_div;
	u32		nm_timer_lvtt;
	u32		nm_timer_init;
	u32		nm_timer_cur;
	u32		nm_timer_div;
	u32		pnmirr_mask;
/*04c*/	u32		__reserved1[45];
/*100*/	atomic64_t	pmirr[16];
/*180*/	u32		__reserved2[24];
/*1e0*/	atomic_t	pnmirr;
	u32		__reserved3[263];
/*600*/	u8		pnmirr_byte[16];
/*610*/	u32		__reserved4[124];
/*800*/	u8		pmirr_byte[1024];
} epic_page_t;

#elif defined(__BIG_ENDIAN)

union cepic_ctrl {
	u32	raw;
	struct	{
		u32	__reserved3	: 21,
			soft_en		:  1,
			__reserved2	:  1,
			bsp_core	:  1,
			__reserved1	:  8;
	} __packed bits;
};

/* Ignore 4 bits of CEPIC (core) ID so that physical core ID is <= 64 */
union cepic_id {
	u32	raw;
	struct	{
		u32	__reserved2	: 22,
			prepicn		:  2,
			cepicn_reserved	:  4,
			cepicn		:  4;
	} __packed bits;
};

union cepic_ctrl2 {
	u32	raw;
	struct	{
		u32	__reserved3	: 23,
			timer_stop	:  1,
			__reserved2	:  3,
			clear_gst	:  1,
			__reserved1	:  1,
			int_hv		:  1,
			nmi_gst_blk	:  1,
			mi_gst_blk	:  1;
	} __packed bits;
};

union cepic_dat {
	u64	raw;
	struct	{
		u64	gst_id		: 12,
			__reserved6	:  2,
			gst_dst		: 10,
			__reserved5	:  8,
			__reserved4	:  2,
			index		: 10,
			__reserved3	:  7,
			stat		:  1,
			__reserved2	:  4,
			dat_cop		:  2,
			__reserved1	:  6;
	} __packed bits;
};

union cepic_epic_int {
	u32	raw;
	struct	{
		u32	__reserved3	: 15,
			mask		:  1,
			__reserved2	:  3,
			stat		:  1,
			__reserved1	:  2,
			vect		: 10;
	} __packed bits;
};

union cepic_epic_int2 {
	u64	raw;
	struct	{
		u64	__reserved4	: 10,
			gst_dst		: 10,
			__reserved3	: 12,
			gst_id		: 12,
			__reserved2	:  4,
			dlvm		:  3,
			__reserved1	:  1,
			dst_sh		:  2,
			vect		: 10;
	} __packed bits;
};

union cepic_cpr {
	u32	raw;
	struct	{
		u32	__reserved2	: 21,
			cpr		:  3,
			__reserved1	:  8;
	} __packed bits;
};

union cepic_esr {
	u32	raw;
	struct	{
		u32	__reserved2	: 20,
			ms_icr_err	:  1,
			ms_err		:  1,
			ms_virt_err	:  1,
			ms_gstid_err	:  1,
			rq_cop_err	:  1,
			rq_virt_err	:  1,
			rq_addr_err	:  1,
			__reserved1	:  5;
	} __packed bits;
};

union cepic_esr2 {
	u32	raw;
	struct	{
		u32	__reserved3	: 15,
			mask		:  1,
			__reserved2	:  3,
			stat		:  1,
			__reserved1	:  2,
			vect		: 10;
	} __packed bits;
};

union cepic_eoi {
	u32	raw;
	struct	{
		u32	__reserved2	: 13,
			rcpr		:  3,
			__reserved1	: 16;
	} __packed bits;
};

union cepic_cir {
	u32	raw;
	struct	{
		u32	__reserved2	: 19,
			stat		:  1,
			__reserved1	:  2,
			vect		: 10;
	} __packed bits;
};

union cepic_gstbase_hi {
	u32	raw;
	struct	{
		u32	__reserved	: 28,
			gstbase_hi	: 4;
	} __packed bits;
};

union cepic_gstid {
	u32	raw;
	struct	{
		u32	__reserved	: 20,
			gstid		: 12;
	} __packed bits;
};

union cepic_pnmirr {
	u32	raw;
	struct	{
		u32	__reserved3	: 14,
			nm_special	:  1,
			nm_timer	:  1,
			__reserved2	:  2,
			int_violat	:  1,
			startup		:  1,
			init		:  1,
			nmi		:  1,
			smi		:  1,
			__reserved1	:  1,
			startup_entry	:  8;
	} __packed bits;
};

union cepic_icr {
	u64	raw;
	struct	{
		u64	__reserved3	: 14,
			dst		: 10,
			__reserved2	:  8,
			gst_id		: 12,
			__reserved1	:  4,
			dlvm		:  3,
			stat		:  1,
			dst_sh		:  2,
			vect		: 10;
	} __packed bits;
};

union cepic_timer_lvtt {
	u32	raw;
	struct	{
		u32	__reserved3	: 14,
			mode		:  1,
			mask		:  1,
			__reserved2	:  3,
			stat		:  1,
			__reserved1	:  2,
			vect		: 10;
	} __packed bits;
};

union cepic_timer_div {
	u32	raw;
	struct	{
		u32	__reserved1	: 28,
			divider		:  4;
	} __packed bits;
};

union cepic_nm_timer_lvtt {
	u32	raw;
	struct	{
		u32	__reserved2	: 14,
			mode		:  1,
			__reserved1	: 17;
	} __packed bits;
};

union cepic_nm_timer_div {
	u32	raw;
	struct	{
		u32	__reserved1	: 28,
			divider		:  4;
	} __packed bits;
};

union cepic_svr {
	u32	raw;
	struct	{
		u32	__reserved1	: 22,
			vect		: 10;
	} __packed bits;
};

union cepic_pnmirr_mask {
	u32	raw;
	struct	{
		u32	__reserved4	: 14,
			nm_special	:  1,
			nm_timer	:  1,
			__reserved3	:  2,
			int_violat	:  1,
			__reserved2	:  2,
			nmi		:  1,
			smi		:  1,
			__reserved1	:  9;
	} __packed bits;
};

union cepic_vect_inta {
	u32	raw;
	struct	{
		u32	__reserved2	:  13,
			cpr		:   3,
			__reserved1	:   6,
			vect		:  10;
	} __packed bits;
};

union prepic_ctrl {
	u32	raw;
	struct	{
		u32	__reserved3	: 20,
			epic_en		:  1,
			__reserved2	:  2,
			bsp		:  1,
			__reserved1	:  8;
	} __packed bits;
};

union prepic_id {
	u32	raw;
	struct	{
		u32	__reserved2	: 22,
			prepicn		:  2,
			__reserved1	:  8;
	} __packed bits;
};

union prepic_ctrl2 {
	u32	raw;
	struct	{
		u32	__reserved3	: 19,
			virt_en		:  1,
			__reserved2	:  2,
			bgi_mode	:  1,
			__reserved1	:  9;
	} __packed bits;
};

union prepic_err_int {
	u32	raw;
	struct	{
		u32	__reserved3	:  2,
			dst		: 10,
			__reserved2	:  3,
			mask		:  1,
			dlvm		:  3,
			stat		:  1,
			__reserved1	:  2,
			vect		: 10;
	} __packed bits;
};

union prepic_linpn {
	u32	raw;
	struct	{
		u32	__reserved3	:  2,
			dst		: 10,
			__reserved2	:  3,
			mask		:  1,
			dlvm		:  3,
			stat		:  1,
			__reserved1	:  2,
			vect		: 10;
	} __packed bits;
};

#else /*__BIG_ENDIAN*/
# error FIXME
#endif
#endif	/* !(__ASSEMBLY__) */
#endif	/* __ASM_L_EPIC_REGS_H */
