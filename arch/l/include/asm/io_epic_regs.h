#ifndef	__ASM_L_IO_EPIC_REGS_H
#define	__ASM_L_IO_EPIC_REGS_H

#include <asm/types.h>

#ifdef __LITTLE_ENDIAN
/* The structure of the IO-EPIC */
union IO_EPIC_ID {
	u32	raw;
	struct {
		u32	id	: 16,
			nodeid	: 16;
	} __packed bits;
};

union IO_EPIC_VERSION {
	u32	raw;
	struct {
		u32	version		: 8,
			__reserved2	: 8,
			entries		: 8,
			__reserved1	: 8;
	} __packed bits;
};

union IO_EPIC_INT_CTRL {
	u32	raw;
	struct {
		u32	__reserved3	: 12,
			delivery_status	:  1,
			software_int	:  1,
			__reserved2	:  1,
			trigger		:  1, /* 0: edge, 1: level */
			mask		:  1, /* 0: enabled, 1: disabled */
			__reserved1	:  15;
	} __packed bits;
};

union IO_EPIC_MSG_DATA {
	u32	raw;
	struct {
		u32	vector		: 10,
			__reserved2	:  3,
			dlvm		:  3,
			__reserved1	: 16;
	} __packed bits;
};

union IO_EPIC_MSG_ADDR_LOW {
	u32	raw;
	struct {
		u32	__reserved3	:  2,
			msg_type	:  3,
			__reserved2	:  1,
			dst		: 10,
			__reserved1	:  4,
			MSI		: 12;
	} __packed bits;
};

union IO_EPIC_REQ_ID {
	u32	raw;
	struct {
		u32	fn		: 3,
			dev		: 5,
			bus		: 8,
			__reserved1	: 16;
	} __packed bits;
};
#elif defined(__BIG_ENDIAN)
/* The structure of the IO-EPIC */
union IO_EPIC_ID {
	u32	raw;
	struct {
		u32	nodeid	: 16,
			id	: 16;
	} __packed bits;
};

union IO_EPIC_VERSION {
	u32	raw;
	struct {
		u32	__reserved1	: 8,
			entries		: 8,
			__reserved2	: 8,
			version		: 8;
	} __packed bits;
};

union IO_EPIC_INT_CTRL {
	u32	raw;
	struct {
		u32	__reserved1	:  15,
			mask		:  1, /* 0: enabled, 1: disabled */
			trigger		:  1, /* 0: edge, 1: level */
			__reserved2	:  1,
			software_int	:  1,
			delivery_status	:  1,
			__reserved3	: 12;
	} __packed bits;
};

union IO_EPIC_MSG_DATA {
	u32	raw;
	struct {
		u32	__reserved1	: 16,
			dlvm		:  3,
			__reserved2	:  3,
			vector		: 10;
	} __packed bits;
};

union IO_EPIC_MSG_ADDR_LOW {
	u32	raw;
	struct {
		u32	MSI		: 12,
			__reserved1	:  4,
			dst		: 10,
			__reserved2	:  1,
			msg_type	:  3,
			__reserved3	:  2;
	} __packed bits;
};

union IO_EPIC_REQ_ID {
	u32	raw;
	struct {
		u32	__reserved1	: 16,
			bus		: 8,
			dev		: 5,
			fn		: 3;
	} __packed bits;
};

#else /*__BIG_ENDIAN*/
# error What is the endianess?
#endif

struct IO_EPIC_route_entry {
	union IO_EPIC_INT_CTRL int_ctrl;
	union IO_EPIC_MSG_DATA msg_data;
	u32 addr_high;
	union IO_EPIC_MSG_ADDR_LOW addr_low;
	union IO_EPIC_REQ_ID rid;
} __packed;

#endif	/* __ASM_L_IO_EPIC_REGS_H */
