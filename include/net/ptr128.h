/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef NET_PTR128_H
#define NET_PTR128_H

#include <linux/socket.h>
#include <linux/in.h>
#include <asm/e2k_ptypes.h>
#include <linux/build_bug.h>


struct ptr128_msghdr {
	e2k_ap_t	msg_name;	/* void * */
	int		msg_namelen;
	e2k_ap_t	msg_iov;	/* struct prot_iovec * */
	size_t		msg_iovlen;
	e2k_ap_t	msg_control;	/* void * */
	size_t		msg_controllen;
	unsigned int	msg_flags;
};

struct ptr128_mmsghdr {
	struct ptr128_msghdr	msg_hdr;
	unsigned int	        msg_len;
};

struct ptr128_rtentry {
	unsigned long   rt_pad1;
	struct sockaddr rt_dst;         /* target address               */
	struct sockaddr rt_gateway;     /* gateway addr (RTF_GATEWAY)   */
	struct sockaddr rt_genmask;     /* target network mask (IP)     */
	unsigned short  rt_flags;
	short           rt_pad2;
	unsigned long   rt_pad3;
	e2k_ap_t	rt_pad4;
	short           rt_metric;      /* +1 for binary compatibility! */
	e2k_ap_t	rt_dev;        /* forcing the device at add    */
	unsigned long   rt_mtu;         /* per route MTU/Window         */
	unsigned long   rt_window;      /* Window clamping              */
	unsigned short  rt_irtt;        /* Initial RTT   		*/
};

/* NOTICE: sizeof(struct __kernel_sockaddr_storage) == 128 */

union ptr128_sockaddr_storage {
	struct __kernel_sockaddr_storage unused;
	e2k_ap_t e2k_align;
};

struct ptr128_group_req {
	__u32				 gr_interface;
	struct __kernel_sockaddr_storage gr_group
		__aligned(16);
} __packed;

struct ptr128_source_req {
	__u32				 gsr_interface;
	struct __kernel_sockaddr_storage gsr_group
		__aligned(16);
	struct __kernel_sockaddr_storage gsr_source
		__aligned(16);
} __packed;

struct ptr128_group_filter {
	union {
		struct {
			__u32				 gf_interface_aux;
			struct __kernel_sockaddr_storage gf_group_aux
				__aligned(16);
			__u32				 gf_fmode_aux;
			__u32				 gf_numsrc_aux;
			struct __kernel_sockaddr_storage gf_slist[1]
				__aligned(16);
		} __packed;
		struct {
			__u32				 gf_interface;
			struct __kernel_sockaddr_storage gf_group
				__aligned(16);
			__u32				 gf_fmode;
			__u32				 gf_numsrc;
			struct __kernel_sockaddr_storage gf_slist_flex[]
				__aligned(16);
		} __packed;
	};
} __packed;

struct ptr128_group_source_req {
	 __u32                            gsr_interface; /* interface index */
	struct __kernel_sockaddr_storage gsr_group __aligned(16);     /* group address */
	struct __kernel_sockaddr_storage gsr_source __aligned(16);    /* source address */
} __packed;

struct ptr128_if_settings {
	unsigned int type;	/* Type of physical device or protocol */
	unsigned int size;	/* Size of the data allocated by the caller */
	e2k_ap_t  ap;		/* interface settings */
};

struct ptr128_ifreq {
	union {
		char	ifrn_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	} ifr_ifrn;

	union {
		struct	sockaddr ifru_addr;
		struct	sockaddr ifru_dstaddr;
		struct	sockaddr ifru_broadaddr;
		struct	sockaddr ifru_netmask;
		struct  sockaddr ifru_hwaddr;
		short	ifru_flags;
		int	ifru_ivalue;
		int	ifru_mtu;
		struct  ifmap ifru_map;
		char	ifru_slave[IFNAMSIZ];	/* Just fits the size */
		char	ifru_newname[IFNAMSIZ];
		e2k_ap_t	ifru_data;
		struct	ptr128_if_settings ifru_settings;
	} ifr_ifru;
};

struct ptr128_ifconf  {
	int		ifc_len;	/* size of buffer */
	e2k_ap_t	ap;
};

#endif /* NET_PTR128_H */
