#ifndef __ASM_L_IOLINKMASK_H
#define __ASM_L_IOLINKMASK_H

/*
 * Based on include/linux/nodemask.h
 * IOLINKmasks provide a bitmap suitable for representing the
 * set of IOLINK's in a system, one bit position per IOLINK domain number.
 *
 * IOLINK can be represented by global domain number and as
 * pair: node and local link number on the node,
 * So main macroses and functions operate with domain number and
 * can have appropriate macroses to operate with pair of node and link #,
 * for axample:
 *	iolink_set(domain, ...)
 *	node_iolink_set(node, link, ...)
 *
 * IOLINK is common name of IO management and can be connected to IOHUB
 * (controller of peripheral interfaces) or RDMA (DMA with remoute systems)
 * So macroses have alternative to operate with IOLINKS as IOHUBs and RDMAs,
 * for example:
 *	iolink_set(...)
 *	iohub_set(...)
 *	rdma_set(...)
 *
 * See detailed comments in the file linux/bitmap.h describing the
 * data type on which these iolinkmasks are based.
 *
 * For details of iolinkmask_scnprintf() and iolinkmask_parse(),
 * see bitmap_scnprintf() and bitmap_parse() in lib/bitmap.c.
 * For details of iolinklist_scnprintf() and iolinklist_parse(), see
 * bitmap_scnlistprintf() and bitmap_parselist(), also in bitmap.c.
 *
 * The available iolinkmask operations are:
 *
 * void iolink_set(iolink, mask)	turn on bit 'iolink' in mask
 * void iolink_clear(iolink, mask)	turn off bit 'iolink' in mask
 * void iolinks_setall(mask)		set all bits
 * void iolinks_clear(mask)		clear all bits
 * int iolink_isset(iolink, mask)	true iff bit 'iolink' set in mask
 * int iolink_test_and_set(iolink, mask) test and set bit 'iolink' in mask
 *
 * void iolinks_and(dst, src1, src2)	dst = src1 & src2  [intersection]
 * void iolinks_or(dst, src1, src2)	dst = src1 | src2  [union]
 * void iolinks_xor(dst, src1, src2)	dst = src1 ^ src2
 * void iolinks_andnot(dst, src1, src2)	dst = src1 & ~src2
 * void iolinks_complement(dst, src)	dst = ~src
 *
 * int iolinks_equal(mask1, mask2)	Does mask1 == mask2?
 * int iolinks_intersects(mask1, mask2)	Do mask1 and mask2 intersect?
 * int iolinks_subset(mask1, mask2)	Is mask1 a subset of mask2?
 * int iolinks_empty(mask)		Is mask empty (no bits sets)?
 * int iolinks_full(mask)		Is mask full (all bits sets)?
 * int iolinks_weight(mask)		Hamming weight - number of set bits
 *
 * void iolinks_shift_right(dst, src, n) Shift right
 * void iolinks_shift_left(dst, src, n)	Shift left
 *
 * int first_iolink(mask)		Number lowest set bit, or MAX_NUMIOLINKS
 * int next_iolink(iolink, mask)	Next iolink past 'iolink', or MAX_NUMIOLINKS
 * int first_unset_iolink(mask)		First iolink not set in mask, or
 *					MAX_NUMIOLINKS.
 *
 * iolinkmask_t iolinkmask_of_iolink(iolink) Return iolinkmask with bit 'iolink' set
 * IOLINK_MASK_ALL			Initializer - all bits set
 * IOLINK_MASK_NONE			Initializer - no bits set
 * unsigned long *iolinks_addr(mask)	Array of unsigned long's in mask
 *
 * int iolinkmask_scnprintf(buf, len, mask) Format iolinkmask for printing
 * int iolinkmask_parse(ubuf, ulen, mask) Parse ascii string as iolinkmask
 * int iolinklist_scnprintf(buf, len, mask) Format iolinkmask as list for printing
 * int iolinklist_parse(buf, map)	Parse ascii string as iolinklist
 *
 * for_each_iolink_mask(iolink, mask)	for-loop iolink over mask
 *
 * int num_online_iolinks()		Number of online IOLINKs
 * int num_possible_iolinks()		Number of all possible IOLINKs
 *
 * int iolink_online(iolink)		Is some iolink domain online?
 * int iolink_possible(iolink)		Is some iolink domain possible?
 *
 * iolink_set_online(iolink)		set bit 'iolink' in iolink_online_map
 * iolink_set_offline(iolink)		clear bit 'iolink' in iolink_online_map
 *
 * for_each_iolink(iolink)		for-loop iolink over iolink_possible_map
 * for_each_online_iolink(iolink)	for-loop iolink over iolink_online_map
 *
 * Subtlety:
 * 1) The 'type-checked' form of iolink_isset() causes gcc (3.3.2, anyway)
 *    to generate slightly worse code.  So use a simple one-line #define
 *    for iolink_isset(), instead of wrapping an inline inside a macro, the
 *    way we do the other calls.
 */

#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/bitmap.h>
#include <linux/numa.h>
#include <linux/topology.h>
#include <asm/bug.h>

#define MAX_NUMIOLINKS	MACH_MAX_NUMIOLINKS
#define MAX_NUMIOHUBS	MAX_NUMIOLINKS
#define NODE_NUMIOLINKS	MACH_NODE_NUMIOLINKS

typedef struct { DECLARE_BITMAP(bits, MAX_NUMIOLINKS); } iolinkmask_t;
extern iolinkmask_t _unused_iolinkmask_arg_;

#define iolink_set(domain, dst) __iolink_set((domain), &(dst))
#define node_iolink_set(node, link, dst)				\
		iolink_set(node_iolink_to_domain((node), (link)), (dst))
#define iohub_set(domain, dst) iolink_set((domain), (dst))
#define node_iohub_set(node, link, dst)				\
		iohub_set(node_iohub_to_domain((node), (link)), (dst))
#define rdma_set(domain, dst) iolink_set((domain), (dst))
#define node_rdma_set(node, link, dst)				\
		rdma_set(node_rdma_to_domain((node), (link)), (dst))
static inline void __iolink_set(int domain, volatile iolinkmask_t *dstp)
{
	set_bit(domain, dstp->bits);
}

#define iolink_clear(domain, dst) __iolink_clear((domain), &(dst))
#define node_iolink_clear(node, link, dst)				\
		iolink_clear(node_iolink_to_domain((node), (link)), (dst))
#define iohub_clear(domain, dst) iolink_clear((domain), (dst))
#define node_iohub_clear(node, link, dst)				\
		iohub_clear(node_iohub_to_domain((node), (link)), (dst))
#define rdma_clear(domain, dst) iolink_clear((domain), (dst))
#define node_rdma_clear(node, link, dst)				\
		rdma_clear(node_rdma_to_domain((node), (link)), (dst))
static inline void __iolink_clear(int domain, volatile iolinkmask_t *dstp)
{
	clear_bit(domain, dstp->bits);
}

#define iolinks_setall(dst) __iolinks_setall(&(dst), MAX_NUMIOLINKS)
static inline void __iolinks_setall(iolinkmask_t *dstp, int nbits)
{
	bitmap_fill(dstp->bits, nbits);
}

#define iolinks_clear(dst) __iolinks_clear(&(dst), MAX_NUMIOLINKS)
static inline void __iolinks_clear(iolinkmask_t *dstp, int nbits)
{
	bitmap_zero(dstp->bits, nbits);
}

/* No static inline type checking - see Subtlety (1) above. */
#define iolink_isset(domain, iolinkmask) test_bit((domain), (iolinkmask).bits)
#define node_iolink_isset(node, link, iolinkmask)			\
		iolink_isset(node_iolink_to_domain((node), (link)),	\
				(iolinkmask).bits)
#define iohub_isset(domain, iolinkmask)	iolink_isset((domain), (iolinkmask))
#define node_iohub_isset(node, link, iolinkmask)			\
		iohub_isset(node_iohub_to_domain((node), (link)),	\
				(iolinkmask).bits)
#define rdma_isset(domain, iolinkmask)	iolink_isset((domain), (iolinkmask))
#define node_rdma_isset(node, link, iolinkmask)				\
		rdma_isset(node_rdma_to_domain((node), (link)),		\
				(iolinkmask).bits)

#define iolink_test_and_set(domain, iolinkmask)				\
		__iolink_test_and_set((domain), &(iolinkmask))
#define node_iolink_test_and_set(node, link, iolinkmask)		\
		iolink_test_and_set(node_iolink_to_domain((node), (link)), \
					(iolinkmask))
#define iohub_test_and_set(domain, iolinkmask)				\
		iolink_test_and_set((domain), (iolinkmask))
#define node_iohub_test_and_set(node, link, iolinkmask)			\
		iohub_test_and_set(node_iohub_to_domain((node), (link)), \
					(iolinkmask))
#define rdma_test_and_set(domain, iolinkmask)				\
		iolink_test_and_set((domain), (iolinkmask))
#define node_rdma_test_and_set(node, link, iolinkmask)			\
		rdma_test_and_set(node_rdma_to_domain((node), (link)),	\
					(iolinkmask))
static inline int __iolink_test_and_set(int domain, iolinkmask_t *addr)
{
	return test_and_set_bit(domain, addr->bits);
}

#define iolinks_and(dst, src1, src2) \
			__iolinks_and(&(dst), &(src1), &(src2), MAX_NUMIOLINKS)
static inline void __iolinks_and(iolinkmask_t *dstp, const iolinkmask_t *src1p,
					const iolinkmask_t *src2p, int nbits)
{
	bitmap_and(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define iolinks_or(dst, src1, src2) \
			__iolinks_or(&(dst), &(src1), &(src2), MAX_NUMIOLINKS)
static inline void __iolinks_or(iolinkmask_t *dstp, const iolinkmask_t *src1p,
					const iolinkmask_t *src2p, int nbits)
{
	bitmap_or(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define iolinks_xor(dst, src1, src2) \
			__iolinks_xor(&(dst), &(src1), &(src2), MAX_NUMIOLINKS)
static inline void __iolinks_xor(iolinkmask_t *dstp, const iolinkmask_t *src1p,
					const iolinkmask_t *src2p, int nbits)
{
	bitmap_xor(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define iolinks_andnot(dst, src1, src2) \
			__iolinks_andnot(&(dst), &(src1), &(src2), MAX_NUMIOLINKS)
static inline void __iolinks_andnot(iolinkmask_t *dstp, const iolinkmask_t *src1p,
					const iolinkmask_t *src2p, int nbits)
{
	bitmap_andnot(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define iolinks_complement(dst, src) \
			__iolinks_complement(&(dst), &(src), MAX_NUMIOLINKS)
static inline void __iolinks_complement(iolinkmask_t *dstp,
					const iolinkmask_t *srcp, int nbits)
{
	bitmap_complement(dstp->bits, srcp->bits, nbits);
}

#define iolinks_equal(src1, src2) \
			__iolinks_equal(&(src1), &(src2), MAX_NUMIOLINKS)
static inline int __iolinks_equal(const iolinkmask_t *src1p,
					const iolinkmask_t *src2p, int nbits)
{
	return bitmap_equal(src1p->bits, src2p->bits, nbits);
}

#define iolinks_intersects(src1, src2) \
			__iolinks_intersects(&(src1), &(src2), MAX_NUMIOLINKS)
static inline int __iolinks_intersects(const iolinkmask_t *src1p,
					const iolinkmask_t *src2p, int nbits)
{
	return bitmap_intersects(src1p->bits, src2p->bits, nbits);
}

#define iolinks_subset(src1, src2) \
			__iolinks_subset(&(src1), &(src2), MAX_NUMIOLINKS)
static inline int __iolinks_subset(const iolinkmask_t *src1p,
					const iolinkmask_t *src2p, int nbits)
{
	return bitmap_subset(src1p->bits, src2p->bits, nbits);
}

#define iolinks_empty(src) __iolinks_empty(&(src), MAX_NUMIOLINKS)
static inline int __iolinks_empty(const iolinkmask_t *srcp, int nbits)
{
	return bitmap_empty(srcp->bits, nbits);
}

#define iolinks_full(iolinkmask) __iolinks_full(&(iolinkmask), MAX_NUMIOLINKS)
static inline int __iolinks_full(const iolinkmask_t *srcp, int nbits)
{
	return bitmap_full(srcp->bits, nbits);
}

#define iolinks_weight(iolinkmask) __iolinks_weight(&(iolinkmask), MAX_NUMIOLINKS)
static inline int __iolinks_weight(const iolinkmask_t *srcp, int nbits)
{
	return bitmap_weight(srcp->bits, nbits);
}

#define iolinks_shift_right(dst, src, n) \
			__iolinks_shift_right(&(dst), &(src), (n), MAX_NUMIOLINKS)
static inline void __iolinks_shift_right(iolinkmask_t *dstp,
					const iolinkmask_t *srcp, int n, int nbits)
{
	bitmap_shift_right(dstp->bits, srcp->bits, n, nbits);
}

#define iolinks_shift_left(dst, src, n) \
			__iolinks_shift_left(&(dst), &(src), (n), MAX_NUMIOLINKS)
static inline void __iolinks_shift_left(iolinkmask_t *dstp,
					const iolinkmask_t *srcp, int n, int nbits)
{
	bitmap_shift_left(dstp->bits, srcp->bits, n, nbits);
}

/* FIXME: better would be to fix all architectures to never return
          > MAX_NUMIOLINKS, then the silly min_ts could be dropped. */

#define first_iolink(src) __first_iolink(&(src))
static inline int __first_iolink(const iolinkmask_t *srcp)
{
	return min_t(int, MAX_NUMIOLINKS, find_first_bit(srcp->bits, MAX_NUMIOLINKS));
}

#define next_iolink(n, src) __next_iolink((n), &(src))
static inline int __next_iolink(int n, const iolinkmask_t *srcp)
{
	return min_t(int, MAX_NUMIOLINKS, find_next_bit(srcp->bits,
			MAX_NUMIOLINKS, n+1));
}

#define iolinkmask_of_iolink(domain)					\
({									\
	typeof(_unused_iolinkmask_arg_) m;				\
	if (sizeof(m) == sizeof(unsigned long)) {			\
		m.bits[0] = 1UL<<(domain);				\
	} else {							\
		iolinks_clear(m);					\
		iolink_set((domain), m);				\
	}								\
	m;								\
})
#define iolinkmask_of_node_iolink(node, link)				\
		iolinkmask_of_iolink(node_iohub_to_domain((node), (link)))

#define first_unset_iolink(mask) __first_unset_iolink(&(mask))
static inline int __first_unset_iolink(const iolinkmask_t *maskp)
{
	return min_t(int,MAX_NUMIOLINKS,
			find_first_zero_bit(maskp->bits, MAX_NUMIOLINKS));
}

#define IOLINK_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(MAX_NUMIOLINKS)

#if MAX_NUMIOLINKS <= BITS_PER_LONG

#define IOLINK_MASK_ALL							\
((iolinkmask_t) { {							\
	[BITS_TO_LONGS(MAX_NUMIOLINKS)-1] = IOLINK_MASK_LAST_WORD		\
} })

#else

#define IOLINK_MASK_ALL							\
((iolinkmask_t) { {							\
	[0 ... BITS_TO_LONGS(MAX_NUMIOLINKS)-2] = ~0UL,			\
	[BITS_TO_LONGS(MAX_NUMIOLINKS)-1] = IOLINK_MASK_LAST_WORD		\
} })

#endif

#define IOLINK_MASK_NONE							\
((iolinkmask_t) { {							\
	[0 ... BITS_TO_LONGS(MAX_NUMIOLINKS)-1] =  0UL			\
} })

#define CHUNKSZ			32
#define nbits_to_hold_value(val)	fls(val)
#define BASEDEC 10		/* fancier cpuset lists input in decimal */

/**
 * bitmap_scnprintf - convert bitmap to an ASCII hex string.
 * @buf: byte buffer into which string is placed
 * @buflen: reserved size of @buf, in bytes
 * @maskp: pointer to bitmap to convert
 * @nmaskbits: size of bitmap, in bits
 *
 * Exactly @nmaskbits bits are displayed.  Hex digits are grouped into
 * comma-separated sets of eight digits per set.  Returns the number of
 * characters which were written to *buf, excluding the trailing \0.
 */
static int bitmap_scnprintf(char *buf, unsigned int buflen,
	const unsigned long *maskp, int nmaskbits)
{
	int i, word, bit, len = 0;
	unsigned long val;
	const char *sep = "";
	int chunksz;
	u32 chunkmask;

	chunksz = nmaskbits & (CHUNKSZ - 1);
	if (chunksz == 0)
		chunksz = CHUNKSZ;

	i = ALIGN(nmaskbits, CHUNKSZ) - CHUNKSZ;
	for (; i >= 0; i -= CHUNKSZ) {
		chunkmask = ((1ULL << chunksz) - 1);
		word = i / BITS_PER_LONG;
		bit = i % BITS_PER_LONG;
		val = (maskp[word] >> bit) & chunkmask;
		len += scnprintf(buf+len, buflen-len, "%s%0*lx", sep,
			(chunksz+3)/4, val);
		chunksz = CHUNKSZ;
		sep = ",";
	}
	return len;
}
#undef CHUNKSZ

/*
 * bscnl_emit(buf, buflen, rbot, rtop, bp)
 *
 * Helper routine for bitmap_scnlistprintf().  Write decimal number
 * or range to buf, suppressing output past buf+buflen, with optional
 * comma-prefix.  Return len of what was written to *buf, excluding the
 * trailing \0.
 */
static inline int bscnl_emit(char *buf, int buflen, int rbot, int rtop, int len)
{
	if (len > 0)
		len += scnprintf(buf + len, buflen - len, ",");
	if (rbot == rtop)
		len += scnprintf(buf + len, buflen - len, "%d", rbot);
	else
		len += scnprintf(buf + len, buflen - len, "%d-%d", rbot, rtop);
	return len;
}

/**
 * bitmap_scnlistprintf - convert bitmap to list format ASCII string
 * @buf: byte buffer into which string is placed
 * @buflen: reserved size of @buf, in bytes
 * @maskp: pointer to bitmap to convert
 * @nmaskbits: size of bitmap, in bits
 *
 * Output format is a comma-separated list of decimal numbers and
 * ranges.  Consecutively set bits are shown as two hyphen-separated
 * decimal numbers, the smallest and largest bit numbers set in
 * the range.  Output format is compatible with the format
 * accepted as input by bitmap_parselist().
 *
 * The return value is the number of characters which were written to *buf
 * excluding the trailing '\0', as per ISO C99's scnprintf.
 */
static int bitmap_scnlistprintf(char *buf, unsigned int buflen,
	const unsigned long *maskp, int nmaskbits)
{
	int len = 0;
	/* current bit is 'cur', most recently seen range is [rbot, rtop] */
	int cur, rbot, rtop;

	if (buflen == 0)
		return 0;
	buf[0] = 0;

	cur = find_first_bit(maskp, nmaskbits);
	rbot = cur;
	while (cur < nmaskbits) {
		rtop = cur;
		cur = find_next_bit(maskp, nmaskbits, cur+1);
		if (cur >= nmaskbits || cur > rtop + 1) {
			len = bscnl_emit(buf, buflen, rbot, rtop, len);
			rbot = cur;
		}
	}
	return len;
}

#define iolinks_addr(src) ((src).bits)

#define iolinkmask_scnprintf(buf, len, src) \
		__iolinkmask_scnprintf((buf), (len), &(src), MAX_NUMIOLINKS)
static inline int __iolinkmask_scnprintf(char *buf, int len,
					const iolinkmask_t *srcp, int nbits)
{
	return bitmap_scnprintf(buf, len, srcp->bits, nbits);
}

#define iolinkmask_parse(ubuf, ulen, dst) \
		__iolinkmask_parse((ubuf), (ulen), &(dst), MAX_NUMIOLINKS)
static inline int __iolinkmask_parse(const char __user *buf, int len,
					iolinkmask_t *dstp, int nbits)
{
	return bitmap_parse(buf, len, dstp->bits, nbits);
}

#define iolinklist_scnprintf(buf, len, src) \
			__iolinklist_scnprintf((buf), (len), &(src), MAX_NUMIOLINKS)
static inline int __iolinklist_scnprintf(char *buf, int len,
					const iolinkmask_t *srcp, int nbits)
{
	return bitmap_scnlistprintf(buf, len, srcp->bits, nbits);
}

#define iolinklist_parse(buf, dst) __iolinklist_parse((buf), &(dst), MAX_NUMIOLINKS)
static inline int __iolinklist_parse(const char *buf, iolinkmask_t *dstp, int nbits)
{
	return bitmap_parselist(buf, dstp->bits, nbits);
}

#if defined(CONFIG_IOHUB_DOMAINS) && MAX_NUMIOLINKS > 1
#define for_each_iolink_mask(domain, mask)				\
		for ((domain) = first_iolink(mask);			\
			(domain) < MAX_NUMIOLINKS;			\
			(domain) = next_iolink((domain), (mask)))
#define for_each_node_iolink_mask(domain, node, link, mask)		\
		for ((domain) = first_iolink(mask),			\
			(node) = iolink_domain_to_node((domain)),	\
			(link) = iolink_domain_to_link((domain));	\
			(domain) < MAX_NUMIOLINKS;			\
			(domain) = next_iolink((domain), (mask)),	\
			(node) = iolink_domain_to_node((domain)),	\
			(link) = iolink_domain_to_link((domain)))
#else /* MAX_NUMIOLINKS == 1 */
#define for_each_iolink_mask(domain, mask)				\
		for ((domain) = 0; (domain) < 1; (domain)++)
#define for_each_node_iolink_mask(domain, node, link, mask)		\
		for ((domain) = 0, (node) = 0, (link) = 0;		\
			(domain) < 1; (domain)++)
#endif /* MAX_NUMIOLINKS */

/*
 * The following particular system iolinkmasks and operations
 * on them manage all possible and online iolinks.
 */

#if defined(CONFIG_IOHUB_DOMAINS) && MAX_NUMIOLINKS > 1
extern int		iolinks_num;
extern iolinkmask_t	iolink_iohub_map;
extern iolinkmask_t	iolink_online_iohub_map;
extern int		iolink_iohub_num;
extern int		iolink_online_iohub_num;
extern iolinkmask_t	iolink_rdma_map;
extern iolinkmask_t	iolink_online_rdma_map;
extern int		iolink_rdma_num;
extern int		iolink_online_rdma_num;

#define	num_online_iolinks()	(num_online_iohubs() + num_online_rdmas())
#define	num_possible_iolinks()	iolinks_num
#define num_online_iohubs()	iolink_online_iohub_num
#define num_possible_iohubs()	iolink_iohub_num
#define num_online_rdmas()	iolink_online_rdma_num
#define num_possible_rdmas()	iolink_rdma_num
#define iolink_online(domain)	(iohub_online(domain) || rdma_online(domain))
#define iolink_possible(domain)	(iohab_possible(domain) || \
					rdma_possible(domain))
#define node_iolink_online(node, link)	\
		iolink_online(node_iolink_to_domain(node, link))
#define node_iolink_possible(node, link)	\
		iolink_possible(node_iolink_to_domain(node, link))
#define iohub_online(domain)	iolink_isset((domain), iolink_online_iohub_map)
#define iohab_possible(domain)	iolink_isset((domain), iolink_iohub_map)
#define node_iohub_online(node, link)	\
		iohub_online(node_iohub_to_domain(node, link))
#define node_iohub_possible(node, link)	\
		iohab_possible(node_iohub_to_domain(node, link))
#define	first_iohub_online()	first_iolink(iolink_online_iohub_map)
#define rdma_online(domain)	iolink_isset((domain), iolink_online_rdma_map)
#define rdma_possible(domain)	iolink_isset((domain), iolink_rdma_map)
#define node_rdma_online(node, link)	\
		rdma_online(node_rdma_to_domain(node, link))
#define node_rdma_possible(node, link)	\
		rdma_possible(node_rdma_to_domain(node, link))
#else
#define iolinks_num		1
#define iolink_iohub_num	1
#define num_online_iolinks()	1
#define num_possible_iolinks()	1
#define num_online_iohubs()	1
#define num_possible_iohubs()	1
#define num_online_rdmas()	0
#define num_possible_rdmas()	0
#define iolink_online(domain)	((domain) == 0)
#define iolink_possible(domain)	((domain) == 0)
#define node_iolink_online(node, link) \
				((node) == 0 && (link) == 0)
#define node_iolink_possible(node, link) \
				((node) == 0 && (link) == 0)
#define iohub_online(domain)	((domain) == 0)
#define iohab_possible(domain)	((domain) == 0)
#define node_iohub_online(node, link) \
				((node) == 0 && (link) == 0)
#define node_iohub_possible(node, link) \
				((node) == 0 && (link) == 0)
#define	first_iohub_online()	0
#define rdma_online(domain)	0
#define rdma_possible(domain)	0
#define node_rdma_online(node, link)	0
#define node_rdma_possible(node, link)	0
#endif

#define iohub_set_online(domain)	\
		set_bit((domain), iolink_online_iohub_map.bits)
#define iohub_set_offline(domain)	\
		clear_bit((domain), iolink_online_iohub_map.bits)
#define node_iohub_set_online(node, link)	\
		iohub_set_online(node_iohub_to_domain((node), (link))
#define node_iohub_set_offline(node, link)	\
		iohub_set_offline(node_iohub_to_domain((node), (link))
#define rdma_set_online(domain)	\
		set_bit((domain), iolink_online_rdma_map.bits)
#define rdma_set_offline(domain)	\
		clear_bit((domain), iolink_online_rdma_map.bits)
#define node_rdma_set_online(node, link)	\
		rdma_set_online(node_rdma_to_domain((node), (link))
#define node_rdma_set_offline(node, link)	\
		rdma_set_offline(node_rdma_to_domain((node), (link))

#define for_each_iohub(domain)		\
		for_each_iolink_mask((domain), iolink_iohub_map)
#define for_each_online_iohub(domain)	\
		for_each_iolink_mask((domain), iolink_online_iohub_map)
#define for_each_node_iohub(domain, node, link)				\
		for_each_node_iolink_mask((domain), (node), (link),	\
						iolink_iohub_map)
#define for_each_online_node_iohub(domain, node, link)			\
		for_each_node_iolink_mask((domain), (node), (link),	\
						iolink_online_iohub_map)
#define for_each_rdma(domain)		\
		for_each_iolink_mask((domain), iolink_rdma_map)
#define for_each_online_rdma(domain)	\
		for_each_iolink_mask((domain), iolink_online_rdma_map)
#define for_each_node_rdma(domain, node, link)				\
		for_each_node_iolink_mask((domain), (node), (link),	\
						iolink_rdma_map)
#define for_each_online_node_rdma(domain, node, link)			\
		for_each_node_iolink_mask((domain), (node), (link),	\
						iolink_online_rdma_map)

#endif /* __ASM_L_IOLINKMASK_H */
