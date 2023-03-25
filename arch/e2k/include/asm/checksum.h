#ifndef _E2K_CHECKSUM_H_
#define _E2K_CHECKSUM_H_

#include <linux/prefetch.h>
#include <linux/in6.h>

extern unsigned int __pure e2k_do_csum(const unsigned char *buff, int len);

/*
 * Fold a partial checksum
 */
#define csum_fold csum_fold
static inline __sum16 csum_fold(__wsum csum)
{
	u32 sum = (__force u32)csum;

	return (__force __sum16) ((~sum - __builtin_e2k_scls(sum, 16)) >> 16);
}

static inline u32 from64to32(u64 x)
{
	x += __builtin_e2k_scld(x, 32);
	return (u32) (x >> 32);
}

/*
 * ihl is always 5 or greater, almost always is 5,
 * and iph is word aligned the majority of the time.
 */
static inline __wsum ip_fast_csum_nofold_maybe_unaligned(const void *iph, unsigned int ihl)
{
	const u32 *iph32 = iph;
	size_t i;
	u64 sum;

	sum = (u64) iph32[0] + (u64) iph32[1] + (u64) iph32[2] +
			(u64) iph32[3] + (u64) iph32[4];

	if (unlikely(ihl > 5)) {
		for (i = 5; i < ihl; i++)
			sum += (u64) iph32[i];
	}

	return (__force __wsum) from64to32(sum);
}
#define ip_fast_csum ip_fast_csum
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	return csum_fold(ip_fast_csum_nofold_maybe_unaligned(iph, ihl));
}

static inline u32 add32_with_carry(u32 a, u32 b)
{
	u64 arg1 = ((u64) a << 32ULL) | (u64) b;
	u64 arg2 = ((u64) b << 32ULL) | (u64) a;

	return (arg1 + arg2) >> 32ULL;
}

#define HAVE_ARCH_CSUM_ADD
static inline __wsum csum_add(__wsum csum, __wsum addend)
{
	return (__force __wsum) add32_with_carry((__force u32) csum,
						 (__force u32) addend);
}


/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 32-bit boundary
 */
__wsum __csum_partial(const void *buff, int len, __wsum sum);

static inline __wsum csum_partial(const void *buff, int len, __wsum sum)
{
	if (__builtin_constant_p(len) && len <= 16 && (len & 1) == 0) {
		u64 sum_64 = (__force u32) sum;

		if (len == 2)
			sum_64 += *(const u16 *) buff;
		if (len >= 4)
			sum_64 += *(const u32 *) buff;
		if (len == 6)
			sum_64 += *(const u16 *) (buff + 4);
		if (len >= 8)
			sum_64 += *(const u32 *) (buff + 4);
		if (len == 10)
			sum_64 += *(const u16 *) (buff + 8);
		if (len >= 12)
			sum_64 += *(const u32 *) (buff + 8);
		if (len == 14)
			sum_64 += *(const u16 *) (buff + 12);
		if (len >= 16)
			sum_64 += *(const u32 *) (buff + 12);

		sum = from64to32(sum_64);
	} else if (__builtin_constant_p(len) && (len & 3) == 0) {
		sum = csum_add(sum, ip_fast_csum_nofold_maybe_unaligned(buff, len >> 2));
	} else {
		prefetch((__force void *) buff);
		sum = __csum_partial(buff, len, sum);
	}
	return sum;
}

#define csum_tcpudp_nofold csum_tcpudp_nofold
static inline __wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum)
{
	u64 s = (__force u32) sum;

	s += (__force u32) saddr;
	s += (__force u32) daddr;
	s += (proto + len) << 8;
	return (__force __wsum) from64to32(s);
}

#define _HAVE_ARCH_IPV6_CSUM
__sum16 csum_ipv6_magic(const struct in6_addr *saddr,
			const struct in6_addr *daddr,
			__u32 len, __u8 proto, __wsum csum);


#include <asm-generic/checksum.h>

#endif /* _E2K_CHECKSUM_H_ */
