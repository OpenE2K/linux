/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Network checksum routines
 *
 *
 * The code coming from arch/alpha/lib/checksum.c and arch/ia-64/lib/checksum.c
 *
 * This file contains network checksum routines that are better done
 * in an architecture-specific manner due to speed..
 */

#include <linux/export.h>
#include <linux/uaccess.h>

#include <net/checksum.h>

#include <asm/byteorder.h>

static inline unsigned short from32to16(u32 x)
{
	x += __builtin_e2k_scls(x, 16);
	return x >> 16;
}

unsigned int __pure e2k_do_csum(const unsigned char *buff, int len)
{
	int odd;
	u32 result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
		result += (*buff << 8);
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const u32 *buff32 = (u32 *) buff;
			int i;
			u64 sum = 0;

			buff += (unsigned) len & ~3;
			if (len > 200) {
				/* Packets */
#pragma vector aligned
#pragma loop count (1000)
#pragma unroll (4)
				for (i = 0; i < len / 4; i++)
					sum += (u64) buff32[i];
			} else {
				/* Packet headers */
#pragma vector aligned
#pragma loop count (10)
				for (i = 0; i < len / 4; i++)
					sum += (u64) buff32[i];
			}

			sum += (u64) result;
			sum += __builtin_e2k_scld(sum, 32);
			result = (u32) (sum >> 32);

			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
		result += *buff;
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}
EXPORT_SYMBOL(e2k_do_csum);

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
__wsum __csum_partial(const void *buff, int len, __wsum wsum)
{
	u32 sum = (__force u32) wsum;
	u32 result = e2k_do_csum(buff, len);

	return (__force __wsum) add32_with_carry(result, sum);
}
EXPORT_SYMBOL(__csum_partial);

/*
 * this routine is used for miscellaneous IP-like checksums, mainly
 * in icmp.c
 */
__sum16 ip_compute_csum(const void *buff, int len)
{
	return (__force __sum16)~e2k_do_csum(buff, len);
}
EXPORT_SYMBOL(ip_compute_csum);

#ifdef _HAVE_ARCH_IPV6_CSUM
__sum16 csum_ipv6_magic(const struct in6_addr *saddr,
			const struct in6_addr *daddr,
			__u32 len, __u8 proto, __wsum csum)
{

	__u32 ulen;
	__u32 uproto;
	__u64 sum = (__force u32) csum;

	sum += (__force u32) saddr->s6_addr32[0];
	sum += (__force u32) saddr->s6_addr32[1];
	sum += (__force u32) saddr->s6_addr32[2];
	sum += (__force u32) saddr->s6_addr32[3];
	sum += (__force u32) daddr->s6_addr32[0];
	sum += (__force u32) daddr->s6_addr32[1];
	sum += (__force u32) daddr->s6_addr32[2];
	sum += (__force u32) daddr->s6_addr32[3];

	ulen = (__force u32) htonl((__u32) len);
	sum += ulen;

	uproto = (__force u32) htonl(proto);
	sum += uproto;

	return csum_fold((__force __wsum) from64to32(sum));
}
EXPORT_SYMBOL(csum_ipv6_magic);
#endif
