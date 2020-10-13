/*
 * Network checksum routines
 *
 *
 * The code coming from arch/alpha/lib/checksum.c and arch/ia-64/lib/checksum.c
 *
 * This file contains network checksum routines that are better done
 * in an architecture-specific manner due to speed..
 */

#include <linux/module.h>

#include <net/checksum.h>

#include <asm/byteorder.h>
#include <asm/uaccess.h>

static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static unsigned int do_csum(const unsigned char *buff, int len)
{
	int odd;
	unsigned int result = 0;

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
			u32 *buff32 = (u32 *) buff;
			int i;
			u64 sum = 0;

			buff += (unsigned) len & ~3;
			if (len > 200) {
				/* Packets */
#pragma loop count (1000)
#pragma unroll (4)
				for (i = 0; i < len / 4; i++)
					sum += (u64) buff32[i];
			} else {
				/* Packet headers */
#pragma loop count (10)
				for (i = 0; i < len / 4; i++)
					sum += (u64) buff32[i];
			}
			sum = (u64) ((u32) sum) + (sum >> 32) + (u64) result;
			if (sum >> 32) {
				sum = (u64) ((u32) sum) + (sum >> 32);
				if (sum >> 32)
					++sum;
			}
			result = (u32) sum;
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

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 */
__sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	return (__force __sum16)~do_csum(iph, ihl*4);
}
EXPORT_SYMBOL(ip_fast_csum);

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
__wsum csum_partial(const void *buff, int len, __wsum wsum)
{
	unsigned int sum = (__force unsigned int)wsum;
	unsigned int result = do_csum(buff, len);

	/* add in old sum, and carry.. */
	result += sum;
	if (sum > result)
		result += 1;
	return (__force __wsum)result;
}
EXPORT_SYMBOL(csum_partial);

/*
 * this routine is used for miscellaneous IP-like checksums, mainly
 * in icmp.c
 */
__sum16 ip_compute_csum(const void *buff, int len)
{
	return (__force __sum16)~do_csum(buff, len);
}
EXPORT_SYMBOL(ip_compute_csum);

/*
 * copy from fs while checksumming, otherwise like csum_partial
 */
__wsum
csum_partial_copy_from_user(const void __user *src, void *dst, int len,
						__wsum sum, int *csum_err)
{
	int missing;

	missing = __copy_from_user(dst, src, len);
	if (missing) {
		memset(dst + len - missing, 0, missing);
		*csum_err = -EFAULT;
	} else {
		*csum_err = 0;
	}

	return csum_partial(dst, len, sum);
}
EXPORT_SYMBOL(csum_partial_copy_from_user);

/*
 * copy from ds while checksumming, otherwise like csum_partial
 */
__wsum
csum_partial_copy(const void *src, void *dst, int len, __wsum sum)
{
	memcpy(dst, src, len);
	return csum_partial(dst, len, sum);
}
EXPORT_SYMBOL(csum_partial_copy);

__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			unsigned short len,
			unsigned short proto,
			__wsum sum)
{
	unsigned long long s = (__force u32)sum;

	s += (__force u32)saddr;
	s += (__force u32)daddr;
	s += (proto + len) << 8;
	s += (s >> 32);
	return (__force __wsum)s;
}
EXPORT_SYMBOL(csum_tcpudp_nofold);
