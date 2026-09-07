/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 MCST
 */

/*
 * Using hardware CLMUL instruction to accelerate the CRC32 disposal.
 * CRC32C polynomial:0x1EDC6F41(BE)/0x82F63B78(LE)
 */

#include <linux/kernel.h>
#include <crypto/internal/hash.h>
#include <e2kintrin.h>
#include "crc32c-e2kv6-constants.h"

#define CRC32C_8B                                                      \
	{                                                              \
		sum = __builtin_e2k_pxord((u64)*p4++, sum);            \
		mul = __builtin_e2k_clmull(sum, 0xdd45aab8LL);         \
		sum = __builtin_e2k_psrlql(0, mul, 4);                 \
		tmp = __builtin_e2k_pxord((u64)*p4++, mul);            \
		mul = __builtin_e2k_clmull(tmp, 0xdea713f100000000LL); \
		mul = __builtin_e2k_clmulh(mul, 0x105ec76f0LL);        \
		sum = __builtin_e2k_pxord(sum, mul);                   \
	}

#define CRC32C_4B                                                      \
	{                                                              \
		tmp = __builtin_e2k_pxord((u64)*p4++, sum);            \
		mul = __builtin_e2k_clmull(tmp, 0xdea713f100000000LL); \
		sum = __builtin_e2k_clmulh(mul, 0x105ec76f0LL);        \
	}

#define CRC32C_2B                                                      \
	{                                                              \
		u64 fmt_shr16 = 0x8080808005040302LL;                  \
		tmp = __builtin_e2k_pxord((u64)*p2++, sum);            \
		mul = __builtin_e2k_clmull(tmp, 0x13f1000000000000LL); \
		mul = __builtin_e2k_clmulh(mul, 0x105ec76f1LL);        \
		tmp = __builtin_e2k_pshufb(0, sum, fmt_shr16);         \
		sum = __builtin_e2k_pxord(mul, tmp);                   \
	}

#define CRC32C_1B                                                      \
	{                                                              \
		u64 fmt_shr8 = 0x8080808004030201LL;                   \
		tmp = __builtin_e2k_pxord((u64)*p1++, sum);            \
		mul = __builtin_e2k_clmull(tmp, 0xf100000000000000LL); \
		mul = __builtin_e2k_clmulh(mul, 0x105ec76f1LL);        \
		tmp = __builtin_e2k_pshufb(0, sum, fmt_shr8);          \
		sum = __builtin_e2k_pxord(mul, tmp);                   \
	}

#define ALIGN_UP(x, align_to) (((x) + ((align_to)-1)) & ~((align_to)-1))
#define ALIGN_PTR_UP(p, ptr_align_to) \
	((typeof(p))ALIGN_UP((unsigned long)(p), ptr_align_to))

/* For length: 1..31 and possible non-aligned pointer to 16 */
static __always_inline u64 crc32c_align(u64 sum, const u8 *p, unsigned int len)
{
	u64 mul, tmp;
	const u8 *p1 = p;
	const u16 *p2 = (const u16 *)ALIGN_PTR_UP(p, 2);
	const u32 *p4 = (const u32 *)ALIGN_PTR_UP(p, 4);
	const long offset = (long)p;

	if (unlikely(len == 0))
		return sum;

	if (unlikely(offset & 1)) {
		CRC32C_1B;
		if (likely(--len == 0))
			return sum;
	}

	if (unlikely((offset + 1) & 2)) {
		if (likely(len >= 2)) {
			CRC32C_2B;
			if (likely(len == 2))
				return sum;
			len -= 2;
		} else {
			CRC32C_1B;
			return sum;
		}
	}

	if (likely(len >= 8)) {
		CRC32C_8B;
		if (likely(len == 8))
			return sum;
	}
	if (likely(len >= 16)) {
		CRC32C_8B;
		if (likely(len == 16))
			return sum;
	}
	if (len >= 24) {
		CRC32C_8B;
	}

	if (likely(!(len & 7)))
		return sum;

	if (len & 4) {
		CRC32C_4B;
		if (likely(!(len & 3)))
			return sum;
	}

	p2 = (u16 *)p4;
	if (len & 2) {
		CRC32C_2B;
	}
	if (likely(!(len & 1)))
		return sum;

	p1 = (u8 *)p2;
	CRC32C_1B;
	return sum;
}

static __always_inline u64 crc32c_tail(u64 sum, const u8 *p, unsigned int len)
{
	/* Len: 1..15, pointer aligned to 16 */
	u64 mul, tmp;
	u32 *p4 = (u32 *)p;
	u16 *p2;
	u8 *p1;

	if (likely(len & 8)) {
		CRC32C_8B;
		if (likely(!(len & 7)))
			return sum;
	}

	if (len & 4) {
		CRC32C_4B;
		if (!(len & 3))
			return sum;
	}

	p2 = (u16 *)p4;
	if (len & 2) {
		CRC32C_2B;
	}
	if (!(len & 1))
		return sum;

	p1 = (u8 *)p2;
	CRC32C_1B;
	return sum;
}

#define QP_ALIGN 16
#define QP_ALIGN_MASK (QP_ALIGN - 1)

static __always_inline u64 __crc32c_e2kv6(u64 sum, const void *p,
					  unsigned int len);

u32 crc32c_e2kv6(u32 crc, const u8 *p, unsigned int len)
{
	u64 sum = (u64)crc;
	u32 tiny = len < QP_ALIGN + QP_ALIGN_MASK;
	u32 unalign = (unsigned long)p & QP_ALIGN_MASK;
	u32 prealign = QP_ALIGN - unalign;
	u32 body;
	u32 tail;

	if (likely(tiny || unalign)) {
		sum = crc32c_align(sum, p, (tiny) ? len : prealign);
		if (likely(tiny))
			return (u32)sum;
		len -= prealign;
		p += prealign;
	}

	body = len & ~QP_ALIGN_MASK;
	sum = __crc32c_e2kv6(sum, p, body);

	tail = len & QP_ALIGN_MASK;
	if (!tail)
		return (u32)sum;

	p += body;
	return (u32)crc32c_tail(sum, p, tail);
}

/*
 * Calculate the checksum of data that is 16 byte aligned and a multiple of
 * 16 bytes.
 *
 * The first step is to reduce it to 1024 bits. We do this in 8 parallel
 * chunks in order to mask the latency of the vpmsum instructions. If we
 * have more than 32 kB of data to checksum we repeat this step multiple
 * times, passing in the previous 1024 bits.
 *
 * The next step is to reduce the 1024 bits to 64 bits. This step adds
 * 32 bits of 0s to the end - this matches what a CRC does. We just
 * calculate constants that land the data in this 32 bits.
 */

#define ACCUMULATE_4x32(hi, lo, data, const_ptr)                           \
	{                                                                  \
		/* copy to locals for single use of arguments */           \
		__v2di d128 = (data);                                      \
		const u32 *cp = (const u32 *)(const_ptr);                  \
									   \
		const u64 c0 = cp[0];                                      \
		const u64 c1 = cp[1];                                      \
		const u64 c2 = cp[2];                                      \
		const u64 c3 = cp[3];                                      \
									   \
		__v2di msw = __builtin_e2k_qpsrld(d128, 32);               \
		__v2di lsw = __builtin_e2k_qpand(                          \
			d128, (__v2di){ 0xFFFFffffull, 0xFFFFffffull });   \
									   \
		hi = __builtin_e2k_plog(0x96, (hi),                        \
					__builtin_e2k_clmull(msw[1], c3),  \
					__builtin_e2k_clmull(lsw[1], c2)); \
		lo = __builtin_e2k_plog(0x96, (lo),                        \
					__builtin_e2k_clmull(msw[0], c1),  \
					__builtin_e2k_clmull(lsw[0], c0)); \
	}

static __always_inline u64 __crc32c_e2kv6(u64 sum, const void *p,
					  unsigned int len)
{
	const __v2di vzero = { 0, 0 };
	const __v2di fmt_4_bytes_left = { 0x131211100f0e0d0cULL,
					  0x1b1a191817161514ULL };

	__v2di *data = (__v2di *)PTR_ALIGN(p, sizeof(__v2di));

	/* vdata0-vdata7 will contain our data (p). */
	__v2di vdata0, vdata1, vdata2, vdata3, vdata4, vdata5, vdata6, vdata7;

	/* v0-v7 will contain our checksums */
	__v2di v0, v1, v2, v3, v4, v5, v6, v7;

	/* {hi,lo}[0..7] accumulators */
	u64 hi0, hi1, hi2, hi3, hi4, hi5, hi6, hi7;
	u64 lo0, lo1, lo2, lo3, lo4, lo5, lo6, lo7;

	u64 tmp, res;

	const __v2di *vcrc_const_ptr;
	u32 offset; /* Constant table offset. */

	int i; /* Counter. */
	unsigned int chunks;

	unsigned int block_size;
	int next_block = 0;

	/* Align by 128 bytes. The last 128 bytes block will be processed at end. */
	unsigned int length = round_down(len, 128);

	__v2di vcrc = __builtin_e2k_qppackdl(0UL, sum);

	/* Short version. */
	if (likely(len < 256)) {
		/* clear accumulators */
		hi0 = 0;
		hi1 = 0;
		lo0 = 0;
		lo1 = 0;

		/* Calculate where in the constant table we need to start. */
		offset = 256 - len;
		vcrc_const_ptr = &vcrc_short_const[offset / 16];

		/* xor initial value*/
		vdata0 = __builtin_e2k_qpxor(*data++, vcrc);

		ACCUMULATE_4x32(hi0, lo0, vdata0, vcrc_const_ptr++);

#pragma loop count(14)
		for (i = 16; i < len; i += 16) {
			ACCUMULATE_4x32(hi1, lo1, *data++, vcrc_const_ptr++);
		}

		/* xor all parallel chunks together. */
		res = __builtin_e2k_pxord(hi0, lo0);
		res = __builtin_e2k_plog(0x96, res, hi1, lo1);

	} else {
		/* Load initial values. */
		vdata0 = data[0];
		vdata1 = data[1];
		vdata2 = data[2];
		vdata3 = data[3];
		vdata4 = data[4];
		vdata5 = data[5];
		vdata6 = data[6];
		vdata7 = data[7];
		data += 8;

		/* xor in initial value */
		vdata0 = __builtin_e2k_qpxor(vdata0, vcrc);

#pragma loop count(2)
		do {
			const u32 *k_ptr;
			u64 k_hi, k_lo;

			/* clear accumulators */
			hi0 = 0;
			hi1 = 0;
			hi2 = 0;
			hi3 = 0;
			hi4 = 0;
			hi5 = 0;
			hi6 = 0;
			hi7 = 0;
			lo0 = 0;
			lo1 = 0;
			lo2 = 0;
			lo3 = 0;
			lo4 = 0;
			lo5 = 0;
			lo6 = 0;
			lo7 = 0;

			/* Checksum in blocks of MAX_SIZE. */
			block_size = min(length, MAX_SIZE);
			length = length - block_size;

			/*
			* Work out the offset into the constants table to start at. Each
			* pair of constants is 8 bytes, and it is used against 128 bytes
			* of input data - 128 / 8 = 16
			*/
			offset = (MAX_SIZE / 8) - (block_size / 8);

			k_ptr = &crc_long_const[offset / 8];
			k_lo = (u64)*k_ptr++;
			k_hi = (u64)*k_ptr++;
			k_lo += k_lo; /* mul by 2 */
			k_hi += k_hi; /* mul by 2 */

			/* We reduce our final 128 bytes in a separate step */
			chunks = (block_size / 128) - 1;

			/*
			 * main loop. We modulo schedule it such that it takes three
			 * iterations to complete - first iteration load, second
			 * iteration vpmsum, third iteration xor.
			 */

#define ACCUMULATE_2x64(hi, lo, x, c_hi, c_lo)                                 \
	{                                                                      \
		hi = __builtin_e2k_plog(0x96, (hi),                            \
					__builtin_e2k_clmulh((x)[1], (c_hi)),  \
					__builtin_e2k_clmulh((x)[0], (c_lo))); \
		lo = __builtin_e2k_plog(0x96, (lo),                            \
					__builtin_e2k_clmull((x)[1], (c_hi)),  \
					__builtin_e2k_clmull((x)[0], (c_lo))); \
	}

#pragma unroll(1)
#pragma loop count(256)
			for (i = 0; i < chunks - 1; i++) {
				ACCUMULATE_2x64(hi0, lo0, vdata0, k_hi, k_lo);
				ACCUMULATE_2x64(hi1, lo1, vdata1, k_hi, k_lo);
				ACCUMULATE_2x64(hi2, lo2, vdata2, k_hi, k_lo);
				ACCUMULATE_2x64(hi3, lo3, vdata3, k_hi, k_lo);
				ACCUMULATE_2x64(hi4, lo4, vdata4, k_hi, k_lo);
				ACCUMULATE_2x64(hi5, lo5, vdata5, k_hi, k_lo);
				ACCUMULATE_2x64(hi6, lo6, vdata6, k_hi, k_lo);
				ACCUMULATE_2x64(hi7, lo7, vdata7, k_hi, k_lo);
				k_lo = (u64)*k_ptr++;
				k_hi = (u64)*k_ptr++;
				k_lo += k_lo; /* mul by 2 */
				k_hi += k_hi; /* mul by 2 */

				vdata0 = data[0];
				vdata1 = data[1];
				vdata2 = data[2];
				vdata3 = data[3];
				vdata4 = data[4];
				vdata5 = data[5];
				vdata6 = data[6];
				vdata7 = data[7];
				data += 8;
			}

			/* First cool down*/
			ACCUMULATE_2x64(hi0, lo0, vdata0, k_hi, k_lo);
			ACCUMULATE_2x64(hi1, lo1, vdata1, k_hi, k_lo);
			ACCUMULATE_2x64(hi2, lo2, vdata2, k_hi, k_lo);
			ACCUMULATE_2x64(hi3, lo3, vdata3, k_hi, k_lo);
			ACCUMULATE_2x64(hi4, lo4, vdata4, k_hi, k_lo);
			ACCUMULATE_2x64(hi5, lo5, vdata5, k_hi, k_lo);
			ACCUMULATE_2x64(hi6, lo6, vdata6, k_hi, k_lo);
			ACCUMULATE_2x64(hi7, lo7, vdata7, k_hi, k_lo);

			/* Second cool down. */
			v0 = __builtin_e2k_qppackdl(hi0, lo0);
			v1 = __builtin_e2k_qppackdl(hi1, lo1);
			v2 = __builtin_e2k_qppackdl(hi2, lo2);
			v3 = __builtin_e2k_qppackdl(hi3, lo3);
			v4 = __builtin_e2k_qppackdl(hi4, lo4);
			v5 = __builtin_e2k_qppackdl(hi5, lo5);
			v6 = __builtin_e2k_qppackdl(hi6, lo6);
			v7 = __builtin_e2k_qppackdl(hi7, lo7);

			/*
			 * vpmsumd produces a 96 bit result in the least significant bits
			 * of the register. Since we are bit reflected we have to shift it
			 * left 32 bits so it occupies the least significant bits in the
			 * bit reflected domain.
			 */
			v0 = __builtin_e2k_qppermb(v0, vzero, fmt_4_bytes_left);
			v1 = __builtin_e2k_qppermb(v1, vzero, fmt_4_bytes_left);
			v2 = __builtin_e2k_qppermb(v2, vzero, fmt_4_bytes_left);
			v3 = __builtin_e2k_qppermb(v3, vzero, fmt_4_bytes_left);
			v4 = __builtin_e2k_qppermb(v4, vzero, fmt_4_bytes_left);
			v5 = __builtin_e2k_qppermb(v5, vzero, fmt_4_bytes_left);
			v6 = __builtin_e2k_qppermb(v6, vzero, fmt_4_bytes_left);
			v7 = __builtin_e2k_qppermb(v7, vzero, fmt_4_bytes_left);

			/* xor with the last 1024 bits. */
			vdata0 = __builtin_e2k_qpxor(v0, data[0]);
			vdata1 = __builtin_e2k_qpxor(v1, data[1]);
			vdata2 = __builtin_e2k_qpxor(v2, data[2]);
			vdata3 = __builtin_e2k_qpxor(v3, data[3]);
			vdata4 = __builtin_e2k_qpxor(v4, data[4]);
			vdata5 = __builtin_e2k_qpxor(v5, data[5]);
			vdata6 = __builtin_e2k_qpxor(v6, data[6]);
			vdata7 = __builtin_e2k_qpxor(v7, data[7]);
			data += 8;

			/* Check if we have more blocks to process */
			next_block = 0;
			if (length != 0) {
				next_block = 1;
			}
			length = length + 128;

		} while (next_block);

		/* clear accumulators */
		hi0 = 0;
		hi1 = 0;
		hi2 = 0;
		hi3 = 0;
		hi4 = 0;
		hi5 = 0;
		hi6 = 0;
		hi7 = 0;
		lo0 = 0;
		lo1 = 0;
		lo2 = 0;
		lo3 = 0;
		lo4 = 0;
		lo5 = 0;
		lo6 = 0;
		lo7 = 0;

		/* Calculate how many bytes we have left. */
		length = (len & 127);

		/* Calculate where in (short) constant table we need to start. */
		offset = 128 - length;

		vcrc_const_ptr = &vcrc_short_const[offset / 16];

		ACCUMULATE_4x32(hi0, lo0, vdata0, &vcrc_const_ptr[0]);
		ACCUMULATE_4x32(hi1, lo1, vdata1, &vcrc_const_ptr[1]);
		ACCUMULATE_4x32(hi2, lo2, vdata2, &vcrc_const_ptr[2]);
		ACCUMULATE_4x32(hi3, lo3, vdata3, &vcrc_const_ptr[3]);
		ACCUMULATE_4x32(hi4, lo4, vdata4, &vcrc_const_ptr[4]);
		ACCUMULATE_4x32(hi5, lo5, vdata5, &vcrc_const_ptr[5]);
		ACCUMULATE_4x32(hi6, lo6, vdata6, &vcrc_const_ptr[6]);
		ACCUMULATE_4x32(hi7, lo7, vdata7, &vcrc_const_ptr[7]);

		vcrc_const_ptr += 8;

		/* Now reduce the tail (0-112 bytes). */
#pragma loop count(7)
		for (i = 0; i < length; i += 16) {
			ACCUMULATE_4x32(hi6, lo6, *data++, vcrc_const_ptr++);
		}

		/* xor all parallel chunks together. */
		lo0 = __builtin_e2k_plog(0x96, hi0, lo0, hi1);
		lo1 = __builtin_e2k_plog(0x96, lo1, hi2, lo2);
		lo2 = __builtin_e2k_plog(0x96, hi3, lo3, hi4);
		lo3 = __builtin_e2k_plog(0x96, lo4, hi5, lo5);
		lo4 = __builtin_e2k_plog(0x96, hi6, lo6, hi7);

		lo0 = __builtin_e2k_plog(0x96, lo7, lo0, lo1);
		lo1 = __builtin_e2k_plog(0x96, lo2, lo3, lo4);

		res = __builtin_e2k_pxord(lo0, lo1);
	}

	/* Barrett Reduction */

	/* shift left one bit */
	res = __builtin_e2k_pslld(res, 1);
	/* bottom 32 bits of a (tmp = res & 0xFFFFffff) */
	tmp = __builtin_e2k_pshufw(0, res, 8);

	/*
	 * The reflected version of Barrett reduction. Instead of bit
	 * reflecting our data (which is expensive to do), we bit reflect our
	 * constants and our algorithm, which means the intermediate data in
	 * our registers goes from 0-63 instead of 63-0. We can reflect
	 * the algorithm because we don't carry in mod 2 arithmetic.
	 */

	/* ma */
	tmp = __builtin_e2k_clmull(tmp, 0x0dea713f1ULL);
	/* bottom 32bits of ma (tmp &= 0xFFFFffff) */
	tmp = __builtin_e2k_pshufw(0, tmp, 8);
	/* qn */
	tmp = __builtin_e2k_clmull(tmp, 0x105ec76f1ULL);
	/* a - qn, subtraction is xor in GF(2) */
	res = __builtin_e2k_pxord(res, tmp);

	/*
	 * Since we are bit reflected, the result (ie the low 32 bits) is in
	 * the high 32 bits.
	 */
	return __builtin_e2k_psrlql(0, res, 4);
}

/*
 * Setting the seed allows arbitrary accumulators and flexible XOR policy
 * If your algorithm starts with ~0, then XOR with ~0 before you set
 * the seed.
 */
static int crc32c_e2kv6_setkey(struct crypto_shash *hash, const u8 *key,
			       unsigned int keylen)
{
	u32 *mctx = crypto_shash_ctx(hash);

	if (keylen != sizeof(u32))
		return -EINVAL;
	*mctx = le32_to_cpup((__le32 *)key);
	return 0;
}

static int crc32c_e2kv6_init(struct shash_desc *desc)
{
	u32 *mctx = crypto_shash_ctx(desc->tfm);
	u32 *crcp = shash_desc_ctx(desc);

	*crcp = *mctx;

	return 0;
}

static int crc32c_e2kv6_update(struct shash_desc *desc, const u8 *data,
			       unsigned int len)
{
	u32 *crcp = shash_desc_ctx(desc);

	*crcp = crc32c_e2kv6(*crcp, data, len);
	return 0;
}

static int __crc32c_e2kv6_finup(u32 *crcp, const u8 *data, unsigned int len,
				u8 *out)
{
	*(__le32 *)out = ~cpu_to_le32(crc32c_e2kv6(*crcp, data, len));
	return 0;
}

static int crc32c_e2kv6_finup(struct shash_desc *desc, const u8 *data,
			      unsigned int len, u8 *out)
{
	return __crc32c_e2kv6_finup(shash_desc_ctx(desc), data, len, out);
}

static int crc32c_e2kv6_final(struct shash_desc *desc, u8 *out)
{
	u32 *crcp = shash_desc_ctx(desc);

	*(__le32 *)out = ~cpu_to_le32p(crcp);
	return 0;
}

static int crc32c_e2kv6_digest(struct shash_desc *desc, const u8 *data,
			       unsigned int len, u8 *out)
{
	return __crc32c_e2kv6_finup(crypto_shash_ctx(desc->tfm), data, len,
				    out);
}

static int crc32c_e2kv6_cra_init(struct crypto_tfm *tfm)
{
	u32 *key = crypto_tfm_ctx(tfm);

	*key = ~0;

	return 0;
}

#define CHKSUM_BLOCK_SIZE 1
#define CHKSUM_DIGEST_SIZE 4

struct shash_alg alg_crc32c_e2kv6 = { .setkey = crc32c_e2kv6_setkey,
				      .init = crc32c_e2kv6_init,
				      .update = crc32c_e2kv6_update,
				      .final = crc32c_e2kv6_final,
				      .finup = crc32c_e2kv6_finup,
				      .digest = crc32c_e2kv6_digest,
				      .descsize = sizeof(u32),
				      .digestsize = CHKSUM_DIGEST_SIZE,
				      .base = {
					      .cra_name = "crc32c",
					      .cra_driver_name = "crc32c-e2kv6",
					      .cra_priority = 200,
					      .cra_flags =
						      CRYPTO_ALG_OPTIONAL_KEY,
					      .cra_blocksize =
						      CHKSUM_BLOCK_SIZE,
					      .cra_ctxsize = sizeof(u32),
					      .cra_module = THIS_MODULE,
					      .cra_init = crc32c_e2kv6_cra_init,
				      } };
