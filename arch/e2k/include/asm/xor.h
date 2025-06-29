/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Optimized RAID-5 checksumming functions for E2K
 */

#include <asm-generic/xor.h>
#include <linux/prefetch.h>

static void xor2_64x32_m0(unsigned long bytes, unsigned long *__restrict p1,
			  const unsigned long *__restrict p2)
{
	long lines = bytes / (sizeof(unsigned long)) / 32;

	do {
		p1[0] ^= p2[0];
		p1[1] ^= p2[1];
		p1[2] ^= p2[2];
		p1[3] ^= p2[3];
		p1[4] ^= p2[4];
		p1[5] ^= p2[5];
		p1[6] ^= p2[6];
		p1[7] ^= p2[7];
		p1[8] ^= p2[8];
		p1[9] ^= p2[9];
		p1[10] ^= p2[10];
		p1[11] ^= p2[11];
		p1[12] ^= p2[12];
		p1[13] ^= p2[13];
		p1[14] ^= p2[14];
		p1[15] ^= p2[15];
		p1[16] ^= p2[16];
		p1[17] ^= p2[17];
		p1[18] ^= p2[18];
		p1[19] ^= p2[19];
		p1[20] ^= p2[20];
		p1[21] ^= p2[21];
		p1[22] ^= p2[22];
		p1[23] ^= p2[23];
		p1[24] ^= p2[24];
		p1[25] ^= p2[25];
		p1[26] ^= p2[26];
		p1[27] ^= p2[27];
		p1[28] ^= p2[28];
		p1[29] ^= p2[29];
		p1[30] ^= p2[30];
		p1[31] ^= p2[31];

		p1 += 32;
		p2 += 32;
	} while (--lines > 0);
}

static void xor2_64x64_m0(unsigned long bytes, unsigned long *__restrict p1,
			  const unsigned long *__restrict p2)
{
	long lines = bytes / (sizeof(unsigned long)) / 64;

	do {
		p1[0] ^= p2[0];
		p1[1] ^= p2[1];
		p1[2] ^= p2[2];
		p1[3] ^= p2[3];
		p1[4] ^= p2[4];
		p1[5] ^= p2[5];
		p1[6] ^= p2[6];
		p1[7] ^= p2[7];
		p1[8] ^= p2[8];
		p1[9] ^= p2[9];
		p1[10] ^= p2[10];
		p1[11] ^= p2[11];
		p1[12] ^= p2[12];
		p1[13] ^= p2[13];
		p1[14] ^= p2[14];
		p1[15] ^= p2[15];
		p1[16] ^= p2[16];
		p1[17] ^= p2[17];
		p1[18] ^= p2[18];
		p1[19] ^= p2[19];
		p1[20] ^= p2[20];
		p1[21] ^= p2[21];
		p1[22] ^= p2[22];
		p1[23] ^= p2[23];
		p1[24] ^= p2[24];
		p1[25] ^= p2[25];
		p1[26] ^= p2[26];
		p1[27] ^= p2[27];
		p1[28] ^= p2[28];
		p1[29] ^= p2[29];
		p1[30] ^= p2[30];
		p1[31] ^= p2[31];
		p1[32] ^= p2[32];
		p1[33] ^= p2[33];
		p1[34] ^= p2[34];
		p1[35] ^= p2[35];
		p1[36] ^= p2[36];
		p1[37] ^= p2[37];
		p1[38] ^= p2[38];
		p1[39] ^= p2[39];
		p1[40] ^= p2[40];
		p1[41] ^= p2[41];
		p1[42] ^= p2[42];
		p1[43] ^= p2[43];
		p1[44] ^= p2[44];
		p1[45] ^= p2[45];
		p1[46] ^= p2[46];
		p1[47] ^= p2[47];
		p1[48] ^= p2[48];
		p1[49] ^= p2[49];
		p1[50] ^= p2[50];
		p1[51] ^= p2[51];
		p1[52] ^= p2[52];
		p1[53] ^= p2[53];
		p1[54] ^= p2[54];
		p1[55] ^= p2[55];
		p1[56] ^= p2[56];
		p1[57] ^= p2[57];
		p1[58] ^= p2[58];
		p1[59] ^= p2[59];
		p1[60] ^= p2[60];
		p1[61] ^= p2[61];
		p1[62] ^= p2[62];
		p1[63] ^= p2[63];

		p1 += 64;
		p2 += 64;
	} while (--lines > 0);
}

static void xor3_64x32_m0(unsigned long bytes, unsigned long *__restrict p1,
			  const unsigned long *__restrict p2,
			  const unsigned long *__restrict p3)
{
	long lines = bytes / (sizeof(unsigned long)) / 32;

	do {
		p1[0] ^= p2[0] ^ p3[0];
		p1[1] ^= p2[1] ^ p3[1];
		p1[2] ^= p2[2] ^ p3[2];
		p1[3] ^= p2[3] ^ p3[3];
		p1[4] ^= p2[4] ^ p3[4];
		p1[5] ^= p2[5] ^ p3[5];
		p1[6] ^= p2[6] ^ p3[6];
		p1[7] ^= p2[7] ^ p3[7];
		p1[8] ^= p2[8] ^ p3[8];
		p1[9] ^= p2[9] ^ p3[9];
		p1[10] ^= p2[10] ^ p3[10];
		p1[11] ^= p2[11] ^ p3[11];
		p1[12] ^= p2[12] ^ p3[12];
		p1[13] ^= p2[13] ^ p3[13];
		p1[14] ^= p2[14] ^ p3[14];
		p1[15] ^= p2[15] ^ p3[15];
		p1[16] ^= p2[16] ^ p3[16];
		p1[17] ^= p2[17] ^ p3[17];
		p1[18] ^= p2[18] ^ p3[18];
		p1[19] ^= p2[19] ^ p3[19];
		p1[20] ^= p2[20] ^ p3[20];
		p1[21] ^= p2[21] ^ p3[21];
		p1[22] ^= p2[22] ^ p3[22];
		p1[23] ^= p2[23] ^ p3[23];
		p1[24] ^= p2[24] ^ p3[24];
		p1[25] ^= p2[25] ^ p3[25];
		p1[26] ^= p2[26] ^ p3[26];
		p1[27] ^= p2[27] ^ p3[27];
		p1[28] ^= p2[28] ^ p3[28];
		p1[29] ^= p2[29] ^ p3[29];
		p1[30] ^= p2[30] ^ p3[30];
		p1[31] ^= p2[31] ^ p3[31];

		p1 += 32;
		p2 += 32;
		p3 += 32;
	} while (--lines > 0);
}

static void xor4_64x32_m0(unsigned long bytes, unsigned long *__restrict p1,
			  const unsigned long *__restrict p2,
			  const unsigned long *__restrict p3,
			  const unsigned long *__restrict p4)
{
	long lines = bytes / (sizeof(unsigned long)) / 32;

	do {
		p1[0] ^= p2[0] ^ p3[0] ^ p4[0];
		p1[1] ^= p2[1] ^ p3[1] ^ p4[1];
		p1[2] ^= p2[2] ^ p3[2] ^ p4[2];
		p1[3] ^= p2[3] ^ p3[3] ^ p4[3];
		p1[4] ^= p2[4] ^ p3[4] ^ p4[4];
		p1[5] ^= p2[5] ^ p3[5] ^ p4[5];
		p1[6] ^= p2[6] ^ p3[6] ^ p4[6];
		p1[7] ^= p2[7] ^ p3[7] ^ p4[7];
		p1[8] ^= p2[8] ^ p3[8] ^ p4[8];
		p1[9] ^= p2[9] ^ p3[9] ^ p4[9];
		p1[10] ^= p2[10] ^ p3[10] ^ p4[10];
		p1[11] ^= p2[11] ^ p3[11] ^ p4[11];
		p1[12] ^= p2[12] ^ p3[12] ^ p4[12];
		p1[13] ^= p2[13] ^ p3[13] ^ p4[13];
		p1[14] ^= p2[14] ^ p3[14] ^ p4[14];
		p1[15] ^= p2[15] ^ p3[15] ^ p4[15];
		p1[16] ^= p2[16] ^ p3[16] ^ p4[16];
		p1[17] ^= p2[17] ^ p3[17] ^ p4[17];
		p1[18] ^= p2[18] ^ p3[18] ^ p4[18];
		p1[19] ^= p2[19] ^ p3[19] ^ p4[19];
		p1[20] ^= p2[20] ^ p3[20] ^ p4[20];
		p1[21] ^= p2[21] ^ p3[21] ^ p4[21];
		p1[22] ^= p2[22] ^ p3[22] ^ p4[22];
		p1[23] ^= p2[23] ^ p3[23] ^ p4[23];
		p1[24] ^= p2[24] ^ p3[24] ^ p4[24];
		p1[25] ^= p2[25] ^ p3[25] ^ p4[25];
		p1[26] ^= p2[26] ^ p3[26] ^ p4[26];
		p1[27] ^= p2[27] ^ p3[27] ^ p4[27];
		p1[28] ^= p2[28] ^ p3[28] ^ p4[28];
		p1[29] ^= p2[29] ^ p3[29] ^ p4[29];
		p1[30] ^= p2[30] ^ p3[30] ^ p4[30];
		p1[31] ^= p2[31] ^ p3[31] ^ p4[31];

		p1 += 32;
		p2 += 32;
		p3 += 32;
		p4 += 32;
	} while (--lines > 0);
}

static void xor3_64x64_m0(unsigned long bytes, unsigned long *__restrict p1,
			  const unsigned long *__restrict p2,
			  const unsigned long *__restrict p3)
{
	long lines = bytes / (sizeof(unsigned long)) / 64;

	do {
		p1[0] ^= p2[0] ^ p3[0];
		p1[1] ^= p2[1] ^ p3[1];
		p1[2] ^= p2[2] ^ p3[2];
		p1[3] ^= p2[3] ^ p3[3];
		p1[4] ^= p2[4] ^ p3[4];
		p1[5] ^= p2[5] ^ p3[5];
		p1[6] ^= p2[6] ^ p3[6];
		p1[7] ^= p2[7] ^ p3[7];
		p1[8] ^= p2[8] ^ p3[8];
		p1[9] ^= p2[9] ^ p3[9];
		p1[10] ^= p2[10] ^ p3[10];
		p1[11] ^= p2[11] ^ p3[11];
		p1[12] ^= p2[12] ^ p3[12];
		p1[13] ^= p2[13] ^ p3[13];
		p1[14] ^= p2[14] ^ p3[14];
		p1[15] ^= p2[15] ^ p3[15];
		p1[16] ^= p2[16] ^ p3[16];
		p1[17] ^= p2[17] ^ p3[17];
		p1[18] ^= p2[18] ^ p3[18];
		p1[19] ^= p2[19] ^ p3[19];
		p1[20] ^= p2[20] ^ p3[20];
		p1[21] ^= p2[21] ^ p3[21];
		p1[22] ^= p2[22] ^ p3[22];
		p1[23] ^= p2[23] ^ p3[23];
		p1[24] ^= p2[24] ^ p3[24];
		p1[25] ^= p2[25] ^ p3[25];
		p1[26] ^= p2[26] ^ p3[26];
		p1[27] ^= p2[27] ^ p3[27];
		p1[28] ^= p2[28] ^ p3[28];
		p1[29] ^= p2[29] ^ p3[29];
		p1[30] ^= p2[30] ^ p3[30];
		p1[31] ^= p2[31] ^ p3[31];
		p1[32] ^= p2[32] ^ p3[32];
		p1[33] ^= p2[33] ^ p3[33];
		p1[34] ^= p2[34] ^ p3[34];
		p1[35] ^= p2[35] ^ p3[35];
		p1[36] ^= p2[36] ^ p3[36];
		p1[37] ^= p2[37] ^ p3[37];
		p1[38] ^= p2[38] ^ p3[38];
		p1[39] ^= p2[39] ^ p3[39];
		p1[40] ^= p2[40] ^ p3[40];
		p1[41] ^= p2[41] ^ p3[41];
		p1[42] ^= p2[42] ^ p3[42];
		p1[43] ^= p2[43] ^ p3[43];
		p1[44] ^= p2[44] ^ p3[44];
		p1[45] ^= p2[45] ^ p3[45];
		p1[46] ^= p2[46] ^ p3[46];
		p1[47] ^= p2[47] ^ p3[47];
		p1[48] ^= p2[48] ^ p3[48];
		p1[49] ^= p2[49] ^ p3[49];
		p1[50] ^= p2[50] ^ p3[50];
		p1[51] ^= p2[51] ^ p3[51];
		p1[52] ^= p2[52] ^ p3[52];
		p1[53] ^= p2[53] ^ p3[53];
		p1[54] ^= p2[54] ^ p3[54];
		p1[55] ^= p2[55] ^ p3[55];
		p1[56] ^= p2[56] ^ p3[56];
		p1[57] ^= p2[57] ^ p3[57];
		p1[58] ^= p2[58] ^ p3[58];
		p1[59] ^= p2[59] ^ p3[59];
		p1[60] ^= p2[60] ^ p3[60];
		p1[61] ^= p2[61] ^ p3[61];
		p1[62] ^= p2[62] ^ p3[62];
		p1[63] ^= p2[63] ^ p3[63];

		p1 += 64;
		p2 += 64;
		p3 += 64;
	} while (--lines > 0);
}

static void xor4_64x64_m0(unsigned long bytes, unsigned long *__restrict p1,
			  const unsigned long *__restrict p2,
			  const unsigned long *__restrict p3,
			  const unsigned long *__restrict p4)
{
	long lines = bytes / (sizeof(unsigned long)) / 64;

	do {
		p1[0] ^= p2[0] ^ p3[0] ^ p4[0];
		p1[1] ^= p2[1] ^ p3[1] ^ p4[1];
		p1[2] ^= p2[2] ^ p3[2] ^ p4[2];
		p1[3] ^= p2[3] ^ p3[3] ^ p4[3];
		p1[4] ^= p2[4] ^ p3[4] ^ p4[4];
		p1[5] ^= p2[5] ^ p3[5] ^ p4[5];
		p1[6] ^= p2[6] ^ p3[6] ^ p4[6];
		p1[7] ^= p2[7] ^ p3[7] ^ p4[7];
		p1[8] ^= p2[8] ^ p3[8] ^ p4[8];
		p1[9] ^= p2[9] ^ p3[9] ^ p4[9];
		p1[10] ^= p2[10] ^ p3[10] ^ p4[10];
		p1[11] ^= p2[11] ^ p3[11] ^ p4[11];
		p1[12] ^= p2[12] ^ p3[12] ^ p4[12];
		p1[13] ^= p2[13] ^ p3[13] ^ p4[13];
		p1[14] ^= p2[14] ^ p3[14] ^ p4[14];
		p1[15] ^= p2[15] ^ p3[15] ^ p4[15];
		p1[16] ^= p2[16] ^ p3[16] ^ p4[16];
		p1[17] ^= p2[17] ^ p3[17] ^ p4[17];
		p1[18] ^= p2[18] ^ p3[18] ^ p4[18];
		p1[19] ^= p2[19] ^ p3[19] ^ p4[19];
		p1[20] ^= p2[20] ^ p3[20] ^ p4[20];
		p1[21] ^= p2[21] ^ p3[21] ^ p4[21];
		p1[22] ^= p2[22] ^ p3[22] ^ p4[22];
		p1[23] ^= p2[23] ^ p3[23] ^ p4[23];
		p1[24] ^= p2[24] ^ p3[24] ^ p4[24];
		p1[25] ^= p2[25] ^ p3[25] ^ p4[25];
		p1[26] ^= p2[26] ^ p3[26] ^ p4[26];
		p1[27] ^= p2[27] ^ p3[27] ^ p4[27];
		p1[28] ^= p2[28] ^ p3[28] ^ p4[28];
		p1[29] ^= p2[29] ^ p3[29] ^ p4[29];
		p1[30] ^= p2[30] ^ p3[30] ^ p4[30];
		p1[31] ^= p2[31] ^ p3[31] ^ p4[31];
		p1[32] ^= p2[32] ^ p3[32] ^ p4[32];
		p1[33] ^= p2[33] ^ p3[33] ^ p4[33];
		p1[34] ^= p2[34] ^ p3[34] ^ p4[34];
		p1[35] ^= p2[35] ^ p3[35] ^ p4[35];
		p1[36] ^= p2[36] ^ p3[36] ^ p4[36];
		p1[37] ^= p2[37] ^ p3[37] ^ p4[37];
		p1[38] ^= p2[38] ^ p3[38] ^ p4[38];
		p1[39] ^= p2[39] ^ p3[39] ^ p4[39];
		p1[40] ^= p2[40] ^ p3[40] ^ p4[40];
		p1[41] ^= p2[41] ^ p3[41] ^ p4[41];
		p1[42] ^= p2[42] ^ p3[42] ^ p4[42];
		p1[43] ^= p2[43] ^ p3[43] ^ p4[43];
		p1[44] ^= p2[44] ^ p3[44] ^ p4[44];
		p1[45] ^= p2[45] ^ p3[45] ^ p4[45];
		p1[46] ^= p2[46] ^ p3[46] ^ p4[46];
		p1[47] ^= p2[47] ^ p3[47] ^ p4[47];
		p1[48] ^= p2[48] ^ p3[48] ^ p4[48];
		p1[49] ^= p2[49] ^ p3[49] ^ p4[49];
		p1[50] ^= p2[50] ^ p3[50] ^ p4[50];
		p1[51] ^= p2[51] ^ p3[51] ^ p4[51];
		p1[52] ^= p2[52] ^ p3[52] ^ p4[52];
		p1[53] ^= p2[53] ^ p3[53] ^ p4[53];
		p1[54] ^= p2[54] ^ p3[54] ^ p4[54];
		p1[55] ^= p2[55] ^ p3[55] ^ p4[55];
		p1[56] ^= p2[56] ^ p3[56] ^ p4[56];
		p1[57] ^= p2[57] ^ p3[57] ^ p4[57];
		p1[58] ^= p2[58] ^ p3[58] ^ p4[58];
		p1[59] ^= p2[59] ^ p3[59] ^ p4[59];
		p1[60] ^= p2[60] ^ p3[60] ^ p4[60];
		p1[61] ^= p2[61] ^ p3[61] ^ p4[61];
		p1[62] ^= p2[62] ^ p3[62] ^ p4[62];
		p1[63] ^= p2[63] ^ p3[63] ^ p4[63];

		p1 += 64;
		p2 += 64;
		p3 += 64;
		p4 += 64;
	} while (--lines > 0);
}

static void xor4_64x64_m2(unsigned long bytes, unsigned long *__restrict p1,
			  const unsigned long *__restrict p2,
			  const unsigned long *__restrict p3,
			  const unsigned long *__restrict p4)
{
	long lines = bytes / (sizeof(unsigned long)) / 64;

#pragma loop count(1000)
#pragma unroll(1)
#pragma novector
	do {
		p1[0] ^= p2[0] ^ p3[0] ^ p4[0];
		p1[1] ^= p2[1] ^ p3[1] ^ p4[1];
		p1[2] ^= p2[2] ^ p3[2] ^ p4[2];
		p1[3] ^= p2[3] ^ p3[3] ^ p4[3];
		p1[4] ^= p2[4] ^ p3[4] ^ p4[4];
		p1[5] ^= p2[5] ^ p3[5] ^ p4[5];
		p1[6] ^= p2[6] ^ p3[6] ^ p4[6];
		p1[7] ^= p2[7] ^ p3[7] ^ p4[7];
		p1[8] ^= p2[8] ^ p3[8] ^ p4[8];
		p1[9] ^= p2[9] ^ p3[9] ^ p4[9];
		p1[10] ^= p2[10] ^ p3[10] ^ p4[10];
		p1[11] ^= p2[11] ^ p3[11] ^ p4[11];
		p1[12] ^= p2[12] ^ p3[12] ^ p4[12];
		p1[13] ^= p2[13] ^ p3[13] ^ p4[13];
		p1[14] ^= p2[14] ^ p3[14] ^ p4[14];
		p1[15] ^= p2[15] ^ p3[15] ^ p4[15];
		p1[16] ^= p2[16] ^ p3[16] ^ p4[16];
		p1[17] ^= p2[17] ^ p3[17] ^ p4[17];
		p1[18] ^= p2[18] ^ p3[18] ^ p4[18];
		p1[19] ^= p2[19] ^ p3[19] ^ p4[19];
		p1[20] ^= p2[20] ^ p3[20] ^ p4[20];
		p1[21] ^= p2[21] ^ p3[21] ^ p4[21];
		p1[22] ^= p2[22] ^ p3[22] ^ p4[22];
		p1[23] ^= p2[23] ^ p3[23] ^ p4[23];
		p1[24] ^= p2[24] ^ p3[24] ^ p4[24];
		p1[25] ^= p2[25] ^ p3[25] ^ p4[25];
		p1[26] ^= p2[26] ^ p3[26] ^ p4[26];
		p1[27] ^= p2[27] ^ p3[27] ^ p4[27];
		p1[28] ^= p2[28] ^ p3[28] ^ p4[28];
		p1[29] ^= p2[29] ^ p3[29] ^ p4[29];
		p1[30] ^= p2[30] ^ p3[30] ^ p4[30];
		p1[31] ^= p2[31] ^ p3[31] ^ p4[31];
		p1[32] ^= p2[32] ^ p3[32] ^ p4[32];
		p1[33] ^= p2[33] ^ p3[33] ^ p4[33];
		p1[34] ^= p2[34] ^ p3[34] ^ p4[34];
		p1[35] ^= p2[35] ^ p3[35] ^ p4[35];
		p1[36] ^= p2[36] ^ p3[36] ^ p4[36];
		p1[37] ^= p2[37] ^ p3[37] ^ p4[37];
		p1[38] ^= p2[38] ^ p3[38] ^ p4[38];
		p1[39] ^= p2[39] ^ p3[39] ^ p4[39];
		p1[40] ^= p2[40] ^ p3[40] ^ p4[40];
		p1[41] ^= p2[41] ^ p3[41] ^ p4[41];
		p1[42] ^= p2[42] ^ p3[42] ^ p4[42];
		p1[43] ^= p2[43] ^ p3[43] ^ p4[43];
		p1[44] ^= p2[44] ^ p3[44] ^ p4[44];
		p1[45] ^= p2[45] ^ p3[45] ^ p4[45];
		p1[46] ^= p2[46] ^ p3[46] ^ p4[46];
		p1[47] ^= p2[47] ^ p3[47] ^ p4[47];
		p1[48] ^= p2[48] ^ p3[48] ^ p4[48];
		p1[49] ^= p2[49] ^ p3[49] ^ p4[49];
		p1[50] ^= p2[50] ^ p3[50] ^ p4[50];
		p1[51] ^= p2[51] ^ p3[51] ^ p4[51];
		p1[52] ^= p2[52] ^ p3[52] ^ p4[52];
		p1[53] ^= p2[53] ^ p3[53] ^ p4[53];
		p1[54] ^= p2[54] ^ p3[54] ^ p4[54];
		p1[55] ^= p2[55] ^ p3[55] ^ p4[55];
		p1[56] ^= p2[56] ^ p3[56] ^ p4[56];
		p1[57] ^= p2[57] ^ p3[57] ^ p4[57];
		p1[58] ^= p2[58] ^ p3[58] ^ p4[58];
		p1[59] ^= p2[59] ^ p3[59] ^ p4[59];
		p1[60] ^= p2[60] ^ p3[60] ^ p4[60];
		p1[61] ^= p2[61] ^ p3[61] ^ p4[61];
		p1[62] ^= p2[62] ^ p3[62] ^ p4[62];
		p1[63] ^= p2[63] ^ p3[63] ^ p4[63];

		p1 += 64;
		p2 += 64;
		p3 += 64;
		p4 += 64;
	} while (--lines > 0);
}

static void xor5_64x32_m0(unsigned long bytes, unsigned long *__restrict p1,
			  const unsigned long *__restrict p2,
			  const unsigned long *__restrict p3,
			  const unsigned long *__restrict p4,
			  const unsigned long *__restrict p5)
{
	long lines = bytes / (sizeof(unsigned long)) / 32;

	do {
		p1[0] ^= p2[0] ^ p3[0] ^ p4[0] ^ p5[0];
		p1[1] ^= p2[1] ^ p3[1] ^ p4[1] ^ p5[1];
		p1[2] ^= p2[2] ^ p3[2] ^ p4[2] ^ p5[2];
		p1[3] ^= p2[3] ^ p3[3] ^ p4[3] ^ p5[3];
		p1[4] ^= p2[4] ^ p3[4] ^ p4[4] ^ p5[4];
		p1[5] ^= p2[5] ^ p3[5] ^ p4[5] ^ p5[5];
		p1[6] ^= p2[6] ^ p3[6] ^ p4[6] ^ p5[6];
		p1[7] ^= p2[7] ^ p3[7] ^ p4[7] ^ p5[7];
		p1[8] ^= p2[8] ^ p3[8] ^ p4[8] ^ p5[8];
		p1[9] ^= p2[9] ^ p3[9] ^ p4[9] ^ p5[9];
		p1[10] ^= p2[10] ^ p3[10] ^ p4[10] ^ p5[10];
		p1[11] ^= p2[11] ^ p3[11] ^ p4[11] ^ p5[11];
		p1[12] ^= p2[12] ^ p3[12] ^ p4[12] ^ p5[12];
		p1[13] ^= p2[13] ^ p3[13] ^ p4[13] ^ p5[13];
		p1[14] ^= p2[14] ^ p3[14] ^ p4[14] ^ p5[14];
		p1[15] ^= p2[15] ^ p3[15] ^ p4[15] ^ p5[15];
		p1[16] ^= p2[16] ^ p3[16] ^ p4[16] ^ p5[16];
		p1[17] ^= p2[17] ^ p3[17] ^ p4[17] ^ p5[17];
		p1[18] ^= p2[18] ^ p3[18] ^ p4[18] ^ p5[18];
		p1[19] ^= p2[19] ^ p3[19] ^ p4[19] ^ p5[19];
		p1[20] ^= p2[20] ^ p3[20] ^ p4[20] ^ p5[20];
		p1[21] ^= p2[21] ^ p3[21] ^ p4[21] ^ p5[21];
		p1[22] ^= p2[22] ^ p3[22] ^ p4[22] ^ p5[22];
		p1[23] ^= p2[23] ^ p3[23] ^ p4[23] ^ p5[23];
		p1[24] ^= p2[24] ^ p3[24] ^ p4[24] ^ p5[24];
		p1[25] ^= p2[25] ^ p3[25] ^ p4[25] ^ p5[25];
		p1[26] ^= p2[26] ^ p3[26] ^ p4[26] ^ p5[26];
		p1[27] ^= p2[27] ^ p3[27] ^ p4[27] ^ p5[27];
		p1[28] ^= p2[28] ^ p3[28] ^ p4[28] ^ p5[28];
		p1[29] ^= p2[29] ^ p3[29] ^ p4[29] ^ p5[29];
		p1[30] ^= p2[30] ^ p3[30] ^ p4[30] ^ p5[30];
		p1[31] ^= p2[31] ^ p3[31] ^ p4[31] ^ p5[31];

		p1 += 32;
		p2 += 32;
		p3 += 32;
		p4 += 32;
		p5 += 32;
	} while (--lines > 0);
}

static void xor5_64x32_m2(unsigned long bytes, unsigned long *__restrict p1,
			  const unsigned long *__restrict p2,
			  const unsigned long *__restrict p3,
			  const unsigned long *__restrict p4,
			  const unsigned long *__restrict p5)
{
	long lines = bytes / (sizeof(unsigned long)) / 32;

#pragma loop count(1000)
#pragma unroll(1)
#pragma novector
	do {
		p1[0] ^= p2[0] ^ p3[0] ^ p4[0] ^ p5[0];
		p1[1] ^= p2[1] ^ p3[1] ^ p4[1] ^ p5[1];
		p1[2] ^= p2[2] ^ p3[2] ^ p4[2] ^ p5[2];
		p1[3] ^= p2[3] ^ p3[3] ^ p4[3] ^ p5[3];
		p1[4] ^= p2[4] ^ p3[4] ^ p4[4] ^ p5[4];
		p1[5] ^= p2[5] ^ p3[5] ^ p4[5] ^ p5[5];
		p1[6] ^= p2[6] ^ p3[6] ^ p4[6] ^ p5[6];
		p1[7] ^= p2[7] ^ p3[7] ^ p4[7] ^ p5[7];
		p1[8] ^= p2[8] ^ p3[8] ^ p4[8] ^ p5[8];
		p1[9] ^= p2[9] ^ p3[9] ^ p4[9] ^ p5[9];
		p1[10] ^= p2[10] ^ p3[10] ^ p4[10] ^ p5[10];
		p1[11] ^= p2[11] ^ p3[11] ^ p4[11] ^ p5[11];
		p1[12] ^= p2[12] ^ p3[12] ^ p4[12] ^ p5[12];
		p1[13] ^= p2[13] ^ p3[13] ^ p4[13] ^ p5[13];
		p1[14] ^= p2[14] ^ p3[14] ^ p4[14] ^ p5[14];
		p1[15] ^= p2[15] ^ p3[15] ^ p4[15] ^ p5[15];
		p1[16] ^= p2[16] ^ p3[16] ^ p4[16] ^ p5[16];
		p1[17] ^= p2[17] ^ p3[17] ^ p4[17] ^ p5[17];
		p1[18] ^= p2[18] ^ p3[18] ^ p4[18] ^ p5[18];
		p1[19] ^= p2[19] ^ p3[19] ^ p4[19] ^ p5[19];
		p1[20] ^= p2[20] ^ p3[20] ^ p4[20] ^ p5[20];
		p1[21] ^= p2[21] ^ p3[21] ^ p4[21] ^ p5[21];
		p1[22] ^= p2[22] ^ p3[22] ^ p4[22] ^ p5[22];
		p1[23] ^= p2[23] ^ p3[23] ^ p4[23] ^ p5[23];
		p1[24] ^= p2[24] ^ p3[24] ^ p4[24] ^ p5[24];
		p1[25] ^= p2[25] ^ p3[25] ^ p4[25] ^ p5[25];
		p1[26] ^= p2[26] ^ p3[26] ^ p4[26] ^ p5[26];
		p1[27] ^= p2[27] ^ p3[27] ^ p4[27] ^ p5[27];
		p1[28] ^= p2[28] ^ p3[28] ^ p4[28] ^ p5[28];
		p1[29] ^= p2[29] ^ p3[29] ^ p4[29] ^ p5[29];
		p1[30] ^= p2[30] ^ p3[30] ^ p4[30] ^ p5[30];
		p1[31] ^= p2[31] ^ p3[31] ^ p4[31] ^ p5[31];

		p1 += 32;
		p2 += 32;
		p3 += 32;
		p4 += 32;
		p5 += 32;
	} while (--lines > 0);
}

/* For build with "-02" */
static struct xor_block_template xor_block_64bit_regs_set1 = {
	.name = "e2k_64bit_regs_set1",
	.do_2 = xor2_64x64_m0,
	.do_3 = xor3_64x64_m0,
	.do_4 = xor4_64x64_m0,
	.do_5 = xor5_64x32_m0,
};
static struct xor_block_template xor_block_64bit_regs_set2 = {
	.name = "e2k_64bit_regs_set2",
	.do_2 = xor2_64x64_m0,
	.do_3 = xor3_64x32_m0,
	.do_4 = xor4_64x32_m0,
	.do_5 = xor5_64x32_m0,
};

/* For build to e8c2 with "-03" */
static struct xor_block_template xor_block_64bit_regs_set3 = {
	.name = "e2k_64bit_regs_set3",
	.do_2 = xor2_64x32_m0,
	.do_3 = xor3_64x64_m0,
	.do_4 = xor4_64x64_m2,
	.do_5 = xor5_64x32_m2,
};

#define XOR_SPEED_64BIT_REGS					\
	do {							\
		if (cpu_has(CPU_FEAT_ISET_V5)) {		\
			xor_speed(&xor_block_64bit_regs_set1);	\
		} else {					\
			xor_speed(&xor_block_64bit_regs_set2);	\
		}						\
		xor_speed(&xor_block_64bit_regs_set3);		\
	} while (0)

#if __iset__ >= 5
typedef long long __v2di __attribute__((__vector_size__(16)));

static void xor2_128x16_m0(unsigned long bytes,
			   unsigned long *__restrict p1_arg,
			   const unsigned long *__restrict p2_arg)
{
	__v2di *__restrict p1 = (__v2di *)p1_arg;
	const __v2di *__restrict p2 = (__v2di *)p2_arg;
	long lines = bytes / (sizeof(__v2di)) / 16;

	do {
		p1[0] = __builtin_e2k_qpxor(p1[0], p2[0]);
		p1[1] = __builtin_e2k_qpxor(p1[1], p2[1]);
		p1[2] = __builtin_e2k_qpxor(p1[2], p2[2]);
		p1[3] = __builtin_e2k_qpxor(p1[3], p2[3]);
		p1[4] = __builtin_e2k_qpxor(p1[4], p2[4]);
		p1[5] = __builtin_e2k_qpxor(p1[5], p2[5]);
		p1[6] = __builtin_e2k_qpxor(p1[6], p2[6]);
		p1[7] = __builtin_e2k_qpxor(p1[7], p2[7]);
		p1[8] = __builtin_e2k_qpxor(p1[8], p2[8]);
		p1[9] = __builtin_e2k_qpxor(p1[9], p2[9]);
		p1[10] = __builtin_e2k_qpxor(p1[10], p2[10]);
		p1[11] = __builtin_e2k_qpxor(p1[11], p2[11]);
		p1[12] = __builtin_e2k_qpxor(p1[12], p2[12]);
		p1[13] = __builtin_e2k_qpxor(p1[13], p2[13]);
		p1[14] = __builtin_e2k_qpxor(p1[14], p2[14]);
		p1[15] = __builtin_e2k_qpxor(p1[15], p2[15]);

		p1 += 16;
		p2 += 16;
	} while (--lines > 0);
}

static void xor2_128x32_m0(unsigned long bytes,
			   unsigned long *__restrict p1_arg,
			   const unsigned long *__restrict p2_arg)
{
	__v2di *__restrict p1 = (__v2di *)p1_arg;
	const __v2di *__restrict p2 = (__v2di *)p2_arg;
	long lines = bytes / (sizeof(__v2di)) / 32;

	do {
		p1[0] = __builtin_e2k_qpxor(p1[0], p2[0]);
		p1[1] = __builtin_e2k_qpxor(p1[1], p2[1]);
		p1[2] = __builtin_e2k_qpxor(p1[2], p2[2]);
		p1[3] = __builtin_e2k_qpxor(p1[3], p2[3]);
		p1[4] = __builtin_e2k_qpxor(p1[4], p2[4]);
		p1[5] = __builtin_e2k_qpxor(p1[5], p2[5]);
		p1[6] = __builtin_e2k_qpxor(p1[6], p2[6]);
		p1[7] = __builtin_e2k_qpxor(p1[7], p2[7]);
		p1[8] = __builtin_e2k_qpxor(p1[8], p2[8]);
		p1[9] = __builtin_e2k_qpxor(p1[9], p2[9]);
		p1[10] = __builtin_e2k_qpxor(p1[10], p2[10]);
		p1[11] = __builtin_e2k_qpxor(p1[11], p2[11]);
		p1[12] = __builtin_e2k_qpxor(p1[12], p2[12]);
		p1[13] = __builtin_e2k_qpxor(p1[13], p2[13]);
		p1[14] = __builtin_e2k_qpxor(p1[14], p2[14]);
		p1[15] = __builtin_e2k_qpxor(p1[15], p2[15]);
		p1[16] = __builtin_e2k_qpxor(p1[16], p2[16]);
		p1[17] = __builtin_e2k_qpxor(p1[17], p2[17]);
		p1[18] = __builtin_e2k_qpxor(p1[18], p2[18]);
		p1[19] = __builtin_e2k_qpxor(p1[19], p2[19]);
		p1[20] = __builtin_e2k_qpxor(p1[20], p2[20]);
		p1[21] = __builtin_e2k_qpxor(p1[21], p2[21]);
		p1[22] = __builtin_e2k_qpxor(p1[22], p2[22]);
		p1[23] = __builtin_e2k_qpxor(p1[23], p2[23]);
		p1[24] = __builtin_e2k_qpxor(p1[24], p2[24]);
		p1[25] = __builtin_e2k_qpxor(p1[25], p2[25]);
		p1[26] = __builtin_e2k_qpxor(p1[26], p2[26]);
		p1[27] = __builtin_e2k_qpxor(p1[27], p2[27]);
		p1[28] = __builtin_e2k_qpxor(p1[28], p2[28]);
		p1[29] = __builtin_e2k_qpxor(p1[29], p2[29]);
		p1[30] = __builtin_e2k_qpxor(p1[30], p2[30]);
		p1[31] = __builtin_e2k_qpxor(p1[31], p2[31]);

		p1 += 32;
		p2 += 32;
	} while (--lines > 0);
}

static void xor2_128x16_m12(unsigned long bytes,
			    unsigned long *__restrict p1_arg __aligned(64),
			    const unsigned long *__restrict p2_arg __aligned(64))
{
	__v2di *__restrict p1 = (__v2di *)p1_arg;
	const __v2di *__restrict p2 = (__v2di *)p2_arg;
	long lines = bytes / (sizeof(__v2di)) / 16;

	p1 = __builtin_assume_aligned(p1, 16);
	p2 = __builtin_assume_aligned(p2, 16);

#pragma no_dam
#pragma ivdep
#pragma loop count(1000)
#pragma unroll(1)
#pragma novector
	do {
		prefetchw(p1 + 96);
		prefetch(p2 + 96);
		prefetchw(p1 + 98);
		prefetch(p2 + 98);
		prefetchw(p1 + 100);
		prefetch(p2 + 100);
		prefetchw(p1 + 102);
		prefetch(p2 + 102);
		prefetchw(p1 + 104);
		prefetch(p2 + 104);
		prefetchw(p1 + 106);
		prefetch(p2 + 106);
		prefetchw(p1 + 108);
		prefetch(p2 + 108);
		prefetchw(p1 + 110);
		prefetch(p2 + 110);

		p1[0] = __builtin_e2k_qpxor(p1[0], p2[0]);
		p1[1] = __builtin_e2k_qpxor(p1[1], p2[1]);
		p1[2] = __builtin_e2k_qpxor(p1[2], p2[2]);
		p1[3] = __builtin_e2k_qpxor(p1[3], p2[3]);
		p1[4] = __builtin_e2k_qpxor(p1[4], p2[4]);
		p1[5] = __builtin_e2k_qpxor(p1[5], p2[5]);
		p1[6] = __builtin_e2k_qpxor(p1[6], p2[6]);
		p1[7] = __builtin_e2k_qpxor(p1[7], p2[7]);
		p1[8] = __builtin_e2k_qpxor(p1[8], p2[8]);
		p1[9] = __builtin_e2k_qpxor(p1[9], p2[9]);
		p1[10] = __builtin_e2k_qpxor(p1[10], p2[10]);
		p1[11] = __builtin_e2k_qpxor(p1[11], p2[11]);
		p1[12] = __builtin_e2k_qpxor(p1[12], p2[12]);
		p1[13] = __builtin_e2k_qpxor(p1[13], p2[13]);
		p1[14] = __builtin_e2k_qpxor(p1[14], p2[14]);
		p1[15] = __builtin_e2k_qpxor(p1[15], p2[15]);

		p1 += 16;
		p2 += 16;
	} while (--lines > 0);
}

static void xor3_128x16_m10(unsigned long bytes,
			    unsigned long *__restrict p1_arg __aligned(64),
			    const unsigned long *__restrict p2_arg __aligned(64),
			    const unsigned long *__restrict p3_arg __aligned(64))
{
	__v2di *__restrict p1 = (__v2di *)p1_arg;
	const __v2di *__restrict p2 = (__v2di *)p2_arg;
	const __v2di *__restrict p3 = (__v2di *)p3_arg;
	long lines = bytes / (sizeof(__v2di)) / 16;

	p1 = __builtin_assume_aligned(p1, 16);
	p2 = __builtin_assume_aligned(p2, 16);
	p3 = __builtin_assume_aligned(p3, 16);

#pragma no_dam
#pragma ivdep
#pragma loop count(1000)
#pragma unroll(1)
#pragma novector
	do {
		prefetchw(p1 + 64);
		prefetch(p2 + 64);
		prefetch(p3 + 64);
		prefetchw(p1 + 66);
		prefetch(p2 + 66);
		prefetch(p3 + 66);
		prefetchw(p1 + 68);
		prefetch(p2 + 68);
		prefetch(p3 + 68);
		prefetchw(p1 + 70);
		prefetch(p2 + 70);
		prefetch(p3 + 70);
		prefetchw(p1 + 72);
		prefetch(p2 + 72);
		prefetch(p3 + 72);
		prefetchw(p1 + 74);
		prefetch(p2 + 74);
		prefetch(p3 + 74);
		prefetchw(p1 + 76);
		prefetch(p2 + 76);
		prefetch(p3 + 76);
		prefetchw(p1 + 78);
		prefetch(p2 + 78);
		prefetch(p3 + 78);

		p1[0] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[0], p2[0]),
					    p3[0]);
		p1[1] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[1], p2[1]),
					    p3[1]);
		p1[2] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[2], p2[2]),
					    p3[2]);
		p1[3] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[3], p2[3]),
					    p3[3]);
		p1[4] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[4], p2[4]),
					    p3[4]);
		p1[5] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[5], p2[5]),
					    p3[5]);
		p1[6] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[6], p2[6]),
					    p3[6]);
		p1[7] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[7], p2[7]),
					    p3[7]);
		p1[8] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[8], p2[8]),
					    p3[8]);
		p1[9] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[9], p2[9]),
					    p3[9]);
		p1[10] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[10], p2[10]), p3[10]);
		p1[11] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[11], p2[11]), p3[11]);
		p1[12] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[12], p2[12]), p3[12]);
		p1[13] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[13], p2[13]), p3[13]);
		p1[14] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[14], p2[14]), p3[14]);
		p1[15] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[15], p2[15]), p3[15]);

		p1 += 16;
		p2 += 16;
		p3 += 16;
	} while (--lines > 0);
}

static void xor3_128x32_m0(unsigned long bytes,
			   unsigned long *__restrict p1_arg,
			   const unsigned long *__restrict p2_arg,
			   const unsigned long *__restrict p3_arg)
{
	__v2di *__restrict p1 = (__v2di *)p1_arg;
	const __v2di *__restrict p2 = (__v2di *)p2_arg;
	const __v2di *__restrict p3 = (__v2di *)p3_arg;
	long lines = bytes / (sizeof(__v2di)) / 32;

	do {
		p1[0] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[0], p2[0]),
					    p3[0]);
		p1[1] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[1], p2[1]),
					    p3[1]);
		p1[2] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[2], p2[2]),
					    p3[2]);
		p1[3] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[3], p2[3]),
					    p3[3]);
		p1[4] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[4], p2[4]),
					    p3[4]);
		p1[5] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[5], p2[5]),
					    p3[5]);
		p1[6] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[6], p2[6]),
					    p3[6]);
		p1[7] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[7], p2[7]),
					    p3[7]);
		p1[8] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[8], p2[8]),
					    p3[8]);
		p1[9] = __builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[9], p2[9]),
					    p3[9]);
		p1[10] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[10], p2[10]), p3[10]);
		p1[11] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[11], p2[11]), p3[11]);
		p1[12] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[12], p2[12]), p3[12]);
		p1[13] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[13], p2[13]), p3[13]);
		p1[14] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[14], p2[14]), p3[14]);
		p1[15] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[15], p2[15]), p3[15]);
		p1[16] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[16], p2[16]), p3[16]);
		p1[17] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[17], p2[17]), p3[17]);
		p1[18] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[18], p2[18]), p3[18]);
		p1[19] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[19], p2[19]), p3[19]);
		p1[20] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[20], p2[20]), p3[20]);
		p1[21] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[21], p2[21]), p3[21]);
		p1[22] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[22], p2[22]), p3[22]);
		p1[23] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[23], p2[23]), p3[23]);
		p1[24] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[24], p2[24]), p3[24]);
		p1[25] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[25], p2[25]), p3[25]);
		p1[26] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[26], p2[26]), p3[26]);
		p1[27] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[27], p2[27]), p3[27]);
		p1[28] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[28], p2[28]), p3[28]);
		p1[29] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[29], p2[29]), p3[29]);
		p1[30] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[30], p2[30]), p3[30]);
		p1[31] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(p1[31], p2[31]), p3[31]);

		p1 += 32;
		p2 += 32;
		p3 += 32;
	} while (--lines > 0);
}

static void xor4_128x16_m8(
	unsigned long bytes,
	unsigned long *__restrict p1_arg __aligned(64),
	const unsigned long *__restrict p2_arg __aligned(64),
	const unsigned long *__restrict p3_arg __aligned(64),
	const unsigned long *__restrict p4_arg __aligned(64))
{
	__v2di *__restrict p1 = (__v2di *)p1_arg;
	const __v2di *__restrict p2 = (__v2di *)p2_arg;
	const __v2di *__restrict p3 = (__v2di *)p3_arg;
	const __v2di *__restrict p4 = (__v2di *)p4_arg;
	long lines = bytes / (sizeof(__v2di)) / 16;

	p1 = __builtin_assume_aligned(p1, 16);
	p2 = __builtin_assume_aligned(p2, 16);
	p3 = __builtin_assume_aligned(p3, 16);
	p4 = __builtin_assume_aligned(p4, 16);

#pragma no_dam
#pragma ivdep
#pragma loop count(1000)
#pragma unroll(1)
#pragma novector
	do {
		prefetchw(p1 + 32);
		prefetch(p2 + 32);
		prefetch(p3 + 32);
		prefetch(p4 + 32);
		prefetchw(p1 + 34);
		prefetch(p2 + 34);
		prefetch(p3 + 34);
		prefetch(p4 + 34);
		prefetchw(p1 + 36);
		prefetch(p2 + 36);
		prefetch(p3 + 36);
		prefetch(p4 + 36);
		prefetchw(p1 + 38);
		prefetch(p2 + 38);
		prefetch(p3 + 38);
		prefetch(p4 + 38);
		prefetchw(p1 + 40);
		prefetch(p2 + 40);
		prefetch(p3 + 40);
		prefetch(p4 + 40);
		prefetchw(p1 + 42);
		prefetch(p2 + 42);
		prefetch(p3 + 42);
		prefetch(p4 + 42);
		prefetchw(p1 + 44);
		prefetch(p2 + 44);
		prefetch(p3 + 44);
		prefetch(p4 + 44);
		prefetchw(p1 + 46);
		prefetch(p2 + 46);
		prefetch(p3 + 46);
		prefetch(p4 + 46);

		p1[0] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[0], p2[0]),
					    p3[0]),
			p4[0]);
		p1[1] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[1], p2[1]),
					    p3[1]),
			p4[1]);
		p1[2] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[2], p2[2]),
					    p3[2]),
			p4[2]);
		p1[3] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[3], p2[3]),
					    p3[3]),
			p4[3]);
		p1[4] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[4], p2[4]),
					    p3[4]),
			p4[4]);
		p1[5] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[5], p2[5]),
					    p3[5]),
			p4[5]);
		p1[6] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[6], p2[6]),
					    p3[6]),
			p4[6]);
		p1[7] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[7], p2[7]),
					    p3[7]),
			p4[7]);
		p1[8] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[8], p2[8]),
					    p3[8]),
			p4[8]);
		p1[9] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[9], p2[9]),
					    p3[9]),
			p4[9]);
		p1[10] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[10], p2[10]),
					    p3[10]),
			p4[10]);
		p1[11] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[11], p2[11]),
					    p3[11]),
			p4[11]);
		p1[12] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[12], p2[12]),
					    p3[12]),
			p4[12]);
		p1[13] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[13], p2[13]),
					    p3[13]),
			p4[13]);
		p1[14] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[14], p2[14]),
					    p3[14]),
			p4[14]);
		p1[15] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[15], p2[15]),
					    p3[15]),
			p4[15]);

		p1 += 16;
		p2 += 16;
		p3 += 16;
		p4 += 16;
	} while (--lines > 0);
}

static void xor4_128x32_m0(unsigned long bytes,
			   unsigned long *__restrict p1_arg,
			   const unsigned long *__restrict p2_arg,
			   const unsigned long *__restrict p3_arg,
			   const unsigned long *__restrict p4_arg)
{
	__v2di *__restrict p1 = (__v2di *)p1_arg;
	const __v2di *__restrict p2 = (__v2di *)p2_arg;
	const __v2di *__restrict p3 = (__v2di *)p3_arg;
	const __v2di *__restrict p4 = (__v2di *)p4_arg;
	long lines = bytes / (sizeof(__v2di)) / 32;

	do {
		p1[0] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[0], p2[0]),
					    p3[0]),
			p4[0]);
		p1[1] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[1], p2[1]),
					    p3[1]),
			p4[1]);
		p1[2] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[2], p2[2]),
					    p3[2]),
			p4[2]);
		p1[3] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[3], p2[3]),
					    p3[3]),
			p4[3]);
		p1[4] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[4], p2[4]),
					    p3[4]),
			p4[4]);
		p1[5] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[5], p2[5]),
					    p3[5]),
			p4[5]);
		p1[6] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[6], p2[6]),
					    p3[6]),
			p4[6]);
		p1[7] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[7], p2[7]),
					    p3[7]),
			p4[7]);
		p1[8] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[8], p2[8]),
					    p3[8]),
			p4[8]);
		p1[9] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[9], p2[9]),
					    p3[9]),
			p4[9]);
		p1[10] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[10], p2[10]),
					    p3[10]),
			p4[10]);
		p1[11] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[11], p2[11]),
					    p3[11]),
			p4[11]);
		p1[12] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[12], p2[12]),
					    p3[12]),
			p4[12]);
		p1[13] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[13], p2[13]),
					    p3[13]),
			p4[13]);
		p1[14] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[14], p2[14]),
					    p3[14]),
			p4[14]);
		p1[15] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[15], p2[15]),
					    p3[15]),
			p4[15]);
		p1[16] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[16], p2[16]),
					    p3[16]),
			p4[16]);
		p1[17] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[17], p2[17]),
					    p3[17]),
			p4[17]);
		p1[18] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[18], p2[18]),
					    p3[18]),
			p4[18]);
		p1[19] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[19], p2[19]),
					    p3[19]),
			p4[19]);
		p1[20] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[20], p2[20]),
					    p3[20]),
			p4[20]);
		p1[21] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[21], p2[21]),
					    p3[21]),
			p4[21]);
		p1[22] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[22], p2[22]),
					    p3[22]),
			p4[22]);
		p1[23] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[23], p2[23]),
					    p3[23]),
			p4[23]);
		p1[24] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[24], p2[24]),
					    p3[24]),
			p4[24]);
		p1[25] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[25], p2[25]),
					    p3[25]),
			p4[25]);
		p1[26] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[26], p2[26]),
					    p3[26]),
			p4[26]);
		p1[27] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[27], p2[27]),
					    p3[27]),
			p4[27]);
		p1[28] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[28], p2[28]),
					    p3[28]),
			p4[28]);
		p1[29] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[29], p2[29]),
					    p3[29]),
			p4[29]);
		p1[30] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[30], p2[30]),
					    p3[30]),
			p4[30]);
		p1[31] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[31], p2[31]),
					    p3[31]),
			p4[31]);

		p1 += 32;
		p2 += 32;
		p3 += 32;
		p4 += 32;
	} while (--lines > 0);
}

static void xor5_128x16_m6(
	unsigned long bytes,
	unsigned long *__restrict p1_arg __aligned(64),
	const unsigned long *__restrict p2_arg __aligned(64),
	const unsigned long *__restrict p3_arg __aligned(64),
	const unsigned long *__restrict p4_arg __aligned(64),
	const unsigned long *__restrict p5_arg __aligned(64))
{
	__v2di *__restrict p1 = (__v2di *)p1_arg;
	const __v2di *__restrict p2 = (__v2di *)p2_arg;
	const __v2di *__restrict p3 = (__v2di *)p3_arg;
	const __v2di *__restrict p4 = (__v2di *)p4_arg;
	const __v2di *__restrict p5 = (__v2di *)p5_arg;
	long lines = bytes / (sizeof(__v2di)) / 16;

	p1 = __builtin_assume_aligned(p1, 16);
	p2 = __builtin_assume_aligned(p2, 16);
	p3 = __builtin_assume_aligned(p3, 16);
	p4 = __builtin_assume_aligned(p4, 16);
	p5 = __builtin_assume_aligned(p5, 16);

#pragma no_dam
#pragma ivdep
#pragma loop count(1000)
#pragma unroll(1)
#pragma novector
	do {
		p1[0] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[0],
									p2[0]),
						    p3[0]),
				p4[0]),
			p5[0]);
		p1[1] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[1],
									p2[1]),
						    p3[1]),
				p4[1]),
			p5[1]);
		p1[2] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[2],
									p2[2]),
						    p3[2]),
				p4[2]),
			p5[2]);
		p1[3] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[3],
									p2[3]),
						    p3[3]),
				p4[3]),
			p5[3]);
		p1[4] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[4],
									p2[4]),
						    p3[4]),
				p4[4]),
			p5[4]);
		p1[5] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[5],
									p2[5]),
						    p3[5]),
				p4[5]),
			p5[5]);
		p1[6] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[6],
									p2[6]),
						    p3[6]),
				p4[6]),
			p5[6]);
		p1[7] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[7],
									p2[7]),
						    p3[7]),
				p4[7]),
			p5[7]);
		p1[8] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[8],
									p2[8]),
						    p3[8]),
				p4[8]),
			p5[8]);
		p1[9] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[9],
									p2[9]),
						    p3[9]),
				p4[9]),
			p5[9]);
		p1[10] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[10],
									p2[10]),
						    p3[10]),
				p4[10]),
			p5[10]);
		p1[11] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[11],
									p2[11]),
						    p3[11]),
				p4[11]),
			p5[11]);
		p1[12] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[12],
									p2[12]),
						    p3[12]),
				p4[12]),
			p5[12]);
		p1[13] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[13],
									p2[13]),
						    p3[13]),
				p4[13]),
			p5[13]);
		p1[14] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[14],
									p2[14]),
						    p3[14]),
				p4[14]),
			p5[14]);
		p1[15] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[15],
									p2[15]),
						    p3[15]),
				p4[15]),
			p5[15]);

		p1 += 16;
		p2 += 16;
		p3 += 16;
		p4 += 16;
		p5 += 16;
	} while (--lines > 0);
}

static void xor5_128x32_m0(unsigned long bytes,
			   unsigned long *__restrict p1_arg,
			   const unsigned long *__restrict p2_arg,
			   const unsigned long *__restrict p3_arg,
			   const unsigned long *__restrict p4_arg,
			   const unsigned long *__restrict p5_arg)
{
	__v2di *__restrict p1 = (__v2di *)p1_arg;
	const __v2di *__restrict p2 = (__v2di *)p2_arg;
	const __v2di *__restrict p3 = (__v2di *)p3_arg;
	const __v2di *__restrict p4 = (__v2di *)p4_arg;
	const __v2di *__restrict p5 = (__v2di *)p5_arg;
	long lines = bytes / (sizeof(__v2di)) / 32;

	do {
		p1[0] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[0],
									p2[0]),
						    p3[0]),
				p4[0]),
			p5[0]);
		p1[1] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[1],
									p2[1]),
						    p3[1]),
				p4[1]),
			p5[1]);
		p1[2] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[2],
									p2[2]),
						    p3[2]),
				p4[2]),
			p5[2]);
		p1[3] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[3],
									p2[3]),
						    p3[3]),
				p4[3]),
			p5[3]);
		p1[4] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[4],
									p2[4]),
						    p3[4]),
				p4[4]),
			p5[4]);
		p1[5] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[5],
									p2[5]),
						    p3[5]),
				p4[5]),
			p5[5]);
		p1[6] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[6],
									p2[6]),
						    p3[6]),
				p4[6]),
			p5[6]);
		p1[7] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[7],
									p2[7]),
						    p3[7]),
				p4[7]),
			p5[7]);
		p1[8] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[8],
									p2[8]),
						    p3[8]),
				p4[8]),
			p5[8]);
		p1[9] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[9],
									p2[9]),
						    p3[9]),
				p4[9]),
			p5[9]);
		p1[10] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[10],
									p2[10]),
						    p3[10]),
				p4[10]),
			p5[10]);
		p1[11] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[11],
									p2[11]),
						    p3[11]),
				p4[11]),
			p5[11]);
		p1[12] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[12],
									p2[12]),
						    p3[12]),
				p4[12]),
			p5[12]);
		p1[13] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[13],
									p2[13]),
						    p3[13]),
				p4[13]),
			p5[13]);
		p1[14] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[14],
									p2[14]),
						    p3[14]),
				p4[14]),
			p5[14]);
		p1[15] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[15],
									p2[15]),
						    p3[15]),
				p4[15]),
			p5[15]);
		p1[16] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[16],
									p2[16]),
						    p3[16]),
				p4[16]),
			p5[16]);
		p1[17] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[17],
									p2[17]),
						    p3[17]),
				p4[17]),
			p5[17]);
		p1[18] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[18],
									p2[18]),
						    p3[18]),
				p4[18]),
			p5[18]);
		p1[19] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[19],
									p2[19]),
						    p3[19]),
				p4[19]),
			p5[19]);
		p1[20] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[20],
									p2[20]),
						    p3[20]),
				p4[20]),
			p5[20]);
		p1[21] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[21],
									p2[21]),
						    p3[21]),
				p4[21]),
			p5[21]);
		p1[22] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[22],
									p2[22]),
						    p3[22]),
				p4[22]),
			p5[22]);
		p1[23] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[23],
									p2[23]),
						    p3[23]),
				p4[23]),
			p5[23]);
		p1[24] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[24],
									p2[24]),
						    p3[24]),
				p4[24]),
			p5[24]);
		p1[25] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[25],
									p2[25]),
						    p3[25]),
				p4[25]),
			p5[25]);
		p1[26] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[26],
									p2[26]),
						    p3[26]),
				p4[26]),
			p5[26]);
		p1[27] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[27],
									p2[27]),
						    p3[27]),
				p4[27]),
			p5[27]);
		p1[28] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[28],
									p2[28]),
						    p3[28]),
				p4[28]),
			p5[28]);
		p1[29] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[29],
									p2[29]),
						    p3[29]),
				p4[29]),
			p5[29]);
		p1[30] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[30],
									p2[30]),
						    p3[30]),
				p4[30]),
			p5[30]);
		p1[31] = __builtin_e2k_qpxor(
			__builtin_e2k_qpxor(
				__builtin_e2k_qpxor(__builtin_e2k_qpxor(p1[31],
									p2[31]),
						    p3[31]),
				p4[31]),
			p5[31]);

		p1 += 32;
		p2 += 32;
		p3 += 32;
		p4 += 32;
		p5 += 32;
	} while (--lines > 0);
}

/* For build with "-02" */
static struct xor_block_template xor_block_128bit_regs_set1 = {
	.name = "e2k_128bit_regs_set1",
	.do_2 = xor2_128x16_m0,
	.do_3 = xor3_128x32_m0,
	.do_4 = xor4_128x32_m0,
	.do_5 = xor5_128x32_m0,
};

/* For build with "-O2 -ffix-lcc-bug146899" */
static struct xor_block_template xor_block_128bit_regs_set2 = {
	.name = "e2k_128bit_regs_set2",
	.do_2 = xor2_128x32_m0,
	.do_3 = xor3_128x32_m0,
	.do_4 = xor4_128x32_m0,
	.do_5 = xor5_128x32_m0,
};

/* For build with "-O3 -ffix-lcc-bug146899" */
static struct xor_block_template xor_block_128bit_regs_set3 = {
	.name = "e2k_128bit_regs_set3",
	.do_2 = xor2_128x16_m12,
	.do_3 = xor3_128x16_m10,
	.do_4 = xor4_128x16_m8,
	.do_5 = xor5_128x16_m6,
};

#define XOR_SPEED_128BIT_REGS                           \
	do {                                            \
		xor_speed(&xor_block_128bit_regs_set1); \
		xor_speed(&xor_block_128bit_regs_set2); \
		xor_speed(&xor_block_128bit_regs_set3); \
	} while (0)
#else

#define XOR_SPEED_128BIT_REGS /* empty */

#endif

#undef XOR_TRY_TEMPLATES
#define XOR_TRY_TEMPLATES                       \
	do {                                    \
		xor_speed(&xor_block_8regs);    \
		xor_speed(&xor_block_8regs_p);  \
		xor_speed(&xor_block_32regs);   \
		xor_speed(&xor_block_32regs_p); \
		XOR_SPEED_64BIT_REGS;           \
		XOR_SPEED_128BIT_REGS;          \
	} while (0)

