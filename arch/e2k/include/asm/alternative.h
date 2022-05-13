#ifndef _ASM_E2K_ALTERNATIVE_H
#define _ASM_E2K_ALTERNATIVE_H

#ifndef __ASSEMBLY__

#include <linux/types.h>

struct alt_instr {
	s32 instr_offset;	/* original instruction */
	s32 repl_offset;	/* offset to replacement instruction */
	u16 instrlen;		/* length of original instruction */
	u16 replacementlen;	/* length of new instruction */
	u16 facility;		/* facility bit set for replacement */
} __aligned(4);

void apply_alternative_instructions(void);
void apply_alternatives(struct alt_instr *start, struct alt_instr *end);

/*
 * An example when first alternative instruction is the biggest,
 * and original instruction is the smallest.
 *
 * Original instruction is padded statically at compile time,
 * while alternative instructions are padded if necessary in
 * runtime when patching them in.
 *
 * |661:       |662:                       |663:
 * +-----------+---------+-----------------+
 * | oldinstr  |  oldinstr_padding         |
 * |           +---------+-----------------+
 * |           | ibranch if length >= 576  |
 * |           | 64-bytes NOPs otherwise   |
 * +-----------+---------+-----------------+
 *		^^^^^^ static padding ^^^^^
 *
 * .altinstr_replacement section
 * +-----------+---------+-----------------+
 * |6641:			           |6651:
 * | alternative instr 1	           |
 * +-----------+---------+- - - - - - - - -+
 * |6642:		 |6652:            |
 * | alternative instr 2 | padding         |
 * +-----------+---------+- - - - - - - - -+
 *			  ^runtime padding^
 *
 *
 * 'struct alt_instr' holds details about how and when
 * instructions must be replaced:
 *
 * .altinstructions section
 * +----------------------------+
 * | alt_instr entries for each |
 * | alternative instruction    |
 * +----------------------------+
 */

#define b_altinstr(num)	"664"#num
#define e_altinstr(num)	"665"#num

#define e_oldinstr_pad_end	"663"
#define oldinstr_len		"662b-661b"
#define oldinstr_total_len	e_oldinstr_pad_end"b-661b"
#define altinstr_len(num)	e_altinstr(num)"b-"b_altinstr(num)"b"
#define oldinstr_pad_len(num) \
	"-(((" altinstr_len(num) ")-(" oldinstr_len ")) > 0) * " \
	"((" altinstr_len(num) ")-(" oldinstr_len "))"

#define INSTR_LEN_SANITY_CHECK(len)					\
	".if (" len ") %% 8\n"						\
	"\t.error \"cpu alternatives instructions length is not divisible by 8\"\n" \
	".endif\n"

#define OLDINSTR_PAD_64_BYTES(num, check) \
	".if " oldinstr_pad_len(num) " >= " __stringify(check) "\n"	\
		"\t.fill   1, 4, 0x00000070\n"				\
		"\t.fill   15, 4, 0\n"					\
	".endif\n"

#define OLDINSTR_PADDING(oldinstr, num)					\
	".if " oldinstr_pad_len(num) " >= 576\n"			\
		"\tibranch " e_oldinstr_pad_end "f\n"			\
		"6620:\n"						\
		"\t.fill (" oldinstr_pad_len(num) " - (6620b-662b)) / 8, 8, 0\n" \
	".else\n"							\
		OLDINSTR_PAD_64_BYTES(num, 512)				\
		OLDINSTR_PAD_64_BYTES(num, 448)				\
		OLDINSTR_PAD_64_BYTES(num, 384)				\
		OLDINSTR_PAD_64_BYTES(num, 320)				\
		OLDINSTR_PAD_64_BYTES(num, 256)				\
		OLDINSTR_PAD_64_BYTES(num, 192)				\
		OLDINSTR_PAD_64_BYTES(num, 128)				\
		OLDINSTR_PAD_64_BYTES(num, 64)				\
		".if ( " oldinstr_pad_len(num) " %% 64 ) == 56\n"	\
			"\t.fill   1, 4, 0x00000060\n"			\
			"\t.fill   13, 4, 0\n"				\
		".endif\n"						\
		".if ( " oldinstr_pad_len(num) " %% 64 ) == 48\n"	\
			"\t.fill   1, 4, 0x00000050\n"			\
			"\t.fill   11, 4, 0\n"				\
		".endif\n"						\
		".if ( " oldinstr_pad_len(num) " %% 64 ) == 40\n"	\
			"\t.fill   1, 4, 0x00000040\n"			\
			"\t.fill   9, 4, 0\n"				\
		".endif\n"						\
		".if ( " oldinstr_pad_len(num) " %% 64 ) == 32\n"	\
			"\t.fill   1, 4, 0x00000030\n"			\
			"\t.fill   7, 4, 0\n"				\
		".endif\n"						\
		".if ( " oldinstr_pad_len(num) " %% 64 ) == 24\n"	\
			"\t.fill   1, 4, 0x00000020\n"			\
			"\t.fill   5, 4, 0\n"				\
		".endif\n"						\
		".if ( " oldinstr_pad_len(num) " %% 64 ) == 16\n"	\
			"\t.fill   1, 4, 0x00000010\n"			\
			"\t.fill   3, 4, 0\n"				\
		".endif\n"						\
		".if ( " oldinstr_pad_len(num) " %% 64 ) == 8\n"		\
			"\t.fill   2, 4, 0\n"				\
		".endif\n"						\
	".endif\n"

#define OLDINSTR(oldinstr, num)						\
	"661:\n\t" oldinstr "\n662:\n"					\
	OLDINSTR_PADDING(oldinstr, num)					\
	e_oldinstr_pad_end ":\n"					\
	INSTR_LEN_SANITY_CHECK(oldinstr_len)

#define OLDINSTR_2(oldinstr, num1, num2)				\
	"661:\n\t" oldinstr "\n662:\n"					\
	".if " altinstr_len(num1) " < " altinstr_len(num2) "\n"		\
	OLDINSTR_PADDING(oldinstr, num2)				\
	".else\n"							\
	OLDINSTR_PADDING(oldinstr, num1)				\
	".endif\n"							\
	e_oldinstr_pad_end ":\n"					\
	INSTR_LEN_SANITY_CHECK(oldinstr_len)

#define ALTINSTR_ENTRY(facility, num)					\
	"\t.align 4\n"							\
	"\t.word 661b - .\n"			/* old instruction */	\
	"\t.word " b_altinstr(num)"b - .\n"	/* alt instruction */	\
	"\t.short " oldinstr_total_len "\n"	/* source len	   */	\
	"\t.short " altinstr_len(num) "\n"	/* alt instruction len */ \
	"\t.short " __stringify(facility) "\n"	/* facility bit    */

#define ALTINSTR_REPLACEMENT(altinstr, num)	/* replacement */	\
	b_altinstr(num)":\n\t" altinstr "\n" e_altinstr(num) ":\n"	\
	INSTR_LEN_SANITY_CHECK(altinstr_len(num))

/* alternative assembly primitive: */
#define ALTERNATIVE(oldinstr, altinstr, facility) \
	".pushsection .altinstr_replacement, \"ax\"\n"			\
	ALTINSTR_REPLACEMENT(altinstr, 1)				\
	".popsection\n"							\
	OLDINSTR(oldinstr, 1)						\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY(facility, 1)					\
	".popsection\n"

#define ALTERNATIVE_2(oldinstr, altinstr1, facility1, altinstr2, facility2)\
	".pushsection .altinstr_replacement, \"ax\"\n"			\
	ALTINSTR_REPLACEMENT(altinstr1, 1)				\
	ALTINSTR_REPLACEMENT(altinstr2, 2)				\
	".popsection\n"							\
	OLDINSTR_2(oldinstr, 1, 2)					\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY(facility1, 1)					\
	ALTINSTR_ENTRY(facility2, 2)					\
	".popsection\n"

/*
 * Alternative instructions for different CPU types or capabilities.
 *
 * This allows to use optimized instructions even on generic binary
 * kernels.
 *
 * oldinstr is padded with jump and nops at compile time if altinstr is
 * longer. altinstr is padded with jump and nops at run-time during patching.
 */
#define alternative(oldinstr, altinstr, _facility, clobbers...) \
	_Pragma("no_asm_inline") \
	asm volatile (ALTERNATIVE(oldinstr, altinstr, %[facility]) \
			:: [facility] "i" (_facility) : clobbers)

#define alternative_2(oldinstr, altinstr1, _facility1, altinstr2, _facility2) \
	_Pragma("no_asm_inline") \
	asm volatile (ALTERNATIVE_2(oldinstr, altinstr1, %[facility1], \
				    altinstr2, %[facility2]) \
			: \
			: [facility1] "i" (_facility1), \
			  [facility2] "i" (_facility2) \
			: clobbers)

/*
 * How to use:
 *
 * 1) There is one alternative
 *
 *	asm volatile (
 *		ALTERNATIVE_1_ALTINSTR
 *		"< alt. instruction >"
 *		ALTERNATIVE_2_OLDINSTR
 *		"< initial instruction >"
 *		ALTERNATIVE_3_FEATURE(feature)
 *		)
 *
 * 2) There are two alternatives
 *
 *	asm volatile (
 *		ALTERNATIVE_1_ALTINSTR
 *		"< first alt. instruction >"
 *		ALTERNATIVE_2_ALTINSTR2
 *		"< second alt. instruction >"
 *		ALTERNATIVE_3_OLDINSTR2
 *		"< initial instruction >"
 *		ALTERNATIVE_4_FEATURE2(feature1, feature2)
 *		)
 */
#define ALTERNATIVE_1_ALTINSTR \
	".pushsection .altinstr_replacement, \"ax\"\n" \
	b_altinstr(1)":\n"

#define ALTERNATIVE_2_OLDINSTR \
	"\n" e_altinstr(1) ":\n" \
	INSTR_LEN_SANITY_CHECK(altinstr_len(1)) \
	".popsection\n" \
	"661:\n"

#define ALTERNATIVE_3_FEATURE(facility) \
	"\n662:\n" \
	OLDINSTR_PADDING(oldinstr, 1) \
	e_oldinstr_pad_end ":\n" \
	INSTR_LEN_SANITY_CHECK(oldinstr_len) \
	".pushsection .altinstructions,\"a\"\n" \
	ALTINSTR_ENTRY(facility, 1) \
	".popsection\n"

#define ALTERNATIVE_2_ALTINSTR2 \
	"\n" e_altinstr(1) ":\n" \
	INSTR_LEN_SANITY_CHECK(altinstr_len(1)) \
	b_altinstr(2)":\n"

#define ALTERNATIVE_3_OLDINSTR2 \
	"\n" e_altinstr(2) ":\n" \
	INSTR_LEN_SANITY_CHECK(altinstr_len(2)) \
	".popsection\n" \
	"661:\n"

#define ALTERNATIVE_4_FEATURE2(facility1, facility2) \
	"\n662:\n" \
	".if " altinstr_len(1) " < " altinstr_len(2) "\n" \
	OLDINSTR_PADDING(oldinstr, 2) \
	".else\n" \
	OLDINSTR_PADDING(oldinstr, 1) \
	".endif\n" \
	e_oldinstr_pad_end ":\n" \
	INSTR_LEN_SANITY_CHECK(oldinstr_len) \
	".pushsection .altinstructions,\"a\"\n" \
	ALTINSTR_ENTRY(facility1, 1) \
	ALTINSTR_ENTRY(facility2, 2) \
	".popsection\n"

#endif /* __ASSEMBLY__ */

#endif /* _ASM_E2K_ALTERNATIVE_H */
