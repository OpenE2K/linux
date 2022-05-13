#ifndef _ASM_E2K_ALTERNATIVE_ASM_H
#define _ASM_E2K_ALTERNATIVE_ASM_H

#ifdef __ASSEMBLY__

/*
 * Check the length of an instruction sequence, must be a multiple of 8.
 */
.macro alt_len_check start,end
	.if ( \end - \start ) % 8
	.error "cpu alternatives instructions length is not divisible by 8\n"
	.endif
.endm

/*
 * Issue one struct alt_instr descriptor entry (need to put it into
 * the section .altinstructions, see below). This entry contains
 * enough information for the alternatives patching code to patch an
 * instruction. See apply_alternatives().
 */
.macro alt_entry orig_start, orig_end, alt_start, alt_end, feature
	.align	4
	.word	\orig_start - .
	.word	\alt_start - .
	.short	\orig_end - \orig_start
	.short	\alt_end - \alt_start
	.short	\feature
.endm

.macro alt_pad_64bytes bytes, check
	.if ( \bytes >= \check )
		.fill 1, 4, 0x00000070
		.fill 15, 4, 0
	.endif
.endm

/*
 * Fill up @bytes with nops.
 */
.macro alt_pad bytes
	.if ( \bytes >= 576 )
		ibranch . + \bytes
		alt_pad_fill \bytes - 16
	.else
		alt_pad_64bytes \bytes, 512
		alt_pad_64bytes \bytes, 448
		alt_pad_64bytes \bytes, 384
		alt_pad_64bytes \bytes, 320
		alt_pad_64bytes \bytes, 256
		alt_pad_64bytes \bytes, 192
		alt_pad_64bytes \bytes, 128
		alt_pad_64bytes \bytes, 64
		.if ( \bytes % 64 ) == 56
			.fill 1, 4, 0x00000060
			.fill 13, 4, 0
		.endif
		.if ( \bytes % 64 ) == 48
			.fill 1, 4, 0x00000050
			.fill 11, 4, 0
		.endif
		.if ( \bytes % 64 ) == 40
			.fill 1, 4, 0x00000040
			.fill 9, 4, 0
		.endif
		.if ( \bytes % 64 ) == 32
			.fill 1, 4, 0x00000030
			.fill 7, 4, 0
		.endif
		.if ( \bytes % 64 ) == 24
			.fill 1, 4, 0x00000020
			.fill 5, 4, 0
		.endif
		.if ( \bytes % 64 ) == 16
			.fill 1, 4, 0x00000010
			.fill 3, 4, 0
		.endif
		.if ( \bytes % 64 ) == 8
			.fill 2, 4, 0
		.endif
	.endif
.endm

/*
 * Define an alternative between two instructions. If @feature is
 * present, early code in apply_alternatives() replaces @oldinstr with
 * @newinstr.
 */
.macro ALTERNATIVE oldinstr, newinstr, feature
	.pushsection .altinstr_replacement,"ax"
770:	\newinstr
771:	.popsection
772:	\oldinstr
773:	alt_len_check 770b, 771b
	alt_len_check 772b, 773b
	alt_pad ( ( 771b - 770b ) - ( 773b - 772b ) )
774:	.pushsection .altinstructions,"a"
	alt_entry 772b, 774b, 770b, 771b, \feature
	.popsection
.endm

/*
 * Define an alternative between three instructions.
 */
.macro ALTERNATIVE_2 oldinstr, newinstr1, feature1, newinstr2, feature2
	.pushsection .altinstr_replacement,"ax"
770:	\newinstr1
771:	\newinstr2
772:	.popsection
773:	\oldinstr
774:	alt_len_check 770b, 771b
	alt_len_check 771b, 772b
	alt_len_check 773b, 774b
	.if ( 771b - 770b > 772b - 771b )
	alt_pad ( ( 771b - 770b ) - ( 774b - 773b ) )
	.else
	alt_pad ( ( 772b - 771b ) - ( 774b - 773b ) )
	.endif
775:	.pushsection .altinstructions,"a"
	alt_entry 773b, 775b, 770b, 771b,\feature1
	alt_entry 773b, 775b, 771b, 772b,\feature2
	.popsection
.endm


/*
 * bug 110687: we cannot pass e2k wide instructions to GNU assembler .macro
 * as a parameter in a sane way so use the following in complex cases.
 * How to use:
 *
 * 1) There is one alternative
 *
 *	ALTERNATIVE_1_ALTINSTR
 *	< alt. instruction >
 *	ALTERNATIVE_2_OLDINSTR
 *	< initial instruction >
 *	ALTERNATIVE_3_FEATURE
 *
 * 2) There are two alternatives
 *
 *	ALTERNATIVE_1_ALTINSTR
 *	"< first alt. instruction >"
 *	ALTERNATIVE_2_ALTINSTR2
 *	"< second alt. instruction >"
 *	ALTERNATIVE_3_OLDINSTR2
 *	"< initial instruction >"
 *	ALTERNATIVE_4_FEATURE2(feature1, feature2)
 */
#define ALTERNATIVE_1_ALTINSTR \
	.pushsection .altinstr_replacement,"ax" ; \
	770:

#define ALTERNATIVE_2_OLDINSTR \
	771: ; \
	.popsection ; \
	772:

#define ALTERNATIVE_3_FEATURE(feature) \
	773: ; \
	alt_len_check 770b, 771b ; \
	alt_len_check 772b, 773b ; \
	alt_pad ( ( 771b - 770b ) - ( 773b - 772b ) ) ; \
	774: ; \
	.pushsection .altinstructions,"a" ; \
	alt_entry 772b, 774b, 770b, 771b, feature ; \
	.popsection

#define ALTERNATIVE_2_ALTINSTR2 \
	771:

#define ALTERNATIVE_3_OLDINSTR2 \
	772: ; \
	.popsection ; \
	773:

#define ALTERNATIVE_4_FEATURE2(feature1, feature2) \
	774: ; \
	alt_len_check 770b, 771b ; \
	alt_len_check 771b, 772b ; \
	alt_len_check 773b, 774b ; \
	.if ( 771b - 770b > 772b - 771b ) ; \
		alt_pad ( ( 771b - 770b ) - ( 774b - 773b ) ) ; \
	.else ; \
		alt_pad ( ( 772b - 771b ) - ( 774b - 773b ) ) ; \
	.endif ; \
	775: ; \
	.pushsection .altinstructions,"a" ; \
	alt_entry 773b, 775b, 770b, 771b, feature1 ; \
	alt_entry 773b, 775b, 771b, 772b, feature2 ; \
	.popsection

#endif	/*  __ASSEMBLY__  */

#endif /* _ASM_E2K_ALTERNATIVE_ASM_H */
