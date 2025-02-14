/****************************************************************************
*
*                       Realmode X86 Emulator Library
*
*               Copyright (C) 1991-2004 SciTech Software, Inc.
*                    Copyright (C) David Mosberger-Tang
*                      Copyright (C) 1999 Egbert Eich
*
*  ========================================================================
*
*  Permission to use, copy, modify, distribute, and sell this software and
*  its documentation for any purpose is hereby granted without fee,
*  provided that the above copyright notice appear in all copies and that
*  both that copyright notice and this permission notice appear in
*  supporting documentation, and that the name of the authors not be used
*  in advertising or publicity pertaining to distribution of the software
*  without specific, written prior permission.  The authors makes no
*  representations about the suitability of this software for any purpose.
*  It is provided "as is" without express or implied warranty.
*
*  THE AUTHORS DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
*  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
*  EVENT SHALL THE AUTHORS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
*  CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
*  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
*  OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
*  PERFORMANCE OF THIS SOFTWARE.
*
*  ========================================================================
*
* Language:     Watcom C++ 10.6 or later
* Environment:  Any
* Developer:    Kendall Bennett
*
* Description:  Inline assembler versions of the primitive operand
*               functions for faster performance. At the moment this is
*               x86 inline assembler, but these functions could be replaced
*               with native inline assembler for each supported processor
*               platform.
*
****************************************************************************/

#ifndef __X86EMU_PRIM_ASM_H
#define __X86EMU_PRIM_ASM_H

#ifdef  __WATCOMC__

#ifndef VALIDATE
#define __HAVE_INLINE_ASSEMBLER__
#endif

u32     get_flags_asm(void);
#pragma aux get_flags_asm =         \
    "pushf"                         \
    "pop    eax"                    \
    value [eax]                     \
    modify exact [eax];

u16     aaa_word_asm(u32 *flags,u16 d);
#pragma aux aaa_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "aaa"                           \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax]                 \
    value [ax]                      \
    modify exact [ax];

u16     aas_word_asm(u32 *flags,u16 d);
#pragma aux aas_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "aas"                           \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax]                 \
    value [ax]                      \
    modify exact [ax];

u16     aad_word_asm(u32 *flags,u16 d);
#pragma aux aad_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "aad"                           \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax]                 \
    value [ax]                      \
    modify exact [ax];

u16     aam_word_asm(u32 *flags,u8 d);
#pragma aux aam_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "aam"                           \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al]                 \
    value [ax]                      \
    modify exact [ax];

u8      adc_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux adc_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "adc    al,bl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [bl]            \
    value [al]                      \
    modify exact [al bl];

u16     adc_word_asm(u32 *flags,u16 d, u16 s);
#pragma aux adc_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "adc    ax,bx"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [bx]            \
    value [ax]                      \
    modify exact [ax bx];

u32     adc_long_asm(u32 *flags,u32 d, u32 s);
#pragma aux adc_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "adc    eax,ebx"                \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [ebx]          \
    value [eax]                     \
    modify exact [eax ebx];

u8      add_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux add_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "add    al,bl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [bl]            \
    value [al]                      \
    modify exact [al bl];

u16     add_word_asm(u32 *flags,u16 d, u16 s);
#pragma aux add_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "add    ax,bx"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [bx]            \
    value [ax]                      \
    modify exact [ax bx];

u32     add_long_asm(u32 *flags,u32 d, u32 s);
#pragma aux add_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "add    eax,ebx"                \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [ebx]          \
    value [eax]                     \
    modify exact [eax ebx];

u8      and_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux and_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "and    al,bl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [bl]            \
    value [al]                      \
    modify exact [al bl];

u16     and_word_asm(u32 *flags,u16 d, u16 s);
#pragma aux and_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "and    ax,bx"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [bx]            \
    value [ax]                      \
    modify exact [ax bx];

u32     and_long_asm(u32 *flags,u32 d, u32 s);
#pragma aux and_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "and    eax,ebx"                \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [ebx]          \
    value [eax]                     \
    modify exact [eax ebx];

u8      cmp_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux cmp_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "cmp    al,bl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [bl]            \
    value [al]                      \
    modify exact [al bl];

u16     cmp_word_asm(u32 *flags,u16 d, u16 s);
#pragma aux cmp_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "cmp    ax,bx"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [bx]            \
    value [ax]                      \
    modify exact [ax bx];

u32     cmp_long_asm(u32 *flags,u32 d, u32 s);
#pragma aux cmp_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "cmp    eax,ebx"                \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [ebx]          \
    value [eax]                     \
    modify exact [eax ebx];

u8      daa_byte_asm(u32 *flags,u8 d);
#pragma aux daa_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "daa"                           \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al]                 \
    value [al]                      \
    modify exact [al];

u8      das_byte_asm(u32 *flags,u8 d);
#pragma aux das_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "das"                           \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al]                 \
    value [al]                      \
    modify exact [al];

u8      dec_byte_asm(u32 *flags,u8 d);
#pragma aux dec_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "dec    al"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al]                 \
    value [al]                      \
    modify exact [al];

u16     dec_word_asm(u32 *flags,u16 d);
#pragma aux dec_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "dec    ax"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax]                 \
    value [ax]                      \
    modify exact [ax];

u32     dec_long_asm(u32 *flags,u32 d);
#pragma aux dec_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "dec    eax"                    \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax]                \
    value [eax]                     \
    modify exact [eax];

u8      inc_byte_asm(u32 *flags,u8 d);
#pragma aux inc_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "inc    al"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al]                 \
    value [al]                      \
    modify exact [al];

u16     inc_word_asm(u32 *flags,u16 d);
#pragma aux inc_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "inc    ax"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax]                 \
    value [ax]                      \
    modify exact [ax];

u32     inc_long_asm(u32 *flags,u32 d);
#pragma aux inc_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "inc    eax"                    \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax]                \
    value [eax]                     \
    modify exact [eax];

u8      or_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux or_byte_asm =           \
    "push   [edi]"                  \
    "popf"                          \
    "or al,bl"                      \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [bl]            \
    value [al]                      \
    modify exact [al bl];

u16     or_word_asm(u32 *flags,u16 d, u16 s);
#pragma aux or_word_asm =           \
    "push   [edi]"                  \
    "popf"                          \
    "or ax,bx"                      \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [bx]            \
    value [ax]                      \
    modify exact [ax bx];

u32     or_long_asm(u32 *flags,u32 d, u32 s);
#pragma aux or_long_asm =           \
    "push   [edi]"                  \
    "popf"                          \
    "or eax,ebx"                    \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [ebx]          \
    value [eax]                     \
    modify exact [eax ebx];

u8      neg_byte_asm(u32 *flags,u8 d);
#pragma aux neg_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "neg    al"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al]                 \
    value [al]                      \
    modify exact [al];

u16     neg_word_asm(u32 *flags,u16 d);
#pragma aux neg_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "neg    ax"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax]                 \
    value [ax]                      \
    modify exact [ax];

u32     neg_long_asm(u32 *flags,u32 d);
#pragma aux neg_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "neg    eax"                    \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax]                \
    value [eax]                     \
    modify exact [eax];

u8      not_byte_asm(u32 *flags,u8 d);
#pragma aux not_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "not    al"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al]                 \
    value [al]                      \
    modify exact [al];

u16     not_word_asm(u32 *flags,u16 d);
#pragma aux not_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "not    ax"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax]                 \
    value [ax]                      \
    modify exact [ax];

u32     not_long_asm(u32 *flags,u32 d);
#pragma aux not_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "not    eax"                    \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax]                \
    value [eax]                     \
    modify exact [eax];

u8      rcl_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux rcl_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "rcl    al,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [cl]            \
    value [al]                      \
    modify exact [al cl];

u16     rcl_word_asm(u32 *flags,u16 d, u8 s);
#pragma aux rcl_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "rcl    ax,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [cl]            \
    value [ax]                      \
    modify exact [ax cl];

u32     rcl_long_asm(u32 *flags,u32 d, u8 s);
#pragma aux rcl_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "rcl    eax,cl"                 \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [cl]           \
    value [eax]                     \
    modify exact [eax cl];

u8      rcr_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux rcr_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "rcr    al,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [cl]            \
    value [al]                      \
    modify exact [al cl];

u16     rcr_word_asm(u32 *flags,u16 d, u8 s);
#pragma aux rcr_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "rcr    ax,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [cl]            \
    value [ax]                      \
    modify exact [ax cl];

u32     rcr_long_asm(u32 *flags,u32 d, u8 s);
#pragma aux rcr_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "rcr    eax,cl"                 \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [cl]           \
    value [eax]                     \
    modify exact [eax cl];

u8      rol_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux rol_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "rol    al,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [cl]            \
    value [al]                      \
    modify exact [al cl];

u16     rol_word_asm(u32 *flags,u16 d, u8 s);
#pragma aux rol_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "rol    ax,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [cl]            \
    value [ax]                      \
    modify exact [ax cl];

u32     rol_long_asm(u32 *flags,u32 d, u8 s);
#pragma aux rol_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "rol    eax,cl"                 \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [cl]           \
    value [eax]                     \
    modify exact [eax cl];

u8      ror_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux ror_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "ror    al,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [cl]            \
    value [al]                      \
    modify exact [al cl];

u16     ror_word_asm(u32 *flags,u16 d, u8 s);
#pragma aux ror_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "ror    ax,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [cl]            \
    value [ax]                      \
    modify exact [ax cl];

u32     ror_long_asm(u32 *flags,u32 d, u8 s);
#pragma aux ror_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "ror    eax,cl"                 \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [cl]           \
    value [eax]                     \
    modify exact [eax cl];

u8      shl_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux shl_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "shl    al,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [cl]            \
    value [al]                      \
    modify exact [al cl];

u16     shl_word_asm(u32 *flags,u16 d, u8 s);
#pragma aux shl_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "shl    ax,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [cl]            \
    value [ax]                      \
    modify exact [ax cl];

u32     shl_long_asm(u32 *flags,u32 d, u8 s);
#pragma aux shl_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "shl    eax,cl"                 \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [cl]           \
    value [eax]                     \
    modify exact [eax cl];

u8      shr_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux shr_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "shr    al,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [cl]            \
    value [al]                      \
    modify exact [al cl];

u16     shr_word_asm(u32 *flags,u16 d, u8 s);
#pragma aux shr_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "shr    ax,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [cl]            \
    value [ax]                      \
    modify exact [ax cl];

u32     shr_long_asm(u32 *flags,u32 d, u8 s);
#pragma aux shr_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "shr    eax,cl"                 \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [cl]           \
    value [eax]                     \
    modify exact [eax cl];

u8      sar_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux sar_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "sar    al,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [cl]            \
    value [al]                      \
    modify exact [al cl];

u16     sar_word_asm(u32 *flags,u16 d, u8 s);
#pragma aux sar_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "sar    ax,cl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [cl]            \
    value [ax]                      \
    modify exact [ax cl];

u32     sar_long_asm(u32 *flags,u32 d, u8 s);
#pragma aux sar_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "sar    eax,cl"                 \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [cl]           \
    value [eax]                     \
    modify exact [eax cl];

u16     shld_word_asm(u32 *flags,u16 d, u16 fill, u8 s);
#pragma aux shld_word_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "shld   ax,dx,cl"               \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [dx] [cl]       \
    value [ax]                      \
    modify exact [ax dx cl];

u32     shld_long_asm(u32 *flags,u32 d, u32 fill, u8 s);
#pragma aux shld_long_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "shld   eax,edx,cl"             \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [edx] [cl]     \
    value [eax]                     \
    modify exact [eax edx cl];

u16     shrd_word_asm(u32 *flags,u16 d, u16 fill, u8 s);
#pragma aux shrd_word_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "shrd   ax,dx,cl"               \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [dx] [cl]       \
    value [ax]                      \
    modify exact [ax dx cl];

u32     shrd_long_asm(u32 *flags,u32 d, u32 fill, u8 s);
#pragma aux shrd_long_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "shrd   eax,edx,cl"             \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [edx] [cl]     \
    value [eax]                     \
    modify exact [eax edx cl];

u8      sbb_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux sbb_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "sbb    al,bl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [bl]            \
    value [al]                      \
    modify exact [al bl];

u16     sbb_word_asm(u32 *flags,u16 d, u16 s);
#pragma aux sbb_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "sbb    ax,bx"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [bx]            \
    value [ax]                      \
    modify exact [ax bx];

u32     sbb_long_asm(u32 *flags,u32 d, u32 s);
#pragma aux sbb_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "sbb    eax,ebx"                \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [ebx]          \
    value [eax]                     \
    modify exact [eax ebx];

u8      sub_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux sub_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "sub    al,bl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [bl]            \
    value [al]                      \
    modify exact [al bl];

u16     sub_word_asm(u32 *flags,u16 d, u16 s);
#pragma aux sub_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "sub    ax,bx"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [bx]            \
    value [ax]                      \
    modify exact [ax bx];

u32     sub_long_asm(u32 *flags,u32 d, u32 s);
#pragma aux sub_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "sub    eax,ebx"                \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [ebx]          \
    value [eax]                     \
    modify exact [eax ebx];

void    test_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux test_byte_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "test   al,bl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [bl]            \
    modify exact [al bl];

void    test_word_asm(u32 *flags,u16 d, u16 s);
#pragma aux test_word_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "test   ax,bx"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [bx]            \
    modify exact [ax bx];

void    test_long_asm(u32 *flags,u32 d, u32 s);
#pragma aux test_long_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "test   eax,ebx"                \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [ebx]          \
    modify exact [eax ebx];

u8      xor_byte_asm(u32 *flags,u8 d, u8 s);
#pragma aux xor_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "xor    al,bl"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [al] [bl]            \
    value [al]                      \
    modify exact [al bl];

u16     xor_word_asm(u32 *flags,u16 d, u16 s);
#pragma aux xor_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "xor    ax,bx"                  \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [ax] [bx]            \
    value [ax]                      \
    modify exact [ax bx];

u32     xor_long_asm(u32 *flags,u32 d, u32 s);
#pragma aux xor_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "xor    eax,ebx"                \
    "pushf"                         \
    "pop    [edi]"                  \
    parm [edi] [eax] [ebx]          \
    value [eax]                     \
    modify exact [eax ebx];

void    imul_byte_asm(u32 *flags,u16 *ax,u8 d,u8 s);
#pragma aux imul_byte_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "imul   bl"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    "mov    [esi],ax"               \
    parm [edi] [esi] [al] [bl]      \
    modify exact [esi ax bl];

void    imul_word_asm(u32 *flags,u16 *ax,u16 *dx,u16 d,u16 s);
#pragma aux imul_word_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "imul   bx"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    "mov    [esi],ax"               \
    "mov    [ecx],dx"               \
    parm [edi] [esi] [ecx] [ax] [bx]\
    modify exact [esi edi ax bx dx];

void    imul_long_asm(u32 *flags,u32 *eax,u32 *edx,u32 d,u32 s);
#pragma aux imul_long_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "imul   ebx"                    \
    "pushf"                         \
    "pop    [edi]"                  \
    "mov    [esi],eax"              \
    "mov    [ecx],edx"              \
    parm [edi] [esi] [ecx] [eax] [ebx] \
    modify exact [esi edi eax ebx edx];

void    mul_byte_asm(u32 *flags,u16 *ax,u8 d,u8 s);
#pragma aux mul_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "mul    bl"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    "mov    [esi],ax"               \
    parm [edi] [esi] [al] [bl]      \
    modify exact [esi ax bl];

void    mul_word_asm(u32 *flags,u16 *ax,u16 *dx,u16 d,u16 s);
#pragma aux mul_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "mul    bx"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    "mov    [esi],ax"               \
    "mov    [ecx],dx"               \
    parm [edi] [esi] [ecx] [ax] [bx]\
    modify exact [esi edi ax bx dx];

void    mul_long_asm(u32 *flags,u32 *eax,u32 *edx,u32 d,u32 s);
#pragma aux mul_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "mul    ebx"                    \
    "pushf"                         \
    "pop    [edi]"                  \
    "mov    [esi],eax"              \
    "mov    [ecx],edx"              \
    parm [edi] [esi] [ecx] [eax] [ebx] \
    modify exact [esi edi eax ebx edx];

void    idiv_byte_asm(u32 *flags,u8 *al,u8 *ah,u16 d,u8 s);
#pragma aux idiv_byte_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "idiv   bl"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    "mov    [esi],al"               \
    "mov    [ecx],ah"               \
    parm [edi] [esi] [ecx] [ax] [bl]\
    modify exact [esi edi ax bl];

void    idiv_word_asm(u32 *flags,u16 *ax,u16 *dx,u16 dlo,u16 dhi,u16 s);
#pragma aux idiv_word_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "idiv   bx"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    "mov    [esi],ax"               \
    "mov    [ecx],dx"               \
    parm [edi] [esi] [ecx] [ax] [dx] [bx]\
    modify exact [esi edi ax dx bx];

void    idiv_long_asm(u32 *flags,u32 *eax,u32 *edx,u32 dlo,u32 dhi,u32 s);
#pragma aux idiv_long_asm =         \
    "push   [edi]"                  \
    "popf"                          \
    "idiv   ebx"                    \
    "pushf"                         \
    "pop    [edi]"                  \
    "mov    [esi],eax"              \
    "mov    [ecx],edx"              \
    parm [edi] [esi] [ecx] [eax] [edx] [ebx]\
    modify exact [esi edi eax edx ebx];

void    div_byte_asm(u32 *flags,u8 *al,u8 *ah,u16 d,u8 s);
#pragma aux div_byte_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "div    bl"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    "mov    [esi],al"               \
    "mov    [ecx],ah"               \
    parm [edi] [esi] [ecx] [ax] [bl]\
    modify exact [esi edi ax bl];

void    div_word_asm(u32 *flags,u16 *ax,u16 *dx,u16 dlo,u16 dhi,u16 s);
#pragma aux div_word_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "div    bx"                     \
    "pushf"                         \
    "pop    [edi]"                  \
    "mov    [esi],ax"               \
    "mov    [ecx],dx"               \
    parm [edi] [esi] [ecx] [ax] [dx] [bx]\
    modify exact [esi edi ax dx bx];

void    div_long_asm(u32 *flags,u32 *eax,u32 *edx,u32 dlo,u32 dhi,u32 s);
#pragma aux div_long_asm =          \
    "push   [edi]"                  \
    "popf"                          \
    "div    ebx"                    \
    "pushf"                         \
    "pop    [edi]"                  \
    "mov    [esi],eax"              \
    "mov    [ecx],edx"              \
    parm [edi] [esi] [ecx] [eax] [edx] [ebx]\
    modify exact [esi edi eax edx ebx];

#else

static inline u32 get_flags_asm(void)
{
  u32 ret;

  asm ( "pushf\n\t"
        "pop %%eax"
	 : "=a"(ret)
	 );
  return ret;
}

static inline u16 aaa_word_asm(u32 *flags, u16 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "aaa\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u16 aas_word_asm(u32 *flags, u16 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "aas\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u16 aad_word_asm(u32 *flags, u16 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "aad\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u16 aam_word_asm(u32 *flags, u16 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "aam\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u8 adc_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "adcb %%bl, %%al\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}

static inline u16 adc_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "adcw %%bx, %%ax\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}

static inline u32 adc_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "adcl %%ebx, %%eax\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}

static inline u8 add_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "addb %%bl, %%al\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}

static inline u16 add_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "addw %%bx, %%ax\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}

static inline u32 add_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "addl %%ebx, %%eax\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}



static inline u8 and_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "andb %%bl, %%al\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}

static inline u16 and_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "andw %%bx, %%ax\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}

static inline u32 and_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "andl %%ebx, %%eax\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}


static inline u8 cmp_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "cmpb %%bl, %%al\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}

static inline u16 cmp_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "cmpw %%bx, %%ax\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}

static inline u32 cmp_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "cmpl %%ebx, %%eax\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}


static inline u8 daa_byte_asm(u32 *flags, u8 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "daa\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u8 das_byte_asm(u32 *flags, u8 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "das\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}



static inline u8 dec_byte_asm(u32 *flags, u8 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "dec %%al\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u16 dec_word_asm(u32 *flags, u16 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "dec %%ax\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u32 dec_long_asm(u32 *flags, u32 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "dec %%eax\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}


static inline u8 inc_byte_asm(u32 *flags, u8 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "inc %%al\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u16 inc_word_asm(u32 *flags, u16 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "inc %%ax\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u32 inc_long_asm(u32 *flags, u32 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "inc %%eax\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u8 or_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "orb %%bl, %%al\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}

static inline u16 or_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "orw %%bx, %%ax\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}

static inline u32 or_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t"
    "popf\n\t"
    "orl %%ebx, %%eax\n\t"
    "pushf\n\t"
    "popl (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d), "b"(s)
     );
  return d;
}


static inline u8 neg_byte_asm(u32 *flags, u8 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "neg %%al\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u16 neg_word_asm(u32 *flags, u16 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "neg %%ax\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u32 neg_long_asm(u32 *flags, u32 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "neg %%eax\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u8 not_byte_asm(u32 *flags, u8 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "not %%al\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u16 not_word_asm(u32 *flags, u16 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "not %%ax\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}

static inline u32 not_long_asm(u32 *flags, u32 d)
{
  asm (
    "push (%%edi)\n\t"
    "popf\n\t"
    "not %%eax\n\t"
    "pushf\n\t"
    "pop (%%edi)"
     : "=D"(flags), "=a"(d)
     : "0"(flags), "1"(d)
     );
  return d;
}


static inline u8 rcl_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "rclb %%cl,%%al\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u16 rcl_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "rclw %%cl,%%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u32 rcl_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "rcll %%cl,%%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}


static inline u8 rcr_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "rcrb %%cl,%%al\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u16 rcr_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "rcrw %%cl,%%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u32 rcr_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "rcrl %%cl,%%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}


static inline u8 rol_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "rolb %%cl,%%al\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u16 rol_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "rolw %%cl,%%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u32 rol_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "roll %%cl,%%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}


static inline u8 ror_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "rorb %%cl,%%al\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u16 ror_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "rorw %%cl,%%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u32 ror_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "rorl %%cl,%%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}


static inline u8 shl_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "shlb %%cl,%%al\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u16 shl_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "shlw %%cl,%%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u32 shl_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "shll %%cl,%%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}


static inline u8 shr_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "shrb %%cl,%%al\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u16 shr_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "shrw %%cl,%%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u32 shr_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "shrl %%cl,%%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}


static inline u8 sar_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "sarb %%cl,%%al\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u16 sar_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "sarw %%cl,%%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}

static inline u32 sar_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "sarl %%cl,%%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "c"(s) );
  return d;
}


static inline u16 shld_word_asm(u32 *flags, u16 data, u16 fill, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "shld %%cl, %%dx, %%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(data) : "0"(flags), "1"(data), "d"(fill), "c"(s) );
  return data;
}

static inline u32 shld_long_asm(u32 *flags, u32 data, u32 fill, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "shldl %%cl, %%edx, %%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(data) : "0"(flags), "1"(data), "d"(fill), "c"(s) );
  return data;
}

static inline u16 shrd_word_asm(u32 *flags, u16 data, u16 fill, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "shrd %%cl, %%dx, %%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(data) : "0"(flags), "1"(data), "d"(fill), "c"(s) );
  return data;
}

static inline u32 shrd_long_asm(u32 *flags, u32 data, u32 fill, u8 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "shrdl %%cl, %%edx, %%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(data) : "0"(flags), "1"(data), "d"(fill), "c"(s) );
  return data;
}


static inline u8 sbb_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
     "pushl (%%edi)\n\t"  "popf\n\t"
     "sbbb %%bl, %%al\n\t"
     "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "b"(s) );
  return d;
}

static inline u16 sbb_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "sbbw %%bx, %%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "b"(s) );
  return d;
}

static inline u32 sbb_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "sbbl %%ebx, %%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "b"(s) );
  return d;
}



static inline u8 sub_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
     "pushl (%%edi)\n\t"  "popf\n\t"
     "subb %%bl, %%al\n\t"
     "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "b"(s) );
  return d;
}

static inline u16 sub_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "subw %%bx, %%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "b"(s) );
  return d;
}

static inline u32 sub_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "subl %%ebx, %%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "b"(s) );
  return d;
}


static inline u8 xor_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
     "pushl (%%edi)\n\t"  "popf\n\t"
     "xorb %%bl, %%al\n\t"
     "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "b"(s) );
  return d;
}

static inline u16 xor_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "xorw %%bx, %%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "b"(s) );
  return d;
}

static inline u32 xor_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "xorl %%ebx, %%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(d) : "0"(flags), "1"(d), "b"(s) );
  return d;
}


static inline void test_byte_asm(u32 *flags, u8 d, u8 s)
{
  __asm__ __volatile__(
     "pushl (%%edi)\n\t"  "popf\n\t"
     "testb %%bl, %%al\n\t"
     "pushf\n\t" "popl (%%edi)"
     : "=D"(flags) : "0"(flags), "a"(d), "b"(s) );
}

static inline void test_word_asm(u32 *flags, u16 d, u16 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "testw %%bx, %%ax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags) : "0"(flags), "a"(d), "b"(s) );
}

static inline void test_long_asm(u32 *flags, u32 d, u32 s)
{
  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "testl %%ebx, %%eax\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags) : "0"(flags), "a"(d), "b"(s) );
}


static inline void imul_byte_asm(u32 *flags,u16 *ax,u8 d,u8 s)
{
  u16 ret;

  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "imul %%bl\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(ret) : "0"(flags), "a"(d), "b"(s) );
  *ax = ret;
}

static inline void imul_word_asm(u32 *flags,u16 *ax,u16 *dx,u16 d,u16 s)
{
  u16 ret_ax, ret_dx;

  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "imulw %%bx\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(ret_ax), "=d"(ret_dx) : "0"(flags), "a"(d), "b"(s) );
  *ax = ret_ax;
  *dx = ret_dx;
}

static inline void imul_long_asm(u32 *flags,u32 *ax,u32 *dx,u32 d,u32 s)
{
  u32 ret_ax, ret_dx;

  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "imull %%ebx\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(ret_ax), "=d"(ret_dx) : "0"(flags), "a"(d), "b"(s) );
  *ax = ret_ax;
  *dx = ret_dx;
}


static inline void mul_byte_asm(u32 *flags,u16 *ax,u8 d,u8 s)
{
  u16 ret;

  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "mul %%bl\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(ret) : "0"(flags), "a"(d), "b"(s) );
  *ax = ret;
}

static inline void mul_word_asm(u32 *flags,u16 *ax,u16 *dx,u16 d,u16 s)
{
  u16 ret_ax, ret_dx;

  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "mulw %%bx\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(ret_ax), "=d"(ret_dx) : "0"(flags), "a"(d), "b"(s) );
  *ax = ret_ax;
  *dx = ret_dx;
}

static inline void mul_long_asm(u32 *flags,u32 *ax,u32 *dx,u32 d,u32 s)
{
  u32 ret_ax, ret_dx;

  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "mull %%ebx\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(ret_ax), "=d"(ret_dx) : "0"(flags), "a"(d), "b"(s) );
  *ax = ret_ax;
  *dx = ret_dx;
}


static inline void idiv_byte_asm(u32 *flags,u8 *al,u8 *ah,u16 d,u8 s)
{
  u16 ret_ax;

  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "idiv %%bl\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(ret_ax) : "0"(flags), "a"(d), "b"(s) );
  *al = ret_ax & 0xff;
  *ah = (ret_ax >> 8) & 0xff;
}

static inline void idiv_word_asm(u32 *flags,u16 *ax,u16 *dx,u16 dlo,u16 dhi,u16 s)
{
  u16 ret_ax, ret_dx;

  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "idiv %%bx\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(ret_ax), "=d"(ret_dx) : "0"(flags), "a"(dlo), "d"(dhi), "b"(s) );
  *ax = ret_ax;
  *dx = ret_dx;
}

static inline void idiv_long_asm(u32 *flags,u32 *eax,u32 *edx,u32 dlo,u32 dhi,u32 s)
{
  u32 ret_ax, ret_dx;

  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "idiv %%ebx\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(ret_ax), "=d"(ret_dx) : "0"(flags), "a"(dlo), "d"(dhi), "b"(s) );
  *eax = ret_ax;
  *edx = ret_dx;
}


static inline void div_byte_asm(u32 *flags,u8 *al,u8 *ah,u16 d,u8 s)
{
  u16 ret_ax;

  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "div %%bl\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(ret_ax) : "0"(flags), "a"(d), "b"(s) );
  *al = ret_ax & 0xff;
  *ah = (ret_ax >> 8) & 0xff;
}

static inline void div_word_asm(u32 *flags,u16 *ax,u16 *dx,u16 dlo,u16 dhi,u16 s)
{
  u16 ret_ax, ret_dx;

  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "div %%bx\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(ret_ax), "=d"(ret_dx) : "0"(flags), "a"(dlo), "d"(dhi), "b"(s) );
  *ax = ret_ax;
  *dx = ret_dx;
}

static inline void div_long_asm(u32 *flags,u32 *eax,u32 *edx,u32 dlo,u32 dhi,u32 s)
{
  u32 ret_ax, ret_dx;

  __asm__ __volatile__(
    "pushl (%%edi)\n\t" "popf\n\t"
    "div %%ebx\n\t"
    "pushf\n\t" "popl (%%edi)"
     : "=D"(flags), "=a"(ret_ax), "=d"(ret_dx) : "0"(flags), "a"(dlo), "d"(dhi), "b"(s) );
  *eax = ret_ax;
  *edx = ret_dx;
}

#endif

#endif /* __X86EMU_PRIM_ASM_H */
