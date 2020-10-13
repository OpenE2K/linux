#ifndef __LINUX_KBUILD_H
#define __LINUX_KBUILD_H

#ifndef CONFIG_E2K
#define DEFINE(sym, val) \
        asm volatile("\n->" #sym " %0 " #val : : "i" (val))

#define BLANK() asm volatile("\n->" : : )
#else /* CONFIG_E2K */
#define e2k_kbuild_name(x,y)	__e2k_kbuild_name(x, y)
#define __e2k_kbuild_name(x,y)	x##y

#define DEFINE(sym, val) \
	long e2k_kbuild_name(_dummy,__LINE__) \
	__attribute__((section(".foo\n->" #sym " @@@ " #val "\n"))) = val

#define BLANK() \
	long e2k_kbuild_name(_dummy,__LINE__) \
	__attribute__((section(".foo\n->\n"))) = 0
#endif /* !CONFIG_E2K */

#define OFFSET(sym, str, mem) \
	DEFINE(sym, offsetof(struct str, mem))

#define COMMENT(x) \
	asm volatile("\n->#" x)

#endif
