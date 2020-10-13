#ifndef _E2K_DIV64_H_
#define _E2K_DIV64_H_

/*
 * Hey, we're already 64-bit, no
 * need to play games..
 */

#define do_div(n,base) ({ \
	int __res; \
	__res = ((unsigned long) (n)) % (unsigned) (base); \
	n = ((unsigned long) (n)) / (unsigned) (base); \
	__res; })


#endif /* _E2K_DIV64_H_ */
