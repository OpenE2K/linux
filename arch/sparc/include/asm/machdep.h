
#ifndef	_SPARC64_RESET_H_
#define	_SPARC64_RESET_H_

#ifndef __ASSEMBLY__

typedef struct machdep {
	void		(*arch_reset)(void);
	void		(*arch_halt)(void);
} machdep_t;

extern machdep_t	machine;

#endif /* __ASSEMBLY__ */

#endif  /* _SPARC64_RESET_H_ */
