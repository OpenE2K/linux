#ifndef _E2K_SIMUL_H_
#define	_E2K_SIMUL_H_

#include <linux/console.h>


#ifdef CONFIG_E2K_MACHINE
# ifdef CONFIG_E2K_SIMULATOR
#  define E2K_HALT_OK()			E2K_LMS_HALT_OK
#  define E2K_HALT_ERROR(err_no)			\
({							\
	dump_stack();					\
	console_flush_on_panic(CONSOLE_REPLAY_ALL);	\
	E2K_LMS_HALT_ERROR(err_no);			\
})
#  define BOOT_E2K_HALT_OK()		E2K_LMS_HALT_OK
#  define BOOT_E2K_HALT_ERROR(err_no)	E2K_LMS_HALT_ERROR(err_no)
# else
#  define E2K_HALT_OK()			{while(1);}
#  define E2K_HALT_ERROR(err_no)		panic("HALT_ERROR(%d)\n", err_no)
#  define BOOT_E2K_HALT_OK()		{while(1);}
#  define BOOT_E2K_HALT_ERROR(err_no)	boot_panic("HALT_ERROR(%d)\n", err_no)
# endif
#else	/* ! CONFIG_E2K_MACHINE */
# define E2K_HALT_OK()						\
({								\
	if (NATIVE_IS_MACHINE_SIM) {				\
		E2K_LMS_HALT_OK;				\
	}							\
	while (1) {						\
	}							\
})
# define E2K_HALT_ERROR(err_no)					\
({								\
	if (NATIVE_IS_MACHINE_SIM) {				\
		dump_stack();					\
		console_flush_on_panic(CONSOLE_REPLAY_ALL);	\
		E2K_LMS_HALT_ERROR(err_no);			\
	}							\
	panic("HALT_ERROR(%d)\n", err_no);			\
})
# define BOOT_E2K_HALT_OK()					\
({								\
	if (BOOT_NATIVE_IS_MACHINE_SIM) {			\
		E2K_LMS_HALT_OK;				\
	}							\
	while (1) {						\
	}							\
})
# define BOOT_E2K_HALT_ERROR(err_no)				\
({								\
	if (BOOT_NATIVE_IS_MACHINE_SIM) {			\
		E2K_LMS_HALT_ERROR(err_no);			\
	} else {						\
		boot_panic("HALT_ERROR(%d)\n", err_no);		\
	}							\
})
#endif /* CONFIG_E2K_MACHINE */

#endif  /* _E2K_SIMUL_H_ */
