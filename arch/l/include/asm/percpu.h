#ifndef _ASM_L_PERCPU_H_
#define _ASM_L_PERCPU_H_

#ifdef CONFIG_SMP

/*
 * Define the "EARLY_PER_CPU" macros.  These are used for some per_cpu
 * variables that are initialized and accessed before there are per_cpu
 * areas allocated.
 */

#define	DEFINE_EARLY_PER_CPU(_type, _name, _initvalue)			\
	DEFINE_PER_CPU(_type, _name) = _initvalue;			\
	__typeof__(_type) _name##_early_map[NR_CPUS] __initdata =	\
				{ [0 ... NR_CPUS-1] = _initvalue };	\
	__typeof__(_type) *_name##_early_ptr __refdata = _name##_early_map

#define DEFINE_EARLY_PER_CPU_READ_MOSTLY(_type, _name, _initvalue)	\
	DEFINE_PER_CPU_READ_MOSTLY(_type, _name) = _initvalue;		\
	__typeof__(_type) _name##_early_map[NR_CPUS] __initdata =	\
				{ [0 ... NR_CPUS-1] = _initvalue };	\
	__typeof__(_type) *_name##_early_ptr __refdata = _name##_early_map

#define EXPORT_EARLY_PER_CPU_SYMBOL(_name)			\
	EXPORT_PER_CPU_SYMBOL(_name);				\
	EXPORT_PER_CPU_SYMBOL(_name##_early_ptr);		\
	EXPORT_PER_CPU_SYMBOL(_name##_early_map);

#define DECLARE_EARLY_PER_CPU(_type, _name)			\
	DECLARE_PER_CPU(_type, _name);				\
	extern __typeof__(_type) *_name##_early_ptr;		\
	extern __typeof__(_type)  _name##_early_map[]

#define DECLARE_EARLY_PER_CPU_READ_MOSTLY(_type, _name)		\
	DECLARE_PER_CPU_READ_MOSTLY(_type, _name);		\
	extern __typeof__(_type) *_name##_early_ptr;		\
	extern __typeof__(_type)  _name##_early_map[]

#define	early_per_cpu_ptr(_name) (_name##_early_ptr)
#define	early_per_cpu_map(_name, _idx) (_name##_early_map[_idx])
#define	early_per_cpu(_name, _cpu) 				\
	*(early_per_cpu_ptr(_name) ?				\
		&early_per_cpu_ptr(_name)[_cpu] :		\
		&per_cpu(_name, _cpu))

#else	/* !CONFIG_SMP */
#define	DEFINE_EARLY_PER_CPU(_type, _name, _initvalue)		\
	DEFINE_PER_CPU(_type, _name) = _initvalue

#define DEFINE_EARLY_PER_CPU_READ_MOSTLY(_type, _name, _initvalue)	\
	DEFINE_PER_CPU_READ_MOSTLY(_type, _name) = _initvalue

#define EXPORT_EARLY_PER_CPU_SYMBOL(_name)			\
	EXPORT_PER_CPU_SYMBOL(_name)

#define DECLARE_EARLY_PER_CPU(_type, _name)			\
	DECLARE_PER_CPU(_type, _name)

#define DECLARE_EARLY_PER_CPU_READ_MOSTLY(_type, _name)		\
	DECLARE_PER_CPU_READ_MOSTLY(_type, _name)

#define	early_per_cpu(_name, _cpu) per_cpu(_name, _cpu)
#define	early_per_cpu_ptr(_name) NULL
/* no early_per_cpu_map() */

#endif	/* !CONFIG_SMP */

#endif /* _ASM_L_PERCPU_H_ */

