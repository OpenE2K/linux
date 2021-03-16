#ifndef M2MLC_DBG_H__
#define M2MLC_DBG_H__


/**
 *  Debug
 *
 *  DEBUG - defined in makefile
 */
#undef PDEBUG
#ifdef DEBUG
#define PDEBUG(msk, fmt, args...) \
do { \
	if (debug_mask & msk) { \
		printk(KERN_DEBUG KBUILD_MODNAME ": " fmt, ## args); \
	} \
} while (0)
#else
#define PDEBUG(msk, fmt, args...) do {} while (0)
#endif

#undef nPDEBUG
#define nPDEBUG(msk, fmt, args...) do {} while (0)

#ifdef DEBUG
#define DEV_DBG(msk, dev, fmt, args...) \
do { \
	if (debug_mask & msk) { \
		dev_dbg(dev, fmt, ## args); \
	} \
} while (0)
#else
#define DEV_DBG(msk, dev, fmt, args...) do {} while (0)
#endif

#undef nDEV_DBG
#define nDEV_DBG(msk, dev, fmt, args...) do {} while (0)

#define ERR_MSG(fmt, args...) \
	printk(KERN_ERR KBUILD_MODNAME ": " fmt, ## args)
#define WRN_MSG(fmt, args...) \
	printk(KERN_WARNING KBUILD_MODNAME ": " fmt, ## args)
#define LOG_MSG(fmt, args...) \
	printk(KERN_INFO KBUILD_MODNAME ": " fmt, ## args)

#ifdef DEBUG
#define assert(expr) \
do { \
	if (!(expr)) { \
		printk(KERN_CRIT KBUILD_MODNAME \
		       ": Assertion failed! %s,%s,%s,line=%d\n", \
		       #expr, __FILE__, __func__, __LINE__); \
	} \
} while (0)
#else
#define assert(expr) do {} while (0)
#endif


#endif /* M2MLC_DBG_H__ */
