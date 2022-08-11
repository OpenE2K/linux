
#ifndef _MCST_WRNVRAM_IOCTL_H_
#define _MCST_WRNVRAM_IOCTL_H_


/*
 * Ioctl definitions
 */

/* Use 'k' as magic number */
#define WRNVRAM_IOC_MAGIC  'w'

#define WRNVRAM_GET_MFGID             _IOR (WRNVRAM_IOC_MAGIC,  1, u_long)
#define WRNVRAM_SET_MFGID             _IOW (WRNVRAM_IOC_MAGIC,  2, u_long)

#define WRNVRAM_IOC_MAXNR       2



#endif  /* !(_MCST_WRNVRAM_IOCTL_H_) */
