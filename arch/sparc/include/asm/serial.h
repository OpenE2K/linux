#ifndef __SPARC_SERIAL_H
#define __SPARC_SERIAL_H

#ifndef CONFIG_E90S
#define BASE_BAUD ( 1843200 / 16 )
#else
#include <asm-l/serial.h>
#endif

#endif /* __SPARC_SERIAL_H */
