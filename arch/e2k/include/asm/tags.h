/*
 *
 * Definitions of most popular hardware tags.
 *
 */

#ifndef _E2K_TAGS_H_
#define _E2K_TAGS_H_

#ifndef __ASSEMBLY__

/* Internal tags list. Old style */
#define	E2K_AP_ITAG		0x0
#define	E2K_PL_ITAG		0x1
#define	E2K_PL_V2_ITAG		0x0
#define	E2K_SAP_ITAG		0x4

#define	ITAG_MASK		ULL(0x4000000040000000)
#define	ITAGDWD_DEBUG		(ITAG_MASK | ULL(0xdead0000dead))
#define	ITAGDWD_IO_DEBUG	(ITAG_MASK | ULL(0x10dead0010dead))

/*
 * Definition of basic external tags. Old style.
 */
#define	E2K_NUMERIC_ETAG	0x0
#define	E2K_NULLPTR_ETAG	0x0
#define	E2K_PL_ETAG		0xA
#define	E2K_PLLO_ETAG		0xF
#define	E2K_PLHI_ETAG		0xF
#define	E2K_AP_HI_ETAG		0xC
#define	E2K_AP_LO_ETAG		0xF
#define	E2K_SAP_HI_ETAG		0xC
#define	E2K_SAP_LO_ETAG		0xF

/* External tags. New style */

#define	ETAGNUM		0x00		/* Num. value. generic */

#define	ETAGNVS		0x00		/* Num. value single */
#define	ETAGEWS		0x01		/* Empty value. single */
#define	ETAGDWS		0x01		/* Diagnostic value. single */

#define	ETAGNVD		0x00		/* Num. value double */
#define	ETAGNPD		0x00		/* Null pointer */
#define	ETAGEWD		0x05		/* Empty value. double */
#define	ETAGDWD		0x05		/* Diagnostic value. double */
#define	ETAGPLD		0x0A		/* Procedure label (v1-v5) */

#define	ETAGNVQ		0x00		/* Num. value quadro */
#define	ETAGNPQ		0x00		/* Null pointer */
#define	ETAGDWQ		0x55		/* Empty quadro */
#define	ETAGAPQ		0xCF		/* Array pointer */
#define	ETAGSAP		0xCF		/* Stack array pointer */
#define	ETAGPLQ		0xFF		/* Procedure label (v6-...) */

#define	ETAGBADQ	0xee	/* Invalid tag for quadro object */

#endif /* !(__ASSEMBLY__) */

#endif /* !(_E2K_TAGS_H_) */
