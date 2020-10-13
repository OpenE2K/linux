#ifndef __LINUX_MBKP1_REG_H__
#define __LINUX_MBKP1_REG_H__

#ifdef	__cplusplus
extern "C" {
#endif

/* 

модули: MBKP1 - Send + Receive, MBKP2 - Receive + Receive 
   xxx1 - приемник в MBKP1 (SR) или приемник 1 в MBKP2 (RR) 
   xxx2 - приемник 2 в MBKP2 (RR) 			     

*/

#define BYTE_IN_TRWD     4 


/*               Смещения регистров МБКП 		     */

/*  Виртуальные адреса буфера и счетчики DVMA-обменов. 	     */ 
/*  Запись в CNT_* является командой запуска обмена буфером  */


#define RESET_MBKP 0x40	/* общий сброс МБКП (обоих каналов)	*/

#if NEW_MBKP
#define SGCNT_MASK  0x00ffffff /* маска счетчика со знаком в доп коде */
#else
#define SGCNT_MASK  0x001fffff /* маска счетчика со знаком в доп коде */
#endif /* NEW_MBKP */

#define MAX_CNT     0x000fffff  /* маска счетчика без знака  	    */
#define COMPL_MASK  0xfff00000  /* знак,счетчик => отриц число */

/* прерывания и маски  */

#define INTR_M_WD 0x18 /* слово маски прерываний		*/
#define INTR_M1   0x02 /* биты маски: нормальные и четность 	*/	
#define INTR_M2   0x04 /* 	      аварийные			*/ 
#define INTR_M3   0x08 /* резерв, пока должен быть 0		*/

#define WRDESC_BUSY 1  /* 1 - приемник еще не принял выданный дескриптор */

#define INTR_EV_WD 0x30 /* слово событий прерываний и		*/
		       /* их биты, Mx=1 - разрешающая маска     */	


#if MBKP1 

#define BUF_TR    0x01 		/* конец передачи буфера приемника 1	- M1 */
#define BUF_RCV1  0x02 		/* конец приема буфера приемника 1	- M1 */
#define PAR_RCV1  0x04 		/* четность данных приемника 1		- M1 */
#define PAR_SBUS  0x08 		/* четность при приеме из SBUS		- M3 */

#define ERR_SBUS  0x10 		/* некорректное подтв или Late_Error	- M2 */
#define DESC_RCV1 0x20 		/* принят дескриптор приемником 1	- M1 */		           
#define CH0_INT  (BUF_RCV1  | PAR_RCV1 | DESC_RCV1)  	/* прерывания канала 0 */
#define CH1_INT  (BUF_TR)  				/* прерывания канала 1 */
#define MOD_INT  ( PAR_SBUS | ERR_SBUS)		    	/* прерывания модуля */

#else

#define M2MAS_RCV1    0x02	/* принят массив приемником 1              - M1 */
#define M2PAR_RCV1    0x04	/* четность массива приемника 1            - M1 */
#define M2SBUS_PAR    0x08	/* четность по sbus - одном из каналов     - M2 */

#define M2SBUS_LATERR 0x10	/* sbus - late error в одном из каналов    - M2 */
#define M2DESC_RCV1   0x20	/* принят дескриптор приемником 1          - M1 */
#define M2MAS_RCV2    0x40	/* принят массив приемником 2              - M1 */
#define M2PAR_RCV2    0x80	/* четность массива приемника 2            - M1 */

#define M2DESC_RCV2  0x100	/* принят дескриптор приемником 2          - M1 */

#define CH0_INT  ( M2MAS_RCV1 | M2PAR_RCV1 | M2DESC_RCV1 )  /* прерывания канала 0 */
#define CH1_INT  ( M2MAS_RCV2 | M2PAR_RCV2 | M2DESC_RCV2 )  /* прерывания канала 1 */
#define MOD_INT  ( M2SBUS_PAR | M2SBUS_LATERR)		    /* прерывания модуля */

#endif

#define ALL_INT (CH0_INT | CH1_INT | MOD_INT)  

/* регистры DVMA-адресов и счетчиков */

#define VA_TR     0x08   /* МБКП1: DVMA-адрес передачи массива */
#define VA_RCV2   0x08   /* МБКП1: DVMA-адрес приема массива по каналу 2 */ 

#define VA_RCV1   0x10   /* DVMA-адрес приема массива по каналу 1 */
#define CNT_RCV1  0x50   /* счетчик слов приема массива по каналу 1 */

#define CNT_TR    0x60   /* МБКП1: сч слов передачи массива по каналу 1 */
#define CNT_RCV2  0x60   /* МБКП1: сч слов передачи массива по каналу 2 */


#define WRCMD_RCV1    0x20  /* МБКП1: зп - запись дескиптора  в канал */
#define SW_TRBA_RCV2  0x20  /* МБКП2: чт - вык, зп - вкл обслуживание ТРБА2 */

#define SW_TRBA_RCV1  0x28  /* зп - вкл, чт - выкл обслуживание ТРБА */
#define RD_DESC_RCV1  0x38  /* чт - читать дескриптор по ТРБА1 */
#define RD_DESC_RCV2  0x68  /* чт - читать дескриптор по ТРБА2 */

#define SCHAN_SEL     0x48   /* чт - основной, зп - резервный канал */

#define RESET_TR1     0x58  /* зп - обнулить удаленный передатчик_1 */
#define RESET_TR2     0x70  /* зп - обнулить удаленный передатчик_2 */

#define RD_FIFO_1     0x78  /* Чтение FIFO приемника 1 		    */
#define RD_FIFO_2     0x88  /* Чтение FIFO приемника 2		    */

#define RESET_PEER_RCV 0x68  /* зп - обнулить удаленный приемник */
#define RESET_PEER_TR  0x78  /* зп - обнулить удаленный передатчик */

#ifdef	__cplusplus
}
#endif

#endif /* __LINUX_MBKP1_REG_H__ */
