#define ERRDMA_NULL_REQUEST		-1
#define ERRDMA_BAD_ABONENT		-2
#define ERRDMA_BAD_VDMA_TM		-3
#define ERRDMA_BAD_FADDR		-4
#define ERRDMA_BIG_FADDR		-5
#define ERRDMA_BAD_SIZE_FS		-6
#define ERRDMA_NULL_BUFFER		-7
#define ERRDMA_IN_INTERRUPT		-8
#define ERRDMA_BAD_STAT			-9 /* попытка выполнить операцию обмена, не дождавшись окончания предыдущей */
#define ERRDMA_SIGNAL			-10 /* поток завершен сигналом */
#define ERRDMA_BAD_SPIN			-11 /* попытка уснуть с открытым семафором */
#define ERRDMA_BAD_WAIT1		-12 /* ошибка читателя при попытке уснуть */
#define ERRDMA_TIMER			-13 /* тайм-аут при операции обмена */
#define ERRDMA_BAD_IRQ_COUNT		-14 /* пропуск прерывания при приеме */
#define ERRDMA_BAD_INT_AC1		-15 /* ошибка драйвера при приеме данных */
#define ERRDMA_BAD_SIZE			-16 /* неверный размер транзакции */
#define ERRDMA_RD_MAX_SMC		-17
#define ERRDMA_BAD_STAT_MSG		-18 /* попытка передать сообщение, не дождавшись передачи предыдущего */
#define ERRDMA_BAD_SEND_MSG		-19 /* ошибка при передаче сообщения */
#define ERRDMA_RD_BAD_WAIT2		-20 /* ошибка в функции пробуждения */
#define ERRDMA_RD_MAX_REPEATE		-21 /* длительность приема больше допустимой */
#define ERRDMA_RD_BAD_IRQ_COUNT1	-22 /* пропуск прерывания при приеме */
#define ERRDMA_RD_MAX_COUNT_RDR_RBC	-23 /* длительность приема больше допустимой */
#define ERRDMA_RD_LOSS_RDC_2		-24 /* длительность приема больше допустимой */
#define ERRDMA_RD_LOSS_RDC_4		-25 /* длительность приема больше допустимой */
#define ERRDMA_RD_BAD_INT_AC2		-26 /* ошибка драйвера при приеме данных */
#define ERRDMA_WR_DSF			-27 /* аппаратная ошибка при передаче */
#define ERRDMA_BAD_CHANNEL		-28 /* неверный номер канала */
#define ERRDMA_BAD_TIMER		-29 /* тайм-аут при операции обмена */
#define ERRDMA_WR_BAD_DMA		-30 /* не задан адрес буфера передачи */
#define ERRDMA_GP0_EXIT			-31 /* выход из ридера по приходу GP0 */
