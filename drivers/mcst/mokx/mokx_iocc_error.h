#ifndef	__MOKX_IOCC_ERROR_H__
#define	__MOKX_IOCC_ERROR_H__

#define ERRDMA_NULL_REQUEST		-1
#define ERRDMA_BAD_ABONENT		-2
#define ERRDMA_BAD_VDMA_TM		-3
#define ERRDMA_BAD_FADDR		-4
#define ERRDMA_BIG_FADDR		-5
#define ERRDMA_BAD_SIZE_FS		-6
#define ERRDMA_NULL_BUFFER		-7
#define ERRDMA_IN_INTERRUPT		-8
#define ERRDMA_BAD_STAT			-9 /* ������� ��������� �������� ������, �� ���������� ��������� ���������� */
#define ERRDMA_SIGNAL			-10 /* ����� �������� �������� */
#define ERRDMA_BAD_SPIN			-11 /* ������� ������ � �������� ��������� */
#define ERRDMA_BAD_WAIT1		-12 /* ������ �������� ��� ������� ������ */
#define ERRDMA_TIMER			-13 /* ����-��� ��� �������� ������ */
#define ERRDMA_BAD_IRQ_COUNT		-14 /* ������� ���������� ��� ������ */
#define ERRDMA_BAD_INT_AC1		-15 /* ������ �������� ��� ������ ������ */
#define ERRDMA_BAD_SIZE			-16 /* �������� ������ ���������� */
#define ERRDMA_RD_MAX_SMC		-17
#define ERRDMA_BAD_STAT_MSG		-18 /* ������� �������� ���������, �� ���������� �������� ����������� */
#define ERRDMA_BAD_SEND_MSG		-19 /* ������ ��� �������� ��������� */
#define ERRDMA_RD_BAD_WAIT2		-20 /* ������ � ������� ����������� */
#define ERRDMA_RD_MAX_REPEATE		-21 /* ������������ ������ ������ ���������� */
#define ERRDMA_RD_BAD_IRQ_COUNT1	-22 /* ������� ���������� ��� ������ */
#define ERRDMA_RD_MAX_COUNT_RDR_RBC	-23 /* ������������ ������ ������ ���������� */
#define ERRDMA_RD_LOSS_RDC_2		-24 /* ������������ ������ ������ ���������� */
#define ERRDMA_RD_LOSS_RDC_4		-25 /* ������������ ������ ������ ���������� */
#define ERRDMA_RD_BAD_INT_AC2		-26 /* ������ �������� ��� ������ ������ */
#define ERRDMA_WR_DSF			-27 /* ���������� ������ ��� �������� */
#define ERRDMA_BAD_CHANNEL		-28 /* �������� ����� ������ */
#define ERRDMA_BAD_TIMER		-29 /* ����-��� ��� �������� ������ */
#define ERRDMA_WR_BAD_DMA		-30 /* �� ����� ����� ������ �������� */
#define ERRDMA_GP0_EXIT			-31 /* ����� �� ������ �� ������� GP0 */
#define ERRDMA_GP0_SEND			-32 /* ������ ��� ������� GP0 */
#define ERRDMA_GP1_SEND			-33 /* ������ ��� ������� GP1 */
#define ERRDMA_GP2_SEND			-34 /* ������ ��� ������� GP2 */
#define ERRDMA_GP3_SEND			-35 /* ������ ��� ������� GP3 */
#define ERRDMA_ID_SEND			-36 /* ������ ��� ������� ID request */
#define ERRDMA_SET_MASK			-37 /* ������ ��������� ����� ���������� */
#define ERRDMA_THREAD_RESET_START	-38 /* ������ �������� ������ reset */

#endif /* __MOKX_IOCC_ERROR_H__ */
