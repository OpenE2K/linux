
#ifndef __LINUX_ME90_INT_H__
#define __LINUX_ME90_INT_H__

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *  The driver modes and state info
 */

extern	int	me90_sbus_clock_freq;
extern	int	me90_sbus_nsec_cycle;
extern	int	me90_mp_clock_freq;
extern	int	me90_mp_nsec_cycle;

/*
 *  The driver debug messages and trace supporting
 */

#define	ME90_DEBUG_MSG_LINE_SIZE	128
#define	ME90_DEBUG_MSG_LINE_NUM		500

#ifdef DEBUG_BUF_USE

extern char	me90_debug_msg_buf[ME90_DEBUG_MSG_LINE_SIZE *
                                   ME90_DEBUG_MSG_LINE_NUM
                                  ];
#else
extern char	*me90_debug_msg_buf;

#endif /* DEBUG_BUF_USE */

extern	int	me90_debug_buf_line;
extern	int	me90_debug_buf_overflow;

int   me90_startup_mp(
	me90drv_state_t	*me90,
	int		cmd,
	int		mode
);
int	me90_bmem_data_transfer(
	me90drv_state_t		*me90,
	bmem_trans_desk_t	*transfer_desk,
	int			write_op,
	int			mode,
	int			char_data,
	caddr_t			kmem_buf,
	caddr_t			*kmem_area_p
);
void	me90_log(
	me90drv_state_t 	*me90,
	int			level,
	const char 		*fmt,
	...
);
int	me90_reset_mp(
	me90drv_state_t	*me90,
	int		halt_mp,
	int		clean_bmem
);
void	me90_clean_base_memory(
	me90drv_state_t	*me90
);
int	me90_wait_async_trans(
	me90drv_state_t		*me90,
	int			channel,
	int			waiting_time,
	me90drv_trans_buf_t	**trans_buf_pp
);
void	me90_output_trans_state(
	me90drv_state_t		*me90,
	me90drv_trans_buf_t	*trans_buf
);
int	me90_retrieve_trans_mode(
	me90drv_state_t		*me90,
	int			drv_comm_area_locked,
	int			unconditional_restsrt,
	me90drv_rd_reg_t	gen_reg_state
);
#ifdef	_STREAMING_TRANSFER_USED_
int	me90_init_streaming(
	me90drv_state_t		*state,
	int			channel,
	streaming_spec_t	*streaming_specs
);
#endif /* _STREAMING_TRANSFER_USED_ */

#ifdef	__cplusplus
}
#endif

#endif /* __LINUX_ME90_INT_H__ */
