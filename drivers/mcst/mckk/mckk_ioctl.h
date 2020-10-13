
#define ME90_DEBUG_MSG_LINE_SIZE        128
#define ME90_DEBUG_MSG_LINE_NUM         500

/*
 * Get driver last tracer info
 */

/*ARGSUSED*/
static int   mckk_get_driver_trace_ioctl(
	mcb_state_t	*state,
	caddr_t		arg,
	int		mode)
{
	drv_trace_msg_t		drv_tracer_msg;
	int			moved_size = 0;
	int			added_size = 0;
	int			rval = 0;
	int			cur_line = 0;

	ME90_LOG(state, ME90_DL_TRACE,
    		"mckk_get_driver_trace_ioctl started\n");

	if (ddi_copyin(arg, (caddr_t) & drv_tracer_msg,
		sizeof (drv_trace_msg_t)/*, mode*/)) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_get_driver_trace_ioctl: ddi_copyin failed\n");
		return EFAULT;
	}
	cur_line = me90_debug_buf_line;
	if (me90_debug_buf_overflow && me90_debug_msg_buf != NULL) {
		moved_size = min(drv_tracer_msg.msg_buf_size,
				ME90_DEBUG_MSG_LINE_NUM *
				ME90_DEBUG_MSG_LINE_SIZE            -
				cur_line * ME90_DEBUG_MSG_LINE_SIZE);
		rval = ddi_copyout(&me90_debug_msg_buf[cur_line * 
						ME90_DEBUG_MSG_LINE_SIZE],
				drv_tracer_msg.msg_buf_addr, moved_size/*, mode*/);
		if (rval != 0) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mckk_get_driver_trace_ioctl: ddi_copyout"
				" failed \n");
			return EFAULT;
		}
	}
	if (cur_line > 0 && moved_size < drv_tracer_msg.msg_buf_size &&
		me90_debug_msg_buf != NULL) {
		added_size = min(drv_tracer_msg.msg_buf_size - moved_size,
				cur_line * ME90_DEBUG_MSG_LINE_SIZE);
		rval = ddi_copyout(me90_debug_msg_buf,
				&drv_tracer_msg.msg_buf_addr[moved_size],
				added_size/*, mode*/);
		if (rval != 0) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mckk_get_driver_trace_ioctl: ddi_copyout "
				"failed\n");
			return EFAULT;
		}
	}
	drv_tracer_msg.msg_line_num = (moved_size + added_size) /
						ME90_DEBUG_MSG_LINE_SIZE;
	drv_tracer_msg.msg_line_size = ME90_DEBUG_MSG_LINE_SIZE;
	if (ddi_copyout((caddr_t) & drv_tracer_msg, arg,
		sizeof (drv_trace_msg_t)/*, mode*/)) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_get_driver_trace_ioctl: ddi_copyout failed\n");
		return EFAULT;
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_get_driver_trace_ioctl succeeded\n");
	return 0;
}

/*
 *  Load MP-driver code to base memory of module
 */
/*ARGSUSED*/
static int   mckk_load_mp_drv_code_ioctl(
	mcb_state_t	*state,
	caddr_t		arg,
	int		mode)
{
	bmem_trans_desk_t	mp_driver_code;
	int			rval = 0;

	if (ddi_copyin(arg, (caddr_t)&mp_driver_code,
		sizeof (bmem_trans_desk_t)) /*,mode*/) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_load_mp_drv_code_ioctl ddi_copyin failed\n"
                     );
		return (EFAULT);
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_load_mp_drv_code_ioctl from 0x%08x to 0x%08x"
		" of BMEM size 0x%x bytes\n",
		mp_driver_code.mem_address,
		mp_driver_code.mp_bmem_address,
		mp_driver_code.byte_size);
	mutex_enter(&state->mutex);			/* start MUTEX */
	rval = me90_bmem_data_transfer(state,&mp_driver_code,1,mode,1,NULL,NULL);
	if (rval != 0) {
		mutex_exit(&state->mutex);		/* end MUTEX */
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_load_mp_drv_code_ioctl BMEM load failed\n");
		return rval;
	}
	state -> mp_drv_loaded = 1;
	mutex_exit(&state->mutex);			/* end MUTEX */
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_load_mp_drv_code_ioctl succeeded\n");
	return 0;
}

/*
 *  Startup MP (driver ur any other code)
 */

/*ARGSUSED*/
static int   mckk_startup_mp_ioctl(
	mcb_state_t	*state,
	int		cmd,
	caddr_t		arg,
	int		mode)
{
	int			rval = 0;

	if (arg != NULL) {
		mutex_enter(&state->mutex);		/* start MUTEX */
		if (ddi_copyin(arg, (caddr_t) &state -> mp_init_code,
			sizeof (bmem_trans_desk_t)/*, mode*/)) {
			mutex_exit(&state->mutex);	/* end MUTEX */
			ME90_LOG(state, ME90_DL_ERROR,
				"mckk_startup_mp_ioctl ddi_copyin failed for "
				"MP init code desk\n");
			return (EFAULT);
		}
		mutex_exit(&state->mutex);		/* end MUTEX */
		if (state -> mp_init_code.byte_size > MP_INIT_AREA_BMEM_SIZE) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mckk_startup_mp_ioctl too long MP init code "
				"%x > %x\n",
				state -> mp_init_code.byte_size,
				MP_INIT_AREA_BMEM_SIZE);
			return (EINVAL);
		}
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_startup_mp_ioctl MP init code load from 0x%08x "
			"to 0x%08x of BMEM size 0x%x bytes\n",
			state -> mp_init_code.mem_address,
			state -> mp_init_code.mp_bmem_address,
			state -> mp_init_code.byte_size);
	} else {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_startup_mp_ioctl started to load MP ROM"
			" driver\n");
	}
	rval = me90_startup_mp(state, cmd, mode);
	if (rval != 0) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_startup_mp_ioctl MP driver init failed\n");
	} else {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_startup_mp_ioctl MP driver init succeeded\n");
	}
	return (rval);
}

/*
 *  Reset MP of module
 */
/*ARGSUSED*/
static int   mckk_reset_mp_ioctl(
	mcb_state_t	*state,
	int		clean_bmem)
{
	int	rval = 0;

	ME90_LOG(state, ME90_DL_TRACE,"mckk_reset_mp_ioctl started\n");
	mutex_enter(&state->mutex);			/* start MUTEX */
	rval = me90_reset_mp(state, 1, clean_bmem);
	mutex_exit(&state->mutex);			/* end MUTEX */
	if (rval != 0) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_reset_mp_ioctl finished with errors\n");
	} else {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_reset_mp_ioctl succeeded\n");
	}
	return 0;
}

/*
 *  Reset MP of module
 */
/*ARGSUSED*/
static int   mckk_set_mp_state_ioctl(
	mcb_state_t	*state,
	int		mp_state)
{
	int	rval = 0;

	ME90_LOG(state, ME90_DL_TRACE,"mckk_set_mp_state_ioctl started\n");
	mutex_enter(&state->mutex);			/* start MUTEX */
	if (mp_state & CLEAN_BMEM_MP_STATE)
		me90_clean_base_memory(state);
	if (mp_state & HALTED_MP_STATE)
		rval = me90drv_reset_general_regs(state,1);
	else
		rval = me90drv_reset_general_regs(state,2);
	mutex_exit(&state->mutex);			/* end MUTEX */
	if (rval != 0) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_set_mp_state_ioctl finished with errors\n");
	} else {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_set_mp_state_ioctl succeeded\n");
	}
	return 0;
}

/*
 *  Get driver modes and state info
 */
/*ARGSUSED*/
static int   mckk_get_driver_info_ioctl(
	mcb_state_t	*state,
	caddr_t		arg,
	int		mode)
{
	int		rval = 0;
	mcb_drv_info_t	driver_info;
#ifdef	_MP_TIME_USE_
        drv_intercom_t		*drv_communication = NULL;
#endif /* _MP_TIME_USE_ */

	ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_get_driver_info_ioctl started\n");
#ifdef	_MP_TIME_USE_
        drv_communication =
           (drv_intercom_t *) &state -> MC_BMEM[TR_CNTR_BUF_BMEM_ADDR];
#endif /* _MP_TIME_USE_ */
	driver_info.sbus_clock_freq = me90_sbus_clock_freq;
	driver_info.sbus_nsec_cycle = me90_sbus_nsec_cycle;
	driver_info.mp_clock_freq = me90_mp_clock_freq;
	driver_info.mp_nsec_cycle = me90_mp_nsec_cycle;
	driver_info.device_type = state -> type_unit;
	driver_info.mp_rom_drv_enable = state -> mp_rom_drv_enable;
#ifdef	_MP_TIME_USE_
	READ_MP_TIME(driver_info.cur_hr_time);
#else
	driver_info.cur_hr_time = ddi_gethrtime();
#endif	/* _MP_TIME_USE_ */
	if (ddi_copyout((caddr_t) & driver_info, arg,
		sizeof (mcb_drv_info_t)/*, mode*/)) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_get_driver_info_ioctl: ddi_copyout failed\n");
		rval = EFAULT;
	}
	if (rval != 0) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_get_driver_info_ioctl: finished\n");
	} else {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_get_driver_info_ioctl succeeded\n");
	}
	return rval;
}

/*
 *  Set locking of reset module on error
 */
/*ARGSUSED*/
static int   mckk_lock_reset_module_on_error_ioctl(mcb_state_t	*state)
{
	int		rval = 0;
	mc_wr_reg_t	tlrm_write_value;

	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_lock_reset_module_on_error_ioctl started\n");
	tlrm_write_value.RGEN_write = 0;
	tlrm_write_value.TLRM_write = 1;
#ifndef WITHOUT_TWISTING
	b2l_convertor_off(state->dip);
#endif
	state->MC_CNTR_ST_REGS->MC_TLRM_write =
					tlrm_write_value.RGEN_write;
#ifndef WITHOUT_TWISTING
	b2l_convertor_on(state->dip);
#endif
	state -> set_tlrm = 1;
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_lock_reset_module_on_error_ioctl succeeded\n");
	return rval;
}

/*
 *  Reset locking of reset module on error
 */
/*ARGSUSED*/
static int   mckk_unlock_reset_module_on_error_ioctl(mcb_state_t	*state)
{
	int		rval = 0;
	mc_wr_reg_t    tlrm_write_value;

	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_unlock_reset_module_on_error_ioctl started\n");
	tlrm_write_value.RGEN_write = 0;
	tlrm_write_value.TLRM_write = 0;
#ifndef WITHOUT_TWISTING
	b2l_convertor_off(state->dip);
#endif
	state -> MC_CNTR_ST_REGS -> MC_TLRM_write =
					tlrm_write_value.RGEN_write;
#ifndef WITHOUT_TWISTING
	b2l_convertor_on(state->dip);
#endif
	state -> set_tlrm = 0;
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_unlock_reset_module_on_error_ioctl succeeded\n");
	return rval;
}

/*
 *  Write register of channel adapter 
 */
/*ARGSUSED*/
static int   mckk_write_adapter_reg_ioctl(
	mcb_state_t	*state,
	caddr_t		arg,
	int		mode)
{
	dev_reg_spec_t	device_reg_write_args;	
	mp_drv_args_t	device_reg_access_args;
	int		rval = 0;

	if (ddi_copyin(arg, (caddr_t) &device_reg_write_args,
		sizeof (dev_reg_spec_t)/*, mode*/)) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_write_adapter_reg_ioctl: ddi_copyin failed\n");
		return EFAULT;
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_write_adapter_reg_ioctl started\n");
	device_reg_access_args.dev_adapter_access.address =
		device_reg_write_args.address;
	device_reg_access_args.dev_adapter_access.reg_value =
		device_reg_write_args.reg_value;
	rval = me90drv_submit_mp_task(state,device_adapter_write_mp_task,
			&device_reg_access_args, 0, NULL, NULL, 0);
	if (rval != 0) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_write_adapter_reg_ioctl failed\n");
		return rval;
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_write_adapter_reg_ioctl finished\n");
	return 0;
}

/*
 *  Read register of channel adapter 
 */
/*ARGSUSED*/
static int   mckk_read_adapter_reg_ioctl(
	mcb_state_t	*state,
	caddr_t		arg,
	int		mode)
{
	dev_reg_spec_t		device_reg_read_args;	
	mp_drv_args_t		device_reg_access_args;
	sparc_drv_args_t	access_results;
	int			rval = 0;

	if (ddi_copyin(arg, (caddr_t) &device_reg_read_args,
		sizeof (dev_reg_spec_t)/*, mode*/)) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_read_adapter_reg_ioctl: ddi_copyin failed\n");
		return EFAULT;
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_read_adapter_reg_ioctl started\n");
	device_reg_access_args.dev_adapter_access.address =
		device_reg_read_args.address;
	device_reg_access_args.dev_adapter_access.reg_value = 0;
	device_reg_read_args.mp_error_code = 0;
	rval = me90drv_submit_mp_task(state,device_adapter_read_mp_task,
			&device_reg_access_args, 0, NULL, &access_results, 0);
	device_reg_read_args.reg_value =
		device_reg_access_args.dev_adapter_access.reg_value;
	if (rval != 0) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_read_adapter_reg_ioctl failed\n");
	} else if (access_results.reg_read_results.mp_error_code != 0) {
		rval = EINVAL;
		device_reg_read_args.mp_error_code =
			access_results.reg_read_results.mp_error_code;
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_read_adapter_reg_ioctl failed with error"
			" detected by MP driver %d\n",
			access_results.reg_read_results.mp_error_code);
	}
	if (ddi_copyout((caddr_t) &device_reg_read_args, arg,
		sizeof (dev_reg_spec_t)/*, mode*/)) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_read_adapter_reg_ioctl: ddi_copyout failed\n");
		return EFAULT;
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_read_adapter_reg_ioctl finished\n");
	return rval;
}

/*
 *  Set driver general modes 
 */
/*ARGSUSED*/
static int   mckk_set_drv_general_mode_ioctl(
	mcb_state_t	*state,
	int		drv_mode_to_set)
{
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_set_drv_general_mode_ioctl to 0x%x\n",
		drv_mode_to_set);
	mutex_enter(&state->mutex);			/* start MUTEX */
	state -> drv_general_modes |= drv_mode_to_set;
	mutex_exit(&state->mutex);			/* end MUTEX */
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_set_drv_general_mode_ioctl succeeded\n");
	return 0;
}

/*
 *  Reset driver general modes 
 */
/*ARGSUSED*/
static int   mckk_reset_drv_general_mode_ioctl(
	mcb_state_t	*state,
	int		drv_mode_to_reset)
{
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_reset_drv_general_mode_ioctl to 0x%x\n",
		drv_mode_to_reset);
	mutex_enter(&state->mutex);			/* start MUTEX */
	state -> drv_general_modes &= ~drv_mode_to_reset;
	mutex_exit(&state->mutex);			/* end MUTEX */
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_reset_drv_general_mode_ioctl succeeded\n");
	return 0;
}

/*
 *  Get driver general modes 
 */
/*ARGSUSED*/
static int   mckk_get_drv_general_mode_ioctl(
	mcb_state_t	*state,
	caddr_t		arg,
	int		mode)
{
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_get_drv_general_mode_ioctl started\n");
	if (ddi_copyout((caddr_t) & state -> drv_general_modes, arg,
		sizeof (state -> drv_general_modes)/*, mode*/)) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_get_drv_general_mode_ioctl: ddi_copyout "
			"failed\n");
		return EFAULT;
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_ioctl get current driver general mode flags"
		" succeeded\n");
	return 0;
}

/*
 *  Put driver general modes 
 */
/*ARGSUSED*/
static int   mckk_put_drv_general_mode_ioctl(
	mcb_state_t	*state,
	int		drv_modes_to_put)
{

	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_put_drv_general_mode_ioctl to 0x%x\n",
		drv_modes_to_put);
	mutex_enter(&state->mutex);			/* start MUTEX */
	state -> drv_general_modes = drv_modes_to_put;
	mutex_exit(&state->mutex);			/* end MUTEX */
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_put_drv_general_mode_ioctl succeeded\n");
	return 0;
}

/*
 *  Wait for asynchronous transfer finish 
 */
/*ARGSUSED*/
static int mckk_wait_for_async_trans_ioctl(
	mcb_state_t	*state,
	int		channel,
	caddr_t		arg,
	int		mode)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	me90drv_aiotrans_wait_t	waiting_request;
	caddr_t			*user_trans_res_info_pp = NULL;
	me90drv_trans_buf_t	*trans_buf_p = NULL;
	me90drv_trans_spec_t	*transfer_spec = NULL;
	caddr_t			user_results_p = NULL;
	int			rval = 0;

	channel_state = &state -> all_channels_state[channel];
	if (ddi_copyin(arg, (caddr_t) &waiting_request,
			sizeof (me90drv_aiotrans_wait_t)/*, mode*/)) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_wait_for_async_trans_ioctl: ddi_copyin "
			"failed in the channel %d\n", channel);
		return EFAULT;
	}
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_wait_for_async_trans_ioctl in the "
		"channel %d with waiting time %d usec\n", channel,
		waiting_request.waiting_time);
	user_trans_res_info_pp = waiting_request.trans_res_info_pp;
	if (user_trans_res_info_pp == NULL) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_wait_for_async_trans_ioctl: NULL pointer of I/O "
			"request results info in the channel %d\n", channel);
		return EINVAL;
	}
	rval = me90_wait_async_trans(state, channel,
		waiting_request.waiting_time, &trans_buf_p);
	if (rval == 0) {
#if	defined(__BLOCK_BUFFER_USE__)
		if (trans_buf_p -> trans_buf_desc.drv_buf_used)
			transfer_spec = (me90drv_trans_spec_t *)
				trans_buf_p -> drv_buf_p ->
						transfer_spec;
		else
		/*	transfer_spec = trans_buf_p ->
						trans_buf_desc.bp -> b_private;*/
			transfer_spec = trans_buf_p ->
						trans_buf_desc.uio_p -> transfer_spec;
#else	/* ! __BLOCK_BUFFER_USE__ */
		transfer_spec = trans_buf_p -> transfer_spec;
#endif	/* __BLOCK_BUFFER_USE__ */
		user_results_p = transfer_spec -> user_results_p;
			rval = me90drv_set_trans_results(state,
				transfer_spec -> trans_res_info,
				NULL,
				(me90drv_trans_info_t *) user_results_p,
				mode);
	}
	if (ddi_copyout((caddr_t) &user_results_p,
		(caddr_t) user_trans_res_info_pp,
		sizeof (caddr_t)/*, mode*/)) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_wait_for_async_trans_ioctl: ddi_copyout failed "
			"for waiting in the channel %d\n", channel);
		rval = EFAULT;
	}
	if (trans_buf_p != NULL)
		me90drv_release_async_trans(state, channel, trans_buf_p);
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_wait_for_async_trans_ioctl in the"
		" channel %d completed with res %d\n", channel, rval);
	return rval;
}

/*
 *  Wait for transfer in progress 
 */
/*ARGSUSED*/
static int
mckk_wait_for_trans_in_progress_ioctl(
	mcb_state_t	*state,
	int		channel,
	caddr_t		arg,
	int		mode)
{
	me90drv_chnl_state_t	*channel_state = NULL;
	clock_t			timeout_usec = (clock_t) arg;
	clock_t			cur_clock_ticks = 0;
	clock_t			timeout_clock_ticks = 0;
	int			rval = 0;

	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_wait_for_trans_in_progress_ioctl wait for transfer in "
		"progress for channel %d and time %d usec\n",
		channel, timeout_usec);
	channel_state = &state -> all_channels_state[channel];
	drv_getparm(LBOLT,(u_long *) &cur_clock_ticks);
	timeout_clock_ticks =
		cur_clock_ticks + drv_usectohz(timeout_usec);
	mutex_enter(&state->mutex);			/* start MUTEX */
	while (1) {
		rval = 0;
		if (channel_state -> in_progress) {
				break;
		}
		rval = cv_timedwait(&state -> trans_start_cv, &state->mutex,
				timeout_clock_ticks);
		if (rval < 0) {
			rval = ETIME;
			break;
		}
	}
	mutex_exit(&state->mutex);			/* end MUTEX */
	if (rval != 0) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_ioctl wait for transfer in progress timeouted "
			"for channel %d error %d\n", channel, rval);
	} else {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_ioctl wait for transfer in progress successed "
			"for channel %d\n", channel);
	}
	return rval;
}

/*
 *  Output last transfer state and results info 
 */
/*ARGSUSED*/
static int
mckk_output_last_trans_state_ioctl(
	mcb_state_t	*state,
	int		channel)
{
	me90drv_chnl_state_t	*channel_state = NULL;

	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_output_last_trans_state_ioctl started\n");
	channel_state = &state -> all_channels_state[channel];
	if (channel_state -> last_term_trans_buf != NULL)
		me90_output_trans_state(state,
			channel_state -> last_term_trans_buf);
	else
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_output_last_trans_state_ioctl: empty last "
			"transfer buf pointer\n");
	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_output_last_trans_state_ioctl finished\n");
	return 0;
}

/*
 *  Wait for transfer in progress 
 */
/*ARGSUSED*/
static int
mckk_restart_board_ioctl(mcb_state_t	*state)
{
	int			rval = 0;
	me90drv_rd_reg_t	gen_reg_state;

	ME90_LOG(state, ME90_DL_TRACE, "mckk_restart_board_ioctl started\n");
	gen_reg_state.ME90DRV_RGEN_read = 0;
	rval = me90_retrieve_trans_mode(state, 0, 1, gen_reg_state);
	if (rval != 0) {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_restart_board_ioctl cannot restart the board\n");
	} else {
		ME90_LOG(state, ME90_DL_TRACE,
			"mckk_restart_board_ioctl succeeded\n");
	}
	return rval;
}

/*
 * Driver ioctl entry point
 */
/*ARGSUSED*/

static int
mckk_ioctl ( struct inode *inode, struct file *file,
                 unsigned int cmd, unsigned long arg)
{
     mcb_state_t		*state;
     dev_t			dev;
     int			instance = 0;
     int			channel;		
     int           		mode = 0;
     int           		rval = 0;
#ifdef	_MP_TIME_USE_
     drv_intercom_t *   drv_communication = NULL;
     u_int          *   cur_mp_time = NULL;
#endif	/* _MP_TIME_USE_ */

     ME90_LOG(NULL, ME90_DL_TRACE,"mckk_ioctl started for instance %d with cmd 0x%x\n", instance, cmd);
     dev = MKDEV(mckk_major, iminor(inode));
     instance = MCB_INST(dev);
     channel = MCB_CHAN(dev);
     state = mckk_states[instance];
     if (state == NULL) {
     	printk("~%s~_ioctl: unattached instance %d\n", mod_name, instance);
       	return (ENXIO);
     };
#ifdef	_MP_TIME_USE_
     drv_communication =
        (drv_intercom_t *) &state -> MC_BMEM[TR_CNTR_BUF_BMEM_ADDR];
     cur_mp_time = &drv_communication -> processing_time.mp_timer;
#endif	/* _MP_TIME_USE_ */
	switch (cmd) {
		case MCBIO_LOAD_MP_DRV_CODE :
			return mckk_load_mp_drv_code_ioctl(state,
						(caddr_t)arg, mode);
		case MCBIO_STARTUP_MP_DRV  :
		case MCBIO_STARTUP_MP_ROM_DRV  :
		case MCBIO_STARTUP_MP_CODE :
			return mckk_startup_mp_ioctl(state, cmd, (caddr_t)arg,
					mode);
		case MCBIO_RESET_MP :
			return mckk_reset_mp_ioctl(state, arg);
		case MCBIO_SET_MP_STATE :
			return mckk_set_mp_state_ioctl(state, arg);
		case MCBIO_GET_DRIVER_INFO :
			return mckk_get_driver_info_ioctl(state, (caddr_t)arg,
					mode);
		case MCBIO_LOCK_RESET_MODULE_ON_ERROR :
			return mckk_lock_reset_module_on_error_ioctl(state);
		case MCBIO_UNLOCK_RESET_MODULE_ON_ERROR :
			return mckk_unlock_reset_module_on_error_ioctl(state);

		case MCBIO_GET_DRIVER_TRACE_MSG :
			return mckk_get_driver_trace_ioctl(state, (caddr_t)arg,
					mode);
		case MCBIO_WRITE_DEV_ADAPTER_REG :
			return mckk_write_adapter_reg_ioctl(state, (caddr_t)arg,
					mode);
		case MCBIO_READ_DEV_ADAPTER_REG :
			return mckk_read_adapter_reg_ioctl(state, (caddr_t)arg,
					mode);
		case MCBIO_SET_DRV_GENERAL_MODE :
			return mckk_set_drv_general_mode_ioctl(state, arg);
		case MCBIO_RESET_DRV_GENERAL_MODE :
			return mckk_reset_drv_general_mode_ioctl(state, arg);
		case MCBIO_GET_DRV_GENERAL_MODES :
			return mckk_get_drv_general_mode_ioctl(state,
					(caddr_t)arg, mode);
		case MCBIO_PUT_DRV_GENERAL_MODES :
			return mckk_put_drv_general_mode_ioctl(state, arg);
        case MCBIO_SPECIFIED_TRANSFER :
        {
	   trans_spec_t         user_transfer_spec;
	   trans_spec_t         transfer_spec;
	   trans_spec_t         *transfer_spec_p;
           trans_info_t		*user_trans_res_info = NULL;
           trans_info_t         drv_trans_res_info;
           trans_info_t         *drv_trans_res_info_p;
	   int			delete_kmem_bufs = 0;
	   int			set_rval = 0;
	   iovec_t 		iov;
	   uio_t 		uio;
	   iovec_t 		*iov_p = NULL;
	   uio_t 		*uio_p = NULL;
#ifdef	DEBUG
           char *               io_mode = NULL;
           char *               dev_access_mode = NULL;
#endif	/* DEBUG */
#ifdef	_MP_TIME_USE_
		u_int		req_receive_time = 0;
#else
		hrtime_t	req_receive_time = ddi_gethrtime();
#endif	/* _MP_TIME_USE_ */

#ifdef	_MP_TIME_USE_
		READ_MP_TIME(req_receive_time);
#endif	/* _MP_TIME_USE_ */

           if (ddi_copyin((caddr_t)arg, (caddr_t) & user_transfer_spec,
                          sizeof (trans_spec_t)/*,
                          mode*/
                         )
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl ddi_copyin failed for transfer specification\n"
                     );
              return (EFAULT);
           }
#ifdef	DEBUG
           if (user_transfer_spec.io_mode_flags & DMA_TRANSFER_IO_MODE)
              io_mode = "DMA";
	   else if (user_transfer_spec.io_mode_flags & PROG_TRANSFER_IO_MODE)
              io_mode = "PROG";
           else if (user_transfer_spec.io_mode_flags & PROG1_TRANSFER_IO_MODE)
              io_mode = "PROG1";
           else if (user_transfer_spec.io_mode_flags & BMEM_TRANSFER_IO_MODE)
              io_mode = "BMEM";
           else
              io_mode = "???";
           if (user_transfer_spec.dev_access_mode == DIRECT_DEV_ACCESS_MODE)
              dev_access_mode = "DIRECT";
           else if (user_transfer_spec.dev_access_mode ==
		    WITH_DEMAND_DEV_ACCESS_MODE)
              dev_access_mode = "with DRQ";
           else if (user_transfer_spec.dev_access_mode ==
		    ON_DEMAND_DEV_ACCESS_MODE)
              dev_access_mode = "on DRQ";
           else
              dev_access_mode = "???";

           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl specified transfer addr 0x%lx len 0x%lx %s %s"
                   " %s burst size 0x%02x"
                   " repeat %d\n",
                   user_transfer_spec.buf_base,
                   user_transfer_spec.buf_byte_size,
                   (user_transfer_spec.read_write_flag == B_READ) ? "READ" :
								    "WRITE",
                   io_mode,
                   dev_access_mode,
                   user_transfer_spec.burst_sizes,
                   user_transfer_spec.repeation_num
                  );
#endif	/* DEBUG */
           if ((user_transfer_spec.read_write_flag & B_READ) == 0  &&
               (user_transfer_spec.read_write_flag & B_WRITE) == 0
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl invalid read/write flag %d\n",
                      user_transfer_spec.read_write_flag
                     );
              return EINVAL;
           }
           if (!(user_transfer_spec.io_mode_flags & DMA_TRANSFER_IO_MODE)    &&
               !(user_transfer_spec.io_mode_flags & PROG_TRANSFER_IO_MODE)   &&
               !(user_transfer_spec.io_mode_flags & PROG1_TRANSFER_IO_MODE)  &&
               !(user_transfer_spec.io_mode_flags & BMEM_TRANSFER_IO_MODE)
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl invalid I/O transfer mode %d\n",
                      user_transfer_spec.io_mode_flags
                     );
              return EINVAL;
           }
           if (user_transfer_spec.dev_access_mode != DIRECT_DEV_ACCESS_MODE
		&&
               user_transfer_spec.dev_access_mode != WITH_DEMAND_DEV_ACCESS_MODE
		&&
               user_transfer_spec.dev_access_mode != ON_DEMAND_DEV_ACCESS_MODE
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl invalid I/O device access mode %d\n",
                      user_transfer_spec.dev_access_mode
                     );
              return EINVAL;
           }
	   if (user_transfer_spec.burst_sizes == 0)
		user_transfer_spec.burst_sizes = MCB_ENABLE_BURST_SIZES;
           if ((user_transfer_spec.burst_sizes & MCB_ENABLE_BURST_SIZES) == 0)
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl empty mask of allowed 0x%02x"
                      " & enable 0x%02x burst sizes\n",
                      user_transfer_spec.burst_sizes,
                      MCB_ENABLE_BURST_SIZES
                     );
              return EINVAL;
           }
           user_trans_res_info = user_transfer_spec.trans_res_info;
	   if (user_transfer_spec.async_trans) {
		if (user_trans_res_info == NULL) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mckk_ioctl cannot do asynchronous "
				"transfer with NULL transfer results "
				"info pointer\n");
			return EINVAL;
		}
/* Memory allocation */
		transfer_spec_p = kmem_alloc(sizeof(trans_spec_t),
					KM_NOSLEEP);
		if (transfer_spec_p == NULL) {
			ME90_LOG(state, ME90_DL_ERROR,
				"mckk_ioctl cannot allocate kernel memory for"
				" simple transfer specifications area\n");
			return EINVAL;
		}
		drv_trans_res_info_p = kmem_alloc(sizeof(trans_info_t),
					KM_NOSLEEP);
		if (drv_trans_res_info_p == NULL) {
			kmem_free(transfer_spec_p, sizeof(trans_spec_t));
			ME90_LOG(state, ME90_DL_ERROR,
				"mckk_ioctl cannot allocate kernel memory for"
				" simple transfer results area\n");
			return EINVAL;
		}
		iov_p = kmem_alloc(sizeof(iovec_t), KM_NOSLEEP);
		if (iov_p == NULL) {
			kmem_free(transfer_spec_p, sizeof(trans_spec_t));
			kmem_free(drv_trans_res_info_p, sizeof(trans_info_t));
			ME90_LOG(state, ME90_DL_ERROR,
				"mckk_ioctl cannot allocate kernel memory for"
				" iov structure area\n");
			return EINVAL;
		}
		uio_p = kmem_alloc(sizeof(uio_t), KM_NOSLEEP);
		if (uio_p == NULL) {
			kmem_free(transfer_spec_p, sizeof(trans_spec_t));
			kmem_free(drv_trans_res_info_p, sizeof(trans_info_t));
			kmem_free(iov_p, sizeof(iovec_t));
			ME90_LOG(state, ME90_DL_ERROR,
				"mckk_ioctl cannot allocate kernel memory for"
				" uio structure area\n");
			return EINVAL;
		}

	   } else {
		transfer_spec_p = &transfer_spec;
		drv_trans_res_info_p = &drv_trans_res_info;
		iov_p = &iov;
		uio_p = &uio;
	   }
/*
* 	Checking if buffer block in user or in kernel space... If user block then 
*	allocation kernel block for coping the first to the one. Later may 
*	be used ddi mapping user memory block to the kernel
*	address space via pgd, pmd, pte (pgd, pmhd, pmld, pte in e2k terms)
*/
/*	   if ((unsigned long)user_transfer_spec.buf_base < TASK_SIZE) {
//		transfer_spec_p -> buf_base = kmalloc(sizeof(user_transfer_spec.buf_byte_size), GFP_KERNEL);
		transfer_spec_p -> buf_base = kmalloc(user_transfer_spec.buf_byte_size, GFP_KERNEL);
		if (transfer_spec_p -> buf_base <= 0) { 
		  printk ("mckk_ioctl: Error allocated memory. 
				User memory block cannot be mapping to kernel... Failed\n");
		  return EFAULT;
		}
		if (ddi_copyin(user_transfer_spec.buf_base, transfer_spec_p -> buf_base,
				user_transfer_spec.buf_byte_size )) {
		  kfree(transfer_spec_p -> buf_base);
		  printk ("mckk_ioctl: Error copy_from_user\n");
		  return EFAULT;
		}
	   } else {
	       transfer_spec_p -> buf_base 			= 	user_transfer_spec.buf_base;
	   }
*/
	   transfer_spec_p -> buf_base 			= 	user_transfer_spec.buf_base;
	   transfer_spec_p -> buf_byte_size 		= 	user_transfer_spec.buf_byte_size;
	   transfer_spec_p -> read_write_flag 		=	user_transfer_spec.read_write_flag;
	   transfer_spec_p -> async_trans 		= 	user_transfer_spec.async_trans;
	   transfer_spec_p -> io_mode_flags 		= 	user_transfer_spec.io_mode_flags;
	   transfer_spec_p -> dev_access_mode 		=	user_transfer_spec.dev_access_mode;
	   transfer_spec_p -> burst_sizes 		= 	user_transfer_spec.burst_sizes;
	   transfer_spec_p -> repeation_num 		=	user_transfer_spec.repeation_num;
	   transfer_spec_p -> timer_interval 		=	user_transfer_spec.timer_interval;
	   transfer_spec_p -> data_waiting_time 	=	user_transfer_spec.data_waiting_time;
	   transfer_spec_p -> timing_interval_t0 	=	user_transfer_spec.timing_interval_t0;
           transfer_spec_p -> user_results_p 		= 	(caddr_t) user_trans_res_info;
           transfer_spec_p -> trans_res_info 		= 	drv_trans_res_info_p;
	   drv_trans_res_info_p -> req_receive_time 	= 	req_receive_time;
	   iov_p -> iov_base 				= 	user_transfer_spec.buf_base;
	   iov_p -> iov_len 				= 	user_transfer_spec.buf_byte_size;
	   memset((caddr_t) uio_p, 0, sizeof (uio_t));
	   uio_p -> uio_iov 				= 	iov_p;
	   uio_p -> uio_iovcnt 				=	1;
           if ((unsigned long)user_transfer_spec.buf_base < TASK_SIZE)
	      uio_p -> uio_segflg 			= 	UIO_USERSPACE;
	   else
	      uio_p -> uio_segflg 			=	UIO_SYSSPACE;
	   uio_p -> uio_resid 				= 	iov_p -> iov_len;
/* mckk_rdwr for testing only */
	   rval = mcb_rdwr(dev, uio_p,
                           user_transfer_spec.read_write_flag,
                           transfer_spec_p);
           if (rval != 0)
		if (user_transfer_spec.async_trans)
			delete_kmem_bufs = 1;
           if (user_trans_res_info != NULL)
           {
		set_rval = mcb_set_trans_results(state, drv_trans_res_info_p,
				NULL, user_trans_res_info, mode);
		if (set_rval != 0)
			rval = set_rval;
           }
           if (rval != 0)
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl transfer finished with error %d for channel"
                      " %d\n",
                      rval,channel
                     );
	   if (delete_kmem_bufs) {
		kmem_free(transfer_spec_p, sizeof(trans_spec_t));
		kmem_free(drv_trans_res_info_p,	sizeof(trans_info_t));
		kmem_free(iov_p, sizeof(iovec_t));
		kmem_free(uio_p, sizeof(uio_t));
	   }

/*	   if ((unsigned long)user_transfer_spec.buf_base < TASK_SIZE && !delete_kmem_bufs) {
		if (ddi_copyout(transfer_spec_p -> buf_base, user_transfer_spec.buf_base,
				user_transfer_spec.buf_byte_size )) {
		  printk ("mckk_ioctl: Error copy_to_user\n");
		}
	   }*/
           return rval;
	}
	case MCBIO_WAIT_FOR_ASYNC_TRANS_END :
		return mckk_wait_for_async_trans_ioctl(state, channel,
				(caddr_t)arg, mode);
        case MCBIO_DRQ_WAITING_TRANSFER_NUM :
        {
           int cur_transfer_num = 0;
           me90drv_chnl_state_t *channel_state = NULL;

           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl get transfer num waiting for DRQ channel %d\n",
                   channel
                  );
           channel_state = &state -> all_channels_state[channel];
	   mutex_enter(&state->mutex);			/* start MUTEX */
           cur_transfer_num = channel_state -> drq_queue_size;
           if (ddi_copyout((caddr_t) & cur_transfer_num,
                           (caddr_t) arg,
                           sizeof (int) /*,
                           mode */
                          )
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl ddi_copyout failed for get waiting DRQ num\n"
                     );
              rval = EFAULT;
           }
	   mutex_exit(&state->mutex);			/* end MUTEX */
           if (rval != 0)
           {
              ME90_LOG(state, ME90_DL_TRACE,
                      "mckk_ioctl get transfer num waiting for DRQ finished "
                      "with errors\n"
                     );
           }
           else
           {
              ME90_LOG(state, ME90_DL_TRACE,
                      "mckk_ioctl get transfer num waiting for DRQ successed\n"
                     );
           }
           return rval;
        }
        case MCBIO_SET_MP_TIMER_INTR :
        {
           mp_tm_intr_set_t  mp_timer_intr_set;
           mp_intr_spec_t *  mp_timer_intr_spec = NULL;
           mp_drv_args_t     mp_timer_set_args;
           int               rval = 0;

           if (ddi_copyin((caddr_t) arg,
                          (caddr_t) & mp_timer_intr_set,
                          sizeof (mp_tm_intr_set_t) /*,
                          mode*/
                         )
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl: ddi_copyin failed for set MP timer intr\n"
                     );
              return EFAULT;
           }
           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl set MP timer interrupt mode with interval %d"
                   " max queue size %d\n",
                   mp_timer_intr_set.interval,
                   mp_timer_intr_set.max_queue_size
                  );
           if (mp_timer_intr_set.interval <= 0)
              mp_timer_intr_set.interval = 1000;        /* 1 mlsec */
	   mutex_enter(&state->mutex);			/* start MUTEX */
           mp_timer_intr_spec = &state -> mp_timer_intrs;
           if (mp_timer_intr_spec -> mp_intr_mode_on == 1)
           {
	      mutex_exit(&state->mutex);			/* end MUTEX */
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl: MP timer intr is seted already\n"
                     );
              return EBUSY;
           }
           mp_timer_intr_spec -> interval = mp_timer_intr_set.interval;
           mp_timer_intr_spec -> max_queue_size =
              mp_timer_intr_set.max_queue_size;
           mp_timer_intr_spec -> losed_intr_num = 0;
           mp_timer_intr_spec -> total_intr_num = 0;
           mp_timer_intr_spec -> total_request_num = 0;
           mp_timer_set_args.mp_timer_set.timer_interval =
              mp_timer_intr_set.interval / me90_mp_nsec_cycle * 1000;
           rval = submit_mp_task(state,mp_timer_intr_set_mp_task,
                                 &mp_timer_set_args,
                                 1,
                                 NULL,
                                 NULL,
                                 0
                                );
           if (rval == 0)
              mp_timer_intr_spec -> mp_intr_mode_on = 1;
	   mutex_exit(&state->mutex);			/* end MUTEX */
           if (rval != 0)
           {
              ME90_LOG(state, ME90_DL_TRACE,
                      "mckk_ioctl: MP timer intr set failed\n"
                     );
           }
           else
           {
              ME90_LOG(state, ME90_DL_TRACE,
                      "mckk_ioctl: MP timer intr set successed\n"
                     );
           }
           return rval;
        }
        case MCBIO_RESET_MP_TIMER_INTR :
        {
           mp_tm_intr_reset_t  mp_timer_intr_reset;
           mp_intr_spec_t *    mp_timer_intr_spec = NULL;
           mp_drv_args_t       mp_timer_reset_args;
           int                 rval = 0;

           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl reset MP timer interrupt mode\n"
                  );
	   mutex_enter(&state->mutex);			/* start MUTEX */
           mp_timer_intr_spec = &state -> mp_timer_intrs;
           if (mp_timer_intr_spec -> mp_intr_mode_on != 1)
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl: MP timer intr is reseted already\n"
                     );
           }
           mp_timer_intr_reset.total_intr_num =
              mp_timer_intr_spec -> total_intr_num;
           mp_timer_intr_reset.unclaimed_intr_num =
              mp_timer_intr_spec -> cur_queue_size;
           mp_timer_intr_reset.losed_intr_num =
              mp_timer_intr_spec -> losed_intr_num;
           mp_timer_reset_args.mp_timer_set.timer_interval = 0;
           rval = submit_mp_task(state,mp_timer_intr_set_mp_task,
                                 &mp_timer_reset_args,
                                 1,
                                 NULL,
                                 NULL,
                                 0
                                );
           remove_mp_timer_intr(state);
           mp_timer_intr_spec -> mp_intr_mode_on = -1;
	   mutex_exit(&state->mutex);			/* end MUTEX */
           if (ddi_copyout((caddr_t) & mp_timer_intr_reset,
                           (caddr_t) arg,
                           sizeof (mp_tm_intr_reset_t)/*,
                           mode*/
                          )
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl: ddi_copyout failed for reset MP timer intr\n"
                     );
              rval = EFAULT;
           }
           if (rval != 0)
           {
              ME90_LOG(state, ME90_DL_TRACE,
                      "mckk_ioctl: MP timer intr reset finished\n"
                     );
           }
           else
           {
              ME90_LOG(state, ME90_DL_TRACE,
                      "mckk_ioctl: MP timer intr reset successed\n"
                     );
           }
           return rval;
        }
        case MCBIO_WAIT_MP_TIMER_INTR :
        {
           mp_tm_intr_info_t   mp_timer_intr_info;
           int                 rval = 0;

#ifdef	_MP_TIME_USE_
           READ_MP_TIME(mp_timer_intr_info.drv_request_start_time);
#else
           mp_timer_intr_info.drv_request_start_time = ddi_gethrtime();
#endif	/* _MP_TIME_USE_ */
           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl wait for MP timer interrupt mode\n"
                  );
           handle_mp_timer_intr_request(state,&mp_timer_intr_info);
#ifdef	_MP_TIME_USE_
           READ_MP_TIME(mp_timer_intr_info.drv_request_end_time);
#else
           mp_timer_intr_info.drv_request_end_time = ddi_gethrtime();
#endif	/* _MP_TIME_USE_ */
           if (ddi_copyout((caddr_t) & mp_timer_intr_info,
                           (caddr_t) arg,
                           sizeof (mp_tm_intr_info_t)/*,
                           mode*/
                          )
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl: ddi_copyout failed for wait for MP timer"
	              " intr\n"
                     );
              rval = EFAULT;
           }
           if (rval != 0)
           {
              ME90_LOG(state, ME90_DL_TRACE,
                      "mckk_ioctl: waiting for MP timer intr finished\n"
                     );
           }
           else
           {
              ME90_LOG(state, ME90_DL_TRACE,
                      "mckk_ioctl: waiting for MP timer intr successed\n"
                     );
           }
           return rval;
        }

		case MCBIO_WAIT_FOR_TRANSFER_IN_PROGRESS :
			return mckk_wait_for_trans_in_progress_ioctl(state,
					channel, (caddr_t)arg, mode);

        case MCBIO_RESET_SBUS_LOGER :
        {
           mc_wr_reg_t    reset_write_value;
           int            clean_bmem = arg;
           int            rval = 0;

           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl reset SBus loger and log memory\n"
                  );
           reset_write_value.RGEN_write = 0;
#ifndef WITHOUT_TWISTING
	   b2l_convertor_off(state->dip);
#endif
           state -> MC_CNTR_ST_REGS -> MC_TGRM_write =
              reset_write_value.RGEN_write;
#ifndef WITHOUT_TWISTING
	   b2l_convertor_on(state->dip);
#endif
           if (clean_bmem)
              me90_clean_base_memory(state);
           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl: reset SBus loger and log memory successed\n"
                  );
           return rval;
        }

		case MCBIO_OUT_LAST_TRANS_STATE :
			return mckk_output_last_trans_state_ioctl(state,
					channel);
		case MCBIO_RESTART_BOARD :
			return mckk_restart_board_ioctl(state);

        case MCBIO_SET_CONNECTION_POLLING :
        {
           cnct_poll_set_t	polling_setup_spec;
           int			rval = 0;

           if (ddi_copyin((caddr_t) arg,
                          (caddr_t) & polling_setup_spec,
                          sizeof (cnct_poll_set_t)/*,
                          mode*/
                         )
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl: ddi_copyin failed for set connection"
                      " polling\n"
                     );
              return EFAULT;
           }
           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl set connection polling with interval %d"
                   " and %s in the time %d msec\n",
                   polling_setup_spec.interval,
                   (polling_setup_spec.cpu_polling) ? "with CPU polling"
                                                    : "without CPU polling",
                   polling_setup_spec.setup_timeout
                  );
           rval = mcb_set_connection_polling(state, &polling_setup_spec);
           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl: set connection polling finished\n"
                  );
           return rval;
        }
        case MCBIO_RESET_CONNECTION_POLLING :
        {
           int			rval = 0;

           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl reset connection polling\n"
                  );
           rval = mcb_reset_connection_polling(state, 0);
           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl: reset connection polling finished\n"
                  );
           return rval;
        }
        case MCBIO_POLL_CONNECTION_STATE :
        {
           poll_cnct_state_t	state_spec;
           int			rval = 0;
	   poll_time_info_t	drv_time_info;
	   poll_time_info_t	*usr_time_info = NULL;

           if (ddi_copyin((caddr_t) arg,
                          (caddr_t) & state_spec,
                          sizeof (poll_cnct_state_t) /*,
                          mode*/
                         )
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl: ddi_copyin failed for poll connection state\n"
                     );
              return EFAULT;
           }
           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl poll connection state with mask 0x%x and"
                   " timeout %d msec\n",
                   state_spec.state_mask,
                   state_spec.timeout
                  );
           usr_time_info = state_spec.time_info;
           if (usr_time_info != NULL)
              state_spec.time_info = &drv_time_info;
           rval = mcb_poll_connection_state(state, &state_spec);
           if (usr_time_info != NULL)
              state_spec.time_info = usr_time_info;
           if (state_spec.connection_events_num != 0 &&
               state_spec.connection_events != NULL
              )
           {
              mutex_enter(&state->mutex);			/* start MUTEX */
              if (state -> max_cnct_events_num == 0  ||
                  state -> connection_events == NULL
                 )
              {
                 state_spec.connection_events_num = 0;
                 state_spec.losed_events_num = state -> losed_events_num;
              }
              else
              {
                 state_spec.connection_events_num =
                    state -> cur_cnct_events_num;
                 state_spec.losed_events_num = state -> losed_events_num;
                 if (ddi_copyout((caddr_t) state -> connection_events,
                                 (caddr_t) state_spec.connection_events,
                                 state -> cur_cnct_events_num *
                                 sizeof (poll_event_info_t) /*,
                                 mode*/
                                )
                    )
                 {
                    ME90_LOG(state, ME90_DL_ERROR,
                            "mckk_ioctl: events info ddi_copyout failed for "
                            "poll connection state\n"
                           );
                    rval = EFAULT;
                 }
              }
              state -> cur_cnct_events_num = 0;
              state -> losed_events_num = 0;
              mutex_exit(&state->mutex);		/* end MUTEX */
           }
           if (ddi_copyout((caddr_t) & state_spec,
                           (caddr_t) arg,
                           sizeof (poll_cnct_state_t) /*,
                           mode*/
                          )
              )
           {
              ME90_LOG(state, ME90_DL_ERROR,
                      "mckk_ioctl: ddi_copyout failed for poll connection"
                      " state\n"
                     );
              return EFAULT;
           }
           if (usr_time_info != NULL)
           {
              if (ddi_copyout((caddr_t) & drv_time_info,
                              (caddr_t) usr_time_info,
                              sizeof (poll_time_info_t)/*,
                              mode*/
                             )
                 )
              {
                 ME90_LOG(state, ME90_DL_ERROR,
                         "mckk_ioctl: time info ddi_copyout failed for poll "
                         "connection state\n"
                        );
                 return EFAULT;
              }
           }
           ME90_LOG(state, ME90_DL_TRACE,
                   "mckk_ioctl: poll connection state finished\n"
                  );
           return rval;
        }
        default :
           ME90_LOG(state, ME90_DL_ERROR,
                   "mckk_ioctl invalid 'ioctl' command 0x%x\n",
                   cmd
                  );
           return (ENOTTY);
     }
}

/*
 * Set the simple transfer results info
 */
/*ARGSUSED*/
int
mcb_set_trans_results(
	mcb_state_t		*state,
	trans_info_t		*drv_trans_res_info_p,
	trans_info_t		*drv_results_p,
	trans_info_t		*user_trans_res_info_p,
	int			mode)
{
	int			rval = 0;

	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_set_trans_results started\n");

#ifdef	_MP_TIME_USE_
	READ_MP_TIME(drv_trans_res_info_p -> transfer_finish);
#else
	drv_trans_res_info_p -> transfer_finish = ddi_gethrtime();
#endif	/* _MP_TIME_USE_ */
	if (ddi_copyout((caddr_t) drv_trans_res_info_p,
		(caddr_t) user_trans_res_info_p,
		sizeof (trans_info_t)/*, mode*/)) {
		ME90_LOG(state, ME90_DL_ERROR,
			"mckk_set_trans_results ddi_copyout failed for"
			" transfer results\n");
		rval = EFAULT;
	}

	ME90_LOG(state, ME90_DL_TRACE,
		"mckk_set_trans_results finished\n");
	return rval;
}
