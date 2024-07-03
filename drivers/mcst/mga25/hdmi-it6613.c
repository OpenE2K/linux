/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "drm/drm_probe_helper.h"

#include "drv.h"

#include "mcu.h"
#include "typedef.h"
#include "HDMI_TX/it6613_drv.h"
#include "HDMI_TX/HDMI_TX.h"

static u8 mga25_i2c_rd(struct i2c_adapter *adapter, u8 slave_addr, u8 addr)
{
	u8 val = 0;
	u8 out_buf[2];
	u8 in_buf[2];
	struct i2c_msg msgs[] = {
		{
		 .addr = slave_addr,
		 .flags = 0,
		 .len = 1,
		 .buf = out_buf,
		 },
		{
		 .addr = slave_addr,
		 .flags = I2C_M_RD,
		 .len = 1,
		 .buf = in_buf,
		 }
	};

	out_buf[0] = addr;
	out_buf[1] = 0;

	if (i2c_transfer(adapter, msgs, 2) == 2) {
		val = in_buf[0];
		if (0) DRM_DEBUG("%s: rd: 0x%02x: 0x%02x\n",
			  adapter->name, addr, val);
	} else {
		DRM_DEBUG("i2c 0x%02x 0x%02x read failed\n", addr, val);
	}
	return val;
}

static void
mga25_i2c_wr(struct i2c_adapter *adapter, u8 slave_addr, u8 addr, u8 val)
{
	uint8_t out_buf[2];
	struct i2c_msg msg = {
		.addr = slave_addr,
		.flags = 0,
		.len = 2,
		.buf = out_buf,
	};

	out_buf[0] = addr;
	out_buf[1] = val;

	if (0) DRM_DEBUG("%s: wr: 0x%02x: 0x%02x\n", adapter->name, addr, val);
	if (i2c_transfer(adapter, &msg, 1) != 1)
		DRM_DEBUG("i2c 0x%02x 0x%02x write failed\n", addr, val);
}

static struct i2c_adapter *mga25_it6613_i2c_adapter;


BYTE _HDMITX_ReadI2C_Byte(BYTE RegAddr)
{
	BYTE Value;
	_HDMITX_ReadI2C_ByteN(RegAddr, &Value, 1);
	return Value;
}

SYS_STATUS _HDMITX_WriteI2C_Byte(BYTE RegAddr, BYTE Data)
{
	return _HDMITX_WriteI2C_ByteN(RegAddr, &Data, 1);
}

SYS_STATUS _HDMITX_ReadI2C_ByteN(BYTE RegAddr, BYTE * pData, int N)
{
	bool bSuccess = TRUE;
	int i;
	for (i = 0; i < N && bSuccess; i++) {
		pData[i] =
		    mga25_i2c_rd(mga25_it6613_i2c_adapter,
				HDMI_TX_I2C_SLAVE_ADDR >> 1, RegAddr + i);
	}
	return bSuccess ? ER_SUCCESS : ER_FAIL;
}

SYS_STATUS _HDMITX_WriteI2C_ByteN(BYTE RegAddr, BYTE * pData, int N)
{
	BOOL bSuccess = TRUE;
	int i;
	for (i = 0; i < N && bSuccess; i++) {
		mga25_i2c_wr(mga25_it6613_i2c_adapter,
			    HDMI_TX_I2C_SLAVE_ADDR >> 1, RegAddr + i,
			    *(pData + i));
	}
	return bSuccess ? ER_SUCCESS : ER_FAIL;
}

struct mga25_it6613 {
	struct drm_connector	connector;
	struct drm_encoder	encoder;
	struct i2c_adapter	*ddc;
	struct device *dev;
	int dev_id;
};

static inline struct mga25_it6613 *
drm_connector_to_mga25_it6613(struct drm_connector *c)
{
	return container_of(c, struct mga25_it6613, connector);
}

static inline struct mga25_it6613 *
drm_encoder_to_mga25_it6613(struct drm_encoder *e)
{
	return container_of(e, struct mga25_it6613, encoder);
}

static int read_edid_block(void *data, u8 *buf, unsigned int blk, size_t length)
{
	extern unsigned char EDID_Buf[128 * 5];
	memcpy(buf, EDID_Buf + 128 * blk,
		length > sizeof(EDID_Buf) ? sizeof(EDID_Buf) : length);
	return 0;
}

static int mga25_it6613_get_modes(struct drm_connector *c)
{
	struct edid *edid = NULL;
	int ret;

	edid = drm_do_get_edid(c, read_edid_block, NULL);
	if (edid) {
		drm_connector_update_edid_property
		    (c, edid);
		ret = drm_add_edid_modes(c, edid);
		kfree(edid);
		return ret;
	} else {
		drm_connector_update_edid_property
		    (c, NULL);
	}
	return 0;
}


static struct drm_connector_helper_funcs mga25_it6613_con_helper_funcs = {
	.get_modes	= mga25_it6613_get_modes,
};

static void
mga25_it6613_connector_destroy(struct drm_connector *c)
{
	struct mga25_it6613 *m = drm_connector_to_mga25_it6613(c);
	drm_connector_cleanup(c);
	i2c_put_adapter(m->ddc);
}

static const struct drm_connector_funcs mga25_it6613_con_funcs = {
	.fill_modes		= drm_helper_probe_single_connector_modes,
	.destroy		= mga25_it6613_connector_destroy,
	.reset			= drm_atomic_helper_connector_reset,
	.atomic_duplicate_state	= drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state	= drm_atomic_helper_connector_destroy_state,
};

static const struct drm_encoder_helper_funcs mga25_it6613_enc_helper_funcs = {
};

static const struct drm_encoder_funcs mga25_it6613_enc_funcs = {
	.destroy	= drm_encoder_cleanup,
};


#define RX_DISABLED

typedef enum {
	DEMO_READY = 0,
	DEMO_TX_ONLY,
	DEMO_LOOPBACK
} DEMO_MODE;
DEMO_MODE gDemoMode = DEMO_READY;


//=========================================================================
// VPG data definition
// VPG: Video Pattern Generation, implement in vpg.v
//=========================================================================

char gszVicText[][64] = {
	"720x480p60   VIC=3",
	"1024x768p60",
	"1280x720p50   VIC=19",
	"1280x720p60   VIC=4",
	"1280x1024",
	"1920x1080i60  VIC=5",
	"1920x1080i50  VIC=20",
	"1920x1080p60  VIC=16",
	"1920x1080p50  VIC=31",
	"1600x1200",
	"1920x1080i120 VIC=46",
};

typedef enum {
	MODE_720x480 = 0,	// 480p,    27      MHZ    VIC=3
	MODE_1024x768 = 1,	// XGA,     65      MHZ  
	MODE_1280x720p50 = 2,	// 720p50   74.25   MHZ    VIC=19
	MODE_1280x720 = 3,	// 720p,    74.25   MHZ    VIC=4 
	MODE_1280x1024 = 4,	// SXGA,    108     MHZ
	MODE_1920x1080i = 5,	// 1080i,   74.25   MHZ    VIC=5 
	MODE_1920x1080i50 = 6,	// 1080i,   74.25   MHZ    VIC=20 
	MODE_1920x1080 = 7,	// 1080p,   148.5   MHZ    VIC=16  
	MODE_1920x1080p50 = 8,	// 1080p50, 148.5   MHZ    VIC=31  
	MODE_1600x1200 = 9,	// UXGA,    162     MHZ 
	MODE_1920x1080i120 = 10	// 1080i120, 148.5   MHZ    VIC=46
} VPG_MODE;

typedef enum {
	VPG_RGB444 = 0,
	VPG_YUV422 = 1,
	VPG_YUV444 = 2
} VPG_COLOR;


VPG_MODE gVpgMode = MODE_1920x1080;   //MODE_1920x1080;MODE_720x480
COLOR_TYPE gVpgColor = COLOR_RGB444;// video pattern generator - output color (defined ind vpg.v)


extern int gEnableColorDepth;
//=========================================================================
// TX video formation control
//=========================================================================

void FindVIC(VPG_MODE Mode, alt_u8 * vic, bool * pb16x9)
{
	switch (Mode) {
	case MODE_720x480:
		*vic = 3;
		break;
	case MODE_1280x720p50:
		*vic = 19;
		break;
	case MODE_1280x720:
		*vic = 4;
		break;
	case MODE_1920x1080i:
		*vic = 5;
		break;
	case MODE_1920x1080i50:
		*vic = 20;
		break;
	case MODE_1920x1080:
		*vic = 16;
		break;
	case MODE_1920x1080p50:
		*vic = 31;
		break;
	case MODE_1920x1080i120:
		*vic = 46;
		break;
	default:
		*vic = 0;
	}
	if (*vic != 0)
		*pb16x9 = TRUE;
	else
		*pb16x9 = FALSE;
}

void SetupTxVIC(VPG_MODE Mode)
{
	alt_u8 tx_vic;
	bool b16x9;
	FindVIC(Mode, &tx_vic, &b16x9);
	HDMITX_ChangeVideoTiming(tx_vic);
}

void VPG_Config(VPG_MODE Mode, COLOR_TYPE Color)
{
#ifndef TX_DISABLED
	//===== check whether vpg function is active
	if (!HDMITX_HPD())
		return;
#ifndef RX_DISABLED
	if (HDMIRX_IsVideoOn())
		return;
#endif				//RX_DISABLED


	OS_PRINTF("===> Pattern Generator Mode: %d (%s)\n", gVpgMode,
		  gszVicText[gVpgMode]);

#if 0
	//===== updagte vpg mode & color   
	IOWR(HDMI_TX_MODE_CHANGE_BASE, 0, 0);
	// change color mode of VPG
	if (gVpgColor == COLOR_RGB444)
		IOWR(HDMI_TX_VPG_COLOR_BASE, 0, VPG_RGB444);	// RGB444
	else if (gVpgColor == COLOR_YUV422)
		IOWR(HDMI_TX_VPG_COLOR_BASE, 0, VPG_YUV422);	// YUV422
	else if (gVpgColor == COLOR_YUV444)
		IOWR(HDMI_TX_VPG_COLOR_BASE, 0, VPG_YUV444);	// YUV444

	IOWR(HDMI_TX_DISP_MODE_BASE, 0, gVpgMode);
	IOWR(HDMI_TX_MODE_CHANGE_BASE, 0, 1);
	IOWR(HDMI_TX_MODE_CHANGE_BASE, 0, 0);
	//
	//HDMITX_EnableVideoOutput();

#endif				//#ifndef TX_DISABLED
#endif
}


bool SetupColorSpace(void)
{
	int ColorDepth = 24;	/* defualt */
	char szColor[][32] = { "RGB444", "YUV422", "YUV444" };
	bool bSuccess = TRUE;
//	bool bRxVideoOn = FALSE;
	COLOR_TYPE TxInputColor;
	COLOR_TYPE TxOutputColor;
#ifndef RX_DISABLED
	bRxVideoOn = HDMIRX_IsVideoOn();
#endif				// RX_DISABLED


#ifndef TX_DISABLED
#if 0
	if (gDemoMode == DEMO_LOOPBACK) {
		// rx-tx loopback
		int RxSourceColor, RxSinkColor;
		bSuccess = HDMIRX_GetSourceColor(&RxSourceColor);
		if (bSuccess) {
			// RX-TX loopback (bypass)
			if (RxSourceColor == COLOR_RGB444 ||
			    (RxSourceColor == COLOR_YUV422
			     && HDMITX_IsSinkSupportYUV422())
			    || (RxSourceColor == COLOR_YUV444
				&& HDMITX_IsSinkSupportYUV444())) {

				// Source color --> RX --> TX ---> Display
				// bypass color space    
				TxInputColor = RxSourceColor;
				TxOutputColor = RxSourceColor;
				RxSinkColor = RxSourceColor;
			} else {
				// Source color --> RX --(RGB color)--> TX --(RBG Color)--> Display
				TxInputColor = COLOR_RGB444;
				TxOutputColor = COLOR_RGB444;
				RxSinkColor = COLOR_RGB444;
			}
			HDMIRX_SetOutputColor(RxSinkColor);
			OS_PRINTF("Set Rx Color Convert:%s->%s\n",
				  szColor[RxSourceColor],
				  szColor[RxSinkColor]);
		}
	} else
#endif
	if (gDemoMode == DEMO_TX_ONLY) {
		// tx-only
#ifdef TX_CSC_DISABLED
		// Transmittor: output color == input color
		TxInputColor = gVpgColor;
		TxOutputColor = gVpgColor;
#else
		// Trasmitter: output color is fixed as RGB 
		TxInputColor = gVpgColor;
		TxOutputColor = COLOR_RGB444;
#endif


	} else {
		return TRUE;
	}

	HDMITX_SetColorSpace(TxInputColor, TxOutputColor);


	// set TX color depth
	if (gEnableColorDepth) {
		if (HDMITX_IsSinkSupportColorDepth36())
			ColorDepth = 36;
		else if (HDMITX_IsSinkSupportColorDepth30())
			ColorDepth = 30;
	}
	HDMITX_SetOutputColorDepth(ColorDepth);

	OS_PRINTF("Set Tx Color Depth: %d bits %s\n", ColorDepth,
		  gEnableColorDepth ? "" : "(default)");
	OS_PRINTF("Set Tx Color Convert:%s->%s\n", szColor[TxInputColor],
		  szColor[TxOutputColor]);

#if 0				// dump debug message
	int i;
	HDMITX_DumpReg(0xC0);
	HDMITX_DumpReg(0x72);
	for (i = 0x73; i <= 0x8d; i++)
		HDMITX_DumpReg(i);
	HDMITX_DumpReg(0x158);
#endif

#endif				//TX_DISABLED
	return bSuccess;
}

static void mga25_it6613_iteration(void)
{

	bool bRxVideoOn = FALSE, bTxSinkOn = FALSE, bRxModeChanged = FALSE;
	//========== TX
	if (HDMITX_DevLoopProc() || bRxModeChanged) {
		bTxSinkOn = HDMITX_HPD();
		if (bTxSinkOn) {
			// update state
			gDemoMode =
			    bRxVideoOn ? DEMO_LOOPBACK : DEMO_TX_ONLY;
			//
			HDMITX_DisableVideoOutput();
			if (gDemoMode == DEMO_TX_ONLY) {
				// tx-only
				VPG_Config(gVpgMode, gVpgColor);
				SetupTxVIC(gVpgMode);
			}
			SetupColorSpace();
			HDMITX_EnableVideoOutput();
		} else {
			HDMITX_DisableVideoOutput();
		}
	}
}

static int mga25_it6613_bind(struct device *dev, struct device *master,
			    void *data)
{
	int ret;
	struct drm_device *drm = data;
	struct device_node *np = dev->of_node;
	struct mga25_it6613 *m = dev_get_drvdata(dev);
	struct drm_encoder *e = &m->encoder;
	struct drm_connector *c = &m->connector;
	struct device_node *ddc_node;

	e->possible_crtcs = drm_of_find_possible_crtcs(drm, dev->of_node);
	if (WARN_ON(e->possible_crtcs == 0))
		return -ENODEV;

	ddc_node = of_parse_phandle(np, "ddc-i2c-bus", 0);
	if (!ddc_node) {
		DRM_DEV_ERROR(m->dev, "no ddc property found\n");
		ret = -ENODEV;
		goto err_out;
	}
	m->ddc = of_get_i2c_adapter_by_node(ddc_node);
	of_node_put(ddc_node);
	if (!m->ddc) {
		DRM_DEV_ERROR(m->dev, "failed to read ddc node\n");
		ret = -ENODEV;
		goto err_out;
	}

	drm_encoder_helper_add(e, &mga25_it6613_enc_helper_funcs);
	ret = drm_encoder_init(drm, e,
			       &mga25_it6613_enc_funcs,
			       DRM_MODE_ENCODER_TMDS,
			       NULL);
	if (ret) {
		DRM_DEV_ERROR(m->dev, "Couldn't initialise the encoder\n");
		goto err_out;
	}

	drm_connector_helper_add(c, &mga25_it6613_con_helper_funcs);
	ret = drm_connector_init(drm, c, &mga25_it6613_con_funcs,
					DRM_MODE_CONNECTOR_HDMIA);
	if (ret) {
		DRM_DEV_ERROR(m->dev, "Couldn't initialise the connector\n");
		goto err_cleanup_connector;
	}

	ret = drm_connector_attach_encoder(c, e);
	if (ret) {
		DRM_DEV_ERROR(m->dev, "Couldn't attach the connector\n");
		goto err_cleanup_connector;
	}
	mga25_it6613_i2c_adapter = m->ddc;

	HDMITX_Init();

	msleep(200);
	mga25_it6613_iteration();

	return 0;
err_cleanup_connector:
	drm_encoder_cleanup(&m->encoder);
err_out:
	if (m)
		i2c_put_adapter(m->ddc);
	return ret;
}

static void mga25_it6613_unbind(struct device *dev, struct device *master,
			       void *data)
{
	struct mga25_it6613 *m = dev_get_drvdata(dev);
	if (!m)
		return;
}

static const struct component_ops mga25_it6613_ops = {
	.bind	= mga25_it6613_bind,
	.unbind	= mga25_it6613_unbind,
};

static int mga25_it6613_probe(struct platform_device *pdev)
{
	int ret;
	struct device *dev = &pdev->dev;
	struct device *parent = dev->parent;
	struct mga25_it6613 *m = devm_kzalloc(dev, sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	m->dev_id = mga25_get_version(parent);
	m->dev = dev;
	dev_set_drvdata(dev, m);

	ret = component_add(&pdev->dev, &mga25_it6613_ops);
	if (WARN_ON(ret))
		goto err;

	return ret;
err:

	return ret;
}

static int mga25_it6613_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id mga25_it6613_dt_ids[] = {
	{ .compatible = "mcst,it6613-hdmi", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, mga25_it6613_dt_ids);

struct platform_driver mga25_it6613_driver = {
	.probe  = mga25_it6613_probe,
	.remove = mga25_it6613_remove,
	.driver = {
		.name = "mga2-it6613-hdmi",
		.of_match_table = mga25_it6613_dt_ids,
	},
};

