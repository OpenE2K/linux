/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG

#include "mga2_drv.h"
#include <drm/drm_encoder_slave.h>
#include <drm/i2c/sil164.h>
#include <drm/drm_probe_helper.h>


static int mga2_get_modes(struct drm_connector *connector)
{
	struct mga2_connector *mga2_connector = to_mga2_connector(connector);
	struct edid *edid = NULL;
	int ret;
	if (!mga2_connector->ddci2c) {
		/* Just add a static list of modes */
		drm_add_modes_noedid(connector, 640, 480);
		drm_add_modes_noedid(connector, 800, 600);
		drm_add_modes_noedid(connector, 1024, 768);
		drm_add_modes_noedid(connector, 1280, 1024);
		return 1;
	}
	edid = drm_get_edid(connector, mga2_connector->ddci2c);
	if (edid) {
		drm_connector_update_edid_property(&mga2_connector->base, edid);
		ret = drm_add_edid_modes(connector, edid);
		kfree(edid);
		return ret;
	} else
		drm_connector_update_edid_property(&mga2_connector->base, NULL);
	return 0;
}

static int mga2_mode_valid(struct drm_connector *connector,
			   struct drm_display_mode *mode)
{
#if 0
	if (mode->hdisplay > 1280)
		return MODE_VIRTUAL_X;
	if (mode->vdisplay > 1200)
		return MODE_VIRTUAL_Y;

	if (mode->hdisplay > 1920)
		return MODE_VIRTUAL_X;
	if (mode->vdisplay > 1200)
		return MODE_VIRTUAL_Y;
#endif
	return MODE_OK;
}

static void mga2_connector_destroy(struct drm_connector *connector)
{
	struct mga2_connector *mga2_connector = to_mga2_connector(connector);
	mga2_i2c_destroy(mga2_connector->ddci2c);
	drm_connector_unregister(connector);
	drm_connector_cleanup(connector);
	kfree(connector);
}

static enum drm_connector_status
mga2_connector_detect(struct drm_connector *connector, bool force)
{
	struct mga2_connector *mga2_connector = to_mga2_connector(connector);
	void __iomem *vid_regs = mga2_connector->regs;

	return rvidc(GPIO_IN) & MGA2_VID0_GPIO_MSEN ?
			connector_status_connected :
			connector_status_disconnected;
}

static const struct drm_connector_helper_funcs mga2_connector_helper_funcs = {
	.mode_valid = mga2_mode_valid,
	.get_modes = mga2_get_modes,
};

static const struct drm_connector_funcs mga2_connector_funcs = {
	.detect = mga2_connector_detect,
	.destroy = mga2_connector_destroy,

	.fill_modes		= drm_helper_probe_single_connector_modes,
	.destroy		= drm_connector_cleanup,
	.reset			= drm_atomic_helper_connector_reset,
	.atomic_duplicate_state	= drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state	= drm_atomic_helper_connector_destroy_state,
};

static void mga2_drm_slave_destroy(struct drm_encoder *enc)
{
	struct drm_encoder_slave *slave = to_encoder_slave(enc);
	struct i2c_client *client = drm_i2c_encoder_get_client(enc);

	if (slave->slave_funcs)
		slave->slave_funcs->destroy(enc);
	if (client)
		i2c_put_adapter(client->adapter);

	drm_encoder_cleanup(&slave->base);
	kfree(slave);
}

static const struct drm_encoder_funcs mga2_drm_slave_encoder_funcs = {
	.destroy	= mga2_drm_slave_destroy,
};

static const struct drm_encoder_helper_funcs drm_slave_encoder_helpers = {
	.dpms = drm_i2c_encoder_dpms,
	.mode_fixup = drm_i2c_encoder_mode_fixup,
	.prepare = drm_i2c_encoder_prepare,
	.commit = drm_i2c_encoder_commit,
	.mode_set = drm_i2c_encoder_mode_set,
	.detect = drm_i2c_encoder_detect,
};

#define	DVO_SIL1178_MASTER_ADDR	 (0x70 >> 1)	/* 7 bit addressing */
#define	DVO_SIL1178_SLAVE_ADDR	 (0x72 >> 1)	/* 7 bit addressing */

static struct i2c_board_info mga2_dvi_sil1178_info = {
	.type = "sil1178",
	.addr = DVO_SIL1178_MASTER_ADDR,
	.platform_data = &(struct sil164_encoder_params) {
		.input_edge = SIL164_INPUT_EDGE_RISING
	}
};

int mga2_dvi_init(struct drm_device *dev, void __iomem *regs,
			resource_size_t regs_phys)
{
	struct mga2_connector *mga2_connector;
	struct drm_connector *conn;
	struct mga2 *mga2 = dev->dev_private;
	struct drm_encoder_slave *slave;
	struct i2c_adapter *adap;
	struct drm_crtc *crtc;
	uint32_t crtc_mask = 0;
	int ret = 0;

	slave = kzalloc(sizeof(*slave), GFP_KERNEL);
	if (!slave)
		return -ENOMEM;

	drm_for_each_crtc(crtc, dev)
		crtc_mask |= drm_crtc_mask(crtc);

	slave->base.possible_crtcs = crtc_mask;

	adap = mga2->dvi_i2c;

	ret = drm_encoder_init(dev, &slave->base,
			       &mga2_drm_slave_encoder_funcs,
			       DRM_MODE_ENCODER_TMDS, NULL);
	if (ret) {
		DRM_ERROR("unable to init encoder\n");
		i2c_put_adapter(adap);
		kfree(slave);
		return ret;
	}

	ret = drm_i2c_encoder_init(dev, slave,
				   adap, &mga2_dvi_sil1178_info);
	if (ret) {
		if (ret != -ENODEV)
			DRM_ERROR("unable to init encoder slave\n");
		mga2_drm_slave_destroy(&slave->base);
		return ret;
	}

	drm_encoder_helper_add(&slave->base, &drm_slave_encoder_helpers);

	mga2_connector = kzalloc(sizeof(struct mga2_connector), GFP_KERNEL);
	if (!mga2_connector) {
		mga2_drm_slave_destroy(&slave->base);
		return -ENOMEM;
	};

	mga2_connector->regs = regs;
	mga2_connector->ddci2c = mga2_i2c_create(dev->dev, regs_phys +
				MGA2_VID0_DDCI2C, "dvi ddc",
				mga2->base_freq, 100 * 1000);

	if (!mga2_connector->ddci2c) {
		mga2_drm_slave_destroy(&slave->base);
		return -1;
	}

	conn = &mga2_connector->base;
	drm_connector_init(dev, conn, &mga2_connector_funcs,
			   DRM_MODE_CONNECTOR_DVID);

	conn->interlace_allowed = 0;
	conn->doublescan_allowed = 0;
	conn->polled = DRM_CONNECTOR_POLL_CONNECT |
			 DRM_CONNECTOR_POLL_DISCONNECT;

	drm_connector_helper_add(conn, &mga2_connector_helper_funcs);

	drm_connector_register(conn);

	ret = slave->slave_funcs->create_resources(&slave->base, conn);
	if (ret) {
		mga2_drm_slave_destroy(&slave->base);
		return ret;
	}

	ret = drm_connector_attach_encoder(conn, &slave->base);
	if (ret) {
		mga2_drm_slave_destroy(&slave->base);
		return ret;
	}

	return ret;
}
