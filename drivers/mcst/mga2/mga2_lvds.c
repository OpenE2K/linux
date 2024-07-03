/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "mga2_drv.h"
#include <drm/drm_probe_helper.h>
#include <video/videomode.h>
#include <video/of_display_timing.h>

struct mga2_vport {
	struct drm_connector	connector;
	struct drm_encoder	encoder;
	struct display_timings *timings;
	struct drm_panel	*panel;
	struct i2c_adapter	*ddci2c;
};

static inline struct mga2_vport *
drm_connector_to_mga2_vport(struct drm_connector *connector)
{
	return container_of(connector, struct mga2_vport,
			    connector);
}

static inline struct mga2_vport *
drm_encoder_to_mga2_vport(struct drm_encoder *encoder)
{
	return container_of(encoder, struct mga2_vport,
			    encoder);
}

static int mga2_vport_add_cmdline_mode(struct drm_connector *connector)
{
	struct drm_cmdline_mode *cmdline_mode;
	struct drm_display_mode *mode;

	cmdline_mode = &connector->cmdline_mode;
	if (!cmdline_mode->specified)
		return 0;

	/* Only add a GTF mode if we find no matching probed modes */
	list_for_each_entry(mode, &connector->probed_modes, head) {
		if (mode->hdisplay != cmdline_mode->xres ||
		    mode->vdisplay != cmdline_mode->yres)
			continue;

		if (cmdline_mode->refresh_specified) {
			/* The probed mode's vrefresh is set until later */
			if (drm_mode_vrefresh(mode) != cmdline_mode->refresh)
				continue;
		}

		return 0;
	}

	mode = drm_mode_create_from_cmdline_mode(connector->dev,
						 cmdline_mode);
	if (mode == NULL)
		return 0;

	mode->type |= DRM_MODE_TYPE_PREFERRED;

	drm_mode_probed_add(connector, mode);
	return 1;
}

static unsigned int mga2_vport_get_timings_modes(struct drm_connector *connector)
{
	struct drm_device *dev = connector->dev;
	struct mga2_vport *vp = drm_connector_to_mga2_vport(connector);
	struct display_timings *timings = vp->timings;
	unsigned i;
	if (!timings)
		return 0;

	for (i = 0; i < timings->num_timings; i++) {
		struct drm_display_mode *mode;
		struct videomode vm;

		if (videomode_from_timings(timings, &vm, i))
			break;

		mode = drm_mode_create(dev);
		if (!mode)
			break;

		drm_display_mode_from_videomode(&vm, mode);

		mode->type = DRM_MODE_TYPE_DRIVER;

		if (timings->native_mode == i)
			mode->type |= DRM_MODE_TYPE_PREFERRED;

		drm_mode_set_name(mode);
		drm_mode_probed_add(connector, mode);
	}

	return i;
}

static int mga2_vport_get_modes(struct drm_connector *connector)
{
	struct edid *edid;
	struct mga2_vport *vp = drm_connector_to_mga2_vport(connector);
	int cnt = mga2_vport_add_cmdline_mode(connector);
	if (cnt > 0)
		return cnt;
	cnt = mga2_vport_get_timings_modes(connector);
	if (cnt > 0)
		return cnt;
	if (vp->panel)
		return drm_panel_get_modes(vp->panel, connector);
	if (!vp->ddci2c)
		return -EINVAL;
	edid = drm_get_edid(connector, vp->ddci2c);
	drm_connector_update_edid_property(connector, edid);
	return drm_add_edid_modes(connector, edid);
}

static struct drm_connector_helper_funcs mga2_vport_con_helper_funcs = {
	.get_modes	= mga2_vport_get_modes,
};

static void
mga2_vport_connector_destroy(struct drm_connector *connector)
{
	struct mga2_vport *vp = drm_connector_to_mga2_vport(connector);
	if (vp->timings)
		display_timings_release(vp->timings);
	mga2_i2c_destroy(vp->ddci2c);
	drm_connector_cleanup(connector);
}

static const struct drm_connector_funcs mga2_vport_con_funcs = {
	.fill_modes		= drm_helper_probe_single_connector_modes,
	.destroy		= mga2_vport_connector_destroy,
	.reset			= drm_atomic_helper_connector_reset,
	.atomic_duplicate_state	= drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state	= drm_atomic_helper_connector_destroy_state,
};

static void mga2_vport_encoder_enable(struct drm_encoder *encoder)
{
	struct mga2_vport *vp = drm_encoder_to_mga2_vport(encoder);

	DRM_DEBUG_DRIVER("Enabling LVDS output\n");

	if (vp->panel) {
		drm_panel_prepare(vp->panel);
		drm_panel_enable(vp->panel);
	}
}

static void mga2_vport_encoder_disable(struct drm_encoder *encoder)
{
	struct mga2_vport *vp = drm_encoder_to_mga2_vport(encoder);
	DRM_DEBUG_DRIVER("Disabling LVDS output\n");

	if (vp->panel) {
		drm_panel_disable(vp->panel);
		drm_panel_unprepare(vp->panel);
	}
}

static const struct drm_encoder_helper_funcs mga2_vport_enc_helper_funcs = {
	.disable	= mga2_vport_encoder_disable,
	.enable		= mga2_vport_encoder_enable,
};

static const struct drm_encoder_funcs mga2_vport_enc_funcs = {
	.destroy	= drm_encoder_cleanup,
};

int mga2_common_connector_init(struct drm_device *drm,
					resource_size_t regs_phys,
					int connector_type, bool i2c,
					uint32_t possible_crtcs)
{
	struct mga2_vport *vp;
	int ret, channels_nr = 0;
	struct mga2 *mga2 = drm->dev_private;

	vp = devm_kzalloc(drm->dev, sizeof(*vp), GFP_KERNEL);
	if (!vp)
		return -ENOMEM;

	ret = drm_of_find_panel_or_bridge(drm->dev->of_node, 0, 0,
					  &vp->panel, NULL);
	if (ret && connector_type == DRM_MODE_CONNECTOR_LVDS)
		DRM_DEBUG("No panel or bridge found (%d)...\n", ret);
	if (vp->panel)
		vp->timings = of_get_display_timings(vp->panel->dev->of_node);

	drm_encoder_helper_add(&vp->encoder,
			       &mga2_vport_enc_helper_funcs);
	ret = drm_encoder_init(drm,
			       &vp->encoder,
			       &mga2_vport_enc_funcs,
			       DRM_MODE_ENCODER_LVDS,
			       NULL);
	if (ret) {
		DRM_ERROR("Couldn't initialise the vp encoder\n");
		goto err_out;
	}

	vp->encoder.possible_crtcs = possible_crtcs;

	drm_connector_helper_add(&vp->connector,
					&mga2_vport_con_helper_funcs);
	ret = drm_connector_init(drm, &vp->connector,
					&mga2_vport_con_funcs,
					connector_type);
	if (ret) {
		DRM_ERROR("Couldn't initialise the vp connector\n");
		goto err_cleanup_connector;
	}

	drm_connector_attach_encoder(&vp->connector, &vp->encoder);

	if (vp->panel) {
		channels_nr = of_graph_get_endpoint_count(
						vp->panel->dev->of_node);

		DRM_INFO("Panel has %d channels\n", channels_nr);
	} else if (i2c) {
		vp->ddci2c =
			mga2_i2c_create(drm->dev, regs_phys + MGA2_VID0_DDCI2C,
				"mga2 ddc", mga2->base_freq, 100 * 1000);
		if (!vp->ddci2c) {
			ret = -ENOSYS;
			DRM_ERROR("failed to add ddc bus for conn\n");
			goto err_cleanup_connector;
		}
	}

	return channels_nr;
err_cleanup_connector:
	drm_encoder_cleanup(&vp->encoder);
err_out:
	return ret;
}
