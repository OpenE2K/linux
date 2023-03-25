#! /bin/bash
# This script deletes lines in which drivers
# vivante and gpu-viv are  mentioned

sed_i_d () {
	echo $2
	sed -i "$1" $2 || exit 1
}

[ -n "$1" ] && cd $1
if [[ `readlink -f $0` == `pwd`/scripts/vivante_del.sh ]]; then
	cp scripts/vivante_del.sh /tmp
	/tmp/vivante_del.sh `pwd`;
	exit
fi
echo Proceccing directoty `pwd`
#set -x
rm scripts/vivante_del.sh > /dev/null 2>&1

echo Edit files:

sed_i_d '/VIVANTE/d; /Vivante/d' arch/e2k/configs/build-config
sed_i_d '/CONFIG_DRM_VIVANTE/d' arch/e2k/configs/defconfig
sed_i_d '/CONFIG_DRM_VIVANTE/d; /Vivante/,/^$/d' arch/sparc/configs/sparc64_defconfig

sed_i_d '/vivante/d' drivers/gpu/drm/Makefile
sed_i_d '/gpu-viv/d' drivers/mcst/Makefile

sed_i_d '/PCI_DEVICE_ID_MCST_3D_VIVANTE_R2000P/d' arch/l/kernel/l-iommu.c
sed_i_d '/Vivante/,/^$/d' drivers/gpu/drm/drm_lock.c

sed_i_d '/config DRM_VIVANTE/,/^$/d' drivers/gpu/drm/Kconfig
sed_i_d '/gpu-viv/,/^$/d' drivers/mcst/Kconfig

rm -rf drivers/gpu/drm/vivante drivers/mcst/gpu-viv/
