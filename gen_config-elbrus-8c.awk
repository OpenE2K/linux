# Key features
/\<CONFIG_E2K_MACHINE\>/  { print "CONFIG_E2K_MACHINE=y"; print "CONFIG_E2K_E8C=y"; next }
/\<CONFIG_DRM\>/          { print "CONFIG_DRM=m"; next }
/\<CONFIG_DRM_IMX_HDMI\>/ { print "CONFIG_DRM_IMX_HDMI=m"; next }

# Disabled drivers
/\<CONFIG_DRM_MGA2\>/        { print "CONFIG_DRM_MGA2=n"; next }
/\<CONFIG_MGA2_PWM\>/        { print "CONFIG_MGA2_PWM=n"; next }
/\<CONFIG_MGA2_GPIO\>/       { print "CONFIG_MGA2_GPIO=n"; next }
/\<CONFIG_ELDSP\>/           { print "CONFIG_ELDSP=n"; next }
/\<CONFIG_HANTRODEC\>/       { print "CONFIG_HANTRODEC=n"; next }
/\<CONFIG_BIGE\>/            { print "CONFIG_BIGE=n"; next }
/\<CONFIG_IMGTEC\>/          { print "CONFIG_IMGTEC=n"; next }
/\<CONFIG_MCST_GPU_IMGTEC\>/ { print "CONFIG_MCST_GPU_IMGTEC=n"; next }
/\<CONFIG_MCST_GPU_VIV\>/    { print "CONFIG_MCST_GPU_VIV=n"; next }
/\<CONFIG_L_PMC\>/           { print "CONFIG_L_PMC=n"; next }
/\<CONFIG_E2K_PCS_CPUFREQ\>/ { print "CONFIG_E2K_PCS_CPUFREQ=n"; next }

#/\<CONFIG_\>/           { print "CONFIG_=n"; next }
$0
