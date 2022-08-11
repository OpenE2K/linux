# Key features
/\<CONFIG_E2K_MACHINE\>/ { print "CONFIG_E2K_MACHINE=y"; print "CONFIG_E2K_E1CP=y"; next }
/\<CONFIG_SMP\>/         { print "CONFIG_SMP=n"; next }

# Disabled drivers
/\<CONFIG_ELDSP\>/           { print "CONFIG_ELDSP=n"; next }
/\<CONFIG_HANTRODEC\>/       { print "CONFIG_HANTRODEC=n"; next }
/\<CONFIG_BIGE\>/            { print "CONFIG_BIGE=n"; next }
/\<CONFIG_E8CPCS\>/          { print "CONFIG_E8CPCS=n"; next }
/\<CONFIG_IMGTEC\>/          { print "CONFIG_IMGTEC=n"; next }
/\<CONFIG_MCST_GPU_IMGTEC\>/ { print "CONFIG_MCST_GPU_IMGTEC=n"; next }
/\<CONFIG_DRM_SMI\>/         { print "CONFIG_DRM_SMI=n"; next }
/\<CONFIG_SMI_PWM\>/         { print "CONFIG_SMI_PWM=n"; next }
/\<CONFIG_SMI_GPIO\>/        { print "CONFIG_SMI_GPIO=n"; next }
/\<CONFIG_E2K_PCS_CPUFREQ\>/ { print "CONFIG_E2K_PCS_CPUFREQ=n"; next }

# No IDE requested by mike
/\<CONFIG_IDE\>/             { print "CONFIG_IDE=n"; next }

#/\<CONFIG_\>/           { print "CONFIG_=n"; next }
$0
