########################################################################### ###
#@File
#@Copyright     Copyright (c) Imagination Technologies Ltd. All Rights Reserved
#@License       Strictly Confidential.
### ###########################################################################

MODULE_CC := $(CC)
MODULE_CXX := $(CXX)

MODULE_CFLAGS := $(ALL_CFLAGS) $($(THIS_MODULE)_cflags)
MODULE_CXXFLAGS := $(ALL_CXXFLAGS) $($(THIS_MODULE)_cxxflags)
MODULE_LDFLAGS := $($(THIS_MODULE)_ldflags) -L$(MODULE_OUT) -Xlinker -rpath-link=$(MODULE_OUT) $(ALL_LDFLAGS)

# Since this is a target module, add system-specific include flags.
MODULE_INCLUDE_FLAGS := \
 $(SYS_INCLUDES_RESIDUAL) \
 $(addprefix -isystem ,$(filter-out $(patsubst -I%,%,$(filter -I%,$(MODULE_INCLUDE_FLAGS))),$(SYS_INCLUDES_ISYSTEM))) \
 $(MODULE_INCLUDE_FLAGS)

# On Linux, we currently don't need to specify any flags to find the system
# libraries.
MODULE_SYSTEM_LIBRARY_DIR_FLAGS :=

MODULE_ARCH_BITNESS := 64
