########################################################################### ###
#@File
#@Title         Set up configuration required by build-directory Makefiles
#@Copyright     Copyright (c) Imagination Technologies Ltd. All Rights Reserved
#@License       Dual MIT/GPLv2
# 
# The contents of this file are subject to the MIT license as set out below.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# Alternatively, the contents of this file may be used under the terms of
# the GNU General Public License Version 2 ("GPL") in which case the provisions
# of GPL are applicable instead of those above.
# 
# If you wish to allow use of your version of this file only under the terms of
# GPL, and not to allow others to use your version of this file under the terms
# of the MIT license, indicate your decision by deleting the provisions above
# and replace them with the notice and other provisions required by GPL as set
# out in the file called "GPL-COPYING" included in this distribution. If you do
# not delete the provisions above, a recipient may use your version of this file
# under the terms of either the MIT license or GPL.
# 
# This License is also included in this distribution in the file called
# "MIT-COPYING".
# 
# EXCEPT AS OTHERWISE STATED IN A NEGOTIATED AGREEMENT: (A) THE SOFTWARE IS
# PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
# BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT; AND (B) IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
### ###########################################################################

# NOTE: Don't put anything in this file that isn't strictly required
# by the build-directory Makefiles. It should go in core.mk otherwise.

TOP := $(abspath ../../..)

# Some miscellaneous things to make comma substitutions easier.
apos := '#'
comma := ,
empty :=
space := $(empty) $(empty)

ifneq ($(words $(TOP)),1)
$(warning This source tree is located in a path which contains whitespace,)
$(warning which is not supported.)
$(warning )
$(warning $(space)The root is: $(TOP))
$(warning )
$(error Whitespace found in $$(TOP))
endif

$(call directory-must-exist,$(TOP))

ifneq ($(SUPPORT_NEUTRINO_PLATFORM),1)

CC_CHECK  := ../tools/cc-check.sh
CHMOD     := chmod

PVR_BUILD_DIR := $(notdir $(abspath .))
ifneq ($(PVR_BUILD_DIR),$(patsubst %_android,%,$(PVR_BUILD_DIR))) # Android build
 include ../common/android/platform_version.mk
 ifeq ($(is_at_least_nougat),1)
  prefer_prebuilt_host_toolchains ?= 1
 endif
 ifneq ($(USE_CLANG),0)
  prefer_clang := true
 else
  $(info WARNING: USE_CLANG=0 is deprecated for Android builds)
 endif
else
 ifeq ($(USE_CLANG),1)
  prefer_clang := true
 endif
endif

CROSS_TRIPLE := $(patsubst %-,%,$(notdir $(CROSS_COMPILE)))

define clangify
 ifneq ($$(strip $$(CROSS_TRIPLE)),)
  _$(1) := $$($(1)) -target $$(patsubst %-,%,$$(CROSS_TRIPLE)) -Qunused-arguments
 else
  _$(1) := $$($(1)) -Qunused-arguments
 endif
endef

# GNU Make has builtin values for CC/CXX which we don't want to trust. This
# is because $(CROSS_COMPILE)$(CC) doesn't always expand to a cross compiler
# toolchain binary name (e.g. most toolchains have 'gcc' but not 'cc').

CLANG ?= clang
ifeq ($(origin CC),default)
 ifeq ($(prefer_clang),true)
  export CC := $(CLANG)
  _CLANG := true
  $(eval $(call clangify,CC))
 else
  CC  := gcc
  _CC := $(CROSS_COMPILE)gcc
 endif
else
 _CLANG := $(shell $(CC_CHECK) --clang --cc "$(CC)")
 ifeq ($(_CLANG),true)
  $(eval $(call clangify,CC))
 else
  _CC := $(CC)
 endif
endif

CLANG_CXX ?= clang++
ifeq ($(origin CXX),default)
 ifeq ($(prefer_clang),true)
  export CXX := $(CLANG_CXX)
 else
  CXX := g++
 endif
endif

CC_SECONDARY ?= $(CC)
CXX_SECONDARY ?= $(CXX)
ifeq ($(prefer_clang),true)
 export CC_SECONDARY
 export CXX_SECONDARY
endif

ifeq ($(prefer_clang),true)
 ifeq ($(HOST_CC),)
  ifeq ($(prefer_prebuilt_host_toolchains),1)
   export HOST_CC := $(CC) -target x86_64-linux-gnu
  else
   export HOST_CC := /usr/bin/clang
  endif
 endif
 ifeq ($(HOST_CXX),)
  ifeq ($(prefer_prebuilt_host_toolchains),1)
   export HOST_CXX := $(CXX) -target x86_64-linux-gnu
  else
   export HOST_CXX := /usr/bin/clang++
  endif
 endif
else
 ifeq ($(prefer_prebuilt_host_toolchains),1)
  export HOST_CC  ?= x86_64-linux-gcc
  export HOST_CXX ?= x86_64-linux-g++
 else
  HOST_CC ?= gcc
 endif
endif

# Work out if we are targeting ARM before we start tweaking _CC.
TARGETING_AARCH64 := $(shell \
 $(_CC) -dM -E - </dev/null | grep -q __aarch64__ && echo 1)

TARGETING_ARM := $(shell \
 $(_CC) -dM -E - </dev/null | grep __arm__ >/dev/null 2>&1 && echo 1)

TARGETING_MIPS := $(shell \
 $(_CC) -dM -E - </dev/null | grep __mips__ >/dev/null 2>&1 && echo 1)

HOST_CC_IS_LINUX := $(shell \
 $(HOST_CC) -dM -E - </dev/null | grep __linux__ >/dev/null 2>&1 && echo 1)

ifneq ($(strip $(KERNELDIR)),)
include ../config/kernel_version.mk
endif

# The user didn't set CROSS_COMPILE. There's probably nothing wrong
# with that, but we'll let them know anyway.
#
ifeq ($(origin CROSS_COMPILE), undefined)
$(warning CROSS_COMPILE is not set. Target components will be built with the host compiler)
endif

endif # !Neutrino

# The user is trying to set one of the old SUPPORT_ options on the
# command line or in the environment. This isn't supported any more
# and will often break the build. The user is generally only trying
# to remove a component from the list of targets to build, so we'll
# point them at the new way of doing this.
define sanity-check-support-option-origin
ifeq ($$(filter undefined file,$$(origin $(1))),)
$$(warning *** Setting $(1) via $$(origin $(1)) is deprecated)
$$(error If you are trying to disable a component, use e.g. EXCLUDED_APIS="opengles1 opengl")
endif
endef
$(foreach _o,SYS_CFLAGS SYS_CXXFLAGS SYS_INCLUDES SYS_EXE_LDFLAGS SYS_LIB_LDFLAGS,$(eval $(call sanity-check-support-option-origin,$(_o))))

# Check for words in EXCLUDED_APIS that aren't understood by the
# common/apis/*.mk files. This should be kept in sync with all the tests on
# EXCLUDED_APIS in those files
_excludable_apis := camerahal cldnn nnhal composerhal hwperftools memtrackhal opencl opengl opengles1 opengles3 openrl renderscript rogue2d scripts sensorhal servicestools testchiptools unittests vulkan
_excluded_apis := $(subst $(comma),$(space),$(EXCLUDED_APIS))

_unrecognised := $(strip $(filter-out $(_excludable_apis),$(_excluded_apis)))
ifneq ($(_unrecognised),)
$(warning *** Ignoring unrecognised entries in EXCLUDED_APIS: $(_unrecognised))
$(warning *** EXCLUDED_APIS was set via $(origin EXCLUDED_APIS) to: $(EXCLUDED_APIS))
$(warning *** Excludable APIs are: $(_excludable_apis))
endif

override EXCLUDED_APIS := $(filter $(_excludable_apis), $(_excluded_apis))

ifeq ($(SUPPORT_NEUTRINO_PLATFORM),1)
include ../common/neutrino/preconfig_neutrino.mk
endif
