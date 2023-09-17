#################################################################
#cross information
#
#################################################################
#
#platform
#

PLATFORM=mips

ifeq ($(TOOL_CHAIN_MODE),binary)
TOOLCHAIN_PATH=/opt/mips_tools/tools/gcc-3.4.4-2.16.1/build_mips/
else
#TOOLCHAIN_PATH=/opt/mips_tools/tools/gcc-3.4.4-2.16.1/build_mips/
endif

LINUXDIR=$(TOP)/linux
LIBDIR=$(TOOLCHAIN_PATH)/lib
TOOLCHAIN=$(TOOLCHAIN_PATH)/bin
BINFILE=$(TOP)/binfile

#
# Paths
#
export PATH:=$(TOOLCHAIN):${PATH}

export TFTPPATH=/tftpboot/

#
#Source bases
#
export PLATFORM LINUXDIR LIBDIR BINFILE

#
# Cross-compile environment variables
#
# Build platform
export BUILD := i386-pc-linux-gnu
export HOSTCC := gcc

export TOOLPREFIX=mips-linux-uclibc-
export CROSS_COMPILE := mips-linux-uclibc-
#export CONFIGURE := ./configure arm-linux-gnu --build=$(BUILD)
export TOOLCHAIN


export CC := $(CROSS_COMPILE)gcc
export AR := $(CROSS_COMPILE)ar
export AS := $(CROSS_COMPILE)as
export LD := $(CROSS_COMPILE)ld
export NM := $(CROSS_COMPILE)nm
export READELF := $(CROSS_COMPILE)readelf
export RANLIB := $(CROSS_COMPILE)ranlib
export STRIP := $(CROSS_COMPILE)strip
export SIZE := $(CROSS_COMPILE)size

#
# Install and target directories
#
INSTALL_ROOT := $(TOP)/rootfs
export INSTALLDIR := $(INSTALL_ROOT)
export TARGETDIR := $(INSTALL_ROOT)

# Module Control
#
WSC=1

