# make all

TOP := $(shell pwd)
export TOP

export MAKEARCH=$(MAKE) ARCH=$(PLATFORM) CROSS_COMPILE=$(CROSS_COMPILE)

ENTRY=`$(READELF) -a vmlinux|grep "Entry"|cut -d":" -f 2`
LDADR=`$(READELF) -a vmlinux|grep "\[ 1\]"|cut -d" " -f 26`

# check if project.mk exist, if not, exit
PROJECT_MK_EXIST=$(shell if [ -f project.mk ];then echo 1;else echo 0;fi )
ifeq ($(PROJECT_MK_EXIST),1)
include project.mk
else
$(error Please run ./prepare_compile.sh first)
endif

include ./rule.mk

export BUS=PCI
export MADWIFITARGET=mipsisa32-be-elf
export TOPDIR:= $(TOP)
export KERNELPATH:= $(LINUXDIR)
export TOOLPATH:= $(TOOLCHAIN_PATH)

export MODULEPATH:= $(INSTALL_ROOT)/lib/modules/2.6.15/net
ENETDIR=$(TOP)/drivers/net/ag7100_giga/

all: first kernel_build apps image

kernel_build:
	@echo " Making Kernel Build Version $(EXTRAVERSION)"
	ln -sf mips-linux-2.6.15 linux
	cd $(LINUXDIR) && $(MAKEARCH) vmlinux.bin
	cd $(LINUXDIR)/arch/$(PLATFORM)/boot && \
	gzip -f vmlinux.bin && \
	cp vmlinux.bin.gz $(BINFILE);
	cd $(LINUXDIR) && rm -f vmlinux.info
	cd $(LINUXDIR) && echo "entry:"${ENTRY} >> vmlinux.info
	cd $(LINUXDIR) && echo "link: 0x"${LDADR} >> vmlinux.info && \
        cp vmlinux.info $(BINFILE) 
	    
apps:
	$(MAKE) -C apps 
	$(MAKE) -C apps install
	
first:
	rm -fr $(INSTALL_ROOT)
	sudo tar -xzf rootfs.tgz
	sudo chown $(USER) rootfs -Rh

image:
	if ( test -e $(BINFILE)/rootfs.squashfs) then rm -rf $(BINFILE)/rootfs.squashfs; fi
	find ./rootfs -name "CVS" -type d | xargs rm -rf
	echo `date -R` > ./rootfs/etc/build_time
	echo `logname` > ./rootfs/etc/builder
	sudo chmod 777 rootfs -R
	./tools/mksquashfs ./rootfs $(BINFILE)/rootfs.squashfs -all-root -be -b 65536 -noappend
	./bb
	@echo "make $@ finished on `date -R`"
	
.PHONY: clean first apps drivers
clean: kernel-clean apps-clean
	rm -fr $(INSTALL_ROOT)

kernel-clean:
	cd $(LINUXDIR) &&  $(MAKEARCH) mrproper 

apps-clean:
	$(MAKE) -C apps clean
