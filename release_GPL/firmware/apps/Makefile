#
# make all apps/* and install to ../rootfs directory
#

ifeq ($(TOP),)
TOP := $(shell pwd)/..
export TOP
endif

include ../rule.mk

IPTABLES = iptables-2.6

#applications directory
obj-y += ppp
obj-y += udhcpd
obj-y += ez-ipupdate-3.0.11b8
obj-y += syslogd
obj-y += cron
obj-y += pptp-linux-1.3.1
obj-y += $(IPTABLES)
obj-y += l2tpd-0.67
obj-y += busybox
obj-y += wireless_tools-28
obj-y += hostapd-0.3.9
obj-y += dnrd-2.17.2
obj-y += miniupnpd
obj-y += lld2-ms
obj-clean := $(foreach obj,$(obj-y) $(obj-n),$(obj)-clean)
obj-install := $(foreach obj,$(obj-y),$(obj)-install)
#end of applications

app: $(obj-y)

install: $(obj-install) etc_install

clean: $(obj-clean)

# not do now
backup_rootdir:   
	@echo pack root file structure to tgz
	if ( test -e $(ROOTFS) ) then rm -rf $(ROOTFS); fi
	cd ../tools && tar cvzf $(ROOTFS) ../
                                                                                
busybox-clean:
	cd ./busybox; $(MAKE) PREFIX=$(INSTALL_ROOT) clean
	
etc_install:
	install -d $(INSTALL_ROOT)/etc
	cp -a etc/* $(INSTALL_ROOT)/etc
	cd $(INSTALL_ROOT) && rm -f resolv.conf version udhcpd.conf htpasswd
	ln -sf /var/resolv.conf $(INSTALL_ROOT)/etc/resolv.conf
	ln -sf /var/version	$(INSTALL_ROOT)/etc/version
	ln -sf /var/udhcpd.conf	$(INSTALL_ROOT)/etc/udhcpd.conf
	ln -sf /var/htpasswd	$(INSTALL_ROOT)/etc/htpasswd

busybox-install:
	cd ./busybox; $(MAKE) PREFIX=$(INSTALL_ROOT) install

$(IPTABLES):
	$(MAKE) -C $(IPTABLES) BINDIR=/usr/sbin LIBDIR=/usr/lib KERNEL_DIR=$(LINUXDIR)

$(IPTABLES)-install:
	install -d $(INSTALLDIR)/usr/lib/iptables
	install -D $(IPTABLES)/iptables $(INSTALLDIR)/usr/sbin/iptables
	$(STRIP) $(INSTALLDIR)/usr/sbin/iptables

udhcpd-install:
	install -D udhcpd/udhcpd $(INSTALLDIR)/usr/sbin/udhcpd
	$(STRIP) $(INSTALLDIR)/usr/sbin/udhcpd
	cd $(INSTALLDIR)/usr/sbin && ln -sf udhcpd udhcpc

upnp: netconf nvram 

#
# Generic rules
#

%:
	[ ! -d $* ] || $(MAKE) -C $*

%-clean:
	[ ! -d $* ] || $(MAKE) -C $* clean

%-install:
	[ ! -d $* ] || $(MAKE) -C $* install 

%-single:
	[ ! -d $* ] || $(MAKE) -C $* && \
	$(MAKE) -C $* install && \
	$(MAKE) -C ../apps rootfs_build

$(obj-y) $(obj-n) $(obj-clean) $(obj-install) $(obj-single): dummy

.PHONY: all clean distclean mrproper install package single
.PHONY: conf mconf oldconf kconf kmconf config menuconfig oldconfig
.PHONY: dummy
   

