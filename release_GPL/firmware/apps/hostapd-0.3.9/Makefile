include ../../rule.mk

ifneq ($(strip $(TOOLPREFIX)),)
CROSS:=$(TOOLPREFIX)
endif

CC		=$(CROSS)gcc
STRIP		=$(CROSS)strip
STRIPFLAGS	= --strip-all --remove-section=.note --remove-section=.comment
DIR_WPA_SUPPLICANT=.
DIR_HOSTAP=.

PREFIX:=`$(TOPDIR)/sbin

ifndef CFLAGS
CFLAGS = -MMD -Wall -D_BYTE_ORDER=_BIG_ENDIAN
endif

ifeq ($(strip $(TOOLPREFIX)), mips-linux-)
CFLAGS += -mips2 -Os
STRIPFLAGS += --remove-section=.pdr
else
CFLAGS += -Os
endif
STRIPCMD	=$(STRIP) $(STRIPFLAGS)

# define HOSTAPD_DUMP_STATE to include SIGUSR1 handler for dumping state to
# a file (undefine it, if you want to save in binary size)
CFLAGS += -DHOSTAPD_DUMP_STATE

# Include directories for CVS version
CFLAGS += -I. -I$(DIR_HOSTAP) -I../utils -I$(DIR_WPA_SUPPLICANT)

# Uncomment following line and set the path to your kernel tree include
# directory if your C library does not include all header files.
# CFLAGS += -DUSE_KERNEL_HEADERS -I/usr/src/linux/include

OBJS =	hostapd.o eloop.o ieee802_1x.o eapol_sm.o radius.o md5.o rc4.o \
	common.o ieee802_11.o config.o ieee802_11_auth.o accounting.o \
	sta_info.o radius_client.o sha1.o wpa.o aes_wrap.o ctrl_iface.o \
	driver_conf.o

-include .config

ifdef CONFIG_IAPP
CFLAGS += -DCONFIG_IAPP
OBJS += iapp.o
endif

ifdef CONFIG_RSN_PREAUTH
CFLAGS += -DCONFIG_RSN_PREAUTH
CONFIG_L2_PACKET=y
endif

ifdef CONFIG_DRIVER_HOSTAP
CFLAGS += -DCONFIG_DRIVER_HOSTAP
OBJS += driver.o
endif

ifdef CONFIG_DRIVER_WIRED
CFLAGS += -DCONFIG_DRIVER_WIRED
OBJS += driver_wired.o
endif

ifdef CONFIG_DRIVER_MADWIFI
CFLAGS += -DCONFIG_DRIVER_MADWIFI
OBJS += driver_madwifi.o
CONFIG_L2_PACKET=y
endif

ifdef CONFIG_DRIVER_PRISM54
CFLAGS += -DCONFIG_DRIVER_PRISM54
OBJS += driver_prism54.o
endif

ifdef CONFIG_DRIVER_BSD
CFLAGS += -DCONFIG_DRIVER_BSD
OBJS += driver_bsd.o
CONFIG_L2_PACKET=y
CONFIG_DNET_PCAP=y
endif

ifdef CONFIG_DRIVER_TEST
CFLAGS += -DCONFIG_DRIVER_TEST
OBJS += driver_test.o
endif

ifdef CONFIG_L2_PACKET
OBJS += $(DIR_WPA_SUPPLICANT)/l2_packet.o
endif

ifdef CONFIG_DNET_PCAP
CFLAGS += -DUSE_DNET_PCAP
LIBS +=-ldnet -lpcap
endif

ifdef CONFIG_EAP_MD5
CFLAGS += -DEAP_MD5
OBJS += eap_md5.o
endif

ifdef CONFIG_EAP_TLS
CFLAGS += -DEAP_TLS
OBJS += eap_tls.o
TLS_FUNCS=y
endif

ifdef CONFIG_EAP_PEAP
CFLAGS += -DEAP_PEAP
OBJS += eap_peap.o
TLS_FUNCS=y
CONFIG_EAP_TLV=y
CONFIG_EAP_MSCHAPV2=y
endif

ifdef CONFIG_EAP_TTLS
CFLAGS += -DEAP_TTLS
OBJS += eap_ttls.o
TLS_FUNCS=y
endif

ifdef CONFIG_EAP_MSCHAPV2
CFLAGS += -DEAP_MSCHAPv2
OBJS += eap_mschapv2.o
MS_FUNCS=y
endif

ifdef CONFIG_EAP_GTC
CFLAGS += -DEAP_GTC
OBJS += eap_gtc.o
endif

ifdef CONFIG_EAP_SIM
CFLAGS += -DEAP_SIM
OBJS += eap_sim.o $(DIR_WPA_SUPPLICANT)/eap_sim_common.o
# Example EAP-SIM interface for GSM authentication. This can be replaced with
# another file implementating the interface specified in eap_sim_db.h.
OBJS += eap_sim_db.o
endif

ifdef CONFIG_EAP_TLV
CFLAGS += -DEAP_TLV
OBJS += eap_tlv.o
endif

ifdef CONFIG_EAP
CFLAGS += -DEAP_AUTHENTICATOR
OBJS += eap.o eap_identity.o
endif

ifdef TLS_FUNCS
# Shared TLS functions (needed for EAP_TLS, EAP_PEAP, and EAP_TTLS)
CFLAGS += -DEAP_TLS_FUNCS
OBJS += eap_tls_common.o $(DIR_WPA_SUPPLICANT)/tls_openssl.o
LIBS += -lssl -lcrypto
LIBS_p += -lcrypto
else
OBJS += $(DIR_WPA_SUPPLICANT)/tls_none.o
endif

ifdef CONFIG_PKCS12
CFLAGS += -DPKCS12_FUNCS
endif

ifdef MS_FUNCS
ifndef TLS_FUNCS
LIBS += -lcrypto
endif
OBJS += $(DIR_WPA_SUPPLICANT)/ms_funcs.o $(DIR_WPA_SUPPLICANT)/crypto.o
endif

ifdef CONFIG_RADIUS_SERVER
CFLAGS += -DRADIUS_SERVER
OBJS += radius_server.o
endif

ifdef CONFIG_JUMPSTART
CFLAGS += -DJUMPSTART  -DOPENSSL_NO_BIO -DOPENSSL_NO_ERR -DOPENSSL_NO_ENGINE
CFLAGS += -DOPENSSL_NO_RSA
OBJS += bn_add.o bn_asm.o bn_ctx.o bn_div.o bn_exp.o bn_gcd.o bn_lib.o \
	bn_mod.o bn_mont.o bn_mul.o bn_rand.o bn_recp.o bn_shift.o \
	bn_sqr.o bn_word.o \
	dh_gen.o dh_key.o dh_lib.o js_prime.o \
	cryptlib.o digest.o ex_data.o lhash.o md_rand.o mem_clr.o mem.o \
	m_sha1.o rand_lib.o stack.o \
	jswAuth.o jswAuthSm.o jswMsg.o
endif

ifeq ($(WSC),1)
CFLAGS += -DLINUX_WSC -DWSC_P2 -DWSC_FEATURE  -I../wsc -I../nvram -I$(TOP)/drivers/wlan/madwifi_wsc/madwifi  
LIBS +=-L../wsc -lwsc -L../nvram -lnvram
else
CFLAGS += -I$(TOP)/drivers/wlan/madwifi/madwifi 
endif

ALL=hostapd 

all: verify_config $(ALL)

verify_config:
	@if [ ! -r .config ]; then \
		echo 'Building hostapd requires a configuration file'; \
		echo '(.config). See README for more instructions. You can'; \
		echo 'run "cp defconfig .config" to create an example'; \
		echo 'configuration.'; \
		exit 1; \
	fi

install: 
	cp -f hostapd $(TOP)/rootfs/sbin/hostapd

hostapd: $(OBJS)
	$(CC) -o hostapd $(OBJS) $(LIBS)
	$(STRIPCMD) hostapd

driver_conf.c: Makefile .config
	rm -f driver_conf.c
	echo '/* THIS FILE AUTOMATICALLY GENERATED, DO NOT EDIT! */' \
							> driver_conf.c
	echo '#include <stdlib.h>'			>> driver_conf.c
	echo '#include <stdio.h>'			>> driver_conf.c
	echo '#include <sys/types.h>'			>> driver_conf.c
	echo '#include <netinet/in.h>'			>> driver_conf.c
	echo '#include "hostapd.h"'			>> driver_conf.c
	echo '#include "driver.h"'			>> driver_conf.c
ifdef CONFIG_DRIVER_HOSTAP
	echo "void hostap_driver_register(void);"	>> driver_conf.c
endif
ifdef CONFIG_DRIVER_WIRED
	echo "void wired_driver_register(void);"	>> driver_conf.c
endif
ifdef CONFIG_DRIVER_MADWIFI
	echo "void madwifi_driver_register(void);"	>> driver_conf.c
endif
ifdef CONFIG_DRIVER_PRISM54
	echo "void prism54_driver_register(void);"	>> driver_conf.c
endif
ifdef CONFIG_DRIVER_BSD
	echo "void bsd_driver_register(void);"		>> driver_conf.c
endif
ifdef CONFIG_DRIVER_TEST
	echo "void test_driver_register(void);"		>> driver_conf.c
endif
	echo 'void register_drivers(void) {'		>> driver_conf.c
ifdef CONFIG_DRIVER_HOSTAP
	echo "hostap_driver_register();"		>> driver_conf.c
endif
ifdef CONFIG_DRIVER_WIRED
	echo "wired_driver_register();"			>> driver_conf.c
endif
ifdef CONFIG_DRIVER_MADWIFI
	echo "madwifi_driver_register();"		>> driver_conf.c
endif
ifdef CONFIG_DRIVER_PRISM54
	echo "prism54_driver_register();"		>> driver_conf.c
endif
ifdef CONFIG_DRIVER_BSD
	echo "bsd_driver_register();"			>> driver_conf.c
endif
ifdef CONFIG_DRIVER_TEST
	echo "test_driver_register();"			>> driver_conf.c
endif
	echo '}'					>> driver_conf.c

hostapd_cli: hostapd_cli.o hostapd_ctrl.o
	$(CC) -o hostapd_cli hostapd_cli.o hostapd_ctrl.o

clean:
	rm -f core *~ *.o hostapd *.d driver_conf.c

-include $(OBJS:%.o=%.d)


