# $Id: Makefile,v 1.1 2007-08-16 09:41:19 oliver_hao Exp $
# http://miniupnp.free.fr/
# Author : Thomas Bernard
# for use with GNU Make
include ../../../rule.mk

CFLAGS = -Wall -O2 -s -D_GNU_SOURCE -I ../include -I ./include -I ../../iptables-2.6/include/ -L ../
LDFLAGS = 
#CFLAGS = -Wall -Os -D_GNU_SOURCE
RM = rm -f
INSTALL = install

BASEOBJS = igd_descgen.o igd_eventxml.o igd_globalvars.o igd_soap.o \
           igd_upnp.o port.o igd_permissions.o igd_redirect.o options.o
		   
LNXOBJS = linux/getifstats.o linux/iptcrdr.o

LIBS = ../../iptables-2.6/libiptc/libiptc.a -lminiupnpd

EXECUTABLES = igd_upnpd

.PHONY:	all clean install depend

all: $(BASEOBJS) $(LNXOBJS)
	$(CC) $(CFLAGS) $(BASEOBJS) $(LNXOBJS) $(LIBS) -o $(EXECUTABLES)
clean:
	$(RM) $(BASEOBJS) $(LNXOBJS) $(EXECUTABLES)

install:	
	cp $(EXECUTABLES) $(INSTALLDIR)/usr/sbin
	cp -rf ./upnp_xml $(TARGETDIR)/usr/
