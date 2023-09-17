# $Id: Makefile,v 1.1 2007-08-16 09:38:49 oliver_hao Exp $
# http://miniupnp.free.fr/
# Author : Thomas Bernard
# for use with GNU Make
include ../../rule.mk
CFLAGS = -Wall -O2 -s -D_GNU_SOURCE -I ./include/ -I ../iptables-2.6/include/
#CFLAGS = -Wall -Os -D_GNU_SOURCE
RM = rm -f
INSTALL = install

BASEOBJS = miniupnpd.o upnphttp.o upnpdescgen.o upnpsoap.o \
           upnpreplyparse.o minixml.o \
		   getifaddr.o daemonize.o minissdp.o upnpevent.o 

LIB_OBJ = libminiupnpd.so libminiupnpdstatic.a 

.PHONY:	all clean install depend

all:	$(LIB_OBJ)
	make -C igd
libminiupnpd.so : $(BASEOBJS)
	$(CC) $(CFLAGS) -shared -Wl,-soname,libminiupnpd.so -o libminiupnpd.so $(BASEOBJS)

libminiupnpdstatic.a : $(BASEOBJS)
	$(AR) -r libminiupnpdstatic.a  $(BASEOBJS)
clean:
	$(RM) $(BASEOBJS) $(LNXOBJS) $(LIB_OBJ)
	make clean -C igd 

install:
	cp libminiupnpd.so $(INSTALLDIR)/lib/ 
	make install -C igd
# genuuid is using the uuidgen CLI tool which is part of libuuid
# from the e2fsprogs
genuuid:
	sed -i -e "s/^uuid=[-0-9a-f]*/uuid=`(genuuid||uuidgen) 2>/dev/null`/" miniupnpd.conf
