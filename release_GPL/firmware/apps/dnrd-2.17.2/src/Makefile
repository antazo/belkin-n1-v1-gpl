#CC		= gcc
#COPT		= -O1
#CDEF		= -D_REENTRANT
include ../../../rule.mk
#CWARN		= -Wall 
#CDBG		= -ggdb
CFLAGS		+= -DEMBED -DENABLE_PIDFILE
#CFLAGS		= ${CWARN} ${COPT} ${CDEF} ${CDBG} -DEMBED -DRTL_PATCHED
#LDFLAGS		+= -Wl,-elf2flt="-s 0x2000"
#LDFLAGS		+= -pthread
##LDFLAGS+=-L$(TOP)/nvram -L$(INSTALLDIR)/nvram/usr/lib -lnvram
#LIBS            += -lpthread
#LIBS		+=$(LDLIBS)
#INSTDIR		= /usr/local/sbin
#MANDIR		= /usr/local/man/man8
SHELL		= /bin/sh

SYSLIBS_DIR=../../libs

CFLAGS += -Os -Wall -I../../nvram -I../../rw_flash
#LIBS = -lnv
LFLAGS = -L../../nvram -L$(INSTALLDIR)/usr/lib -lnvram

all:	dnrd

clean:
	rm -f dnrd core tags ID *.o *.d *~ *.bak *.gdb

install: dnrd
	cp -f dnrd $(INSTALLDIR)/usr/sbin/
#	strip dnrd
#	install -m 0751 -o root -g root -s dnrd ${INSTDIR}
#	install -m 0644 -o root -g root -s ../doc/dnrd.8 ${MANDIR}

sources = args.c check.c dns.c lib.c master.c query.c relay.c srvnode.c udp.c \
	  cache.c common.c domnode.c main.c qid.c rand.c sig.c tcp.c

	  

#include $(sources:.c=.d)

dnrd:	$(sources:.c=.o)
	$(CC) -o $@ $^  $(LFLAGS)
#$(LIBS)

%.o : %.c Makefile
	$(CC) -c $(CFLAGS) $<

%.d: %.c
	@$(SHELL) -ec '$(CC) -MM $(CFLAGS) $< \
		      | sed '\''s/\($*\)\.o[ :]*/\1.o $@ : /g'\'' > $@; \
		      [ -s $@ ] || rm -f $@'
