#include ../../rules.mk

CFLAGS += -Os -Wall 
LIBS = 
LFLAGS = 

OBJS = bpalogin.o protocol.o transaction.o gen_md5.o unixmain.o ../nvram/nvram.o

bpalogin: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS) $(LFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -fr *.o bpalogin

$(OBJS): bpalogin.h

install: bpalogin bpalogin.init
	install -D bpalogin $(INSTALLDIR)/usr/sbin/bpalogin
	$(STRIP) $(INSTALLDIR)/usr/sbin/bpalogin
