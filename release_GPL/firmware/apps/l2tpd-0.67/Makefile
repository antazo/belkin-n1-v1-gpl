#include ../../rules.mk

LDFLAGS+= -Wl,-N -Wl,-Bstatic -Wl,-q -Wl,--no-undefined -Wl,--warn-once -Wl,--warn-common -Wl,--warn-constructors

CFLAGS+= $(DFLAGS) -Wall -DSANITY $(OSFLAGS) -DLINUX -DIP_ALLOCATION
HDRS=l2tp.h avp.h misc.h control.h call.h scheduler.h file.h aaa.h md5.h
OBJS=l2tpd.o pty.o misc.o control.o avp.o call.o network.o avpsend.o scheduler.o file.o aaa.o md5.o
LIBS= $(OSLIB) # -lc -lgcc# -lefence # efence for malloc checking
BIN=l2tpd
BINDIR=/usr/sbin
ETCDIR=/etc

all: $(BIN)

clean:
	rm -f $(OBJS) $(BIN)

$(BIN): $(OBJS) $(HDRS)
	$(CC) $(CFLAGS) -o $(BIN) $(DFLAGS) $(OBJS) $(LIBS)

install:
	$(STRIP) $(BIN)
	install -D $(BIN) $(INSTALLDIR)/usr/sbin/$(BIN)
