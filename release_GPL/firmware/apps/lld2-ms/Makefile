include ../../rule.mk

CFLAGS += -Os -s -Wall
BIN = lld2

CONFIG_FILES = lld2d.conf
CONFIG_FILES += icon.ico
CONFIG_FILES += f5d8231.large.ico

OBJS =  main.c event.c util.c packetio.c band.c \
	    state.c sessionmgr.c enumeration.c mapping.c seeslist.c \
	    tlv.c qospktio.c osl-linux.c

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -s -o $@ $^

install: all
	$(STRIP) $(BIN)
	cp -rf  $(BIN) $(INSTALLDIR)/usr/sbin/$(BIN)
	cp -rf $(CONFIG_FILES) $(INSTALLDIR)/etc/
clean:
	-rm -f $(BIN) *.o

