CFLAGS += -Os -Wall -s 
BIN =syslogd #klogd


LIBS  = syslogd.c klogd.c ../nvram/nvram.o ../shared/fw_time.o

all: make_links $(BIN) 

syslogd:$(LIBS)
	$(CC) $(CFLAGS) -o $@ $(LIBS)
	$(STRIP) $@
#klogd:klogd.c
#	$(CC) $(CFLAGS) -o $@ $^

install:
#	rm -f klogd
#	ln -s syslogd klogd
#	cp -a syslogd klogd ../../target/sbin
	install -D syslogd $(INSTALLDIR)/sbin/syslogd
	$(STRIP) $(INSTALLDIR)/sbin/syslogd
	ln -sf /sbin/syslogd $(INSTALLDIR)/sbin/klogd
clean:
	rm -f $(BIN) 

make_links:
	./mklnks
