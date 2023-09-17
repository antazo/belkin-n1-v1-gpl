#
# Makefile for cron daemon
#
#


#CC=mips-uclibc-gcc

all: crond 

crond : ../nvram/nvram.o ../shared/fw_time.o cron.o cron-parent.o
	$(CC) -s -o $@ $(LDFLAGS)  $^ 

install: all
	install -D crond $(INSTALLDIR)/usr/sbin/crond
clean:
	rm -f *~ crond *.o
