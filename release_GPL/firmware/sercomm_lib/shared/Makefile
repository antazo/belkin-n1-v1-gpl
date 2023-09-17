include ../../rule.mk
INC_KERNEL_PATH=$(LINUXDIR)/include

CFLAGS  = -Os -s -Wall  -I$(INC_KERNEL_PATH)
LDFLAGS	+= -L../nvram

all: eth_link.o fw.o fw_time.o cagent.o

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<
	
install:
ifneq ($(WL_PREFIX), 7)
	install 5416regc $(INSTALLDIR)/sbin
endif	

clean:
	rm -rf *~ *.o 

