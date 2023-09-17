# $Id: Makefile,v 1.1 2007-07-04 09:33:45 oliver_hao Exp $
# made for GNU Make
CFLAGS = -Wall -g
EXECUTABLES = testobsdrdr testgetifstats

all:	$(EXECUTABLES)

clean:
	rm -f *.o $(EXECUTABLES)

testobsdrdr:	testobsdrdr.o obsdrdr.o

obsdrdr.o:	obsdrdr.c obsdrdr.h

testobsdrdr.o:	testobsdrdr.c obsdrdr.h

testgetifstats:	testgetifstats.o getifstats.o -lkvm

