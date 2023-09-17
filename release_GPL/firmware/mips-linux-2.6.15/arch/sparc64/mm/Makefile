# $Id: //depot/sw/src3/linux/kernels/mips-linux-2.6.15/arch/sparc64/mm/Makefile#1 $
# Makefile for the linux Sparc64-specific parts of the memory manager.
#

EXTRA_AFLAGS := -ansi
EXTRA_CFLAGS := -Werror

obj-y    := ultra.o tlb.o fault.o init.o generic.o

obj-$(CONFIG_HUGETLB_PAGE) += hugetlbpage.o
