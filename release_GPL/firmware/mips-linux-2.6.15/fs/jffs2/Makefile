#
# Makefile for the Linux Journalling Flash File System v2 (JFFS2)
#
# $Id: //depot/sw/src3/linux/kernels/mips-linux-2.6.15/fs/jffs2/Makefile#1 $
#

obj-$(CONFIG_JFFS2_FS) += jffs2.o

jffs2-y	:= compr.o dir.o file.o ioctl.o nodelist.o malloc.o
jffs2-y	+= read.o nodemgmt.o readinode.o write.o scan.o gc.o
jffs2-y	+= symlink.o build.o erase.o background.o fs.o writev.o
jffs2-y	+= super.o debug.o

jffs2-$(CONFIG_JFFS2_FS_WRITEBUFFER)	+= wbuf.o
jffs2-$(CONFIG_JFFS2_RUBIN)	+= compr_rubin.o
jffs2-$(CONFIG_JFFS2_RTIME)	+= compr_rtime.o
jffs2-$(CONFIG_JFFS2_ZLIB)	+= compr_zlib.o
jffs2-$(CONFIG_JFFS2_SUMMARY)   += summary.o
