#!/bin/sh
/opt/crosstool/uClibc_v5te_gcc_4_1_1-eabi-nfpu/bin/arm-linux-gcc \
-Os -march=armv5te -mtune=arm926ej-s -Wall -Wunused \
-Iinclude/ \
-DIPTABLES_VERSION=\"1.3.5\"  -fPIC -o extensions/hello.o -c extensions/hello.c
