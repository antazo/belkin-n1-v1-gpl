#ifndef _ASM_M32R_UNALIGNED_H
#define _ASM_M32R_UNALIGNED_H

/* $Id: //depot/sw/src3/linux/kernels/mips-linux-2.6.15/include/asm-m32r/unaligned.h#1 $ */

/* orig : generic 2.4.18 */

/*
 * For the benefit of those who are trying to port Linux to another
 * architecture, here are some C-language equivalents.
 */

#include <asm/string.h>


#define get_unaligned(ptr) \
  ({ __typeof__(*(ptr)) __tmp; memmove(&__tmp, (ptr), sizeof(*(ptr))); __tmp; })

#define put_unaligned(val, ptr)				\
  ({ __typeof__(*(ptr)) __tmp = (val);			\
     memmove((ptr), &__tmp, sizeof(*(ptr)));		\
     (void)0; })


#endif  /* _ASM_M32R_UNALIGNED_H */
