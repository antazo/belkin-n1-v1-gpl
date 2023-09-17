/* =============================================================================      
 * Copyright (C) 2006-2007, Sercomm (Suzhou) R&D Center,  All Rights Reserved
 * =============================================================================
 */
 
#define LINUX_PORTING
#include <assert.h>
#define ASSERT     assert
#define OK 0
#define ERROR -1

#define TRUE 1
#define FALSE 0

#ifdef VXWORKS
#include "wlantype.h"
#else
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>

typedef char                    A_CHAR;
typedef unsigned char           A_UCHAR;
typedef A_CHAR                  A_INT8;
typedef A_UCHAR                 A_UINT8;
typedef short                   A_INT16;
typedef unsigned short          A_UINT16;
typedef int                     A_INT32;
typedef unsigned int            A_UINT32;
typedef unsigned int            A_UINT;
typedef A_UCHAR                 A_BOOL;
typedef unsigned long long      A_UINT64;

typedef A_UINT32                UINT32;
typedef A_INT16                 INT16;
typedef A_INT32			INT32;
typedef char			CHAR;
typedef unsigned char		BYTE;
typedef unsigned short 		WORD;
typedef unsigned long		DWORD;
typedef void 			VOID;
#endif

#define A_swab16(x) \
        ((A_UINT16)( \
                (((A_UINT16)(x) & (A_UINT16)0x00ffU) << 8) | \
                (((A_UINT16)(x) & (A_UINT16)0xff00U) >> 8) ))
#define A_swab32(x) \
        ((A_UINT32)( \
                (((A_UINT32)(x) & (A_UINT32)0x000000ffUL) << 24) | \
                (((A_UINT32)(x) & (A_UINT32)0x0000ff00UL) <<  8) | \
                (((A_UINT32)(x) & (A_UINT32)0x00ff0000UL) >>  8) | \
                (((A_UINT32)(x) & (A_UINT32)0xff000000UL) >> 24) ))
#ifdef WIN32
/* Windows chose not to implement the standard ULL constant suffix */
#define A_swab64(x) \
        ((A_UINT64)( \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x00000000000000ff) << 56) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x000000000000ff00) << 40) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x0000000000ff0000) << 24) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x00000000ff000000) <<  8) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x000000ff00000000) >>  8) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x0000ff0000000000) >> 24) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x00ff000000000000) >> 40) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0xff00000000000000) >> 56) ))
#else /* WIN32 */
#define A_swab64(x) \
        ((A_UINT64)( \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x00000000000000ffULL) << 56) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x000000000000ff00ULL) << 40) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x0000000000ff0000ULL) << 24) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x00000000ff000000ULL) <<  8) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x000000ff00000000ULL) >>  8) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x0000ff0000000000ULL) >> 24) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0x00ff000000000000ULL) >> 40) | \
                (A_UINT64)(((A_UINT64)(x) & (A_UINT64)0xff00000000000000ULL) >> 56) ))
#endif /* WIN32 */

#ifdef BIG_ENDIAN

#define cpu2le64(x) A_swab64((x))
#define le2cpu64(x) A_swab64((x))
#define cpu2le32(x) A_swab32((x))
#define le2cpu32(x) A_swab32((x))
#define cpu2le16(x) A_swab16((x))
#define le2cpu16(x) A_swab16((x))
#define cpu2be64(x) ((A_UINT64)(x))
#define be2cpu64(x) ((A_UINT64)(x))
#define cpu2be32(x) ((A_UINT32)(x))
#define be2cpu32(x) ((A_UINT32)(x))
#define cpu2be16(x) ((A_UINT16)(x))
#define be2cpu16(x) ((A_UINT16)(x))

#else /* Little_Endian */

#define cpu2le64(x) ((A_UINT64)(x))
#define le2cpu64(x) ((A_UINT64)(x))
#define cpu2le32(x) ((A_UINT32)(x))
#define le2cpu32(x) ((A_UINT32)(x))
#define cpu2le16(x) ((A_UINT16)(x))
#define le2cpu16(x) ((A_UINT16)(x))
#define cpu2be64(x) A_swab64((x))
#define be2cpu64(x) A_swab64((x))
#define cpu2be32(x) A_swab32((x))
#define be2cpu32(x) A_swab32((x))
#define cpu2be16(x) A_swab16((x))
#define be2cpu16(x) A_swab16((x))

#endif /* Endianness */


#ifdef __GNUC__
#define __ATTRIB_PACK           __attribute__ ((packed))
#define __ATTRIB_PRINTF         __attribute__ ((format (printf, 1, 2)))
#define __ATTRIB_NORETURN       __attribute__ ((noreturn))
#define INLINE                  __inline__
#else /* Not GCC */
#define __ATTRIB_PACK
#define __ATTRIB_PRINTF
#define __ATTRIB_NORETURN
#define INLINE                  __inline
#endif /* End __GNUC__ */

typedef enum {
    A_ERROR = -1,               /* Generic error return */
    A_OK = 0,                   /* success */
                                /* Following values start at 1 */
    A_DEVICE_NOT_FOUND,         /* not able to find PCI device */
    A_NO_MEMORY,                /* not able to allocate memory, not available */
    A_MEMORY_NOT_AVAIL,         /* memory region is not free for mapping */
    A_NO_FREE_DESC,             /* no free descriptors available */
    A_BAD_ADDRESS,              /* address does not match descriptor */
    A_WIN_DRIVER_ERROR,         /* used in NT_HW version, if problem at init */
    A_REGS_NOT_MAPPED,          /* registers not correctly mapped */
    A_EPERM,                    /* Not superuser */
    A_EACCES,                   /* Access denied */
    A_ENOENT,                   /* No such entry, search failed, etc. */
    A_EEXIST,                   /* The object already exists (can't create) */
    A_EFAULT,                   /* Bad address fault */
    A_EBUSY,                    /* Object is busy */
    A_EINVAL,                   /* Invalid parameter */
    A_EMSGSIZE,                 /* Inappropriate message buffer length */
    A_ECANCELED,                /* Operation canceled */
    A_ENOTSUP,                  /* Operation not supported */
    A_ECOMM,                    /* Communication error on send */
    A_EPROTO,                   /* Protocol error */
    A_ENODEV,                   /* No such device */
    A_NO_RESOURCE,              /* No resources for requested operation */
    A_HARDWARE,                 /* Hardware failure */
    A_PENDING,                  /* Asynchronous routine; will send up results later (typically in callback) */
    A_EBADCHANNEL,              /* The channel cannot be used */
    A_DECRYPT_ERROR,            /* Decryption error */
    A_DECOMP_ERROR,             /* Decompression error */
    A_CRC_ERROR,               /* RX CRC error */
    A_PHY_ERROR,                /* RX PHY error */
    A_CONSUMED,                 /* Object was consumed */
    A_TIMEOUT,
    A_BUFFER_TOO_SMALL
} A_STATUS;

/*
 * Define some useful macros
 */


#define A_MAX(x, y)         (((x) > (y)) ? (x) : (y))
#define A_MIN(x, y)         (((x) < (y)) ? (x) : (y))
#define A_ABS(x)            (((x) >= 0) ? (x) : (-(x)))
#define A_LPF_RATE(x, y, len) ((x) ? (((x) * ((len) - 1) + (y)) / (len)) : (y))
#define A_ROUNDUP(x, y)     ((((x) + ((y) - 1)) / (y)) * (y))
#define A_ROUNDUP_PAD(x, y) (A_ROUNDUP(x, y) - (x))
#define MAKE_BOOL(x)        ((x) ? TRUE : FALSE)
#define A_TOLOWER(c)        (((c) >= 'A' && (c) <= 'Z') ? ((c)-'A'+'a') : (c))
#define A_TOUPPER(c)        (((c) >= 'a' && (c) <= 'z') ? ((c)-'a'+'A') : (c))
#define TU_TO_MS(x)         ((x) * 1024 / 1000)
#define TU_TO_US(x)         ((x) << 10)
#define MS_TO_TU(x)         ((x) * 1000 / 1024)
#define KHZ_TO_MHZ(x)       ((x) / 1000)
#define MHZ_TO_KHZ(x)       ((x) * 1000)

#define min(a,b)        ( (a) < (b) ? (a) : (b) )
#define max(a,b)        ( (a) > (b) ? (a) : (b) )
									   
#define sc_printf           printf

#ifdef LINUX_PORTING
#define SetByte(dest,source,len) memcpy((dest),(source),(len))
char * generate_pin(void);
WORD GetWord(BYTE * buf);
DWORD GetDword(BYTE * buf);
VOID SetWord(BYTE * buf, WORD wValue);
VOID SetDword(BYTE * buf, DWORD dwValue);
//int RAND_poll(void);
//int hostapd_get_rand(BYTE *buf, size_t len);					     
#endif					     

