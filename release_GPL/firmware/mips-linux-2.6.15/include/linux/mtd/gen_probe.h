/*
 * (C) 2001, 2001 Red Hat, Inc.
 * GPL'd
 * $Id: //depot/sw/src3/linux/kernels/mips-linux-2.6.15/include/linux/mtd/gen_probe.h#1 $
 */

#ifndef __LINUX_MTD_GEN_PROBE_H__
#define __LINUX_MTD_GEN_PROBE_H__

#include <linux/mtd/flashchip.h>
#include <linux/mtd/map.h>
#include <linux/mtd/cfi.h>
#include <linux/bitops.h>

struct chip_probe {
	char *name;
	int (*probe_chip)(struct map_info *map, __u32 base,
			  unsigned long *chip_map, struct cfi_private *cfi);
};

struct mtd_info *mtd_do_chip_probe(struct map_info *map, struct chip_probe *cp);

#endif /* __LINUX_MTD_GEN_PROBE_H__ */
