/* linux/include/mtd/plat-ram.h
 *
 * (c) 2004 Simtec Electronics
 *	http://www.simtec.co.uk/products/SWLINUX/
 *	Ben Dooks <ben@simtec.co.uk>
 *
 * Generic platform device based RAM map
 *
 * $Id: //depot/sw/src3/linux/kernels/mips-linux-2.6.15/include/linux/mtd/plat-ram.h#1 $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef __LINUX_MTD_PLATRAM_H
#define __LINUX_MTD_PLATRAM_H __FILE__

#define PLATRAM_RO (0)
#define PLATRAM_RW (1)

struct platdata_mtd_ram {
	char			*mapname;
	char		       **probes;
	struct mtd_partition	*partitions;
	int			 nr_partitions;
	int			 bankwidth;

	/* control callbacks */

	void	(*set_rw)(struct device *dev, int to);
};

#endif /* __LINUX_MTD_PLATRAM_H */
