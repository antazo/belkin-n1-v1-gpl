/* $Id: //depot/sw/src3/linux/kernels/mips-linux-2.6.15/drivers/isdn/sc/debug.h#1 $
 *
 * Copyright (C) 1996  SpellCaster Telecommunications Inc.
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 *
 * For more information, please contact gpl-info@spellcast.com or write:
 *
 *     SpellCaster Telecommunications Inc.
 *     5621 Finch Avenue East, Unit #3
 *     Scarborough, Ontario  Canada
 *     M1B 2T9
 *     +1 (416) 297-8565
 *     +1 (416) 297-6433 Facsimile
 */

#define REQUEST_IRQ(a,b,c,d,e) request_irq(a,b,c,d,e)
#define FREE_IRQ(a,b) free_irq(a,b)
