#ifndef __iop_sap_out_defs_h
#define __iop_sap_out_defs_h

/*
 * This file is autogenerated from
 *   file:           ../../inst/io_proc/rtl/iop_sap_out.r
 *     id:           <not found>
 *     last modfied: Mon Apr 11 16:08:46 2005
 *
 *   by /n/asic/design/tools/rdesc/src/rdes2c --outfile iop_sap_out_defs.h ../../inst/io_proc/rtl/iop_sap_out.r
 *      id: $Id: //depot/sw/src3/linux/kernels/mips-linux-2.6.15/include/asm-cris/arch-v32/hwregs/iop/iop_sap_out_defs.h#1 $
 * Any changes here will be lost.
 *
 * -*- buffer-read-only: t -*-
 */
/* Main access macros */
#ifndef REG_RD
#define REG_RD( scope, inst, reg ) \
  REG_READ( reg_##scope##_##reg, \
            (inst) + REG_RD_ADDR_##scope##_##reg )
#endif

#ifndef REG_WR
#define REG_WR( scope, inst, reg, val ) \
  REG_WRITE( reg_##scope##_##reg, \
             (inst) + REG_WR_ADDR_##scope##_##reg, (val) )
#endif

#ifndef REG_RD_VECT
#define REG_RD_VECT( scope, inst, reg, index ) \
  REG_READ( reg_##scope##_##reg, \
            (inst) + REG_RD_ADDR_##scope##_##reg + \
	    (index) * STRIDE_##scope##_##reg )
#endif

#ifndef REG_WR_VECT
#define REG_WR_VECT( scope, inst, reg, index, val ) \
  REG_WRITE( reg_##scope##_##reg, \
             (inst) + REG_WR_ADDR_##scope##_##reg + \
	     (index) * STRIDE_##scope##_##reg, (val) )
#endif

#ifndef REG_RD_INT
#define REG_RD_INT( scope, inst, reg ) \
  REG_READ( int, (inst) + REG_RD_ADDR_##scope##_##reg )
#endif

#ifndef REG_WR_INT
#define REG_WR_INT( scope, inst, reg, val ) \
  REG_WRITE( int, (inst) + REG_WR_ADDR_##scope##_##reg, (val) )
#endif

#ifndef REG_RD_INT_VECT
#define REG_RD_INT_VECT( scope, inst, reg, index ) \
  REG_READ( int, (inst) + REG_RD_ADDR_##scope##_##reg + \
	    (index) * STRIDE_##scope##_##reg )
#endif

#ifndef REG_WR_INT_VECT
#define REG_WR_INT_VECT( scope, inst, reg, index, val ) \
  REG_WRITE( int, (inst) + REG_WR_ADDR_##scope##_##reg + \
	     (index) * STRIDE_##scope##_##reg, (val) )
#endif

#ifndef REG_TYPE_CONV
#define REG_TYPE_CONV( type, orgtype, val ) \
  ( { union { orgtype o; type n; } r; r.o = val; r.n; } )
#endif

#ifndef reg_page_size
#define reg_page_size 8192
#endif

#ifndef REG_ADDR
#define REG_ADDR( scope, inst, reg ) \
  ( (inst) + REG_RD_ADDR_##scope##_##reg )
#endif

#ifndef REG_ADDR_VECT
#define REG_ADDR_VECT( scope, inst, reg, index ) \
  ( (inst) + REG_RD_ADDR_##scope##_##reg + \
    (index) * STRIDE_##scope##_##reg )
#endif

/* C-code for register scope iop_sap_out */

/* Register rw_gen_gated, scope iop_sap_out, type rw */
typedef struct {
  unsigned int clk0_src       : 2;
  unsigned int clk0_gate_src  : 2;
  unsigned int clk0_force_src : 3;
  unsigned int clk1_src       : 2;
  unsigned int clk1_gate_src  : 2;
  unsigned int clk1_force_src : 3;
  unsigned int clk2_src       : 2;
  unsigned int clk2_gate_src  : 2;
  unsigned int clk2_force_src : 3;
  unsigned int clk3_src       : 2;
  unsigned int clk3_gate_src  : 2;
  unsigned int clk3_force_src : 3;
  unsigned int dummy1         : 4;
} reg_iop_sap_out_rw_gen_gated;
#define REG_RD_ADDR_iop_sap_out_rw_gen_gated 0
#define REG_WR_ADDR_iop_sap_out_rw_gen_gated 0

/* Register rw_bus0, scope iop_sap_out, type rw */
typedef struct {
  unsigned int byte0_clk_sel   : 3;
  unsigned int byte0_gated_clk : 2;
  unsigned int byte0_clk_inv   : 1;
  unsigned int byte1_clk_sel   : 3;
  unsigned int byte1_gated_clk : 2;
  unsigned int byte1_clk_inv   : 1;
  unsigned int byte2_clk_sel   : 3;
  unsigned int byte2_gated_clk : 2;
  unsigned int byte2_clk_inv   : 1;
  unsigned int byte3_clk_sel   : 3;
  unsigned int byte3_gated_clk : 2;
  unsigned int byte3_clk_inv   : 1;
  unsigned int dummy1          : 8;
} reg_iop_sap_out_rw_bus0;
#define REG_RD_ADDR_iop_sap_out_rw_bus0 4
#define REG_WR_ADDR_iop_sap_out_rw_bus0 4

/* Register rw_bus1, scope iop_sap_out, type rw */
typedef struct {
  unsigned int byte0_clk_sel   : 3;
  unsigned int byte0_gated_clk : 2;
  unsigned int byte0_clk_inv   : 1;
  unsigned int byte1_clk_sel   : 3;
  unsigned int byte1_gated_clk : 2;
  unsigned int byte1_clk_inv   : 1;
  unsigned int byte2_clk_sel   : 3;
  unsigned int byte2_gated_clk : 2;
  unsigned int byte2_clk_inv   : 1;
  unsigned int byte3_clk_sel   : 3;
  unsigned int byte3_gated_clk : 2;
  unsigned int byte3_clk_inv   : 1;
  unsigned int dummy1          : 8;
} reg_iop_sap_out_rw_bus1;
#define REG_RD_ADDR_iop_sap_out_rw_bus1 8
#define REG_WR_ADDR_iop_sap_out_rw_bus1 8

/* Register rw_bus0_lo_oe, scope iop_sap_out, type rw */
typedef struct {
  unsigned int byte0_clk_sel   : 3;
  unsigned int byte0_clk_ext   : 3;
  unsigned int byte0_gated_clk : 2;
  unsigned int byte0_clk_inv   : 1;
  unsigned int byte0_logic     : 2;
  unsigned int byte1_clk_sel   : 3;
  unsigned int byte1_clk_ext   : 3;
  unsigned int byte1_gated_clk : 2;
  unsigned int byte1_clk_inv   : 1;
  unsigned int byte1_logic     : 2;
  unsigned int dummy1          : 10;
} reg_iop_sap_out_rw_bus0_lo_oe;
#define REG_RD_ADDR_iop_sap_out_rw_bus0_lo_oe 12
#define REG_WR_ADDR_iop_sap_out_rw_bus0_lo_oe 12

/* Register rw_bus0_hi_oe, scope iop_sap_out, type rw */
typedef struct {
  unsigned int byte2_clk_sel   : 3;
  unsigned int byte2_clk_ext   : 3;
  unsigned int byte2_gated_clk : 2;
  unsigned int byte2_clk_inv   : 1;
  unsigned int byte2_logic     : 2;
  unsigned int byte3_clk_sel   : 3;
  unsigned int byte3_clk_ext   : 3;
  unsigned int byte3_gated_clk : 2;
  unsigned int byte3_clk_inv   : 1;
  unsigned int byte3_logic     : 2;
  unsigned int dummy1          : 10;
} reg_iop_sap_out_rw_bus0_hi_oe;
#define REG_RD_ADDR_iop_sap_out_rw_bus0_hi_oe 16
#define REG_WR_ADDR_iop_sap_out_rw_bus0_hi_oe 16

/* Register rw_bus1_lo_oe, scope iop_sap_out, type rw */
typedef struct {
  unsigned int byte0_clk_sel   : 3;
  unsigned int byte0_clk_ext   : 3;
  unsigned int byte0_gated_clk : 2;
  unsigned int byte0_clk_inv   : 1;
  unsigned int byte0_logic     : 2;
  unsigned int byte1_clk_sel   : 3;
  unsigned int byte1_clk_ext   : 3;
  unsigned int byte1_gated_clk : 2;
  unsigned int byte1_clk_inv   : 1;
  unsigned int byte1_logic     : 2;
  unsigned int dummy1          : 10;
} reg_iop_sap_out_rw_bus1_lo_oe;
#define REG_RD_ADDR_iop_sap_out_rw_bus1_lo_oe 20
#define REG_WR_ADDR_iop_sap_out_rw_bus1_lo_oe 20

/* Register rw_bus1_hi_oe, scope iop_sap_out, type rw */
typedef struct {
  unsigned int byte2_clk_sel   : 3;
  unsigned int byte2_clk_ext   : 3;
  unsigned int byte2_gated_clk : 2;
  unsigned int byte2_clk_inv   : 1;
  unsigned int byte2_logic     : 2;
  unsigned int byte3_clk_sel   : 3;
  unsigned int byte3_clk_ext   : 3;
  unsigned int byte3_gated_clk : 2;
  unsigned int byte3_clk_inv   : 1;
  unsigned int byte3_logic     : 2;
  unsigned int dummy1          : 10;
} reg_iop_sap_out_rw_bus1_hi_oe;
#define REG_RD_ADDR_iop_sap_out_rw_bus1_hi_oe 24
#define REG_WR_ADDR_iop_sap_out_rw_bus1_hi_oe 24

#define STRIDE_iop_sap_out_rw_gio 4
/* Register rw_gio, scope iop_sap_out, type rw */
typedef struct {
  unsigned int out_clk_sel   : 3;
  unsigned int out_clk_ext   : 4;
  unsigned int out_gated_clk : 2;
  unsigned int out_clk_inv   : 1;
  unsigned int out_logic     : 1;
  unsigned int oe_clk_sel    : 3;
  unsigned int oe_clk_ext    : 3;
  unsigned int oe_gated_clk  : 2;
  unsigned int oe_clk_inv    : 1;
  unsigned int oe_logic      : 2;
  unsigned int dummy1        : 10;
} reg_iop_sap_out_rw_gio;
#define REG_RD_ADDR_iop_sap_out_rw_gio 28
#define REG_WR_ADDR_iop_sap_out_rw_gio 28


/* Constants */
enum {
  regk_iop_sap_out_and                     = 0x00000002,
  regk_iop_sap_out_clk0                    = 0x00000000,
  regk_iop_sap_out_clk1                    = 0x00000001,
  regk_iop_sap_out_clk12                   = 0x00000002,
  regk_iop_sap_out_clk2                    = 0x00000002,
  regk_iop_sap_out_clk200                  = 0x00000001,
  regk_iop_sap_out_clk3                    = 0x00000003,
  regk_iop_sap_out_ext                     = 0x00000003,
  regk_iop_sap_out_gated                   = 0x00000004,
  regk_iop_sap_out_gio1                    = 0x00000000,
  regk_iop_sap_out_gio13                   = 0x00000002,
  regk_iop_sap_out_gio13_clk               = 0x0000000c,
  regk_iop_sap_out_gio15                   = 0x00000001,
  regk_iop_sap_out_gio18                   = 0x00000003,
  regk_iop_sap_out_gio18_clk               = 0x0000000d,
  regk_iop_sap_out_gio1_clk                = 0x00000008,
  regk_iop_sap_out_gio21_clk               = 0x0000000e,
  regk_iop_sap_out_gio23                   = 0x00000002,
  regk_iop_sap_out_gio29_clk               = 0x0000000f,
  regk_iop_sap_out_gio31                   = 0x00000003,
  regk_iop_sap_out_gio5                    = 0x00000001,
  regk_iop_sap_out_gio5_clk                = 0x00000009,
  regk_iop_sap_out_gio6_clk                = 0x0000000a,
  regk_iop_sap_out_gio7                    = 0x00000000,
  regk_iop_sap_out_gio7_clk                = 0x0000000b,
  regk_iop_sap_out_gio_in13                = 0x00000001,
  regk_iop_sap_out_gio_in21                = 0x00000002,
  regk_iop_sap_out_gio_in29                = 0x00000003,
  regk_iop_sap_out_gio_in5                 = 0x00000000,
  regk_iop_sap_out_inv                     = 0x00000001,
  regk_iop_sap_out_nand                    = 0x00000003,
  regk_iop_sap_out_no                      = 0x00000000,
  regk_iop_sap_out_none                    = 0x00000000,
  regk_iop_sap_out_rw_bus0_default         = 0x00000000,
  regk_iop_sap_out_rw_bus0_hi_oe_default   = 0x00000000,
  regk_iop_sap_out_rw_bus0_lo_oe_default   = 0x00000000,
  regk_iop_sap_out_rw_bus1_default         = 0x00000000,
  regk_iop_sap_out_rw_bus1_hi_oe_default   = 0x00000000,
  regk_iop_sap_out_rw_bus1_lo_oe_default   = 0x00000000,
  regk_iop_sap_out_rw_gen_gated_default    = 0x00000000,
  regk_iop_sap_out_rw_gio_default          = 0x00000000,
  regk_iop_sap_out_rw_gio_size             = 0x00000020,
  regk_iop_sap_out_spu0_gio0               = 0x00000002,
  regk_iop_sap_out_spu0_gio1               = 0x00000003,
  regk_iop_sap_out_spu0_gio12              = 0x00000004,
  regk_iop_sap_out_spu0_gio13              = 0x00000004,
  regk_iop_sap_out_spu0_gio14              = 0x00000004,
  regk_iop_sap_out_spu0_gio15              = 0x00000004,
  regk_iop_sap_out_spu0_gio2               = 0x00000002,
  regk_iop_sap_out_spu0_gio3               = 0x00000003,
  regk_iop_sap_out_spu0_gio4               = 0x00000002,
  regk_iop_sap_out_spu0_gio5               = 0x00000003,
  regk_iop_sap_out_spu0_gio6               = 0x00000002,
  regk_iop_sap_out_spu0_gio7               = 0x00000003,
  regk_iop_sap_out_spu1_gio0               = 0x00000005,
  regk_iop_sap_out_spu1_gio1               = 0x00000006,
  regk_iop_sap_out_spu1_gio12              = 0x00000007,
  regk_iop_sap_out_spu1_gio13              = 0x00000007,
  regk_iop_sap_out_spu1_gio14              = 0x00000007,
  regk_iop_sap_out_spu1_gio15              = 0x00000007,
  regk_iop_sap_out_spu1_gio2               = 0x00000005,
  regk_iop_sap_out_spu1_gio3               = 0x00000006,
  regk_iop_sap_out_spu1_gio4               = 0x00000005,
  regk_iop_sap_out_spu1_gio5               = 0x00000006,
  regk_iop_sap_out_spu1_gio6               = 0x00000005,
  regk_iop_sap_out_spu1_gio7               = 0x00000006,
  regk_iop_sap_out_timer_grp0_tmr2         = 0x00000004,
  regk_iop_sap_out_timer_grp1_tmr2         = 0x00000005,
  regk_iop_sap_out_timer_grp2_tmr2         = 0x00000006,
  regk_iop_sap_out_timer_grp3_tmr2         = 0x00000007,
  regk_iop_sap_out_tmr                     = 0x00000005,
  regk_iop_sap_out_yes                     = 0x00000001
};
#endif /* __iop_sap_out_defs_h */
