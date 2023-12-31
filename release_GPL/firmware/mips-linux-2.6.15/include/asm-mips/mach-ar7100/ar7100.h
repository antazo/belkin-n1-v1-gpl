#ifndef _AR7100_H
#define _AR7100_H

#ifdef CONFIG_AR9100
#ifndef AR9100
#define AR9100
#endif
#endif

#include <asm/addrspace.h>

typedef unsigned int ar7100_reg_t;

#define ar7100_reg_rd(_phys)    (*(volatile ar7100_reg_t *)KSEG1ADDR(_phys))
#define ar7100_reg_wr_nf(_phys, _val) \
                    ((*(volatile ar7100_reg_t *)KSEG1ADDR(_phys)) = (_val))

#define ar7100_reg_wr(_phys, _val) do {     \
         ar7100_reg_wr_nf(_phys, _val);     \
         ar7100_reg_rd(_phys);       \
}while(0);

#define ar7100_reg_rmw_set(_reg, _mask)  do {                        \
    ar7100_reg_wr((_reg), (ar7100_reg_rd((_reg)) | (_mask)));      \
    ar7100_reg_rd((_reg));                                           \
}while(0);

#define ar7100_reg_rmw_clear(_reg, _mask)  do {                        \
    ar7100_reg_wr((_reg), (ar7100_reg_rd((_reg)) & ~(_mask)));      \
    ar7100_reg_rd((_reg));                                           \
}while(0);

/*
 * Address map
 */
#ifndef AR9100
#define AR7100_PCI_MEM_BASE             0x10000000  /* 128M */
#endif
#define AR7100_APB_BASE                 0x18000000  /* 384M */
#define AR7100_GE0_BASE                 0x19000000  /* 16M */
#define AR7100_GE1_BASE                 0x1a000000  /* 16M */
#define AR7100_USB_EHCI_BASE            0x1b000000  
#define AR7100_USB_OHCI_BASE            0x1c000000

/*
 * APB block
 */
#define AR7100_DDR_CTL_BASE             AR7100_APB_BASE+0x00000000
#define AR7100_CPU_BASE                 AR7100_APB_BASE+0x00010000
#define AR7100_UART_BASE                AR7100_APB_BASE+0x00020000
#define AR7100_USB_CONFIG_BASE          AR7100_APB_BASE+0x00030000
#define AR7100_GPIO_BASE                AR7100_APB_BASE+0x00040000
#define AR7100_PLL_BASE                 AR7100_APB_BASE+0x00050000
#define AR7100_RESET_BASE               AR7100_APB_BASE+0x00060000
#define AR7100_SLIC_BASE                AR7100_APB_BASE+0x00090000
#define AR7100_DMA_BASE                 AR7100_APB_BASE+0x000A0000
#define AR7100_STEREO_BASE              AR7100_APB_BASE+0x000B0000
#ifdef AR9100
#define AR9100_WMAC_BASE                AR7100_APB_BASE+0x000c0000
#define AR9100_WMAC_LEN                 0x4000
#endif


/*
 * DDR block, gmac flushing
 */
#ifdef AR9100
#define AR7100_DDR_GE0_FLUSH            AR7100_DDR_CTL_BASE+0x7c
#define AR7100_DDR_GE1_FLUSH            AR7100_DDR_CTL_BASE+0x80
#define AR7100_DDR_USB_FLUSH            AR7100_DDR_CTL_BASE+0x84
#define AR7100_DDR_WMAC_FLUSH            AR7100_DDR_CTL_BASE+0x88
#else
#define AR7100_DDR_GE0_FLUSH            AR7100_DDR_CTL_BASE+0x9c
#define AR7100_DDR_GE1_FLUSH            AR7100_DDR_CTL_BASE+0xa0
#define AR7100_DDR_USB_FLUSH            AR7100_DDR_CTL_BASE+0xa4
#define AR7100_DDR_PCI_FLUSH            AR7100_DDR_CTL_BASE+0xa8
#endif

/*
 * PLL block
 */
#define AR7100_PLL_CONFIG               AR7100_PLL_BASE+0x0

#ifndef AR9100
#define AR7100_USB_PLL_CONFIG           AR7100_PLL_BASE+0x4

#define AR7100_USB_PLL_GE0_OFFSET       AR7100_PLL_BASE+0x10
#define AR7100_USB_PLL_GE1_OFFSET       AR7100_PLL_BASE+0x14

#define PLL_DIV_SHIFT   3
#define PLL_DIV_MASK    0x1f
#define CPU_DIV_SHIFT   16
#define CPU_DIV_MASK    0x3
#define DDR_DIV_SHIFT   18
#define DDR_DIV_MASK    0x3
#define AHB_DIV_SHIFT   20
#define AHB_DIV_MASK    0x7
#else
#define PLL_DIV_SHIFT   0
#define PLL_DIV_MASK    0x3ff
#define DDR_DIV_SHIFT   22
#define DDR_DIV_MASK    0x3
#define AHB_DIV_SHIFT   19
#define AHB_DIV_MASK    0x1
#define AR9100_ETH_PLL_CONFIG           AR7100_PLL_BASE+0x4

#define AR9100_ETH_INT0_CLK             AR7100_PLL_BASE+0x14
#define AR9100_ETH_INT1_CLK             AR7100_PLL_BASE+0x18
#endif

/*
 * USB block
 */
#define AR7100_USB_FLADJ_VAL            AR7100_USB_CONFIG_BASE
#define AR7100_USB_CONFIG               AR7100_USB_CONFIG_BASE+0x4
#define AR7100_USB_WINDOW               0x1000000

#ifndef AR9100
/*
 * PCI block
 */
#define AR7100_PCI_WINDOW           0x8000000       /* 128MB */
#define AR7100_PCI_WINDOW0_OFFSET   AR7100_DDR_CTL_BASE+0x7c
#define AR7100_PCI_WINDOW1_OFFSET   AR7100_DDR_CTL_BASE+0x80
#define AR7100_PCI_WINDOW2_OFFSET   AR7100_DDR_CTL_BASE+0x84
#define AR7100_PCI_WINDOW3_OFFSET   AR7100_DDR_CTL_BASE+0x88
#define AR7100_PCI_WINDOW4_OFFSET   AR7100_DDR_CTL_BASE+0x8c
#define AR7100_PCI_WINDOW5_OFFSET   AR7100_DDR_CTL_BASE+0x90
#define AR7100_PCI_WINDOW6_OFFSET   AR7100_DDR_CTL_BASE+0x94
#define AR7100_PCI_WINDOW7_OFFSET   AR7100_DDR_CTL_BASE+0x98

#define AR7100_PCI_WINDOW0_VAL      0x10000000
#define AR7100_PCI_WINDOW1_VAL      0x11000000
#define AR7100_PCI_WINDOW2_VAL      0x12000000
#define AR7100_PCI_WINDOW3_VAL      0x13000000
#define AR7100_PCI_WINDOW4_VAL      0x14000000
#define AR7100_PCI_WINDOW5_VAL      0x15000000
#define AR7100_PCI_WINDOW6_VAL      0x16000000
#define AR7100_PCI_WINDOW7_VAL      0x07000000

#define ar7100_write_pci_window(_no)             \
  ar7100_reg_wr(AR7100_PCI_WINDOW##_no##_OFFSET, AR7100_PCI_WINDOW##_no##_VAL);

/*
 * CRP. To access the host controller config and status registers
 */
#define AR7100_PCI_CRP   (AR7100_PCI_MEM_BASE|(AR7100_PCI_WINDOW7_VAL+0x10000))

#define AR7100_PCI_CRP_AD_CBE            AR7100_PCI_CRP
#define AR7100_PCI_CRP_WRDATA            AR7100_PCI_CRP+0x4
#define AR7100_PCI_CRP_RDDATA            AR7100_PCI_CRP+0x8
#define AR7100_PCI_ERROR                 AR7100_PCI_CRP+0x1c
#define AR7100_PCI_ERROR_ADDRESS         AR7100_PCI_CRP+0x20
#define AR7100_PCI_AHB_ERROR             AR7100_PCI_CRP+0x24
#define AR7100_PCI_AHB_ERROR_ADDRESS     AR7100_PCI_CRP+0x28

#define AR7100_CRP_CMD_WRITE             0x00010000
#define AR7100_CRP_CMD_READ              0x00000000

/*
 * PCI CFG. To generate config cycles
 */
#define AR7100_PCI_CFG_AD           AR7100_PCI_CRP+0xc
#define AR7100_PCI_CFG_CBE          AR7100_PCI_CRP+0x10
#define AR7100_PCI_CFG_WRDATA       AR7100_PCI_CRP+0x14
#define AR7100_PCI_CFG_RDDATA       AR7100_PCI_CRP+0x18
#define AR7100_CFG_CMD_READ         0x0000000a
#define AR7100_CFG_CMD_WRITE        0x0000000b

#define AR7100_PCI_IDSEL_ADLINE_START           17
#endif

/*
 * gpio configs
 */
#define AR7100_GPIO_OE                  AR7100_GPIO_BASE+0x0
#define AR7100_GPIO_IN                  AR7100_GPIO_BASE+0x4
#define AR7100_GPIO_OUT                 AR7100_GPIO_BASE+0x8
#define AR7100_GPIO_SET                 AR7100_GPIO_BASE+0xc
#define AR7100_GPIO_CLEAR               AR7100_GPIO_BASE+0x10
#define AR7100_GPIO_INT_ENABLE          AR7100_GPIO_BASE+0x14
#define AR7100_GPIO_INT_TYPE            AR7100_GPIO_BASE+0x18
#define AR7100_GPIO_INT_POLARITY        AR7100_GPIO_BASE+0x1c
#define AR7100_GPIO_INT_PENDING         AR7100_GPIO_BASE+0x20
#define AR7100_GPIO_INT_MASK            AR7100_GPIO_BASE+0x24
#define AR7100_GPIO_FUNCTIONS           AR7100_GPIO_BASE+0x28

/*
 * IRQ Map.
 * There are 4 conceptual ICs in the system. We generally give a block of 16
 * irqs to each IC.
 * CPU:                     0    - 0xf
 *      MISC:               0x10 - 0x1f
 *          GPIO:           0x20 - 0x2f
 *      PCI :               0x30 - 0x40
 * 
 */
#define AR7100_CPU_IRQ_BASE         0x00
#define AR7100_MISC_IRQ_BASE        0x10
#define AR7100_GPIO_IRQ_BASE        0x20
#ifndef AR9100
#define AR7100_PCI_IRQ_BASE         0x30
#endif

/*
 * The IPs. Connected to CPU (hardware IP's; the first two are software)
 */
#ifdef AR9100
#define AR7100_CPU_IRQ_WMAC                 AR7100_CPU_IRQ_BASE+2
#else
#define AR7100_CPU_IRQ_PCI                  AR7100_CPU_IRQ_BASE+2
#endif
#define AR7100_CPU_IRQ_USB                  AR7100_CPU_IRQ_BASE+3
#define AR7100_CPU_IRQ_GE0                  AR7100_CPU_IRQ_BASE+4
#define AR7100_CPU_IRQ_GE1                  AR7100_CPU_IRQ_BASE+5
#define AR7100_CPU_IRQ_MISC                 AR7100_CPU_IRQ_BASE+6
#define AR7100_CPU_IRQ_TIMER                AR7100_CPU_IRQ_BASE+7

/*
 * Interrupts connected to the CPU->Misc line.
 */
#define AR7100_MISC_IRQ_TIMER               AR7100_MISC_IRQ_BASE+0
#define AR7100_MISC_IRQ_ERROR               AR7100_MISC_IRQ_BASE+1
#define AR7100_MISC_IRQ_GPIO                AR7100_MISC_IRQ_BASE+2
#define AR7100_MISC_IRQ_UART                AR7100_MISC_IRQ_BASE+3
#define AR7100_MISC_IRQ_WATCHDOG            AR7100_MISC_IRQ_BASE+4
#define AR7100_MISC_IRQ_PERF_COUNTER        AR7100_MISC_IRQ_BASE+5
#define AR7100_MISC_IRQ_USB_OHCI            AR7100_MISC_IRQ_BASE+6
#define AR7100_MISC_IRQ_DMA                 AR7100_MISC_IRQ_BASE+7

#define AR7100_MISC_IRQ_COUNT                 8

#define MIMR_TIMER                          0x01
#define MIMR_ERROR                          0x02
#define MIMR_GPIO                           0x04
#define MIMR_UART                           0x08
#define MIMR_WATCHDOG                       0x10
#define MIMR_PERF_COUNTER                   0x20
#define MIMR_OHCI_USB                       0x40
#define MIMR_DMA                            0x80

#define MISR_TIMER                          MIMR_TIMER
#define MISR_ERROR                          MIMR_ERROR
#define MISR_GPIO                           MIMR_GPIO
#define MISR_UART                           MIMR_UART
#define MISR_WATCHDOG                       MIMR_WATCHDOG
#define MISR_PERF_COUNTER                   MIMR_PERF_COUNTER
#define MISR_OHCI_USB                       MIMR_OHCI_USB
#define MISR_DMA                            MIMR_DMA


/*
 * Interrupts connected to the Misc->GPIO line
 */
#define AR7100_GPIO_IRQn(_gpio)             AR7100_GPIO_IRQ_BASE+(_gpio)
#define AR7100_GPIO_IRQ_COUNT                 16

#ifndef AR9100
/*
 * Interrupts connected to CPU->PCI
 */
#define AR7100_PCI_IRQ_DEV0                  AR7100_PCI_IRQ_BASE+0
#define AR7100_PCI_IRQ_DEV1                  AR7100_PCI_IRQ_BASE+1
#define AR7100_PCI_IRQ_DEV2                  AR7100_PCI_IRQ_BASE+2
#define AR7100_PCI_IRQ_CORE                  AR7100_PCI_IRQ_BASE+3
#define AR7100_PCI_IRQ_COUNT                 4

/*
 * PCI interrupt mask and status
 */
#define PIMR_DEV0                           0x01
#define PIMR_DEV1                           0x02
#define PIMR_DEV2                           0x04
#define PIMR_CORE                           0x10

#define PISR_DEV0                           PIMR_DEV0
#define PISR_DEV1                           PIMR_DEV1
#define PISR_DEV2                           PIMR_DEV2
#define PISR_CORE                           PIMR_CORE
#endif

#define AR7100_GPIO_COUNT                   16

/*
 * GPIO Function Enables
 */

#define AR7100_GPIO_FUNCTION_STEREO_EN       (1<<17)
#define AR7100_GPIO_FUNCTION_SLIC_EN         (1<<16)
#define AR7100_GPIO_FUNCTION_SPI_CS_1_EN     (1<<15)
#define AR7100_GPIO_FUNCTION_SPI_CS_0_EN     (1<<14)
#define AR7100_GPIO_FUNCTION_UART_EN         (1<< 8)
#define AR7100_GPIO_FUNCTION_OVERCURRENT_EN  (1<< 4)
#define AR7100_GPIO_FUNCTION_USB_CLK_CORE_EN (1<< 0)

static void inline ar7100_gpio_enable_slic(void)    
{ 
  ar7100_reg_rmw_set(AR7100_GPIO_FUNCTIONS, AR7100_GPIO_FUNCTION_SLIC_EN);
}

static void inline ar7100_gpio_enable_uart(void)
{
  ar7100_reg_rmw_set(AR7100_GPIO_FUNCTIONS, AR7100_GPIO_FUNCTION_UART_EN);
  ar7100_reg_rmw_clear(AR7100_GPIO_OE, 1<<9);
  ar7100_reg_rmw_set(AR7100_GPIO_OE, 1<<10);
}
  
static void inline ar7100_gpio_enable_stereo(void)  
{ 
  ar7100_reg_rmw_clear (AR7100_GPIO_INT_ENABLE,  1<<11);
  ar7100_reg_rmw_clear (AR7100_GPIO_OE,          1<<11);
  ar7100_reg_rmw_set(   AR7100_GPIO_FUNCTIONS, AR7100_GPIO_FUNCTION_STEREO_EN);
}

static void inline ar7100_gpio_enable_i2c_on_gpio_0_1(void)
{
  ar7100_reg_rmw_clear( AR7100_GPIO_FUNCTIONS,   AR7100_GPIO_FUNCTION_SPI_CS_0_EN|AR7100_GPIO_FUNCTION_SPI_CS_1_EN);
  ar7100_reg_rmw_clear (AR7100_GPIO_INT_ENABLE,  3);
  ar7100_reg_rmw_clear (AR7100_GPIO_OE,          3);
}

/* Helper functions for software i2c using gpio 0 and 1 */

static void inline ar7100_gpio_drive_low(unsigned int  mask)
{
  ar7100_reg_wr      (AR7100_GPIO_CLEAR, mask);
  ar7100_reg_rmw_set (AR7100_GPIO_OE,    mask);
}

static void inline ar7100_gpio_drive_high(unsigned int  mask)
{
  ar7100_reg_wr      (AR7100_GPIO_SET,   mask);
  ar7100_reg_rmw_set (AR7100_GPIO_OE,    mask);
}

/* Allow bits in mask to float to their quiescent state and test results */
static unsigned int inline ar7100_gpio_float_high_test(unsigned int mask)
{
  volatile unsigned int d;
  ar7100_reg_rmw_clear(AR7100_GPIO_OE,  mask);
  d = ar7100_reg_rd(AR7100_GPIO_IN);
  d = ar7100_reg_rd(AR7100_GPIO_IN) & mask;
  return d!=mask;
}

/*
 * Reset block
 */
#define AR7100_GENERAL_TMR            AR7100_RESET_BASE+0
#define AR7100_GENERAL_TMR_RELOAD     AR7100_RESET_BASE+4
#define AR7100_WATCHDOG_TMR_CONTROL   AR7100_RESET_BASE+8
#define AR7100_WATCHDOG_TMR           AR7100_RESET_BASE+0xc
#define AR7100_MISC_INT_STATUS        AR7100_RESET_BASE+0x10
#define AR7100_MISC_INT_MASK          AR7100_RESET_BASE+0x14
#ifndef AR9100
#define AR7100_PCI_INT_STATUS         AR7100_RESET_BASE+0x18
#define AR7100_PCI_INT_MASK           AR7100_RESET_BASE+0x1c
#define AR7100_GLOBAL_INT_STATUS      AR7100_RESET_BASE+0x20
#define AR7100_RESET                  AR7100_RESET_BASE+0x24
#else
#define AR7100_GLOBAL_INT_STATUS      AR7100_RESET_BASE+0x18
#define AR7100_RESET                  AR7100_RESET_BASE+0x1c
#endif
#define AR7100_OBSERVATION_ENABLE     AR7100_RESET_BASE+0x28

static void          inline ar7100_misc_enable_irq     (unsigned int mask) { ar7100_reg_rmw_set(AR7100_MISC_INT_MASK, mask );   }
static void          inline ar7100_misc_disable_irq    (unsigned int mask) { ar7100_reg_rmw_clear(AR7100_MISC_INT_MASK, mask ); }
static unsigned int  inline ar7100_misc_get_irq_mask   (void)              { return ar7100_reg_rd(AR7100_MISC_INT_MASK);         }
static unsigned int  inline ar7100_misc_get_irq_status (void)              { return ar7100_reg_rd(AR7100_MISC_INT_STATUS);       }

/*
 * Performace counters
 */
#ifndef AR9100
#define AR7100_PERF_CTL               AR7100_RESET_BASE+0x2c
#define AR7100_PERF0_COUNTER          AR7100_RESET_BASE+0x30
#define AR7100_PERF1_COUNTER          AR7100_RESET_BASE+0x34
#else
#define AR7100_PERF_CTL               AR7100_RESET_BASE+0x20
#define AR7100_PERF0_COUNTER          AR7100_RESET_BASE+0x24
#define AR7100_PERF1_COUNTER          AR7100_RESET_BASE+0x28
#endif


/*
 * SLIC/STEREO DMA Size Configurations 
 */

#define AR7100_DMA_BUF_SIZE_4X2      0x00
#define AR7100_DMA_BUF_SIZE_8X2      0x01
#define AR7100_DMA_BUF_SIZE_16X2     0x02
#define AR7100_DMA_BUF_SIZE_32X2     0x03
#define AR7100_DMA_BUF_SIZE_64X2     0x04
#define AR7100_DMA_BUF_SIZE_128X2    0x05
#define AR7100_DMA_BUF_SIZE_256X2    0x06
#define AR7100_DMA_BUF_SIZE_512X2    0x07

/*
 * SLIC/STEREO DMA Assignments
 */

#define AR7100_DMA_CHAN_SLIC0_RX     0
#define AR7100_DMA_CHAN_SLIC1_RX     1
#define AR7100_DMA_CHAN_STEREO_RX    2
#define AR7100_DMA_CHAN_SLIC0_TX     3
#define AR7100_DMA_CHAN_SLIC1_TX     4
#define AR7100_DMA_CHAN_STEREO_TX    5

static void inline ar7100_dma_addr_wr  (int chan, unsigned int val) { ar7100_reg_wr(  AR7100_DMA_BASE + 0 + chan * 12, val); }
static void inline ar7100_dma_config_wr(int chan, unsigned int val) { ar7100_reg_wr(  AR7100_DMA_BASE + 4 + chan * 12, val); }
static void inline ar7100_dma_update_wr(int chan, unsigned int val) { ar7100_reg_wr(  AR7100_DMA_BASE + 8 + chan * 12, val); }

static unsigned int inline ar7100_dma_addr_rd  (int chan) { return ar7100_reg_rd(  AR7100_DMA_BASE + 0 + chan * 12);      }
static unsigned int inline ar7100_dma_config_rd(int chan) { return ar7100_reg_rd(  AR7100_DMA_BASE + 4 + chan * 12);      }

static void inline ar7100_dma_config_buffer(int chan, void *buffer, int sizeCfg)
{
  unsigned int addr = KSEG1ADDR(buffer);
  ar7100_dma_addr_wr  (chan, (unsigned int)addr);
  ar7100_dma_config_wr(chan, ((sizeCfg&0x7)<<4)|0x100);
}

/*
 * SLIC register definitions
 */

#define AR7100_SLIC_STATUS                   (AR7100_SLIC_BASE+0x00)
#define AR7100_SLIC_CNTRL                    (AR7100_SLIC_BASE+0x04)
#define AR7100_SLIC_SLOT0_NUM                (AR7100_SLIC_BASE+0x08)
#define AR7100_SLIC_SLOT1_NUM                (AR7100_SLIC_BASE+0x0c)
#define AR7100_SLIC_SAM_POS                  (AR7100_SLIC_BASE+0x2c)
#define AR7100_SLIC_FREQ_DIV                 (AR7100_SLIC_BASE+0x30)

/*
 * SLIC Control bits
 */
#define AR7100_SLIC_CNTRL_ENABLE             (1<<0)
#define AR7100_SLIC_CNTRL_SLOT0_ENABLE       (1<<1)
#define AR7100_SLIC_CNTRL_SLOT1_ENABLE       (1<<2)
#define AR7100_SLIC_CNTRL_IRQ_ENABLE         (1<<3)

static unsigned int inline ar7100_slic_status_rd(void) { return ar7100_reg_rd(AR7100_SLIC_STATUS); }
static unsigned int inline ar7100_slic_cntrl_rd(void)  { return ar7100_reg_rd(AR7100_SLIC_CNTRL);  }

static void inline ar7100_slic_cntrl_wr(unsigned int val) { ar7100_reg_wr(  AR7100_SLIC_CNTRL, val);    }
static void inline ar7100_slic_0_slot_pos_wr(unsigned int val) { ar7100_reg_wr( AR7100_SLIC_SLOT0_NUM, val); }
static void inline ar7100_slic_1_slot_pos_wr(unsigned int val) { ar7100_reg_wr( AR7100_SLIC_SLOT1_NUM, val); } 
static void inline ar7100_slic_freq_div_wr(unsigned int val) { ar7100_reg_wr( AR7100_SLIC_FREQ_DIV,  val); }
static void inline ar7100_slic_sample_pos_wr (unsigned int val) { ar7100_reg_wr( AR7100_SLIC_SAM_POS,   val); }

/*
 * STEREO register definitions
 */

#define AR7100_STEREO_CONFIG                 (AR7100_STEREO_BASE+0x00)
#define AR7100_STEREO_VOLUME                 (AR7100_STEREO_BASE+0x04)

/*
 * Stereo Configuration Bits
 */
#define AR7100_STEREO_CONFIG_ENABLE          (1<<24)
#define AR7100_STEREO_CONFIG_RESET           (1<<23)
#define AR7100_STEREO_CONFIG_DELAY           (1<<22)
#define AR7100_STEREO_CONFIG_MIC_WORD_SIZE   (1<<20)

#define AR7100_STEREO_CONFIG_MODE(x)           ((3&x)<<18)
#define AR7100_STEREO_MODE_STERO                0
#define AR7100_STEREO_MODE_MONO_LEFT            1
#define AR7100_STEREO_MODE_MONO_RIGHT           2

#define AR7100_STEREO_CONFIG_DATA_WORD_SIZE(x) ((3&x)<<16)

#define AR7100_STEREO_CONFIG_32_BITS         (1<<15)
#define AR7100_STEREO_CONFIG_MASTER          (1<<8)
#define AR7100_STEREO_CONFIG_PSEDGE(x)       (0xff&x)

#define AR7100_STEREO_WS_8B                     0
#define AR7100_STEREO_WS_16B                    1

static void inline ar7100_stereo_config_wr(unsigned int val) { ar7100_reg_wr(  AR7100_STEREO_CONFIG, val);    }
static void inline ar7100_stereo_volume_wr(unsigned int val) { ar7100_reg_wr(  AR7100_STEREO_VOLUME, val);    }

static unsigned int  inline ar7100_stereo_config_rd (void) { return ar7100_reg_rd( AR7100_STEREO_CONFIG );    }
static unsigned int  inline ar7100_stereo_volume_rd (void) { return ar7100_reg_rd( AR7100_STEREO_VOLUME );    }

static inline signed short 
ar7100_stereo_sample_16b_cvt(signed short v) { return (((v<<8)&0xff00)|((v>>8)&0xff)) & 0xffff; }

/* 48 kHz, 16 bit data & i2s 32fs */
static inline void ar7100_setup_for_stereo_master(int x)
{
  volatile unsigned int reset;
    
  ar7100_gpio_enable_stereo();
  ar7100_stereo_config_wr(
			  AR7100_STEREO_CONFIG_ENABLE  | 
			  AR7100_STEREO_CONFIG_DELAY   |
			  AR7100_STEREO_CONFIG_RESET   | 
			  AR7100_STEREO_CONFIG_DATA_WORD_SIZE(x) |
			  AR7100_STEREO_CONFIG_MASTER  |
			  AR7100_STEREO_CONFIG_PSEDGE(27)
			  );
  do {
    reset = ar7100_stereo_config_rd();
  } while (reset & AR7100_STEREO_CONFIG_RESET);
}

/* 48 kHz, 16 bit data & 32fs i2s */
static inline void ar7100_setup_for_stereo_slave(int x)
{
  volatile unsigned int reset;
  
  ar7100_gpio_enable_stereo();
  ar7100_stereo_config_wr(
			  AR7100_STEREO_CONFIG_ENABLE  | 
			  AR7100_STEREO_CONFIG_DELAY   |
			  AR7100_STEREO_CONFIG_RESET   |
			  AR7100_STEREO_CONFIG_DATA_WORD_SIZE(x) |
			  AR7100_STEREO_CONFIG_PSEDGE(27)
			  );
  do {
    reset = ar7100_stereo_config_rd();
  } while (reset & AR7100_STEREO_CONFIG_RESET);
}

/*
 * PERF CTL bits
 */
#define PERF_CTL_PCI_AHB_0           ( 0)
#define PERF_CTL_PCI_AHB_1           ( 1)
#define PERF_CTL_USB_0               ( 2)
#define PERF_CTL_USB_1               ( 3)
#define PERF_CTL_GE0_PKT_CNT         ( 4)
#define PERF_CTL_GEO_AHB_1           ( 5)
#define PERF_CTL_GE1_PKT_CNT         ( 6)
#define PERF_CTL_GE1_AHB_1           ( 7)
#define PERF_CTL_PCI_DEV_0_BUSY      ( 8)
#define PERF_CTL_PCI_DEV_1_BUSY      ( 9)
#define PERF_CTL_PCI_DEV_2_BUSY      (10)
#define PERF_CTL_PCI_HOST_BUSY       (11)
#define PERF_CTL_PCI_DEV_0_ARB       (12)
#define PERF_CTL_PCI_DEV_1_ARB       (13)
#define PERF_CTL_PCI_DEV_2_ARB       (14)
#define PERF_CTL_PCI_HOST_ARB        (15)
#define PERF_CTL_PCI_DEV_0_ACTIVE    (16)
#define PERF_CTL_PCI_DEV_1_ACTIVE    (17)
#define PERF_CTL_PCI_DEV_2_ACTIVE    (18)
#define PERF_CTL_HOST_ACTIVE         (19)

#define ar7100_perf0_ctl(_val) ar7100_reg_wr(AR7100_PERF_CTL, (_val))
#define ar7100_perf1_ctl(_val) ar7100_reg_rmw_set(AR7100_PERF_CTL, ((_val) << 8))

/*
 * Chip revision Id
 */
#define AR7100_CHIP_REV               AR7100_RESET_BASE+0x90
#define AR7100_CHIP_REV_MAJOR_M       0x000000f0
#define AR7100_CHIP_REV_MAJOR_S       4
#define AR7100_CHIP_REV_MINOR_M       0x0000000f
#define AR7100_CHIP_REV_MINOR_S       0

/*
 * AR7100_RESET bit defines
 */
#define AR7100_RESET_EXTERNAL               (1 << 28)
#define AR7100_RESET_FULL_CHIP              (1 << 24)
#define AR7100_RESET_CPU_NMI                (1 << 21)
#define AR7100_RESET_CPU_COLD_RESET_MASK    (1 << 20)
#define AR7100_RESET_DMA                    (1 << 19)
#define AR7100_RESET_SLIC                   (1 << 18)
#define AR7100_RESET_STEREO                 (1 << 17)
#define AR7100_RESET_DDR                    (1 << 16)
#define AR7100_RESET_GE1_MAC                (1 << 13)
#define AR7100_RESET_GE1_PHY                (1 << 12)
#define AR7100_RESET_GE0_MAC                (1 << 9)
#define AR7100_RESET_GE0_PHY                (1 << 8)
#define AR7100_RESET_USB_OHCI_DLL           (1 << 6)
#define AR7100_RESET_USB_HOST               (1 << 5)
#define AR7100_RESET_USB_PHY                (1 << 4)
#ifndef AR9100
#define AR7100_RESET_PCI_BUS                (1 << 1)
#define AR7100_RESET_PCI_CORE               (1 << 0)
#endif

#define ar7100_reset(_mask) do { \
  ar7100_reg_rmw_set(AR7100_RESET,   _mask); \
  udelay(10); \
  ar7100_reg_rmw_clear(AR7100_RESET, _mask); \
} while (0);

/*
 * Mii block
 */
#define AR7100_MII0_CTRL                    0x18070000
#define AR7100_MII1_CTRL                    0x18070004

#define BIT(_x) (1 << (_x))

#define ar7100_get_bit(_reg, _bit)  (ar7100_reg_rd((_reg)) & (1 << (_bit)))

#define ar7100_flush_ge(_unit) do {                             \
    u32     reg = (_unit) ? AR7100_DDR_GE1_FLUSH : AR7100_DDR_GE0_FLUSH;   \
    ar7100_reg_wr(reg, 1);                 \
    while((ar7100_reg_rd(reg) & 0x1));   \
    ar7100_reg_wr(reg, 1);                 \
    while((ar7100_reg_rd(reg) & 0x1));   \
}while(0);
#ifndef AR9100
#define ar7100_flush_pci() do {                             \
    ar7100_reg_wr(AR7100_DDR_PCI_FLUSH, 1);                 \
    while((ar7100_reg_rd(AR7100_DDR_PCI_FLUSH) & 0x1));   \
    ar7100_reg_wr(AR7100_DDR_PCI_FLUSH, 1);                 \
    while((ar7100_reg_rd(AR7100_DDR_PCI_FLUSH) & 0x1));   \
}while(0);
#else
#define ar9100_flush_wmac() do {                             \
    ar7100_reg_wr(AR7100_DDR_WMAC_FLUSH, 1);                 \
    while((ar7100_reg_rd(AR7100_DDR_WMAC_FLUSH) & 0x1));   \
    ar7100_reg_wr(AR7100_DDR_WMAC_FLUSH, 1);                 \
    while((ar7100_reg_rd(AR7100_DDR_WMAC_FLUSH) & 0x1));   \
}while(0);
#endif

#define ar7100_flush_USB() do {                             \
    ar7100_reg_wr(AR7100_DDR_USB_FLUSH, 1);                 \
    while((ar7100_reg_rd(AR7100_DDR_USB_FLUSH) & 0x1));   \
    ar7100_reg_wr(AR7100_DDR_USB_FLUSH, 1);                 \
    while((ar7100_reg_rd(AR7100_DDR_USB_FLUSH) & 0x1));   \
}while(0);

void ar7100_gpio_irq_init(int irq_base);
void ar7100_pci_irq_init(int irq_base);
int ar7100_local_read_config(int where, int size, u32 *value);
int ar7100_local_write_config(int where, int size, u32 value);
int ar7100_check_error(void);
unsigned char __ar7100_readb(const volatile void __iomem *p);
unsigned short __ar7100_readw(const volatile void __iomem *p);
#ifdef _SC_BUILD_
int sercomm_flash_write(loff_t to, size_t len, const u_char *buf);
#endif
#endif
