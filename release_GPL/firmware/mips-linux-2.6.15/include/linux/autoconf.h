/*
 * Automatically generated C config: don't edit
 * Linux kernel version: 2.6.15--LSDK-6.1.1.65
 * Tue Mar 31 18:41:19 2009
 */
#define AUTOCONF_INCLUDED
#define CONFIG_MIPS 1

/*
 * Machine selection
 */
#undef CONFIG_MIPS_MTX1
#undef CONFIG_MIPS_BOSPORUS
#undef CONFIG_MIPS_PB1000
#undef CONFIG_MIPS_PB1100
#undef CONFIG_MIPS_PB1500
#undef CONFIG_MIPS_PB1550
#undef CONFIG_MIPS_PB1200
#undef CONFIG_MIPS_DB1000
#undef CONFIG_MIPS_DB1100
#undef CONFIG_MIPS_DB1500
#undef CONFIG_MIPS_DB1550
#undef CONFIG_MIPS_DB1200
#undef CONFIG_MIPS_MIRAGE
#undef CONFIG_MIPS_COBALT
#undef CONFIG_MACH_DECSTATION
#undef CONFIG_MIPS_EV64120
#undef CONFIG_MIPS_EV96100
#undef CONFIG_MIPS_IVR
#undef CONFIG_MIPS_ITE8172
#undef CONFIG_MACH_JAZZ
#undef CONFIG_LASAT
#undef CONFIG_MIPS_ATLAS
#undef CONFIG_MIPS_MALTA
#undef CONFIG_MIPS_SEAD
#undef CONFIG_MIPS_SIM
#undef CONFIG_MOMENCO_JAGUAR_ATX
#undef CONFIG_MOMENCO_OCELOT
#undef CONFIG_MOMENCO_OCELOT_3
#undef CONFIG_MOMENCO_OCELOT_C
#undef CONFIG_MOMENCO_OCELOT_G
#undef CONFIG_MIPS_XXS1500
#undef CONFIG_PNX8550_V2PCI
#undef CONFIG_PNX8550_JBS
#undef CONFIG_DDB5074
#undef CONFIG_DDB5476
#undef CONFIG_DDB5477
#undef CONFIG_MACH_VR41XX
#undef CONFIG_PMC_YOSEMITE
#undef CONFIG_QEMU
#undef CONFIG_SGI_IP22
#undef CONFIG_SGI_IP27
#undef CONFIG_SGI_IP32
#undef CONFIG_SIBYTE_BIGSUR
#undef CONFIG_SIBYTE_SWARM
#undef CONFIG_SIBYTE_SENTOSA
#undef CONFIG_SIBYTE_RHONE
#undef CONFIG_SIBYTE_CARMEL
#undef CONFIG_SIBYTE_PTSWARM
#undef CONFIG_SIBYTE_LITTLESUR
#undef CONFIG_SIBYTE_CRHINE
#undef CONFIG_SIBYTE_CRHONE
#undef CONFIG_SNI_RM200_PCI
#undef CONFIG_TOSHIBA_JMR3927
#undef CONFIG_TOSHIBA_RBTX4927
#undef CONFIG_TOSHIBA_RBTX4938
#define CONFIG_MACH_AR7100 1
#undef CONFIG_AR9100
#undef CONFIG_AR7100_EMULATION
#define CONFIG_RWSEM_GENERIC_SPINLOCK 1
#define CONFIG_GENERIC_CALIBRATE_DELAY 1
#define CONFIG_DMA_NONCOHERENT 1
#define CONFIG_DMA_NEED_PCI_MAP_STATE 1
#define CONFIG_I8259 1
#define CONFIG_CPU_BIG_ENDIAN 1
#undef CONFIG_CPU_LITTLE_ENDIAN
#define CONFIG_SYS_SUPPORTS_BIG_ENDIAN 1
#define CONFIG_IRQ_CPU 1
#define CONFIG_MIPS_L1_CACHE_SHIFT 5

/*
 * CPU selection
 */
#undef CONFIG_CPU_MIPS32_R1
#define CONFIG_CPU_MIPS32_R2 1
#undef CONFIG_CPU_MIPS64_R1
#undef CONFIG_CPU_MIPS64_R2
#undef CONFIG_CPU_R3000
#undef CONFIG_CPU_TX39XX
#undef CONFIG_CPU_VR41XX
#undef CONFIG_CPU_R4300
#undef CONFIG_CPU_R4X00
#undef CONFIG_CPU_TX49XX
#undef CONFIG_CPU_R5000
#undef CONFIG_CPU_R5432
#undef CONFIG_CPU_R6000
#undef CONFIG_CPU_NEVADA
#undef CONFIG_CPU_R8000
#undef CONFIG_CPU_R10000
#undef CONFIG_CPU_RM7000
#undef CONFIG_CPU_RM9000
#undef CONFIG_CPU_SB1
#define CONFIG_SYS_HAS_CPU_MIPS32_R1 1
#define CONFIG_SYS_HAS_CPU_MIPS32_R2 1
#define CONFIG_CPU_MIPS32 1
#define CONFIG_CPU_MIPSR2 1
#define CONFIG_SYS_SUPPORTS_32BIT_KERNEL 1
#define CONFIG_CPU_SUPPORTS_32BIT_KERNEL 1

/*
 * Kernel type
 */
#define CONFIG_32BIT 1
#undef CONFIG_64BIT
#define CONFIG_PAGE_SIZE_4KB 1
#undef CONFIG_PAGE_SIZE_8KB
#undef CONFIG_PAGE_SIZE_16KB
#undef CONFIG_PAGE_SIZE_64KB
#define CONFIG_CPU_HAS_PREFETCH 1
#undef CONFIG_MIPS_MT
#undef CONFIG_64BIT_PHYS_ADDR
#define CONFIG_CPU_ADVANCED 1
#define CONFIG_CPU_HAS_LLSC 1
#undef CONFIG_CPU_HAS_WB

/*
 * MIPSR2 Interrupt handling
 */
#undef CONFIG_CPU_MIPSR2_IRQ_VI
#undef CONFIG_CPU_MIPSR2_IRQ_EI
#define CONFIG_CPU_HAS_SYNC 1
#define CONFIG_GENERIC_HARDIRQS 1
#define CONFIG_GENERIC_IRQ_PROBE 1
#define CONFIG_ARCH_FLATMEM_ENABLE 1
#define CONFIG_SELECT_MEMORY_MODEL 1
#define CONFIG_FLATMEM_MANUAL 1
#undef CONFIG_DISCONTIGMEM_MANUAL
#undef CONFIG_SPARSEMEM_MANUAL
#define CONFIG_FLATMEM 1
#define CONFIG_FLAT_NODE_MEM_MAP 1
#undef CONFIG_SPARSEMEM_STATIC
#define CONFIG_SPLIT_PTLOCK_CPUS 4
#define CONFIG_PREEMPT_NONE 1
#undef CONFIG_PREEMPT_VOLUNTARY
#undef CONFIG_PREEMPT

/*
 * Code maturity level options
 */
#define CONFIG_EXPERIMENTAL 1
#define CONFIG_CLEAN_COMPILE 1
#define CONFIG_BROKEN_ON_SMP 1
#define CONFIG_INIT_ENV_ARG_LIMIT 32

/*
 * General setup
 */
#define CONFIG_LOCALVERSION ""
#define CONFIG_LOCALVERSION_AUTO 1
#undef CONFIG_SWAP
#define CONFIG_SYSVIPC 1
#undef CONFIG_POSIX_MQUEUE
#undef CONFIG_BSD_PROCESS_ACCT
#define CONFIG_SYSCTL 1
#undef CONFIG_AUDIT
#define CONFIG_HOTPLUG 1
#define CONFIG_KOBJECT_UEVENT 1
#undef CONFIG_IKCONFIG
#define CONFIG_INITRAMFS_SOURCE ""
#define CONFIG_CC_OPTIMIZE_FOR_SIZE 1
#define CONFIG_EMBEDDED 1
#define CONFIG_KALLSYMS 1
#undef CONFIG_KALLSYMS_EXTRA_PASS
#define CONFIG_PRINTK 1
#define CONFIG_BUG 1
#define CONFIG_BASE_FULL 1
#define CONFIG_FUTEX 1
#undef CONFIG_EPOLL
#undef CONFIG_SHMEM
#define CONFIG_CC_ALIGN_FUNCTIONS 0
#define CONFIG_CC_ALIGN_LABELS 0
#define CONFIG_CC_ALIGN_LOOPS 0
#define CONFIG_CC_ALIGN_JUMPS 0
#define CONFIG_TINY_SHMEM 1
#define CONFIG_BASE_SMALL 0

/*
 * Loadable module support
 */
#define CONFIG_MODULES 1
#define CONFIG_MODULE_UNLOAD 1
#define CONFIG_MODULE_FORCE_UNLOAD 1
#define CONFIG_OBSOLETE_MODPARM 1
#undef CONFIG_MODVERSIONS
#undef CONFIG_MODULE_SRCVERSION_ALL
#undef CONFIG_KMOD

/*
 * Block layer
 */
#undef CONFIG_LBD

/*
 * IO Schedulers
 */
#define CONFIG_IOSCHED_NOOP 1
#undef CONFIG_IOSCHED_AS
#define CONFIG_IOSCHED_DEADLINE 1
#undef CONFIG_IOSCHED_CFQ
#undef CONFIG_DEFAULT_AS
#define CONFIG_DEFAULT_DEADLINE 1
#undef CONFIG_DEFAULT_CFQ
#undef CONFIG_DEFAULT_NOOP
#define CONFIG_DEFAULT_IOSCHED "deadline"

/*
 * Bus options (PCI, PCMCIA, EISA, ISA, TC)
 */
#define CONFIG_HW_HAS_PCI 1
#define CONFIG_PCI 1
#define CONFIG_PCI_LEGACY_PROC 1
#define CONFIG_MMU 1

/*
 * PCCARD (PCMCIA/CardBus) support
 */
#undef CONFIG_PCCARD

/*
 * PCI Hotplug Support
 */
#undef CONFIG_HOTPLUG_PCI

/*
 * Executable file formats
 */
#define CONFIG_BINFMT_ELF 1
#undef CONFIG_BINFMT_MISC
#define CONFIG_TRAD_SIGNALS 1

/*
 * Networking
 */
#define CONFIG_NET 1

/*
 * Networking options
 */
#define CONFIG_PACKET 1
#undef CONFIG_PACKET_MMAP
#define CONFIG_UNIX 1
#undef CONFIG_NET_KEY
#define CONFIG_INET 1
#define CONFIG_IP_MULTICAST 1
#undef CONFIG_IP_ADVANCED_ROUTER
#define CONFIG_IP_FIB_HASH 1
#undef CONFIG_IP_PNP
#undef CONFIG_NET_IPIP
#define CONFIG_NET_IPGRE 1
#undef CONFIG_NET_IPGRE_BROADCAST
#define CONFIG_IP_MROUTE 1
#undef CONFIG_IP_PIMSM_V1
#undef CONFIG_IP_PIMSM_V2
#undef CONFIG_ARPD
#undef CONFIG_SYN_COOKIES
#undef CONFIG_INET_AH
#undef CONFIG_INET_ESP
#undef CONFIG_INET_IPCOMP
#undef CONFIG_INET_TUNNEL
#define CONFIG_INET_DIAG 1
#define CONFIG_INET_TCP_DIAG 1
#undef CONFIG_TCP_CONG_ADVANCED
#define CONFIG_TCP_CONG_BIC 1

/*
 * IP: Virtual Server Configuration
 */
#undef CONFIG_IP_VS
#undef CONFIG_IPV6
#define CONFIG_NETFILTER 1
#undef CONFIG_NETFILTER_DEBUG
#undef CONFIG_BRIDGE_NETFILTER

/*
 * Core Netfilter Configuration
 */
#define CONFIG_NETFILTER_NETLINK 1
#define CONFIG_NETFILTER_NETLINK_QUEUE 1
#define CONFIG_NETFILTER_NETLINK_LOG 1

/*
 * IP: Netfilter Configuration
 */
#define CONFIG_IP_NF_CONNTRACK 1
#define CONFIG_IP_NF_CT_ACCT 1
#define CONFIG_IP_NF_CONNTRACK_MARK 1
#define CONFIG_IP_NF_CONNTRACK_EVENTS 1
#undef CONFIG_IP_NF_CONNTRACK_NETLINK
#undef CONFIG_IP_NF_CT_PROTO_SCTP
#define CONFIG_IP_NF_FTP 1
#define CONFIG_IP_NF_IRC 1
#undef CONFIG_IP_NF_NETBIOS_NS
#define CONFIG_IP_NF_TFTP 1
#undef CONFIG_IP_NF_AMANDA
#define CONFIG_IP_NF_PPTP 1
#undef CONFIG_IP_NF_QUEUE
#define CONFIG_IP_NF_IPTABLES 1
#define CONFIG_IP_NF_MATCH_LIMIT 1
#define CONFIG_IP_NF_MATCH_IPRANGE 1
#define CONFIG_IP_NF_MATCH_MAC 1
#undef CONFIG_IP_NF_MATCH_PKTTYPE
#define CONFIG_IP_NF_MATCH_MARK 1
#define CONFIG_IP_NF_MATCH_MULTIPORT 1
#define CONFIG_IP_NF_MATCH_TOS 1
#undef CONFIG_IP_NF_MATCH_RECENT
#undef CONFIG_IP_NF_MATCH_ECN
#undef CONFIG_IP_NF_MATCH_DSCP
#define CONFIG_IP_NF_MATCH_AH_ESP 1
#undef CONFIG_IP_NF_MATCH_LENGTH
#undef CONFIG_IP_NF_MATCH_TTL
#undef CONFIG_IP_NF_MATCH_TCPMSS
#define CONFIG_IP_NF_MATCH_HELPER 1
#define CONFIG_IP_NF_MATCH_STATE 1
#define CONFIG_IP_NF_MATCH_CONNTRACK 1
#undef CONFIG_IP_NF_MATCH_OWNER
#undef CONFIG_IP_NF_MATCH_ADDRTYPE
#undef CONFIG_IP_NF_MATCH_REALM
#undef CONFIG_IP_NF_MATCH_SCTP
#undef CONFIG_IP_NF_MATCH_DCCP
#undef CONFIG_IP_NF_MATCH_COMMENT
#undef CONFIG_IP_NF_MATCH_CONNMARK
#undef CONFIG_IP_NF_MATCH_CONNBYTES
#undef CONFIG_IP_NF_MATCH_HASHLIMIT
#define CONFIG_IP_NF_MATCH_STRING 1
#define CONFIG_IP_NF_FILTER 1
#define CONFIG_IP_NF_TARGET_REJECT 1
#define CONFIG_IP_NF_TARGET_LOG 1
#undef CONFIG_IP_NF_TARGET_ULOG
#define CONFIG_IP_NF_TARGET_TCPMSS 1
#undef CONFIG_IP_NF_TARGET_NFQUEUE
#define CONFIG_IP_NF_NAT 1
#define CONFIG_IP_NF_NAT_NEEDED 1
#define CONFIG_IP_NF_TARGET_MASQUERADE 1
#define CONFIG_IP_NF_TARGET_REDIRECT 1
#undef CONFIG_IP_NF_TARGET_NETMAP
#undef CONFIG_IP_NF_TARGET_SAME
#undef CONFIG_IP_NF_NAT_SNMP_BASIC
#define CONFIG_IP_NF_NAT_IRC 1
#define CONFIG_IP_NF_NAT_FTP 1
#define CONFIG_IP_NF_NAT_TFTP 1
#define CONFIG_IP_NF_NAT_PPTP 1
#define CONFIG_IP_NF_MANGLE 1
#define CONFIG_IP_NF_TARGET_TOS 1
#undef CONFIG_IP_NF_TARGET_ECN
#undef CONFIG_IP_NF_TARGET_DSCP
#define CONFIG_IP_NF_TARGET_MARK 1
#undef CONFIG_IP_NF_TARGET_CLASSIFY
#undef CONFIG_IP_NF_TARGET_TTL
#undef CONFIG_IP_NF_TARGET_CONNMARK
#undef CONFIG_IP_NF_TARGET_CLUSTERIP
#undef CONFIG_IP_NF_RAW
#undef CONFIG_IP_NF_ARPTABLES
#define CONFIG_IP_NF_NAT_H323 1
#define CONFIG_IP_NF_H323 1

/*
 * Bridge: Netfilter Configuration
 */
#undef CONFIG_BRIDGE_NF_EBTABLES

/*
 * DCCP Configuration (EXPERIMENTAL)
 */
#undef CONFIG_IP_DCCP

/*
 * SCTP Configuration (EXPERIMENTAL)
 */
#undef CONFIG_IP_SCTP
#undef CONFIG_ATM
#define CONFIG_BRIDGE 1
#define CONFIG_VLAN_8021Q 1
#undef CONFIG_DECNET
#undef CONFIG_LLC2
#undef CONFIG_IPX
#undef CONFIG_ATALK
#undef CONFIG_X25
#undef CONFIG_LAPB
#undef CONFIG_NET_DIVERT
#undef CONFIG_ECONET
#undef CONFIG_WAN_ROUTER

/*
 * QoS and/or fair queueing
 */
#undef CONFIG_NET_SCHED

/*
 * Network testing
 */
#undef CONFIG_NET_PKTGEN
#undef CONFIG_HAMRADIO
#undef CONFIG_IRDA
#undef CONFIG_BT
#undef CONFIG_IEEE80211

/*
 * Device Drivers
 */

/*
 * Generic Driver Options
 */
#define CONFIG_STANDALONE 1
#define CONFIG_PREVENT_FIRMWARE_BUILD 1
#define CONFIG_FW_LOADER 1

/*
 * Connector - unified userspace <-> kernelspace linker
 */
#undef CONFIG_CONNECTOR

/*
 * Memory Technology Devices (MTD)
 */
#define CONFIG_MTD 1
#undef CONFIG_MTD_DEBUG
#define CONFIG_MTD_CONCAT 1
#define CONFIG_MTD_PARTITIONS 1
#define CONFIG_MTD_REDBOOT_PARTS 1
#define CONFIG_MTD_REDBOOT_DIRECTORY_BLOCK -3
#undef CONFIG_MTD_REDBOOT_PARTS_UNALLOCATED
#undef CONFIG_MTD_REDBOOT_PARTS_READONLY
#define CONFIG_MTD_CMDLINE_PARTS 1

/*
 * User Modules And Translation Layers
 */
#define CONFIG_MTD_CHAR 1
#define CONFIG_MTD_BLOCK 1
#undef CONFIG_FTL
#undef CONFIG_NFTL
#undef CONFIG_INFTL
#undef CONFIG_RFD_FTL

/*
 * RAM/ROM/Flash chip drivers
 */
#undef CONFIG_MTD_CFI
#undef CONFIG_MTD_JEDECPROBE
#define CONFIG_MTD_MAP_BANK_WIDTH_1 1
#define CONFIG_MTD_MAP_BANK_WIDTH_2 1
#define CONFIG_MTD_MAP_BANK_WIDTH_4 1
#undef CONFIG_MTD_MAP_BANK_WIDTH_8
#undef CONFIG_MTD_MAP_BANK_WIDTH_16
#undef CONFIG_MTD_MAP_BANK_WIDTH_32
#define CONFIG_MTD_CFI_I1 1
#define CONFIG_MTD_CFI_I2 1
#undef CONFIG_MTD_CFI_I4
#undef CONFIG_MTD_CFI_I8
#undef CONFIG_MTD_RAM
#undef CONFIG_MTD_ROM
#undef CONFIG_MTD_ABSENT

/*
 * Mapping drivers for chip access
 */
#define CONFIG_MTD_COMPLEX_MAPPINGS 1
#undef CONFIG_MTD_PCI
#undef CONFIG_MTD_PLATRAM

/*
 * Self-contained MTD device drivers
 */
#undef CONFIG_MTD_PMC551
#undef CONFIG_MTD_SLRAM
#undef CONFIG_MTD_PHRAM
#undef CONFIG_MTD_MTDRAM
#undef CONFIG_MTD_BLKMTD
#undef CONFIG_MTD_BLOCK2MTD

/*
 * Disk-On-Chip Device Drivers
 */
#undef CONFIG_MTD_DOC2000
#undef CONFIG_MTD_DOC2001
#undef CONFIG_MTD_DOC2001PLUS
#define CONFIG_MTD_AR7100_SPI_FLASH 1
#undef CONFIG_MTD_AR9100_PARALLEL_FLASH

/*
 * NAND Flash Device Drivers
 */
#undef CONFIG_MTD_NAND

/*
 * OneNAND Flash Device Drivers
 */
#undef CONFIG_MTD_ONENAND

/*
 * Parallel port support
 */
#undef CONFIG_PARPORT

/*
 * Plug and Play support
 */

/*
 * Block devices
 */
#undef CONFIG_BLK_CPQ_DA
#undef CONFIG_BLK_CPQ_CISS_DA
#undef CONFIG_BLK_DEV_DAC960
#undef CONFIG_BLK_DEV_UMEM
#undef CONFIG_BLK_DEV_COW_COMMON
#undef CONFIG_BLK_DEV_LOOP
#undef CONFIG_BLK_DEV_NBD
#undef CONFIG_BLK_DEV_SX8
#undef CONFIG_BLK_DEV_RAM
#define CONFIG_BLK_DEV_RAM_COUNT 16
#undef CONFIG_CDROM_PKTCDVD
#undef CONFIG_ATA_OVER_ETH

/*
 * ATA/ATAPI/MFM/RLL support
 */
#undef CONFIG_IDE

/*
 * SCSI device support
 */
#undef CONFIG_RAID_ATTRS
#undef CONFIG_SCSI

/*
 * Multi-device support (RAID and LVM)
 */
#undef CONFIG_MD

/*
 * Fusion MPT device support
 */
#undef CONFIG_FUSION

/*
 * IEEE 1394 (FireWire) support
 */
#undef CONFIG_IEEE1394

/*
 * I2O device support
 */
#undef CONFIG_I2O

/*
 * Network device support
 */
#define CONFIG_NETDEVICES 1
#undef CONFIG_DUMMY
#undef CONFIG_BONDING
#undef CONFIG_EQUALIZER
#undef CONFIG_TUN

/*
 * ARCnet devices
 */
#undef CONFIG_ARCNET

/*
 * PHY device support
 */
#undef CONFIG_PHYLIB

/*
 * Ethernet (10 or 100Mbit)
 */
#define CONFIG_NET_ETHERNET 1
#define CONFIG_MII 1
#undef CONFIG_HAPPYMEAL
#undef CONFIG_SUNGEM
#undef CONFIG_CASSINI
#undef CONFIG_NET_VENDOR_3COM

/*
 * Tulip family network device support
 */
#undef CONFIG_NET_TULIP
#undef CONFIG_HP100
#undef CONFIG_NET_PCI

/*
 * Ethernet (1000 Mbit)
 */
#undef CONFIG_ACENIC
#undef CONFIG_DL2K
#undef CONFIG_E1000
#undef CONFIG_NS83820
#undef CONFIG_HAMACHI
#undef CONFIG_YELLOWFIN
#define CONFIG_R8169 1
#undef CONFIG_R8169_NAPI
#undef CONFIG_R8169_VLAN
#undef CONFIG_SIS190
#undef CONFIG_SKGE
#undef CONFIG_SK98LIN
#undef CONFIG_TIGON3
#undef CONFIG_BNX2
#define CONFIG_AG7100_MODULE 1
#undef CONFIG_AG7100_GE0_MII
#undef CONFIG_AG7100_GE0_RMII
#define CONFIG_AG7100_GE0_RGMII 1
#undef CONFIG_AG7100_GE0_GMII
#undef CONFIG_AG7100_GE1_IS_CONNECTED
#undef CONFIG_ATHR_PHY
#undef CONFIG_VITESSE_PHY
#undef CONFIG_VITESSE_8601_PHY
#undef CONFIG_VITESSE_8601_7395_PHY
#undef CONFIG_ICPLUS_PHY
#undef CONFIG_REALTEK_PHY
#define CONFIG_ADM6996FC_PHY 1

/*
 * Ethernet (10000 Mbit)
 */
#undef CONFIG_CHELSIO_T1
#undef CONFIG_IXGB
#undef CONFIG_S2IO

/*
 * Token Ring devices
 */
#undef CONFIG_TR

/*
 * Wireless LAN (non-hamradio)
 */
#define CONFIG_NET_RADIO 1

/*
 * Obsolete Wireless cards support (pre-802.11)
 */
#undef CONFIG_STRIP

/*
 * Wireless 802.11b ISA/PCI cards support
 */
#undef CONFIG_HERMES
#undef CONFIG_ATMEL

/*
 * Prism GT/Duette 802.11(a/b/g) PCI/Cardbus support
 */
#undef CONFIG_PRISM54
#undef CONFIG_HOSTAP
#define CONFIG_NET_WIRELESS 1

/*
 * Wan interfaces
 */
#undef CONFIG_WAN
#undef CONFIG_FDDI
#undef CONFIG_HIPPI
#define CONFIG_PPP 1
#undef CONFIG_PPP_MULTILINK
#undef CONFIG_PPP_FILTER
#define CONFIG_PPP_ASYNC 1
#define CONFIG_PPP_SYNC_TTY 1
#define CONFIG_PPP_DEFLATE 1
#define CONFIG_PPP_BSDCOMP 1
#undef CONFIG_PPP_MPPE
#define CONFIG_PPPOE 1
#define CONFIG_SLIP 1
#define CONFIG_SLIP_COMPRESSED 1
#undef CONFIG_SLIP_SMART
#undef CONFIG_SLIP_MODE_SLIP6
#undef CONFIG_SHAPER
#undef CONFIG_NETCONSOLE
#undef CONFIG_NETPOLL
#undef CONFIG_NET_POLL_CONTROLLER

/*
 * ISDN subsystem
 */
#undef CONFIG_ISDN

/*
 * Telephony Support
 */
#undef CONFIG_PHONE

/*
 * Input device support
 */
#define CONFIG_INPUT 1

/*
 * Userland interfaces
 */
#undef CONFIG_INPUT_MOUSEDEV
#undef CONFIG_INPUT_JOYDEV
#undef CONFIG_INPUT_TSDEV
#undef CONFIG_INPUT_EVDEV
#undef CONFIG_INPUT_EVBUG

/*
 * Input Device Drivers
 */
#undef CONFIG_INPUT_KEYBOARD
#undef CONFIG_INPUT_MOUSE
#undef CONFIG_INPUT_JOYSTICK
#undef CONFIG_INPUT_TOUCHSCREEN
#undef CONFIG_INPUT_MISC

/*
 * Hardware I/O ports
 */
#undef CONFIG_SERIO
#undef CONFIG_GAMEPORT

/*
 * Character devices
 */
#define CONFIG_VT 1
#define CONFIG_VT_CONSOLE 1
#define CONFIG_HW_CONSOLE 1
#undef CONFIG_SERIAL_NONSTANDARD

/*
 * Serial drivers
 */
#define CONFIG_SERIAL_8250 1
#define CONFIG_SERIAL_8250_CONSOLE 1
#define CONFIG_SERIAL_8250_NR_UARTS 4
#undef CONFIG_SERIAL_8250_EXTENDED

/*
 * Non-8250 serial port support
 */
#define CONFIG_SERIAL_CORE 1
#define CONFIG_SERIAL_CORE_CONSOLE 1
#undef CONFIG_SERIAL_JSM
#define CONFIG_UNIX98_PTYS 1
#define CONFIG_LEGACY_PTYS 1
#define CONFIG_LEGACY_PTY_COUNT 256

/*
 * IPMI
 */
#undef CONFIG_IPMI_HANDLER

/*
 * Watchdog Cards
 */
#undef CONFIG_WATCHDOG
#undef CONFIG_RTC
#undef CONFIG_GEN_RTC
#undef CONFIG_DTLK
#undef CONFIG_R3964
#undef CONFIG_APPLICOM

/*
 * Ftape, the floppy tape device driver
 */
#undef CONFIG_DRM
#undef CONFIG_RAW_DRIVER

/*
 * TPM devices
 */
#undef CONFIG_TCG_TPM
#undef CONFIG_TELCLOCK

/*
 * I2C support
 */
#undef CONFIG_I2C

/*
 * Dallas's 1-wire bus
 */
#undef CONFIG_W1

/*
 * Hardware Monitoring support
 */
#undef CONFIG_HWMON
#undef CONFIG_HWMON_VID

/*
 * Misc devices
 */

/*
 * Multimedia Capabilities Port drivers
 */

/*
 * Multimedia devices
 */
#undef CONFIG_VIDEO_DEV

/*
 * Digital Video Broadcasting Devices
 */
#undef CONFIG_DVB

/*
 * Graphics support
 */
#undef CONFIG_FB

/*
 * Console display driver support
 */
#undef CONFIG_VGA_CONSOLE
#define CONFIG_DUMMY_CONSOLE 1

/*
 * Sound
 */
#undef CONFIG_SOUND

/*
 * USB support
 */
#define CONFIG_USB_ARCH_HAS_HCD 1
#define CONFIG_USB_ARCH_HAS_OHCI 1
#define CONFIG_USB_ARCH_HAS_EHCI 1
#undef CONFIG_USB

/*
 * NOTE: USB_STORAGE enables SCSI, and 'SCSI disk support'
 */

/*
 * USB Gadget Support
 */
#undef CONFIG_USB_GADGET

/*
 * MMC/SD Card support
 */
#undef CONFIG_MMC

/*
 * InfiniBand support
 */
#undef CONFIG_INFINIBAND

/*
 * SN Devices
 */

/*
 * File systems
 */
#undef CONFIG_EXT2_FS
#undef CONFIG_EXT3_FS
#undef CONFIG_JBD
#undef CONFIG_REISERFS_FS
#undef CONFIG_JFS_FS
#undef CONFIG_FS_POSIX_ACL
#undef CONFIG_XFS_FS
#undef CONFIG_MINIX_FS
#undef CONFIG_ROMFS_FS
#undef CONFIG_INOTIFY
#undef CONFIG_QUOTA
#undef CONFIG_DNOTIFY
#undef CONFIG_AUTOFS_FS
#undef CONFIG_AUTOFS4_FS
#undef CONFIG_FUSE_FS

/*
 * CD-ROM/DVD Filesystems
 */
#undef CONFIG_ISO9660_FS
#undef CONFIG_UDF_FS

/*
 * DOS/FAT/NT Filesystems
 */
#undef CONFIG_MSDOS_FS
#undef CONFIG_VFAT_FS
#undef CONFIG_NTFS_FS

/*
 * Pseudo filesystems
 */
#define CONFIG_PROC_FS 1
#define CONFIG_PROC_KCORE 1
#define CONFIG_SYSFS 1
#undef CONFIG_TMPFS
#undef CONFIG_HUGETLB_PAGE
#define CONFIG_RAMFS 1
#undef CONFIG_RELAYFS_FS

/*
 * Miscellaneous filesystems
 */
#undef CONFIG_ADFS_FS
#undef CONFIG_AFFS_FS
#undef CONFIG_HFS_FS
#undef CONFIG_HFSPLUS_FS
#undef CONFIG_BEFS_FS
#undef CONFIG_BFS_FS
#undef CONFIG_EFS_FS
#undef CONFIG_JFFS_FS
#undef CONFIG_JFFS2_FS
#undef CONFIG_CRAMFS
#define CONFIG_SQUASHFS 1
#define CONFIG_SQUASHFS_EMBEDDED 1
#define CONFIG_SQUASHFS_FRAGMENT_CACHE_SIZE 3
#define CONFIG_SQUASHFS_VMALLOC 1
#undef CONFIG_VXFS_FS
#undef CONFIG_HPFS_FS
#undef CONFIG_QNX4FS_FS
#undef CONFIG_SYSV_FS
#undef CONFIG_UFS_FS

/*
 * Network File Systems
 */
#undef CONFIG_NFS_FS
#undef CONFIG_NFSD
#undef CONFIG_SMB_FS
#undef CONFIG_CIFS
#undef CONFIG_NCP_FS
#undef CONFIG_CODA_FS
#undef CONFIG_AFS_FS
#undef CONFIG_9P_FS

/*
 * Partition Types
 */
#undef CONFIG_PARTITION_ADVANCED
#define CONFIG_MSDOS_PARTITION 1

/*
 * Native Language Support
 */
#define CONFIG_NLS 1
#define CONFIG_NLS_DEFAULT "iso8859-1"
#undef CONFIG_NLS_CODEPAGE_437
#undef CONFIG_NLS_CODEPAGE_737
#undef CONFIG_NLS_CODEPAGE_775
#undef CONFIG_NLS_CODEPAGE_850
#undef CONFIG_NLS_CODEPAGE_852
#undef CONFIG_NLS_CODEPAGE_855
#undef CONFIG_NLS_CODEPAGE_857
#undef CONFIG_NLS_CODEPAGE_860
#undef CONFIG_NLS_CODEPAGE_861
#undef CONFIG_NLS_CODEPAGE_862
#undef CONFIG_NLS_CODEPAGE_863
#undef CONFIG_NLS_CODEPAGE_864
#undef CONFIG_NLS_CODEPAGE_865
#undef CONFIG_NLS_CODEPAGE_866
#undef CONFIG_NLS_CODEPAGE_869
#undef CONFIG_NLS_CODEPAGE_936
#undef CONFIG_NLS_CODEPAGE_950
#undef CONFIG_NLS_CODEPAGE_932
#undef CONFIG_NLS_CODEPAGE_949
#undef CONFIG_NLS_CODEPAGE_874
#undef CONFIG_NLS_ISO8859_8
#undef CONFIG_NLS_CODEPAGE_1250
#undef CONFIG_NLS_CODEPAGE_1251
#undef CONFIG_NLS_ASCII
#undef CONFIG_NLS_ISO8859_1
#undef CONFIG_NLS_ISO8859_2
#undef CONFIG_NLS_ISO8859_3
#undef CONFIG_NLS_ISO8859_4
#undef CONFIG_NLS_ISO8859_5
#undef CONFIG_NLS_ISO8859_6
#undef CONFIG_NLS_ISO8859_7
#undef CONFIG_NLS_ISO8859_9
#undef CONFIG_NLS_ISO8859_13
#undef CONFIG_NLS_ISO8859_14
#undef CONFIG_NLS_ISO8859_15
#undef CONFIG_NLS_KOI8_R
#undef CONFIG_NLS_KOI8_U
#undef CONFIG_NLS_UTF8

/*
 * Profiling support
 */
#undef CONFIG_PROFILING

/*
 * Kernel hacking
 */
#undef CONFIG_PRINTK_TIME
#undef CONFIG_DEBUG_KERNEL
#define CONFIG_LOG_BUF_SHIFT 14
#define CONFIG_CROSSCOMPILE 1
#define CONFIG_CMDLINE "console=ttyS0,115200 root=31:03 rootfstype=squashfs init=/sbin/init"

/*
 * Security options
 */
#undef CONFIG_KEYS
#undef CONFIG_SECURITY

/*
 * Cryptographic options
 */
#define CONFIG_CRYPTO 1
#define CONFIG_CRYPTO_HMAC 1
#undef CONFIG_CRYPTO_NULL
#undef CONFIG_CRYPTO_MD4
#undef CONFIG_CRYPTO_MD5
#undef CONFIG_CRYPTO_SHA1
#undef CONFIG_CRYPTO_SHA256
#undef CONFIG_CRYPTO_SHA512
#undef CONFIG_CRYPTO_WP512
#undef CONFIG_CRYPTO_TGR192
#undef CONFIG_CRYPTO_DES
#undef CONFIG_CRYPTO_BLOWFISH
#undef CONFIG_CRYPTO_TWOFISH
#undef CONFIG_CRYPTO_SERPENT
#define CONFIG_CRYPTO_AES 1
#undef CONFIG_CRYPTO_CAST5
#undef CONFIG_CRYPTO_CAST6
#undef CONFIG_CRYPTO_TEA
#undef CONFIG_CRYPTO_ARC4
#undef CONFIG_CRYPTO_KHAZAD
#undef CONFIG_CRYPTO_ANUBIS
#undef CONFIG_CRYPTO_DEFLATE
#undef CONFIG_CRYPTO_MICHAEL_MIC
#undef CONFIG_CRYPTO_CRC32C
#undef CONFIG_CRYPTO_TEST

/*
 * Hardware crypto devices
 */

/*
 * Library routines
 */
#define CONFIG_CRC_CCITT 1
#undef CONFIG_CRC16
#define CONFIG_CRC32 1
#define CONFIG_LIBCRC32C_MODULE 1
#define CONFIG_ZLIB_INFLATE 1
#define CONFIG_ZLIB_DEFLATE 1
#define CONFIG_TEXTSEARCH 1
#define CONFIG_TEXTSEARCH_KMP 1
#define CONFIG_TEXTSEARCH_BM 1
#define CONFIG_TEXTSEARCH_FSM 1
