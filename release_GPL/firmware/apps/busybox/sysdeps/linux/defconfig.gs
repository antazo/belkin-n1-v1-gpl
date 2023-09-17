#
# Automatically generated make config: don't edit
#
HAVE_DOT_CONFIG=y

#
# General Configuration
#
# CONFIG_FEATURE_BUFFERS_USE_MALLOC is not set
CONFIG_FEATURE_BUFFERS_GO_ON_STACK=y
# CONFIG_FEATURE_BUFFERS_GO_IN_BSS is not set
CONFIG_FEATURE_VERBOSE_USAGE=y
# CONFIG_FEATURE_INSTALLER is not set
# CONFIG_LOCALE_SUPPORT is not set
# CONFIG_FEATURE_DEVFS is not set
# CONFIG_FEATURE_DEVPTS is not set
# CONFIG_FEATURE_CLEAN_UP is not set
# CONFIG_FEATURE_SUID is not set
# CONFIG_SELINUX is not set

#
# Build Options
#
# CONFIG_STATIC is not set
# CONFIG_LFS is not set
USING_CROSS_COMPILER=y
CROSS_COMPILER_PREFIX="/opt/toolchains/uclibc-crosstools/bin/mips-linux-uclibc-"
EXTRA_CFLAGS_OPTIONS=""

#
# Installation Options
#
# CONFIG_INSTALL_NO_USR is not set
PREFIX="./_install"

#
# Archival Utilities
#
# CONFIG_AR is not set
# CONFIG_BUNZIP2 is not set
# CONFIG_CPIO is not set
# CONFIG_DPKG is not set
# CONFIG_DPKG_DEB is not set
# CONFIG_GUNZIP is not set
CONFIG_GZIP=y
# CONFIG_RPM2CPIO is not set
# CONFIG_RPM is not set
CONFIG_TAR=y
CONFIG_FEATURE_TAR_CREATE=y
# CONFIG_FEATURE_TAR_BZIP2 is not set
# CONFIG_FEATURE_TAR_FROM is not set
CONFIG_FEATURE_TAR_GZIP=y
# CONFIG_FEATURE_TAR_COMPRESS is not set
# CONFIG_FEATURE_TAR_OLDGNU_COMPATABILITY is not set
CONFIG_FEATURE_TAR_GNU_EXTENSIONS=y
# CONFIG_FEATURE_TAR_LONG_OPTIONS is not set
# CONFIG_UNCOMPRESS is not set
# CONFIG_UNZIP is not set

#
# Common options for cpio and tar
#
# CONFIG_FEATURE_UNARCHIVE_TAPE is not set

#
# Coreutils
#
# CONFIG_BASENAME is not set
# CONFIG_CAL is not set
CONFIG_CAT=y
# CONFIG_CHGRP is not set
CONFIG_CHMOD=y
CONFIG_CHOWN=y
# CONFIG_CHROOT is not set
# CONFIG_CMP is not set
CONFIG_CP=y
# CONFIG_CUT is not set
# CONFIG_DATE is not set
# CONFIG_DD is not set
CONFIG_DF=y
# CONFIG_DIRNAME is not set
# CONFIG_DOS2UNIX is not set
# CONFIG_DU is not set
CONFIG_ECHO=y
CONFIG_FEATURE_FANCY_ECHO=y
# CONFIG_ENV is not set
CONFIG_EXPR=y
# CONFIG_FALSE is not set
# CONFIG_FOLD is not set
# CONFIG_HEAD is not set
# CONFIG_HOSTID is not set
# CONFIG_ID is not set
# CONFIG_INSTALL is not set
# CONFIG_LENGTH is not set
CONFIG_LN=y
# CONFIG_LOGNAME is not set
CONFIG_LS=y
CONFIG_FEATURE_LS_FILETYPES=y
CONFIG_FEATURE_LS_FOLLOWLINKS=y
CONFIG_FEATURE_LS_RECURSIVE=y
CONFIG_FEATURE_LS_SORTFILES=y
CONFIG_FEATURE_LS_TIMESTAMPS=y
CONFIG_FEATURE_LS_USERNAME=y
CONFIG_FEATURE_LS_COLOR=y
# CONFIG_MD5SUM is not set
CONFIG_MKDIR=y
# CONFIG_MKFIFO is not set
# CONFIG_MKNOD is not set
# CONFIG_MV is not set
# CONFIG_OD is not set
# CONFIG_PRINTF is not set
CONFIG_PWD=y
# CONFIG_REALPATH is not set
CONFIG_RM=y
# CONFIG_RMDIR is not set
# CONFIG_SEQ is not set
# CONFIG_SHA1SUM is not set
CONFIG_SLEEP=y
# CONFIG_FEATURE_FANCY_SLEEP is not set
# CONFIG_SORT is not set
# CONFIG_STTY is not set
# CONFIG_SYNC is not set
# CONFIG_TAIL is not set
# CONFIG_TEE is not set
CONFIG_TEST=y

#
# test (forced enabled for use with shell)
#
# CONFIG_FEATURE_TEST_64 is not set
# CONFIG_TOUCH is not set
# CONFIG_TR is not set
# CONFIG_TRUE is not set
CONFIG_TTY=y
# CONFIG_UNAME is not set
# CONFIG_UNIQ is not set
# CONFIG_USLEEP is not set
# CONFIG_UUDECODE is not set
# CONFIG_UUENCODE is not set
# CONFIG_WATCH is not set
# CONFIG_WC is not set
# CONFIG_WHO is not set
# CONFIG_WHOAMI is not set
# CONFIG_YES is not set

#
# Common options for cp and mv
#
CONFIG_FEATURE_PRESERVE_HARDLINKS=y

#
# Common options for ls and more
#
CONFIG_FEATURE_AUTOWIDTH=y

#
# Common options for df, du, ls
#
# CONFIG_FEATURE_HUMAN_READABLE is not set

#
# Console Utilities
#
# CONFIG_CHVT is not set
# CONFIG_CLEAR is not set
# CONFIG_DEALLOCVT is not set
# CONFIG_DUMPKMAP is not set
# CONFIG_LOADFONT is not set
# CONFIG_LOADKMAP is not set
# CONFIG_OPENVT is not set
# CONFIG_RESET is not set
# CONFIG_SETKEYCODES is not set

#
# Debian Utilities
#
# CONFIG_MKTEMP is not set
# CONFIG_PIPE_PROGRESS is not set
# CONFIG_READLINK is not set
# CONFIG_RUN_PARTS is not set
# CONFIG_START_STOP_DAEMON is not set
# CONFIG_WHICH is not set

#
# Editors
#
# CONFIG_AWK is not set
# CONFIG_PATCH is not set
# CONFIG_SED is not set
# CONFIG_VI is not set

#
# Finding Utilities
#
# CONFIG_FIND is not set
# CONFIG_GREP is not set
# CONFIG_XARGS is not set

#
# Init Utilities
#
CONFIG_INIT=y
CONFIG_FEATURE_USE_INITTAB=y
CONFIG_FEATURE_INITRD=y
# CONFIG_FEATURE_INIT_COREDUMPS is not set
# CONFIG_FEATURE_EXTRA_QUIET is not set
# CONFIG_HALT is not set
# CONFIG_POWEROFF is not set
CONFIG_REBOOT=y
# CONFIG_MESG is not set

#
# Login/Password Management Utilities
#
# CONFIG_USE_BB_PWD_GRP is not set
# CONFIG_ADDGROUP is not set
# CONFIG_DELGROUP is not set
# CONFIG_ADDUSER is not set
# CONFIG_DELUSER is not set
# CONFIG_GETTY is not set
# CONFIG_LOGIN is not set
# CONFIG_PASSWD is not set
# CONFIG_SU is not set
# CONFIG_SULOGIN is not set
# CONFIG_VLOCK is not set

#
# Miscellaneous Utilities
#
# CONFIG_ADJTIMEX is not set
# CONFIG_CROND is not set
# CONFIG_CRONTAB is not set
# CONFIG_DC is not set
# CONFIG_DEVFSD is not set
# CONFIG_LAST is not set
# CONFIG_HDPARM is not set
# CONFIG_MAKEDEVS is not set
# CONFIG_MT is not set
# CONFIG_RX is not set
# CONFIG_STRINGS is not set
# CONFIG_TIME is not set
# CONFIG_WATCHDOG is not set
CONFIG_SYSINFO=y

#
# Linux Module Utilities
#
CONFIG_INSMOD=y
# CONFIG_FEATURE_2_4_MODULES is not set
CONFIG_FEATURE_2_6_MODULES=y
CONFIG_LSMOD=y
CONFIG_MODPROBE=y
CONFIG_RMMOD=y
# CONFIG_FEATURE_CHECK_TAINTED_MODULE is not set

#
# Networking Utilities
#
# CONFIG_FEATURE_IPV6 is not set
# CONFIG_ARPING is not set
# CONFIG_SENDARP is not set
# CONFIG_TFTPD is not set
# CONFIG_FTPGET is not set
# CONFIG_FTPPUT is not set
# CONFIG_HOSTNAME is not set
# CONFIG_HTTPD is not set
CONFIG_IFCONFIG=y
CONFIG_FEATURE_IFCONFIG_STATUS=y
# CONFIG_FEATURE_IFCONFIG_SLIP is not set
# CONFIG_FEATURE_IFCONFIG_MEMSTART_IOADDR_IRQ is not set
CONFIG_FEATURE_IFCONFIG_HW=y
# CONFIG_FEATURE_IFCONFIG_BROADCAST_PLUS is not set
# CONFIG_IFUPDOWN is not set
# CONFIG_INETD is not set
# CONFIG_IP is not set
# CONFIG_IPCALC is not set
# CONFIG_IPADDR is not set
# CONFIG_IPLINK is not set
# CONFIG_IPROUTE is not set
# CONFIG_IPTUNNEL is not set
# CONFIG_NAMEIF is not set
# CONFIG_NC is not set
# CONFIG_NETSTAT is not set
# CONFIG_NSLOOKUP is not set
CONFIG_PING=y
CONFIG_FEATURE_FANCY_PING=y
CONFIG_ROUTE=y
# CONFIG_TELNET is not set
# CONFIG_TELNETD is not set
# CONFIG_TFTP is not set
CONFIG_TRACEROUTE=y
# CONFIG_FEATURE_TRACEROUTE_VERBOSE is not set
# CONFIG_VCONFIG is not set
# CONFIG_WGET is not set

#
# Process Utilities
#
CONFIG_FREE=y
CONFIG_KILL=y
CONFIG_KILLALL=y
# CONFIG_PIDOF is not set
CONFIG_PS=y
# CONFIG_RENICE is not set
# CONFIG_TOP is not set
# CONFIG_UPTIME is not set
# CONFIG_SYSCTL is not set

#
# Another Bourne-like Shell
#
CONFIG_FEATURE_SH_IS_ASH=y
# CONFIG_FEATURE_SH_IS_HUSH is not set
# CONFIG_FEATURE_SH_IS_LASH is not set
# CONFIG_FEATURE_SH_IS_MSH is not set
# CONFIG_FEATURE_SH_IS_NONE is not set
CONFIG_ASH=y

#
# Ash Shell Options
#
CONFIG_ASH_JOB_CONTROL=y
# CONFIG_ASH_ALIAS is not set
# CONFIG_ASH_MATH_SUPPORT is not set
# CONFIG_ASH_GETOPTS is not set
# CONFIG_ASH_CMDCMD is not set
# CONFIG_ASH_MAIL is not set
CONFIG_ASH_OPTIMIZE_FOR_SIZE=y
# CONFIG_ASH_RANDOM_SUPPORT is not set
# CONFIG_HUSH is not set
# CONFIG_LASH is not set
# CONFIG_MSH is not set

#
# Bourne Shell Options
#
# CONFIG_FEATURE_SH_EXTRA_QUIET is not set
# CONFIG_FEATURE_SH_STANDALONE_SHELL is not set
CONFIG_FEATURE_COMMAND_EDITING=y
CONFIG_FEATURE_COMMAND_HISTORY=15
# CONFIG_FEATURE_COMMAND_SAVEHISTORY is not set
CONFIG_FEATURE_COMMAND_TAB_COMPLETION=y
# CONFIG_FEATURE_COMMAND_USERNAME_COMPLETION is not set
# CONFIG_FEATURE_SH_FANCY_PROMPT is not set

#
# System Logging Utilities
#
# CONFIG_SYSLOGD is not set
# CONFIG_LOGGER is not set

#
# Linux System Utilities
#
CONFIG_DMESG=y
# CONFIG_FBSET is not set
# CONFIG_FDFLUSH is not set
# CONFIG_FDFORMAT is not set
# CONFIG_FDISK is not set
# CONFIG_FREERAMDISK is not set
# CONFIG_FSCK_MINIX is not set
# CONFIG_MKFS_MINIX is not set
# CONFIG_GETOPT is not set
# CONFIG_HEXDUMP is not set
# CONFIG_HWCLOCK is not set
# CONFIG_LOSETUP is not set
# CONFIG_MKSWAP is not set
# CONFIG_MORE is not set
# CONFIG_PIVOT_ROOT is not set
# CONFIG_RDATE is not set
# CONFIG_SWAPONOFF is not set
CONFIG_MOUNT=y
# CONFIG_NFSMOUNT is not set
# CONFIG_UMOUNT is not set

#
# Common options for mount/umount
#
# CONFIG_FEATURE_MOUNT_LOOP is not set
# CONFIG_FEATURE_MTAB_SUPPORT is not set

#
# Debugging Options
#
# CONFIG_DEBUG is not set
