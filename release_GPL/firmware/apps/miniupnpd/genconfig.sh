#! /bin/sh
# $Id: genconfig.sh,v 1.1 2007-08-16 09:38:50 oliver_hao Exp $
# miniupnp daemon
# http://miniupnp.free.fr or http://miniupnp.tuxfamily.org/
# (c) 2006 Thomas Bernard
# This software is subject to the conditions detailed in the
# LICENCE file provided within the distribution

RM="rm -f"
CONFIGFILE="config.h"
CONFIGMACRO="__CONFIG_H__"

# version reported in XML descritptions
UPNP_VERSION=20070228
# Facility to syslog
LOG_MINIUPNPD="LOG_DAEMON"

# detecting the OS name and version
OS_NAME=`uname -s`
OS_VERSION=`uname -r`

# Debian GNU/Linux special case
if [ -f /etc/debian_version ]; then
	OS_NAME=Debian
	OS_VERSION=`cat /etc/debian_version`
fi

# pfSense special case
if [ -f /etc/platform ]; then
	if [ `cat /etc/platform` = "pfSense" ]; then
		OS_NAME=pfSense
		OS_VERSION=`cat /etc/version`
	fi
fi

${RM} ${CONFIGFILE}

echo "/* MiniUPnP Project" >> ${CONFIGFILE}
echo " * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/" >> ${CONFIGFILE}
echo " * (c) 2006 Thomas Bernard" >> ${CONFIGFILE}
echo " * generated by $0 on `date` */" >> ${CONFIGFILE}
echo "#ifndef $CONFIGMACRO" >> ${CONFIGFILE}
echo "#define $CONFIGMACRO" >> ${CONFIGFILE}
echo "" >> ${CONFIGFILE}
echo -e "#define UPNP_VERSION\t\"$UPNP_VERSION\"" >> ${CONFIGFILE}
echo -e "#define OS_NAME\t\t\"$OS_NAME\"" >> ${CONFIGFILE}
echo -e "#define OS_VERSION\t\"$OS_NAME/$OS_VERSION\"" >> ${CONFIGFILE}

# OS Specific stuff
case $OS_NAME in
	OpenBSD)
		MAJORVER=`echo $OS_VERSION | sed 's/\.[0-9]*//'`
		#echo "OpenBSD majorversion=$MAJORVER"
		# rtableid was introduced in OpenBSD 4.0
		if [ $MAJORVER -ge 4 ]; then
			echo "#define PFRULE_HAS_RTABLEID" >> ${CONFIGFILE}
		fi
		OS_URL=http://www.openbsd.org/
		;;
	FreeBSD)
		OS_URL=http://www.freebsd.org/
		;;
	pfSense)
		OS_URL=http://www.pfsense.com/
		;;
	NetBSD)
		OS_URL=http://www.netbsd.org/
		;;
	Debian)
		OS_URL=http://www.debian.org/
		;;
	Linux)
		OS_URL=http://www.kernel.org/
		;;
	*)
		echo "Unknown OS : $OS_NAME"
		echo "Please contact the author at http://miniupnp.free.fr/"
		exit 1
		;;
esac

echo -e "#define OS_URL\t\t\"${OS_URL}\"" >> ${CONFIGFILE}
echo "" >> ${CONFIGFILE}

echo -e "#define LOG_MINIUPNPD\t\t ${LOG_MINIUPNPD}" >> ${CONFIGFILE}
echo "" >> ${CONFIGFILE}
echo "#endif" >> ${CONFIGFILE}

exit 0
