/* vi: set sw=4 ts=4: */
/*
 * Mini syslogd implementation for busybox
 *
 * Copyright (C) 1999,2000 by Lineo, inc. and Erik Andersen
 * Copyright (C) 1999,2000,2001 by Erik Andersen <andersee@debian.org>
 *
 * Copyright (C) 2000 by Karl M. Hegbloom <karlheg@debian.org>
 *
 * "circular buffer" Copyright (C) 2001 by Gennady Feldman <gfeldman@cachier.com>
 *
 * Maintainer: Gennady Feldman <gena01@cachier.com> as of Mar 12, 2001
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include "sysklogd.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
/* SYSLOG_NAMES defined to pull some extra junk from syslog.h */
#define SYSLOG_NAMES
#include <sys/syslog.h>
#include <sys/uio.h>
#include "../nvram/nvram.h" 
/* Path for the file where all log messages are written */
#define __LOG_FILE "/var/log/messages"
#define __CONF_FILE "/etc/syslog.conf"

/* Path to the unix socket */
static char lfile[MAXPATHLEN] = "";

static char *logFilePath = __LOG_FILE;

#define dprintf(msg,...)
struct syslog_conf conf;

#define ALERT_MAX_INTERVAL 3*60

/* interval between marks in seconds */
static int MarkInterval = 10 * 60;

#ifdef SHOW_HOSTNAME 
/* localhost's name */
static char LocalHostName[64] = "";
#endif

#ifdef BB_FEATURE_REMOTE_LOG
#include <netinet/in.h> 
/* udp socket for logging to remote host */
static int remotefd = -1;
/* where do we log? */
static char *RemoteHost = NULL;
/* what port to log to? */
static int RemotePort = 514;
/* To remote log or not to remote log, that is the question. */
static int doRemoteLog = FALSE;
static int local_logging = FALSE;
#endif

#define MAXLINE         1024            /* maximum line length */
#define LAN_IF			"br0"
#define WAN_IF			"eth0"

/* circular buffer variables/structures */
#ifdef BB_FEATURE_IPC_SYSLOG
#if __GNU_LIBRARY__ < 5
#error Sorry.  Looks like you are using libc5.
#error libc5 shm support isnt good enough.
#error Please disable BB_FEATURE_IPC_SYSLOG
#endif

#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>

/* our shared key */
static const long KEY_ID = 0x414e4547; /*"GENA"*/

// Semaphore operation structures
static struct shbuf_ds
{
    int size;               // size of data written
    int head;               // start of message list
    int tail;               // end of message list
    /* can't use char *data */
    char data[1];           // data/messages
}
*buf = NULL;                  // shared memory pointer

static struct sembuf SMwup[1] =
    {
        {
            1, -1, IPC_NOWAIT
        }
    }
    ; // set SMwup
static struct sembuf SMwdn[3] =
    {
        {
            0, 0
        }
        , {1, 0}, {1, + 1}
    }
    ; // set SMwdn

static int shmid = -1;     // ipc shared memory id
static int s_semid = -1;   // ipc semaphore id
int data_size = 16000; // data size
int shm_size = 16000 + sizeof(*buf); // our buffer size
static int circular_logging = TRUE;

static void clear_signal(int sig);
static void reload_signal(int sig);
static void login(int sig);
static void logout(int sig);
static void strupper(char *str);

#ifdef __SYSLOG_DEBUG__
void mBUG(char *format, ...);
#endif

static char last_log[1024] = "";
static char timestamp[64] = "";

void logMessage (int pri, char *msg);
void get_timestamp(void);
int time_adjust(char *tz);
int daylight_saving(void);

/*
 * sem_up - up()'s a semaphore.
 */
static inline void sem_up(int semid)
{
    if ( semop(semid, SMwup, 1) == -1 )
        perror_msg_and_die("semop[SMwup]");
}

/*
 * sem_down - down()'s a semaphore
 */
static inline void sem_down(int semid)
{
    if ( semop(semid, SMwdn, 3) == -1 )
        perror_msg_and_die("semop[SMwdn]");
}


void ipcsyslog_cleanup(void)
{
    dprintf("Exiting Syslogd!\n");
    if (shmid != -1)
        shmdt(buf);

    if (shmid != -1)
        shmctl(shmid, IPC_RMID, NULL);
    if (s_semid != -1)
        semctl(s_semid, 0, IPC_RMID, 0);
}

void ipcsyslog_init(void)
{
    if (buf == NULL)
    {
        if ((shmid = shmget(KEY_ID, shm_size, IPC_CREAT | 1023)) == -1)
            perror_msg_and_die("shmget");


        if ((buf = shmat(shmid, (char *)NULL, 0)) == -1)
            perror_msg_and_die("shmat");


        buf->size = data_size;
        buf->head = buf->tail = 0;

        // we'll trust the OS to set initial semval to 0 (let's hope)
        if ((s_semid = semget(KEY_ID, 2, IPC_CREAT | IPC_EXCL | 1023)) == -1)
        {
            if (errno == EEXIST)
            {
                if ((s_semid = semget(KEY_ID, 2, 0)) == -1)
                    perror_msg_and_die("semget");
            }
            else
                perror_msg_and_die("semget");
        }
    }
    else
    {
        dprintf("Buffer already allocated just grab the semaphore?");
    }
}

static void send_mail_signal(int sig)
{
    //	sem_down(s_semid);

    if (conf.mail_enable == 1)
    {
        char cmd[1024];

        sprintf(cmd, "/usr/sbin/smtpc -m -h %s -r %s -f %s -s \"%s\" </var/log/messages "
                , conf.mail_server
                , conf.mail_receiver
                , conf.mail_sender
                , conf.mail_subject);

        if (system(cmd) == 0)
        {
            buf->head = 0;
            buf->tail = 0;
        }
    }

    //	sem_up(s_semid);
}

/* write message to buffer */
void circ_message(const char *msg)
{
    int l = strlen(msg); /* count the whole message w/ '\0' included */

    sem_down(s_semid);

    if ( (buf->tail + l) < buf->size )
    {
        if ( buf->tail < buf->head)
        {
            if ( (buf->tail + l) >= buf->head )
            {
                int k = buf->tail + l - buf->head;
                char *c = memchr(buf->data + buf->head + k, '\n', buf->size - (buf->head + k));
                buf->head = (c != NULL) ? ( c - buf->data + 1) : 0;

            }
        }
        strncpy(buf->data + buf->tail, msg, l); /* append our message */
        buf->tail += l;
    }
    else
    {
        char *c;
        int k = buf->tail + l - buf->size;

        c = memchr(buf->data + k , '\n', buf->size - k);

        if (c != NULL)
        {
            buf->head = c - buf->data + 1;
            strncpy(buf->data + buf->tail, msg, l - k - 1);
            strcpy(buf->data, &msg[l - k - 1]);
            buf->tail = k + 1;
        }
        else
        {
            buf->head = buf->tail = 0;
        }

    }
    sem_up(s_semid);
}
#endif  /* BB_FEATURE_IPC_SYSLOG */

/* try to open up the specified device */
int device_open(char *device, int mode)
{
    int m, f, fd = -1;

    m = mode | O_NONBLOCK;

    /* Retry up to 5 times */
    for (f = 0; f < 5; f++)
        if ((fd = open(device, m, 0600)) >= 0)
            break;
    if (fd < 0)
        return fd;
    /* Reset original flags. */
    if (m != mode)
        fcntl(fd, F_SETFL, mode);
    return fd;
}
int vdprintf(int d, const char *format, va_list ap)
{
    char buf[BUF_SIZE];
    int len;

    len = vsnprintf(buf, sizeof(buf), format, ap);
    return write(d, buf, len);
}


/* Note: There is also a function called "message()" in init.c */
/* Print a message to the log file. */
static void message (char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
static void message (char *fmt, ...)
{
    int fd;
    struct flock fl;
    va_list arguments;

    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 1;
#ifdef BB_FEATURE_IPC_SYSLOG

    if ((circular_logging == TRUE) && (buf != NULL))
    {
        char b[1024];
        va_start (arguments, fmt);
        vsnprintf (b, sizeof(b) - 1, fmt, arguments);
        va_end (arguments);
        circ_message(b);

#ifdef __SYSLOG_DEBUG__

        printf("head=%d tail=%d\n", buf->head, buf->tail);
#endif 
        /* print_circ_buf */
        if ((fd = open(logFilePath, O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK)) < 0)
            return ;
        fl.l_type = F_WRLCK;
        fcntl(fd, F_SETLKW, &fl);
        if (buf->tail > buf->head)
        {
            write(fd, buf->data, buf->tail);
            write(fd, "\0", 1);
        }
        else
        {

            write(fd, buf->data + buf->head, buf->size - buf->head - 1);
            write(fd, buf->data, buf->tail);
            write(fd, "\0", 1);

            if (conf.mail_log_full == 1)
                send_mail_signal(0);
        }
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLKW, &fl);
        close(fd);
    }
    else
#endif
    if ((fd = device_open (logFilePath,
                           O_WRONLY | O_CREAT | O_NOCTTY | O_APPEND |
                           O_NONBLOCK)) >= 0)
    {
        fl.l_type = F_WRLCK;
        fcntl (fd, F_SETLKW, &fl);
        va_start (arguments, fmt);
        vdprintf (fd, fmt, arguments);
        va_end (arguments);
        fl.l_type = F_UNLCK;
        fcntl (fd, F_SETLKW, &fl);
        close (fd);
    }
    else
    {
        /* Always send console messages to /dev/console so people will see them. */
        if ((fd = device_open (_PATH_CONSOLE,
                               O_WRONLY | O_NOCTTY | O_NONBLOCK)) >= 0)
        {
            va_start (arguments, fmt);
            vdprintf (fd, fmt, arguments);
            va_end (arguments);
            close (fd);
        }
        else
        {
            fprintf (stderr, "Bummer, can't print: ");
            va_start (arguments, fmt);
            vfprintf (stderr, fmt, arguments);
            fflush (stderr);
            va_end (arguments);
        }
    }
}

void strccpy2(char *dst, char *src, char *key, char c)
{
    char *pt = strstr(src, key);
    if (pt == NULL)
    {
        dst[0] = '\0';
        return ;
    }
    pt += strlen(key);
    for (;*pt != c && *pt != '\0';*dst++ = *pt++)
        ;
    *dst = '\0';

}

#define min(x, y) ((x) < (y) ? (x) : (y))

void logMessage (int pri, char *msg)
{
    char *p, *p1, *p2;
    char name[20];
    char srcip[16], dstip[16], srcport[6], dstport[6], protocal[20];
    char dhcpip[16], dhcpmac[20], LeaOrReq[15];
    char logip[16], getip[16];
    char *poe_mode, *ppp_mode;

    if (msg != NULL)
    {
        p = msg;
        p1 = msg;
        p2 = msg;
    }
    else
        return ;

    /* if msg had time stamp ,remove it*/
    if (strlen(msg) > 16 && msg[3] == ' ' && msg[6] == ' ' &&
            msg[9] == ':' && msg[12] == ':' && msg[15] == ' ')
        msg += 16;
    
    /* get current time */
    get_timestamp();
    
#ifdef __SYSLOG_DEBUG__

    printf("%s,%s\n", msg, timestamp);
    mBUG("%s\n", msg);
#endif

    p1 = strstr(p1, "[");
    p2 = strstr(p2, "]");

    if (p1 == NULL || p2 == NULL)
        return ;

    snprintf(name, min(sizeof(name), p2 - p1), "%s", p1 + 1);

#ifdef __SYSLOG_DEBUG__

    printf("name=%s\n", name);
#endif
    
    /* parse system log*/
    if (strcmp(name, "Unauthorized") == 0)
    {
        //msg format: [Unauthorized] 192.168.2.2 Unauthorized login
        sscanf(p2 + 2, "%[^ ] ", logip);
        message("[%s] %s %s Unauthorized login\r\n", name, timestamp, logip);
        return ;

    }
    else if (strcmp(name, "Wan") == 0)
    { 
        message("[%s] %s %s\r\n", name, timestamp, p2 + 2);
        return ;

    }
    else if (strcmp(name, "Dhcp") == 0)
    { //DHCP server message
        //msg format: [DHCP] X.X.X.X XX:XX:XX:XX:XX:XX Request/Release
        sscanf(p2 + 2, "%s %s %s", dhcpip, dhcpmac, LeaOrReq);
        message("[%s] %s %s  %s %s\r\n", name, timestamp, dhcpip, dhcpmac, LeaOrReq);
        return ;

    }
    else if (strcmp(name, "Dhcpc") == 0)
    { // dhcp client message
        //[Dhcpc] X.X.X.X obtain
        sscanf(p2 + 2, "%[^ ] ", getip);
        message("[Wan] %s WAN DHCP Client Connected IP %s\r\n", timestamp, getip);
        return ;
    }
    else if ( strcmp(name, "PPPoE") == 0)
    {
        poe_mode = nvram_get("wan_mode");
        if (strcmp(poe_mode, "pppoe") == 0)
            message("[Wan] %s WAN %s\r\n", timestamp, p2 + 2);

        if (poe_mode)
            free(poe_mode);
        return ;
    }
    else if ((strcmp(name, "PPTP") == 0) || (strcmp(name, "BPA") == 0) || (strcmp(name, "L2TP") == 0))
    {
        message("[Wan] %s WAN %s\r\n", timestamp, p2 + 2);
        return ;
    }
    else if (strcmp(name, "PPP") == 0)
    { // connected or disconnected
        ppp_mode = nvram_get("wan_mode");
        strupper(ppp_mode);

        if (strstr(p2, "disconnected") && strcmp(ppp_mode, "L2TP"))
            message("[Wan] %s WAN %s disconnected\r\n", timestamp, ppp_mode);
        else
            message("[Wan] %s WAN %s\r\n", timestamp, p2 + 2);
        
        if (ppp_mode)
            free(ppp_mode);
        return ;
    }
    else if (strcmp(name, "Error") == 0)
    { // error event message
        message("[%s] %s %s\r\n", name, timestamp, p2 + 2);
        return ;
    }
    else if (strcmp(name, "MACFILTER") == 0)
    { 
        char src_mac[18] = {0};
        char *mac = strstr(p2, "MAC="); //MAC=ff:ff:ff:ff:ff:ff:00:00:63:80:00:70:08:00

        strncpy(src_mac, mac + 22, 17);
        
        message("[%s] %s Mac %s is blocked by firewall mac filter\r\n", name, timestamp, src_mac);
        return ;
    }

    /*
     * parser the message dropped by firewall
     */
    if ((strcmp(name, "Block") == 0) || (strcmp(name , "Dos") == 0))
    {
        /* msg format: [Block]IN=br0 OUT=eth1 SRC=192.168.1.100 DST=61.172.201.47
         *            					LEN=48 TOS=0x00 PREC=0x00 TTL=127 ID=4421 DF 
         *								PROTO=TCP SPT=1106 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
         *
            * msg format: [Dos]IN=eth0 OUT= MAC=00:c0:02:77:82:32:00:0c:76:23:9e:57:08:00 
        	 *                     SRC=172.21.4.93 DST=172.21.4.87 LEN=48 
        	 *	             	  TOS=0x06 PREC=0x00 TTL=125 ID=54633 PROTO=UDP SPT=7553 DPT=65130 LEN=28 	
        	 * ICMP format:
        	 *              ICMP flood: [Dos] IN=eth0 OUT= MAC=00:c0:02:77:82:32:00:0c:76:23:9e:57:08:00 
        	 *                     SRC=172.21.4.93 DST=172.21.4.87 LEN=48 PROTO=ICMP
        	 *              PingOfDeath: [Dos] PingOfDeath SRC=x.x.x.x DST=x.x.x.x
        	 */
        p1 = strstr(p1, "SRC");
        if (p1)
            sscanf(p1 + 4, "%[^ ] ", srcip);
        else
            return ;

        p1 = strstr(p1, "DST");
        if (p1)
            sscanf(p1 + 4, "%[^ ] ", dstip);
        else
            return ;

        if (strstr(p2, "PingOfDeath"))
        {
            message("[%s] %s Ping Of Death attack from %s to %s droped\r\n", name, timestamp, srcip, dstip);
            return ;
        }

        p1 = strstr(p1, "PROTO=");
        if (p1)
            sscanf(p1 + 6, "%[^ ] ", protocal);
        else
            return ;

        if (strcmp(protocal, "ICMP") == 0)
        {
            message("[%s] %s %s flood From %s To %s droped\r\n", name, timestamp, protocal, srcip, dstip);
            return ;
        }

        p1 = strstr(p1, "SPT");
        if (p1)
            sscanf(p1 + 4, "%[^ ] ", srcport);
        else
            return ;

        p1 = strstr(p1, "DPT");
        if (p1)
            sscanf(p1 + 4, "%[^ ] ", dstport);
        else
            return ;

        if (strcmp(name, "Dos") == 0)
        {
            /* UDP or TCP flood */
            message("[%s] %s %s flood From %s port:%s To %s port:%s droped\r\n", name, timestamp, protocal, srcip, srcport, dstip, dstport);
        }
        else /* Block */
            message("[%s] %s %s From %s port:%s To %s port:%s blocked\r\n", name, timestamp, protocal, srcip, srcport, dstip, dstport);

        return ;
    }
}

static void quit_signal(int sig)
{
    //logMessage(LOG_SYSLOG | LOG_INFO, "System log daemon exiting.");
    unlink(lfile);
#ifdef BB_FEATURE_IPC_SYSLOG

    ipcsyslog_cleanup();
#endif

    exit(TRUE);
}

static inline void router_start()
{
    char tmp_tz[20];
    
    if (access("/var/ntp_get_time_success", F_OK))
        return;
        
    unlink("/var/ntp_get_time_success");
    
    get_timestamp();
    
    /* For exampe: GMT+12:3:1 */
    strncpy(tmp_tz, conf.TZ, sizeof(tmp_tz) - 1);
    
    /* set first ':' to '\0' */
    if(tmp_tz[5] < '0' || tmp_tz[5] > '9')
        tmp_tz[5] = '\0';
    else
        tmp_tz[6] = '\0';
        
    message("%s %s - %s %s\r\n", "[Time]", timestamp, "Router get real time with time-zone", &tmp_tz[3]);
}

void get_timestamp(void)
{
    time_t now;
    char *wday[7] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    struct tm *st;

    time(&now);
    if (*conf.daylight == '1')
        now += (daylight_saving()) * 60 * 60;
    now += time_adjust(conf.TZ) * 60;
    st = localtime(&now);

    snprintf(timestamp, sizeof(timestamp), "%s %d-%02d-%02d %02d:%02d:%02d"
            , wday[st->tm_wday]
            , st->tm_year + 1900
            , st->tm_mon + 1
            , st->tm_mday
            , st->tm_hour
            , st->tm_min
            , st->tm_sec);
}

static void domark(int sig)
{
        router_start();
    last_log[0] = '\0';
    alarm(MarkInterval);
}
static void login(int sig)
{
    char *login_ip;

    login_ip = nvram_get("login_ip");
    get_timestamp();

    message("%s %s %s %s\r\n", "[Login]", timestamp, login_ip, "login");

    if (login_ip)
        free(login_ip);
}
static void logout(int sig)
{
    char *login_ip;

    login_ip = nvram_get("login_ip");
    get_timestamp();
    message("%s %s %s %s\r\n", "[Logout]", timestamp, login_ip, "logout");

    if (login_ip)
        free(login_ip);
}
/* This must be a #define, since when DODEBUG and BUFFERS_GO_IN_BSS are
 * enabled, we otherwise get a "storage size isn't constant error. */
static int serveConnection (char* tmpbuf, int n_read)
{
    char *p = tmpbuf;

    while (p < tmpbuf + n_read)
    {

        int pri = (LOG_USER | LOG_NOTICE);
        char line[ MAXLINE + 1 ];
        unsigned char c;
        int find = 0;

        char *q = line;

        while ( (c = *p) && q < &line[ sizeof (line) - 1 ])
        {
            if (c == '<' && find == 0)
            {
                /* Parse the magic priority number. */
                pri = 0;
                find = 1;
                while (isdigit (*(++p)))
                {
                    pri = 10 * pri + (*p - '0');
                }
                if (pri & ~(LOG_FACMASK | LOG_PRIMASK))
                {
                    pri = (LOG_USER | LOG_NOTICE);
                }
            }
            else if (c == '\n')
            {
                *q++ = ' ';
            }
            else if (iscntrl (c) && (c < 0177))
            {
                *q++ = '^';
                *q++ = c ^ 0100;
            }
            else
            {
                *q++ = c;
            }
            p++;
        }
        *q = '\0';
        p++;
        /* Now log it */
        logMessage (pri, line);
    }
    return n_read;
}


#ifdef BB_FEATURE_REMOTE_LOG
static void init_RemoteLog (void)
{

    struct sockaddr_in remoteaddr;
    struct hostent *hostinfo;
    int len = sizeof(remoteaddr);
    int so_bc = 1;

    memset(&remoteaddr, 0, len);

    remotefd = socket(AF_INET, SOCK_DGRAM, 0);

    if (remotefd < 0)
    {
        error_msg_and_die("cannot create socket");
    }

    remoteaddr.sin_family = AF_INET;

    /* Ron */
    /* allow boardcast */
    setsockopt(remotefd, SOL_SOCKET, SO_BROADCAST, &so_bc, sizeof(so_bc));
    hostinfo = gethostbyname(RemoteHost);
    remoteaddr.sin_addr = *(struct in_addr *) * hostinfo->h_addr_list;
    remoteaddr.sin_port = htons(RemotePort);

    /*
       Since we are using UDP sockets, connect just sets the default host and port
       for future operations
    */
    if ( 0 != (connect(remotefd, (struct sockaddr *) &remoteaddr, len)))
    {
        error_msg_and_die("cannot connect to remote host %s:%d", RemoteHost, RemotePort);
    }
}
#endif

static void doSyslogd (void) __attribute__ ((noreturn));
static void doSyslogd (void)
{
    struct sockaddr_un sunx;
    socklen_t addrLength;

    int sock_fd;
    fd_set fds;

    /* Set up signal handlers. */
    signal (SIGINT, quit_signal);
    signal (SIGTERM, quit_signal);
    signal (SIGQUIT, quit_signal);
    signal (SIGHUP, send_mail_signal);
    signal (SIGUSR1, clear_signal);
    signal (SIGUSR2, reload_signal);
    signal (SIGCHLD, SIG_IGN);
#ifdef SIGCLD

    signal (SIGCLD, SIG_IGN);
#endif

    signal (SIGTTIN, login);
    signal (SIGTTOU, logout);

    signal (SIGALRM, domark);
    //wait ntp get correct time
    alarm (MarkInterval);

    /* Create the syslog file so realpath() can work. */
    if (realpath (_PATH_LOG, lfile) != NULL)
        unlink (lfile);

    memset (&sunx, 0, sizeof (sunx));
    sunx.sun_family = AF_UNIX;
    strncpy (sunx.sun_path, lfile, sizeof (sunx.sun_path));
    if ((sock_fd = socket (AF_UNIX, SOCK_DGRAM, 0)) < 0)
        perror_msg_and_die ("Couldn't get file descriptor for socket " _PATH_LOG);

    addrLength = sizeof (sunx.sun_family) + strlen (sunx.sun_path);
    if (bind(sock_fd, (struct sockaddr *) &sunx, addrLength) < 0)
        perror_msg_and_die ("Could not connect to socket " _PATH_LOG);

    if (chmod (lfile, 0666) < 0)
        perror_msg_and_die ("Could not set permission on " _PATH_LOG);

    if (circular_logging == TRUE )
    {
        ipcsyslog_init();
    }
#ifdef BB_FEATURE_REMOTE_LOG
    if (doRemoteLog == TRUE)
    {
        init_RemoteLog();
    }
#endif

    for (;;)
    {

        FD_ZERO (&fds);
        FD_SET (sock_fd, &fds);

        if (select (sock_fd + 1, &fds, NULL, NULL, NULL) < 0)
        {
            if (errno == EINTR)
            {
                /* alarm may have happened. */
                continue;
            }
            perror_msg_and_die ("select error");
        }

        if (FD_ISSET (sock_fd, &fds))
        {
            int i;
            RESERVE_BB_BUFFER(tmpbuf, BUFSIZ + 1);

            memset(tmpbuf, '\0', BUFSIZ + 1);
            if ( (i = recv(sock_fd, tmpbuf, BUFSIZ, 0)) > 0)
            {
                serveConnection(tmpbuf, i);
            }
            else
            {
                perror_msg_and_die ("UNIX socket error");
            }
            RELEASE_BB_BUFFER (tmpbuf);
        } /* FD_ISSET() */
    } /* for main loop */
}

char *config_file_path;

int parse_config(char *conf_path);

static void clear_signal(int sig)
{
    buf->head = 0;
    buf->tail = 0;
}

static void reload_signal(int sig)
{
    char old_tz[20] = {0};
    
    strncpy(old_tz, conf.TZ, sizeof(old_tz) - 1);
    parse_config(config_file_path);
    if(strncmp(&old_tz[3], &conf.TZ[3], 3))
    {
        get_timestamp();
        strncpy(old_tz, conf.TZ, sizeof(old_tz) - 1);
        if(old_tz[5] < '0' || old_tz[5] > '9')
            old_tz[5] = '\0';
        else
            old_tz[6] = '\0';
            
        message("%s %s - %s %s\r\n", "[Time]", timestamp, "Change time-zone to", &old_tz[3]);
    }
}


/* Modify by Jeff -Feb.22.2005- */
int parse_config(char *conf_path)
{
    FILE *fp;
    char buf[1024];
#ifdef DEBUG

    printf("conf_path==%s\n", conf_path);
#endif

    if (conf_path == NULL)
        fp = fopen(__CONF_FILE, "r");
    else
        fp = fopen(conf_path, "r");

    if (fp == NULL)
        return FALSE;

    fread(buf, 1024, 1, fp);
    fclose(fp);

    /* initial conf */
    bzero(&conf, sizeof(conf));
    memset(&conf.log_list, -1, sizeof(conf.log_list));
    /* initial conf */

    if (strstr(buf, "email_alert=1"))
        conf.mail_enable = 1;

    /* if email is not enable ,we don't need to parser those config*/
    if (conf.mail_enable == 1)
    {
        if (strstr(buf, "mail_log_full=1"))
            conf.mail_log_full = 1;
        strccpy2(conf.mail_server, buf, "smtp_mail_server=", '\n');
        strccpy2(conf.mail_receiver, buf, "email_alert_addr=", '\n');
        strccpy2(conf.mail_sender, buf, "email_return_addr=", '\n');
        strccpy2(conf.mail_subject, buf, "mail_subject=", '\n');
        strccpy2(conf.mail_subject_alert, buf, "mail_subject_alert=", '\n');
        strccpy2(conf.mail_keyword, buf, "mail_keyword=", '\n');
        strccpy2(conf.dos_thresholds, buf, "dos_thresholds=", '\n');
    }


    strccpy2(conf.TZ, buf, "TZ=", '\n');

    strccpy2(conf.daylight, buf, "daylight=", '\n');

    if (strstr(buf, "log_enable=1"))
        conf.log_enable = 1;

    strccpy2(conf.log_keyword, buf, "log_keyword=", '\n');

    return TRUE;
}

int syslogd_main(int argc, char **argv)
{
    int opt;
#if ! defined(__uClinux__)

    int doFork = TRUE;
#endif

    /* do normal option parsing */
    while ((opt = getopt(argc, argv, "m:nO:R:f:LC")) > 0)
    {
        switch (opt)
        {
            case 'm':
                MarkInterval = atoi(optarg) * 60;
                break;
#if ! defined(__uClinux__)

            case 'n':
                doFork = FALSE;
                break;
#endif

            case 'O':
                logFilePath = strdup(optarg);
                break;
#ifdef BB_FEATURE_REMOTE_LOG

            case 'R':
                if (RemoteHost != NULL)
                    free(RemoteHost);
                RemoteHost = strdup(optarg);
                if ( (p = strchr(RemoteHost, ':')))
                {
                    RemotePort = atoi(p + 1);
                    *p = '\0';
                }
                doRemoteLog = TRUE;
                break;
            case 'L':
                local_logging = TRUE;
                break;
#endif
#ifdef BB_FEATURE_IPC_SYSLOG

            case 'C':
                circular_logging = TRUE;
                break;
#endif

            case 'f':
                config_file_path = optarg;
                if (parse_config(optarg) == FALSE)
                    show_usage();
                break;

            default:
                show_usage();
        }
    }
#ifdef BB_FEATURE_REMOTE_LOG
    /* If they have not specified remote logging, then log locally */
    if (doRemoteLog == FALSE)
        local_logging = TRUE;
#endif

#ifdef SHOW_HOSTNAME 
    //	}
    /* Store away localhost's name before the fork */
    gethostname(LocalHostName, sizeof(LocalHostName));
    if ((p = strchr(LocalHostName, '.')))
    {
        *p++ = '\0';
    }
#endif
    umask(0);

#if ! defined(__uClinux__)

    if (doFork == TRUE)
    {
        if (daemon(0, 1) < 0)
            perror_msg_and_die("daemon");
    }
#endif
    doSyslogd();

    return EXIT_SUCCESS;
}
#if 1
extern int klogd_main (int argc , char **argv);

int main(int argc , char **argv)
{
    int ret = 0;
    char *base = strrchr(argv[0], '/');

    if (strstr(base ? (base + 1) : argv[0], "syslogd"))
        ret = syslogd_main(argc, argv);
    else if (strstr(base ? (base + 1) : argv[0], "klogd"))
        ret = klogd_main(argc, argv);
    else
        show_usage();

    return ret;
}
#endif

static void strupper(char *str)
{
    char *c = str;

    if (!str)
        return ;

    while (*c)
    {
        *c = ( *c >= 'a' && *c <= 'z' ) ? *c - 32 : *c;
        c++;
    }
}

void mBUG(char *format, ...)
{
    va_list args;
    FILE *fp;

    fp = fopen("/var/syslogd_test", "a+");
    if (!fp)
    {
        return ;
    }
    va_start(args, format);
    vfprintf(fp, format, args);
    va_end(args);
    fprintf(fp, "\n");
    fflush(fp);
    fclose(fp);
    system("/bin/chmod 777 /var/syslogd_test");
}
/*
Local Variables
c-file-style: "linux"
c-basic-offset: 4
tab-width: 4
End:
*/
