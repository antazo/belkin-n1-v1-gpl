#define TRUE  (int)1
#define FALSE (int)0
#define BUF_SIZE        8192
#define BB_BANNER
#define RESERVE_BB_BUFFER(buffer,len)  static          char buffer[len]

#define RELEASE_BB_BUFFER(buffer)      ((void)0)

//#define __SYSLOG_DEBUG__

#ifdef __SYSLOG_DEBUG__
#define perror_msg_and_die(msg) {puts(msg); exit(FALSE);}
#define error_msg_and_die(msg,...) perror_msg_and_die(msg)
#else
#define perror_msg_and_die(msg) 
#define error_msg_and_die(msg,...)
#endif

#define show_usage() exit(0)
//#define BB_FEATURE_REMOTE_LOG
#define BB_FEATURE_IPC_SYSLOG


struct syslog_conf {
	int mail_enable;
	int mail_log_full;
    char dos_thresholds[4];//20-100
	char mail_server[128];
	char mail_sender[128];
	char mail_receiver[128];
	char mail_subject[128];
	char mail_subject_alert[128];
	char TZ[8];
	char daylight[2];
	char mail_keyword[128];
    int log_enable;//new
	char log_keyword[512];
	int log_list[20];
};
