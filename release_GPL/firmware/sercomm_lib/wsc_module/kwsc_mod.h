/* =============================================================================      
 * Copyright (C) 2006-2007, Sercomm (Suzhou) R&D Center,  All Rights Reserved
 * =============================================================================
 */

#ifndef KWSC_MOD_H
#define KWSC_MOD_H

#define WSC_STA_CALLBACK 1
#define WSC_TX_UPNPEVENT 2
#define WSC_DAEMON 3
#define WSC_PUSH_BUTTON 4
#define WSC_SETPIN	5

#define NETLINK_WSC  27

#define SETPIN 0x01
#define CANCEL_PIN 0x02

#define WSC_MSG_LEN 2048

//from libwsc


#define SIZE_1_BYTE         1
#define SIZE_2_BYTES        2
#define SIZE_4_BYTES        4
#define SIZE_6_BYTES        6
#define SIZE_8_BYTES        8
#define SIZE_16_BYTES       16
#define SIZE_20_BYTES       20
#define SIZE_32_BYTES       32
#define SIZE_64_BYTES       64
#define SIZE_80_BYTES       80
#define SIZE_128_BYTES      128
#define SIZE_192_BYTES      192


#define SIZE_64_BITS        8
#define SIZE_128_BITS       16
#define SIZE_160_BITS       20
#define SIZE_256_BITS       32

#define SIZE_ENCR_IV            SIZE_128_BITS
#define ENCR_DATA_BLOCK_SIZE    SIZE_128_BITS
#define SIZE_DATA_HASH          SIZE_160_BITS
#define SIZE_PUB_KEY_HASH       SIZE_160_BITS
#define SIZE_UUID               SIZE_16_BYTES
#define SIZE_MAC_ADDR           SIZE_6_BYTES
#define SIZE_PUB_KEY            SIZE_192_BYTES //1536 BITS
#define SIZE_ENROLLEE_NONCE     SIZE_128_BITS

// Data Element Definitions
#define WSC_ID_AP_CHANNEL         0x1001
#define WSC_ID_ASSOC_STATE        0x1002
#define WSC_ID_AUTH_TYPE          0x1003
#define WSC_ID_AUTH_TYPE_FLAGS    0x1004
#define WSC_ID_AUTHENTICATOR      0x1005
#define WSC_ID_CONFIG_METHODS     0x1008
#define WSC_ID_CONFIG_ERROR       0x1009
#define WSC_ID_CONF_URL4          0x100A
#define WSC_ID_CONF_URL6          0x100B
#define WSC_ID_CONN_TYPE          0x100C
#define WSC_ID_CONN_TYPE_FLAGS    0x100D
#define WSC_ID_CREDENTIAL         0x100E
#define WSC_ID_DEVICE_NAME        0x1011
#define WSC_ID_DEVICE_PWD_ID      0x1012
#define WSC_ID_E_HASH1            0x1014
#define WSC_ID_E_HASH2            0x1015
#define WSC_ID_E_SNONCE1          0x1016
#define WSC_ID_E_SNONCE2          0x1017
#define WSC_ID_ENCR_SETTINGS      0x1018
#define WSC_ID_ENCR_TYPE          0x100F
#define WSC_ID_ENCR_TYPE_FLAGS    0x1010
#define WSC_ID_ENROLLEE_NONCE     0x101A
#define WSC_ID_FEATURE_ID         0x101B
#define WSC_ID_IDENTITY           0x101C
#define WSC_ID_IDENTITY_PROOF     0x101D
#define WSC_ID_INIT_VECTOR        0x104B //this becomes 0x1060 later
//#define WSC_ID_KEY_WRAP_AUTH      WSC_ID_AUTHENTICATOR //this becomes 0x101E later
#define WSC_ID_KEY_WRAP_AUTH      0x101E // HH changed for MS beta 2 testing
#define WSC_ID_KEY_IDENTIFIER     0x101F
#define WSC_ID_MAC_ADDR           0x1020
#define WSC_ID_MANUFACTURER       0x1021
#define WSC_ID_MSG_TYPE           0x1022
#define WSC_ID_MODEL_NAME         0x1023
#define WSC_ID_MODEL_NUMBER       0x1024
#define WSC_ID_NW_INDEX           0x1026
#define WSC_ID_NW_KEY             0x1027
#define WSC_ID_NW_KEY_INDEX       0x1028
#define WSC_ID_NEW_DEVICE_NAME    0x1029
#define WSC_ID_NEW_PWD            0x102A        
#define WSC_ID_OOB_DEV_PWD        0x102C
#define WSC_ID_OS_VERSION         0x102D
#define WSC_ID_POWER_LEVEL        0x102F
#define WSC_ID_PSK_CURRENT        0x1030
#define WSC_ID_PSK_MAX            0x1031
#define WSC_ID_PUBLIC_KEY         0x1032
#define WSC_ID_RADIO_ENABLED      0x1033
#define WSC_ID_REBOOT             0x1034
#define WSC_ID_REGISTRAR_CURRENT  0x1035
#define WSC_ID_REGISTRAR_ESTBLSHD 0x1036
#define WSC_ID_REGISTRAR_LIST     0x1037
#define WSC_ID_REGISTRAR_MAX      0x1038
#define WSC_ID_REGISTRAR_NONCE    0x1039
#define WSC_ID_REQ_TYPE           0x103A
#define WSC_ID_RESP_TYPE          0x103B
#define WSC_ID_RF_BAND            0x103C
#define WSC_ID_R_HASH1            0x103D
#define WSC_ID_R_HASH2            0x103E
#define WSC_ID_R_SNONCE1          0x103F
#define WSC_ID_R_SNONCE2          0x1040
#define WSC_ID_SEL_REGISTRAR      0x1041
#define WSC_ID_SERIAL_NUM         0x1042
#define WSC_ID_SC_STATE           0x1044
#define WSC_ID_SSID               0x1045
#define WSC_ID_TOT_NETWORKS       0x1046
#define WSC_ID_UUID_E             0x1047
#define WSC_ID_UUID_R             0x1048
#define WSC_ID_VENDOR_EXT         0x1049
#define WSC_ID_VERSION            0x104A
#define WSC_ID_X509_CERT_REQ      0x104B
#define WSC_ID_X509_CERT          0x104C
#define WSC_ID_EAP_IDENTITY       0x104D
#define WSC_ID_MSG_COUNTER        0x104E
#define WSC_ID_PUBKEY_HASH        0x104F
#define WSC_ID_REKEY_KEY          0x1050
#define WSC_ID_KEY_LIFETIME       0x1051
#define WSC_ID_PERM_CFG_METHODS   0x1052
#define WSC_ID_SEL_REG_CFG_METHODS 0x1053
#define WSC_ID_PRIM_DEV_TYPE      0x1054
#define WSC_ID_SEC_DEV_TYPE_LIST  0x1055
#define WSC_ID_PORTABLE_DEVICE    0x1056
#define WSC_ID_AP_SETUP_LOCKED    0x1057
#define WSC_ID_APP_LIST           0x1058
#define WSC_ID_LAST               (WSC_ID_APP_LIST+1)

#define WSC_IE_SIZE    (WSC_ID_LAST & 0xFFF)
#define WSC_IE_MASK(x)  (x & 0xFFF)


#define UPNP_EVENT_PROBE            1
#define UPNP_EVENT_EAP              2

//PIN mode
#define DEV_PWD_MODE_PBC            0
#define DEV_PWD_MODE_PIN            1

//Role Define
#define WSC_REGISTRAR               0
#define WSC_ENCROLLEE               1
#define WSC_PROXY                   2

//Authentication Type
#define AUTHTYPE_OPEN           0x0001
#define AUTHTYPE_WPAPSK         0x0002
#define AUTHTYPE_SHARED         0x0004
#define AUTHTYPE_WPA            0x0008
#define AUTHTYPE_WPA2           0x0010
#define AUTHTYPE_WPA2PSK        0x0020

// Encryption type
#define ENCRTYPE_NONE    0x0001
#define ENCRTYPE_WEP     0x0002
#define ENCRTYPE_TKIP    0x0004
#define ENCRTYPE_AES     0x0008



// Device request/response type
#define WSC_MSGTYPE_ENROLLEE_INFO_ONLY    0x00
#define WSC_MSGTYPE_ENROLLEE_OPEN_8021X   0x01
#define WSC_MSGTYPE_REGISTRAR             0x02
#define WSC_MSGTYPE_AP_WLAN_MGR           0x03

// Simple Config state
#define WSC_SCSTATE_UNCONFIGURED    0x01
#define WSC_SCSTATE_CONFIGURED      0x02

typedef char                    A_CHAR;
typedef unsigned char           A_UCHAR;
typedef A_CHAR                  A_INT8;
typedef A_UCHAR                 A_UINT8;
typedef short                   A_INT16;
typedef unsigned short          A_UINT16;
typedef int                     A_INT32;
typedef unsigned int            A_UINT32;
typedef unsigned int            A_UINT;
typedef A_UCHAR                 A_BOOL;
typedef unsigned long long      A_UINT64;

typedef A_UINT32                UINT32;
typedef A_INT16                 INT16;
typedef A_INT32			INT32;
typedef char			CHAR;
typedef unsigned char		BYTE;
typedef unsigned short 		WORD;
typedef unsigned long		DWORD;
typedef void 			VOID;

#ifndef PACKED
#define  PACKED __attribute__((packed))
#endif

/*
 * struct definition, for kwsc_module communication with upper layer's wsc
 */
#include "wsc_shared.h"

/* ********************************************************
 * struct definition . Wireless driver use netlink to send 
 * cmd to hostapd and call function in libwsc 
 * ********************************************************/

#define MAX_ARGV_COUNTER 10
typedef struct
{
	int argc;
	int len[MAX_ARGV_COUNTER];
}PACKED wsc_argv_head;

typedef struct
{
	wsc_argv_head  head;
	void *data;
}PACKED wsc_argv_buf;

int DATALEN(wsc_argv_head head)
{
	int sum=0,i=0;
	for(i=0;i<head.argc;i++) 
	{
		sum+=head.len[i];
	}
	return sum;
}

int wsc_sendto_user(unsigned short type,void *data,int len);
int wsc_wpaIEGet(char *iestr, unsigned char *wpa_ie, int len);
int wsc_wpa2IEGet(char *iestr, unsigned char *wpa2_ie, int len);
int wsc_wscIEGet(char * iestr, int beacon);
unsigned char kget_wsc_enable(void);	
unsigned char kget_wsc_devcfstat(void);
unsigned char kget_wsc_context(void);
unsigned char kget_wsc_version(void);
unsigned char *kget_wsc_mac(void);
unsigned char *kget_wsc_manfa(void);
unsigned char *kget_wsc_ssid(void);
unsigned char *kget_wsc_modelname(void);
unsigned char *kget_wsc_modelnumber(void);
unsigned char *kget_wsc_serialnumber(void);
unsigned char *kget_wsc_devicename(void);

int kget_wscadmin_role(void);
int kget_wscadmin_pwdMode(void);
unsigned char kget_wpaIEneedChange(void);
char *kget_wscadmin_wsc_pin(void);

int kget_wscadmin_seesionTimeout(void);
int kget_wscadmin_retransmitTimeout(void);
int kget_wscadmin_retryLimit(void);
int kget_wscamin_messageTimeout(void);
unsigned char  kget_wscadmin_configured(void);
unsigned char kget_wscadmin_pbcIsRunning(void);
unsigned char  kget_wscadmin_selectedReg(void);
unsigned long kget_wscadmin_selectedRegTime(void);
unsigned short  kget_wscadmin_selectRegConfigMethod(void);
unsigned short  kget_wscadmin_selectRegDevPwdId(void);
unsigned char kget_wscadmin_selfPbcPressed(void);
unsigned long kget_wscadmin_selfPbcPressedTime(void);
unsigned char kget_wsc_encrytype(void);
int wsc_msWirelessProvisioningServiceIE(char *ie_data);

#endif /* KWSC_MOD_H */
