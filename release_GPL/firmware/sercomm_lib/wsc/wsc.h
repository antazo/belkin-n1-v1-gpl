/* =============================================================================      
 * Copyright (C) 2006-2007, Sercomm (Suzhou) R&D Center,  All Rights Reserved
 * =============================================================================
 */

#ifndef _WSC_H_
#define _WSC_H_

#include "wsc_porting.h"
#include "socket_tools.h"
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/***************************************************
               Marco and Variable Define
***************************************************/
typedef enum
{
    WSC_ERROR = -1,
    WSC_OK,
    WSC_INVALID,
    WSC_NONE,
    WSC_STATE_ERROR,
    WSC_NO_AUTH_FIELD
} WSC_STATUS;

#define WSCCONFIG_STATIC  0
#define WSCCONFIG_DYNA  1

#define WALK_TIME 12
/*
*If the supplicant want to adding as an external Registrar,
* The EAP Identity is "WFA-SimpleConfig-Registrar-1-0"
*If adding as an encrollee, it should be "WFA-SimpleConfig-Encrollee-1-0"
*/
#define EAP_IDENTITY_REGISTRAR  "WFA-SimpleConfig-Registrar-1-0"
#define EAP_IDENTITY_ENCROLLEE  "WFA-SimpleConfig-Enrollee-1-0"

#define EAP_VERSION  (0x01)
#define MORE_FLAGS      0x01
#define LENGTH_FIELD    0x02

/*The 802.1x auth layer's type*/
#define  EAP_PACKET 0
#define  EAPOL_START 1 
#define  EAPOL_KEY   3


/*The EAP layer's code*/
#define  EAP_REQUEST  1
#define  EAP_RESPONSE 2
#define  EAP_SUCCESS  3
#define  EAP_FAIL     4 /*just a guess*/

/*The EAP layer's type*/
#define EAP_TYPE_IDENTITY   1
#define EAP_TYPE_WSC        254
/*The strange thing, is, for the EAP Success, has not this type attribute?*/

/*
*WSC op code
*/
#define WSC_CODE_START 0x01
#define WSC_CODE_ACK   0x02
#define WSC_CODE_NACK  0x03
#define WSC_CODE_MSG   0x04
#define WSC_CODE_DONE  0x05
#define WSC_CODE_FRAG_ACK   0x06


/*
*Basically, EAP request are from AP/Registrar to Encrollee,
*EAP response are from Encrollee to AP/Registrar.
*/
/*
*Buddles in the message data.
*/
#define  WSC_BEACON     0x01
#define  WSC_PROBE_REQ  0x02
#define  WSC_PROBE_RESP 0x03

#define  WSC_M1 0x04
#define  WSC_M2 0x05
#define  WSC_M2D 0x06
#define  WSC_M3  0x07
#define  WSC_M4  0x08
#define  WSC_M5  0x09
#define  WSC_M6  0x0a
#define  WSC_M7  0x0b
#define  WSC_M8  0x0c
#define  WSC_ACK  0x0d
#define  WSC_NACK  0x0e
#define  WSC_DONE  0x0f

typedef enum 
{
    _IDLE = 0,
    _EAPOL_START,
    _EAP_REQ_ID,
    _EAP_RESP_ID,
    _SEND_START,
    _START,
    _SEND_M1,
    _M1,
    _SEND_M2D,
    _SEND_M2,
    _M2,
    _M2D,
    _SEND_M3,
    _M3,
    _SEND_M4,
    _M4,
    _SEND_M5,
    _M5,
    _SEND_M6,
    _M6,
    _SEND_M7,
    _M7,
    _SEND_M8,
    _M8,
    _SEND_DONE,
    _DONE,
    _FAIL
} WSC_STATE;

/********
*include from wsctypes.h
********/
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
#define WSC_ID_DEVICE_TYPE        0x1013
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
/****/


/**
*The following Included from the regProtoTlv.h
**/

// Association states
#define WSC_ASSOC_NOT_ASSOCIATED  0
#define WSC_ASSOC_CONN_SUCCESS    1
#define WSC_ASSOC_CONFIG_FAIL     2
#define WSC_ASSOC_ASSOC_FAIL      3
#define WSC_ASSOC_IP_FAIL         4

// Authentication types
#define WSC_AUTHTYPE_OPEN        0x0001
#define WSC_AUTHTYPE_WPAPSK      0x0002
#define WSC_AUTHTYPE_SHARED      0x0004
#define WSC_AUTHTYPE_WPA         0x0008
#define WSC_AUTHTYPE_WPA2        0x0010
#define WSC_AUTHTYPE_WPA2PSK     0x0020

// Config methods
#define WSC_CONFMET_USBA            0x0001
#define WSC_CONFMET_ETHERNET        0x0002
#define WSC_CONFMET_LABEL           0x0004
#define WSC_CONFMET_DISPLAY         0x0008
#define WSC_CONFMET_EXT_NFC_TOK     0x0010
#define WSC_CONFMET_INT_NFC_TOK     0x0020
#define WSC_CONFMET_NFC_INTF        0x0040
#define WSC_CONFMET_PBC             0x0080
#define WSC_CONFMET_KEYPAD          0x0100

// WSC error messages
#define WSC_ERROR_NO_ERROR                0
#define WSC_ERROR_OOB_INT_READ_ERR        1
#define WSC_ERROR_DECRYPT_CRC_FAIL        2
#define WSC_ERROR_CHAN24_NOT_SUPP         3
#define WSC_ERROR_CHAN50_NOT_SUPP         4
#define WSC_ERROR_SIGNAL_WEAK             5
#define WSC_ERROR_NW_AUTH_FAIL            6
#define WSC_ERROR_NW_ASSOC_FAIL           7
#define WSC_ERROR_NO_DHCP_RESP            8
#define WSC_ERROR_FAILED_DHCP_CONF        9
#define WSC_ERROR_IP_ADDR_CONFLICT        10
#define WSC_ERROR_FAIL_CONN_REGISTRAR     11
#define WSC_ERROR_MULTI_PBC_DETECTED      12
#define WSC_ERROR_ROGUE_SUSPECTED         13
#define WSC_ERROR_DEVICE_BUSY             14
#define WSC_ERROR_SETUP_LOCKED            15
#define WSC_ERROR_MSG_TIMEOUT             16
#define WSC_ERROR_REG_SESSION_TIMEOUT     17
#define WSC_ERROR_DEV_PWD_AUTH_FAIL       18

// Connection types
#define WSC_CONNTYPE_ESS    0x01
#define WSC_CONNTYPE_IBSS   0x02

// Device password ID
#define WSC_DEVICEPWDID_DEFAULT          0x0000
#define WSC_DEVICEPWDID_USER_SPEC        0x0001
#define WSC_DEVICEPWDID_MACHINE_SPEC     0x0002
#define WSC_DEVICEPWDID_REKEY            0x0003
#define WSC_DEVICEPWDID_PUSH_BTN         0x0004
#define WSC_DEVICEPWDID_REG_SPEC         0x0005

// Encryption type
#define WSC_ENCRTYPE_NONE    0x0001
#define WSC_ENCRTYPE_WEP     0x0002
#define WSC_ENCRTYPE_TKIP    0x0004
#define WSC_ENCRTYPE_AES     0x0008

//Device Type categories for primary and secondary device types
#define WSC_DEVICE_TYPE_CAT_COMPUTER        1
#define WSC_DEVICE_TYPE_CAT_INPUT_DEVICE    2
#define WSC_DEVICE_TYPE_CAT_PRINTER         3
#define WSC_DEVICE_TYPE_CAT_CAMERA          4
#define WSC_DEVICE_TYPE_CAT_STORAGE         5
#define WSC_DEVICE_TYPE_CAT_NW_INFRA        6
#define WSC_DEVICE_TYPE_CAT_DISPLAYS        7
#define WSC_DEVICE_TYPE_CAT_MM_DEVICES      8
#define WSC_DEVICE_TYPE_CAT_GAME_DEVICES    9
#define WSC_DEVICE_TYPE_CAT_TELEPHONE       10

//Device Type sub categories for primary and secondary device types
#define WSC_DEVICE_TYPE_SUB_CAT_COMP_PC         1
#define WSC_DEVICE_TYPE_SUB_CAT_COMP_SERVER     2
#define WSC_DEVICE_TYPE_SUB_CAT_COMP_MEDIA_CTR  3
#define WSC_DEVICE_TYPE_SUB_CAT_PRTR_PRINTER    1
#define WSC_DEVICE_TYPE_SUB_CAT_PRTR_SCANNER    2
#define WSC_DEVICE_TYPE_SUB_CAT_CAM_DGTL_STILL  1
#define WSC_DEVICE_TYPE_SUB_CAT_STOR_NAS        1
#define WSC_DEVICE_TYPE_SUB_CAT_NW_AP           1
#define WSC_DEVICE_TYPE_SUB_CAT_NW_ROUTER       2
#define WSC_DEVICE_TYPE_SUB_CAT_NW_SWITCH       3
#define WSC_DEVICE_TYPE_SUB_CAT_DISP_TV         1
#define WSC_DEVICE_TYPE_SUB_CAT_DISP_PIC_FRAME  2
#define WSC_DEVICE_TYPE_SUB_CAT_DISP_PROJECTOR  3
#define WSC_DEVICE_TYPE_SUB_CAT_MM_DAR          1
#define WSC_DEVICE_TYPE_SUB_CAT_MM_PVR          2
#define WSC_DEVICE_TYPE_SUB_CAT_MM_MCX          3
#define WSC_DEVICE_TYPE_SUB_CAT_GAM_XBOX        1
#define WSC_DEVICE_TYPE_SUB_CAT_GAM_XBOX_360    2
#define WSC_DEVICE_TYPE_SUB_CAT_GAM_PS          3
#define WSC_DEVICE_TYPE_SUB_CAT_PHONE_WM        1

// Device request/response type
#define WSC_MSGTYPE_ENROLLEE_INFO_ONLY    0x00
#define WSC_MSGTYPE_ENROLLEE_OPEN_8021X   0x01
#define WSC_MSGTYPE_REGISTRAR             0x02
#define WSC_MSGTYPE_AP_WLAN_MGR           0x03

// RF Band
#define WSC_RFBAND_24GHZ    0x01
#define WSC_RFBAND_50GHZ    0x02

// Simple Config state
#define WSC_SCSTATE_UNCONFIGURED    0x01
#define WSC_SCSTATE_CONFIGURED      0x02

//WSC OUI for primary and secondary device type sub-category
#define WSC_OUI     0x0050f204
#define WSC_IE_ID   221
/*Element ID + Lenght + OUI + Data*/
/*|<-1------>|<-1--->|<--4-->|<-1..251->|*/

#define BUF_SIZE_64_BITS    8
#define BUF_SIZE_128_BITS   16
#define BUF_SIZE_160_BITS   20
#define BUF_SIZE_256_BITS   32
#define BUF_SIZE_512_BITS   64
#define BUF_SIZE_1024_BITS  128
#define BUF_SIZE_1536_BITS  192

#define PERSONALIZATION_STRING  "Wi-Fi Easy and Secure Key Derivation"
#define PRF_DIGEST_SIZE         BUF_SIZE_256_BITS
#define KDF_KEY_BITS            640

#define  safe_free(x)  {if (x) free(x); x=0;}


/***************************************************
                Data Structure Define
***************************************************/
#ifndef PACKED
#define  PACKED __attribute__((packed))
#endif

typedef struct monitorCache_S
{
    char            mac[6];
    unsigned long   time;
    unsigned char   used;
}PACKED MonitorCache;

typedef struct _eap_header
{
    unsigned char ver;
    unsigned char type;
    unsigned short len;
}PACKED WSC_EAP_HEADER;

typedef struct _eap_msg
{
    unsigned char code;
    unsigned char id;
    unsigned short len;
    unsigned char type;
}PACKED WSC_EAP_MSG;


typedef struct _eap_wsc_submsg
{
    unsigned char eaph_ver;  
    unsigned char eaph_type;
    unsigned short eaph_len;  /*Bad news, need duplicate these fields for pure EAP header
                    * By Al @ Wifi*/

    unsigned char code; /*1 request, 2 response*/
    unsigned char id;
    unsigned short len; /*overall len for eap packet*/
    unsigned char type; /*for simple config, set to 254*/
    unsigned char vendor_id[3];      /*WFA SMI code: 0x00372A*/
    unsigned char vendor_type[4];    /*for simple config:0x00000001*/
    unsigned char op_code; 
    unsigned char flags; /*0x01: more frags(MF), 0x02: length filed(LF), 0x04-0x08:reserved*/           
    unsigned char data[0];
}PACKED EAP_WSC_SUBMSG;

typedef struct _eap_wsc_submsg_frag
{

    unsigned char eaph_ver;  
    unsigned char eaph_type;
    unsigned short eaph_len;  /*Bad news, need duplicate these fields for pure EAP header
                    * By Al @ Wifi*/
    unsigned char code; /*1 request, 2 response*/
    unsigned char id;
    unsigned short len; /*overall len for eap packet*/
    unsigned char type; /*for simple config, set to 254*/
    unsigned char vendor_id[3];      /*WFA SMI code: 0x00372A*/
    unsigned char vendor_type[4];    /*for simple config:0x00000001*/
    unsigned char op_code; 
    unsigned char flags; /*0x01: more frags(MF), 0x02: length filed(LF), 0x04-0x08:reserved*/           
    unsigned short msg_len;
    unsigned char data[0];
}PACKED EAP_WSC_SUBMSG_FRAG;

typedef struct _wsc_tlv
{
    unsigned short type;
    unsigned short len;
    unsigned char * val;
}PACKED WSC_TLV;

typedef struct _device_info_
{
    unsigned char   version; 
    unsigned char   uuid[SIZE_UUID];
    unsigned char   mac[SIZE_MAC_ADDR];
    unsigned char   nonce[SIZE_128_BITS]; 
    DH              *DHSecret;

    unsigned short  auth_type;
    unsigned short  enc_type;
    unsigned short  conn_type;
    unsigned short  config_methods;
    unsigned short  sc_state;

    unsigned char   manufacturer[SIZE_32_BYTES];
    unsigned char   model_name[SIZE_32_BYTES];
    unsigned char   model_number[SIZE_32_BYTES];
    unsigned char   serial_number[SIZE_32_BYTES];

    unsigned short  prim_dev_category;
    unsigned long   prim_dev_oui;
    unsigned short  prim_dev_sub_category;

    unsigned char   device_name[SIZE_32_BYTES];

    unsigned char   rf_band;
    unsigned long   os_version;
    unsigned long   feature_id;
    unsigned short  assoc_state;
    unsigned short  dev_pwd_id;
    unsigned short  config_error;
    
    unsigned char   b_ap;
    unsigned char   ssid[SIZE_32_BYTES];
    unsigned char   key_mgmt[SIZE_20_BYTES];

}PACKED DEVICE_INFO;


typedef struct _wsc_session_control_block_
{
    unsigned char   in_use; 
        #define WSC_SCB_FREE    0
        #define WSC_SCB_IN_USE  1
    unsigned char   peerType;
        #define EAP_PEER        0
        #define UPNP_PEER       1
    char            isUpnpRegistrar;
    unsigned char   peer_mac[6];
    unsigned char   configured;     /* Does the STA finished the WSC */
    unsigned char   state;          /*Currently, where are we staying 
                                     *The state value is the name of some message, 
                                     *It indicates we has sent out this message,
                                     *Or we are excepting the message from the peer.
                                     *Whether we are the AP/Registrar or Encrollee.
                                     */
    unsigned char   currentId;
    unsigned char   inWorking;
    unsigned long   session_start;  /*In seconds?*/
    unsigned long   msg_start;      /*In seconds?*/
    unsigned char   retried;
    
#define WSC_MSG_LEN 2048
    char            in_msg[WSC_MSG_LEN];
    unsigned short  in_msg_offset;
    unsigned short  in_len;

    char            out_msg[WSC_MSG_LEN];
    unsigned short  out_msg_offset;
    unsigned short  out_len;
    
    char            out_msg_m3[WSC_MSG_LEN];
    unsigned short  out_m3_len;

#define WSC_FRAME_LEN 3072    
    char            outFrame[WSC_FRAME_LEN];
    unsigned short  outFrameLength;
    

    int             devIndex;    
    int             wscIe;

    DEVICE_INFO     peer_info;
    DEVICE_INFO     *own_info;      /*Here use a pointer to reduce the memory.*/

    unsigned char   registrar_nonce[SIZE_128_BITS];
    unsigned char   encrollee_nonce[SIZE_128_BITS];
    DH              *DHSecret;      /*Let it do has something*/
    BIGNUM          *DH_PubKey_Peer;/*Let it has some thing, not only the pointer, by Al.*/
    unsigned char   pkr[SIZE_PUB_KEY];
    unsigned char   pke[SIZE_PUB_KEY];

    unsigned char   auth_key[SIZE_256_BITS];
    unsigned char   key_wrap_key[SIZE_128_BITS];
    unsigned char   emsk[SIZE_256_BITS];

    unsigned char   e_hash1[SIZE_256_BITS];
    unsigned char   e_hash2[SIZE_256_BITS];

    unsigned char   r_hash1[SIZE_256_BITS];
    unsigned char   r_hash2[SIZE_256_BITS];

    unsigned char   e_snonce1[SIZE_128_BITS];
    unsigned char   e_snonce2[SIZE_128_BITS];

    unsigned char   psk1[SIZE_128_BITS];
    unsigned char   psk2[SIZE_128_BITS];

    unsigned char   rs1[SIZE_128_BITS];
    unsigned char   rs2[SIZE_128_BITS];

    unsigned char   es1[SIZE_128_BITS];
    unsigned char   es2[SIZE_128_BITS];

    unsigned char   *id_proof;  /*In receiving M7, need this*/
    unsigned short  id_proof_len;

#define SIZE_PWD_LEN (64)
    unsigned char   password[SIZE_PWD_LEN]; /*Since i donot know how long it.*/

    unsigned char   *x509Cert;
    unsigned short  x509Cert_len;

    unsigned char   *x509Cert_req;
    unsigned short  x509Cert_req_len;
}PACKED WSC_SESSION_CB;

//Globle configuration
typedef struct _global_control_block_
{
    int             role;   //enrollee, proxy, registrar
    int             pwdMode;
    char            wsc_pin[9];
    
    int             seesionTimeout;
    int             retransmitTimeout;
    int             retryLimit;
    
    int             messageTimeout;
    unsigned char   configured;
    unsigned char   pbcIsRunning;
    
    unsigned char   selectedReg;
    unsigned long   selectedRegTime;
    unsigned short  selectRegConfigMethod;
    
    unsigned short  selectRegDevPwdId;
    unsigned char   selfPbcPressed;
    unsigned long   selfPbcPressedTime;
    
    int             ackFlag;
    unsigned long   ackTime;
    unsigned char   associated;
        #define IDLE        0;
        #define CONFIGURING 1;
    unsigned char   registrar_uuid[SIZE_UUID];
    WSC_SESSION_CB  *ackSCB;
    WSC_SESSION_CB  *workingSCB;
}PACKED WSC_ADMIN;

typedef struct _wsc_session_queue_
{
    WSC_SESSION_CB              *wsccb;
    struct _wsc_session_queue_  *next;
}WSC_SESSION_QUEUE;

#define SSID_MAX_LEN    32
#define KEY_MAX_LEN     128

typedef struct 
{
	int auth_type;
	int encr_type;
	int key_index;
	int nw_index;
	char ssid[SSID_MAX_LEN+1];
	char keys[KEY_MAX_LEN+1];	
}PACKED reg_info;

typedef struct
{
	WSC_ADMIN gadmin;
	DEVICE_INFO ggOwnDevInfo;
	reg_info gregtoap_info;
	int gisPinSet;
	int gintelIE;
	int grestartFlag;
	MonitorCache gprobeCache[2];
	int  gprobeCount;
	int gsessionQueueLock;
	int gwscIEChangeCounter;
	int gwpaIEChangeCounter;
	int gwpa2IEChangeCounter;	
}PACKED smem_block;


#define  admin				    (gsmem_block->gadmin)
#define  gOwnDevInfo		    (gsmem_block->ggOwnDevInfo)
#define  isPinSet			    (gsmem_block->gisPinSet) 		
#define  intelIE			    (gsmem_block->gintelIE)  		
#define  restartFlag		    (gsmem_block->grestartFlag) 
#define  probeCache			    (gsmem_block->gprobeCache)
#define  probeCount 			(gsmem_block->gprobeCount)
#define  sessionQueueLock		(gsmem_block->gsessionQueueLock)
#define  regtoap_info			(gsmem_block->gregtoap_info)
#define  wscIEChangeCounter		(gsmem_block->gwscIEChangeCounter)		
#define  wpaIEChangeCounter		(gsmem_block->gwpaIEChangeCounter)
#define	 wpa2IEChangeCounter	(gsmem_block->gwpa2IEChangeCounter)

typedef struct 
{
	char ssid[SIZE_32_BYTES+1];
	unsigned char authtype;
	unsigned char encrytype;
	unsigned char keyindex;
	char networkkey[SIZE_128_BYTES];
	
}userconfig;

#define WFA_VAL_MAXLEN 2048

/* Share memory buffer struct define */
typedef struct{
    int type;
    int len;
    char data[WFA_VAL_MAXLEN+512];
}SHM_STRUCT;

/* Hostapd to WSCUPNP ShareMem define */
#define H2W_SHM_KEY 0xC2
typedef enum{
	H2W_SHM_TYPE_IDLE,
	H2W_SHM_TYPE_GetDeviceInfoResp,
	H2W_SHM_TYPE_PutMessageResp,
	H2W_SHM_TYPE_GetAPSettingsResp,
	H2W_SHM_TYPE_SetAPSettingsResp,
	H2W_SHM_TYPE_DelAPSettingsResp,
	H2W_SHM_TYPE_GetSTASettingsResp,
	H2W_SHM_TYPE_SetSTASettingsResp,
	H2W_SHM_TYPE_DelSTASettingsResp,	
	H2W_SHM_TYPE_RebootAPResp,
	H2W_SHM_TYPE_ResetAPResp,
	H2W_SHM_TYPE_RebootSTAResp,
	H2W_SHM_TYPE_ResetSTAResp,
	H2W_SHM_TYPE_EXIT
}H2W_SHM_TYPE_ENUM;

/* WSCUPNP to Hostapd ShareMem define */
#define W2H_SHM_KEY 0xC3
typedef enum{
	W2H_SHM_TYPE_IDLE,
	W2H_SHM_TYPE_GetDeviceInfo,
	W2H_SHM_TYPE_PutMessage,
	W2H_SHM_TYPE_GetAPSettings,
	W2H_SHM_TYPE_SetAPSettings,
	W2H_SHM_TYPE_DelAPSettings,
	W2H_SHM_TYPE_GetSTASettings,
	W2H_SHM_TYPE_SetSTASettings,
	W2H_SHM_TYPE_DelSTASettings,	
	W2H_SHM_TYPE_PutWLANResponse,
	W2H_SHM_TYPE_SetSelectedRegistrar,
	W2H_SHM_TYPE_RebootAP,
	W2H_SHM_TYPE_ResetAP,
	W2H_SHM_TYPE_RebootSTA,
	W2H_SHM_TYPE_ResetSTA,
	W2H_SHM_TYPE_EXIT
}W2H_SHM_TYPE_ENUM;


/***************************************************
                Internal Routine
***************************************************/
unsigned short Get2Byte(unsigned char *x);
unsigned long Get4Byte(unsigned char *x);
void Set2Byte(unsigned char* p, unsigned short v);
void Set4Byte(unsigned char *p, unsigned long v);

#define INF  int

unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
		            const unsigned char *d, size_t n, unsigned char *md,
		            unsigned int *md_len);
const EVP_MD *EVP_sha256(void);
unsigned char *SHA256(const unsigned char *d, size_t n,unsigned char *md);

const EVP_CIPHER *EVP_aes_128_cbc(void);
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
		            const unsigned char *d, size_t n, unsigned char *md,
		            unsigned int *md_len);

void hmac_sha256(unsigned char *text, int text_len,
                unsigned char *key, int key_len,
                unsigned char *digest);

/*Definition over*/
extern WSC_TLV msg_tlvs[WSC_IE_SIZE];

#define ASSERT_WSC_TLV_TYPE(x) //ASSERT(msg_tlvs[WSC_IE_MASK(x)].type);
#define WSC_TLV_VAL_P(x)   msg_tlvs[WSC_IE_MASK(x)].val
#define WSC_TLV_LEN(x)     msg_tlvs[WSC_IE_MASK(x)].len



/*From wsc_config.c*/
int init_ie_width();
unsigned short TLV_CONFIG_LEN(unsigned short x);
unsigned short ADD_TLV_DATA(unsigned short type, unsigned short len, char * value, unsigned char * msg, unsigned short now_len);
unsigned short ADD_TLV_P(unsigned short type, unsigned short len, char * value,  unsigned char * msg, unsigned short now_len);

/*From wsc.c*/
void update_wsccfb(int type);

/*From secret-c*/
WSC_STATUS parse_es_validateMAC(unsigned short type, unsigned char * plain_text, 
    unsigned short mlen, unsigned char * auth_key, unsigned char * e_snonce, WSC_SESSION_CB  * scb);
WSC_STATUS parse_esnonce2(unsigned short type, unsigned char* plain_text,
    unsigned short mlen,unsigned char * auth_key, unsigned char * e_snonce2,  WSC_SESSION_CB  * scb);

WSC_STATUS AddFullMAC(char * o_m, unsigned short m_d_len, WSC_SESSION_CB * scb, char * hmac);
WSC_STATUS EncryptData(char * plainText, UINT32 plain_len, 
                          char * encrKey, 
                          char * authKey, 
                          unsigned char * p_cipherText,
                          unsigned short *p_cipherLen,
                          char * iv);

WSC_STATUS DecryptData(unsigned char * cipherText, unsigned short len,
                          unsigned char * iv,
                          unsigned char * encrKey, 
                          unsigned char * authKey, 
                          unsigned char * p_plainText, 
                          unsigned short * p_plainLen
                            );

unsigned long GenerateDHKeyPair(DH **DHKeyPair, unsigned char * pub_key);
void DeriveKey(char * KDK, 
               char * prsnlString, 
               unsigned long keyBits, 
               char * key);

WSC_STATUS AddKeyWrapAuth(unsigned char * enc_data, unsigned short *enc_len, 
        WSC_SESSION_CB * scb);

WSC_STATUS ValidateFullMAC(WSC_SESSION_CB * scb , char *msg, int len, unsigned char msgType);
WSC_STATUS ValidateMac(unsigned char * data, unsigned short data_len, unsigned char *hmac, unsigned char * key);

int general_save_settings();

int sc_print_hex(const char *str, int len);
char * wsc_get_ssid();
A_UINT16 wsc_get_wpapsk_len();
A_INT8* wsc_get_wpapsk_key();

#endif /* _WSC_H_ */
