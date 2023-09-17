/* =============================================================================      
 * Copyright (C) 2006-2007, Sercomm (Suzhou) R&D Center,  All Rights Reserved
 * =============================================================================
 */

#ifndef _WSC_API_H_
#define _WSC_API_H_


//#define WSC_DEBUG

#define PRE   __FILE__,__LINE__

#ifdef  WSC_DEBUG
#include <stdarg.h>
extern int wsc_debug(char *filename, int line, char *format, ...);
#else
extern void wsc_debug(char *filename, int line, char *format, ...);
#endif /* WSC_DEBUG */

/* wps status file */
#define WPS_INPROCESS       "/var/wps_start"
#define WPS_ERR_DETECT      "/var/wps_error"
#define WPS_OVERLAP         "/var/wps_overlap"
#define WPS_SUCCESS         "/var/wps_success"
#define WPS_STOP            "/var/wps_stop"
#define WPS_TIMEOUT         "/var/wps_timeout"

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

#define SHM_WSCUPnPEVENT_KEY 0xC1
#define WLANEventStrMaxLen 2048

typedef enum{
	SHM_STATUS_DATA_INVALID=0,
	SHM_STATUS_DATA_VALID=1,
	SHM_STATUS_EXIT=2
}SHM_STATUS_ENUM;

typedef struct{
    int SHMSTATUS; /* 0:data in this share memory is invalid, 1:data in this share memory is valid */
    char WLANEventMAC[6];
    int WLANEventType;
    char WLANEventStr[WLANEventStrMaxLen];
    int WLANEventStrLen;
}WSCUPnPEventFuncArgStc;



struct sk_buff;

/*
==========================================================================================
Name: wsc_init
Function: OS should call it when bootup for intialize the WSC.
Parameter: NULL
Return: NULL
==========================================================================================
*/
void wsc_init();


unsigned char getDeviceConfigureState();
void setDeviceConfigureState(unsigned char value);


/*
==========================================================================================
Name: wsc_getBeaconIe
Function: Get WSC IE for beacon send
          It will allocate memory, Caller need free it.
Parameter:
    outputIE[OUT]: Full IE buffer of probe response, NULL means don't need add WSC IE.
    outputIELEngth[OUT]: Length of IE buffer in probe response
Return: NULL
==========================================================================================
*/
void wsc_getBeaconIe(char *outputIE, int *outputIELEngth);


/*
==========================================================================================
Name: wsc_probeRequestHandler
Function: Driver should call it when receive a probe request with WSC IE
Parameter:
    mac[IN]: MAC Address of probe request sender
    inputIE[IN]: Full IE buffer in probe request
    inputIELength[IN]: Length of IE buffer in probe request
Return: NULL
==========================================================================================
*/
//void wsc_probeRequestHandler(char *mac, char *inputIE, int inputIELength);
void wsc_probeRequestHandler(unsigned char *mac, char *inputIE, int inputIELength, char *outputIE, int *outputIELength);

/*
==========================================================================================
Name: wsc_getProbeRespIe
Function: Driver should call it before send a probe response to client, 
          It will allocate memory, Caller need free it.
Parameter:
    mac[IN]: MAC Address that probe response to be send to.
    outputIE[OUT]: Full IE buffer of probe response, NULL means don't need add WSC IE.
    outputIELEngth[OUT]: Length of IE buffer in probe response
Return: NULL
==========================================================================================
*/
void wsc_getProbeRespIe(char *outputIE, int *outputIELEngth);



/*
==========================================================================================
Name: wsc_UPNPWLANResponseeHandler
Function: Process UPNP ResponseWLANMessage action, called by UPNP kernel.
Parameter:
    mac[IN]: MAC of UPNP action variable.
    inputMsg[IN]: Input message buffer.
    msgLength[IN]: Length of input message buffer.
Return: Status
==========================================================================================
*/
void wsc_UPNPWLANResponseeHandler(char *fromMac, char *mac, char *inputMsg, int msgLength);

/*
==========================================================================================
Name: wsc_UPNPGetDeviceInfoHandler
Function: Process UPNP GetDeviceInfo action, called by UPNP kernel.
Parameter:
    outputMsg[OUT]: Output message buffer.
    outputMsgLen[OUT]: Length of output message buffer.
Return: Status
==========================================================================================
*/
//void wsc_UPNPGetDeviceInfoHandler(char *fromMac, char *outputMsg, int *outputMsgLen);
void wsc_UPNPGetDeviceInfoHandler(char *fromMac, char *outputMsg, int *outputMsgLen);
/*
==========================================================================================
Name: wsc_UPNPPutMessageHandler
Function: Process UPNP PutMessage action, called by UPNP kernel.
Parameter:
    inputMsg[IN]: Input message buffer.
    msgLength[IN]: Length of input message buffer.
    outputMsg[OUT]: Output message buffer.
    outputMsgLen[OUT]: Length of output message buffer.
Return: Status
==========================================================================================
*/
void wsc_UPNPPutMessageHandler(char *fromMac,char *inputMsg, int msgLength, char *outputMsg, int *outputMsgLen);

/*
==========================================================================================
Name: wsc_setSelectedRegistrarHandler
Function: Process UPNP SelectedRegistrar action, called by UPNP kernel.
Parameter:
    inputMsg[IN]: Input message buffer.
    msgLength[IN]: Length of input message buffer.
Return: Status
==========================================================================================
*/
void wsc_setSelectedRegistrarHandler(char *fromMac, char *inputMsg, int msgLength);

/*
==========================================================================================
Name: wsc_txUPNPEvent
Function: Transmit a UPNP event to subscriber.
Parameter:
    mac[IN]: Destination MAC address.
    type[IN]: Message type, Probe or EAP.
    inputMsg[IN]: Message buffer.
    msgLength[IN]: Length of message buffer.
Return: Status
==========================================================================================
*/
void wsc_txUPNPEvent(char *mac, int type,char *msgBody, int msgLen);


//typedef void (*WSCUPnPEventCallbackFunc)(char *mac, int type,char *msgBody, int msgLen);
//extern WSCUPnPEventCallbackFunc wsc_txUPNPEvent;
/*
==========================================================================================
Name: Set_WSCUPnPEvent_Callback
Function: register function wsc_txUPNPEvent
Parameter:
    WSCUPnPEventFunc[IN]: WSC UPnP Event function.
Return: Status
==========================================================================================
*/
//void Set_WSCUPnPEvent_Callback(WSCUPnPEventCallbackFunc WSCUPnPEventFunc);




void wsc_init();
void wsc_daemon();




int txFullEAP(char * eap_msg, int buflen, char * dst, int devIndex);
unsigned long getSystemTime();
void systemDelay(unsigned long  second);

char * wsc_get_ssid();
char* wsc_getNetworkKey();
int wsc_getAuthType();
int wsc_getEncryptType();
char wsc_getKeyIndex();
unsigned char * wsc_get_mac();

//int getPwdMode();
void setPwdMode(int mode);
int getRole();
void setRole(int role);
char *getPin();
void setPin(char *pin);
char * generate_pin();
int get_wsc_context();
void set_wsc_context(int flag);
/*
#ifndef LINUX_PORTING
extern int wsc_send_eapol(unsigned char *macAddr, unsigned char *data, unsigned int dataLen, int encrypt);
#else
int wsc_send_eapol(unsigned char *macAddr, unsigned char *data, unsigned int dataLen, int encrypt);
#endif
*/

void wsc_pushButtonPressed();

int wsc_ongoing(char *mac_addr);
int isWSCClient(char *mac_addr);


/* 
WSC IE
    ---------------------------------------------------------
    | Element ID  |  Length  |        OUI       |   DATA    |
    ---------------------------------------------------------
Bytes     1             1              4            1~251       
    
    the Element ID has a value of 221 and OUI is 00 50 F2 04.
*/


/* 
* Funtion:  
*            wsc_enable
* Description:  
*           Driver will use this function to know the wsc is enabled or not.
* Parameters: 
* Return:   
*       1: enabled; 0: disabled
*/    
int wsc_enable(void);
void set_wsc_enable(void);
void set_wsc_disable(void);
/* 
* Funtion:  
*            wsc_wscIEGet
* Description:  
*           Driver will use this function to get current WSC IE which should be added 
*           into beacon and probe response when WSC is enabled.
* Parameters: 
*           char *iestr: Driver should provide the memory for fw to fillin the ie.   
*           int beacon : 1 for beacon, 0 for probe response
* Return:   
*       The length of the WSC IE         
*/    
int wsc_wscIEGet(char *iestr, int beacon);


/* 
* Funtion:  
*            wsc_wscIEChanged
* Description:  
*           Driver will use this function to know if the wsc ie has been updated/changed.
*           If yes, driver should get the current WSC IE with function wsc_wscIEGet. 
* Parameters: 
* Return:   
*           1 : wsc ie changed
*           0 : not changed   
*/
int wsc_wscIEChanged();


/* 
* Funtion:  
*            wsc_wpaIEGet
* Description:  
*           When WSC is enabled, Driver will use this function to get current 
*           WPA IE which should be added into beacon and probe response.
* Parameters: 
*           char *iestr: Driver should provide the memory for fw to fillin the ie.   
* Return:   
*       The length of the wpa IE         
*/    
int wsc_wpaIEGet(char *iestr, unsigned char *wpa_ie, int len);


/* 
* Funtion:  
*            wsc_wpaIEChanged
* Description:  
*           Driver will use this function to know if the wpa ie has been updated/changed.
*           If yes, driver should get the current IE with function wsc_wpaIEGet. 
* Parameters: 
* Return:   
*           1 : ie changed
*           0 : not changed   
*/
int wsc_wpaIEChanged();


/* 
* Funtion:  
*            wsc_wpa2IEGet
* Description:  
*           When WSC is enabled, Driver will use this function to get current 
*           WPA2 IE which should be added into beacon and probe response.
* Parameters: 
*           char *iestr: Driver should provide the memory for fw to fillin the ie.   
* Return:   
*       The length of the wpa2 IE         
*/    
int wsc_wpa2IEGet(char *iestr, unsigned char *wpa2_ie, int len);


/* 
* Funtion:  
*            wsc_wpa2IEChanged
* Description:  
*           Driver will use this function to know if the wpa2 ie has been updated/changed.
*           If yes, driver should get the current IE with function wsc_wpa2IEGet. 
* Parameters: 
* Return:   
*           1 : ie changed
*           0 : not changed   
*/
int wsc_wpa2IEChanged();

/* 
* Funtion:  
*            wsc_StaAssocCallback
* Description:  
*           FW should provide this function to Driver.
*           When some one wireless client associates successfully, Driver should call this api 
*           to inform FW. 
*           And if any following IE exists in the associate request, please pass 
*           them up: WPA IE, WPA2 IE, WSC IE. 
*           If not existing, please use NULL for ie string point,and zero for IE length.
* Parameters: 
*               
* Return:         
*/
void wsc_staAssocCallback(  char *mac, int radioIndex, 
                            char *wpaIe, int wpaIeLen,
                            char *wpa2Ie, int wpa2IeLen,
                            char *wscIe, int wscIeLen);

/* 
* Funtion:  
*            wsc_EapHandler
* Description:  
*           FW should provide this function to Driver.
*           When Driver receives a EAP packet, this handler should go first.
*           And the handler will not free the memory of skb.  
* Parameters: 
* Return:   
*            1 - the EAP packet is for WSC; 
*            0 - the EAP packet is not for WSC.          
*/
//int wsc_EapHandler(struct sk_buff *skb,int unit);
int wsc_EapHandler(struct sk_buff *skb,int buflen,int unit,int (*send_eapol_api)(unsigned char *addr, unsigned char  *data,int data_len, int encrypt));

/* 
* Funtion:  
*            wsc_EapolSend
* Description:  
*           Driver should provide this function to FW.
*           FW will use it to transmit the eap packets.
* Parameters: 
*           char *dst: Dest mac address
*           char *eap_msg : point to eap message to be sent out    
*           int buflen: eap message length
*           int encrypt: not used , always 0
* Return:   
*            1 - success; 
*            0 - fail.          
*/
int wsc_EapolSend(char *dst, char *eap_msg, int buflen, int encrypt);

int wpaIEneedChange(void);
void wsc_free_shm(void);

void wps_pbc_cancel(void);
void wps_pin_cancel(void);

#endif
