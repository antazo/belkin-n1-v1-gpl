/* =============================================================================      
 * Copyright (C) 2006-2007, Sercomm (Suzhou) R&D Center,  All Rights Reserved
 * =============================================================================
 */

#ifndef _WSC_SHARED_H_
#define _WSC_SHARED_H_

#ifndef PACKED
#define  PACKED __attribute__((packed))
#endif
#define PIN_SIZE 9
/* must the same order with wsc.h's admin */
typedef struct _global_control_block_shared
{    
    int             role;  /* enrollee, proxy, register */ 
    int             pwdMode; 
    char            wsc_pin[PIN_SIZE]; 
    
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
}PACKED 
WSC_ADMIN_SHARED;

/* struct definition which will be used by wireless driver and updated by libwsc */
typedef struct
{
	unsigned char wsc_enable;
	unsigned char wsc_context;
	unsigned char wsc_version;
	unsigned char wsc_devcfstat;
	
	WSC_ADMIN_SHARED wsc_admin;
	unsigned char wsc_mac[SIZE_MAC_ADDR];
	unsigned char wsc_manfa[SIZE_32_BYTES];
	unsigned char wsc_ssid[SIZE_32_BYTES];
	unsigned char wsc_modelname[SIZE_32_BYTES];
	unsigned char wsc_modelnumber[SIZE_32_BYTES];
	unsigned char wsc_serialnumber[SIZE_32_BYTES];
	unsigned char wsc_devicename[SIZE_32_BYTES];
	unsigned char wsc_encrytype;
}PACKED 
wsc_config_static;

typedef struct
{
    int             role;   //enrollee, proxy, register
    int             pwdMode;
    unsigned short  selectRegConfigMethod;
    unsigned short  selectRegDevPwdId;
    unsigned char   configured;
    unsigned char   wsc_context;
    unsigned char   selectedReg;
    unsigned char   wsc_iechanged;
    unsigned char   wpaIEneedChange;
    char            wsc_pin[PIN_SIZE];
}PACKED 
wsc_config_dyna;

#endif /* _WSC_SHARED_H_ */

