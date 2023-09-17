/* =============================================================================      
 * Copyright (C) 2006-2007, Sercomm (Suzhou) R&D Center,  All Rights Reserved
 * =============================================================================
 */

#ifndef _NVRAM_
#define _NVRAM_
#include <stdlib.h>
#include <string.h>
/*
 * 2003/02/27  		             			    
 * 		       				released by Ron     
 */

/* line terminator by 0x00 
 * data terminator by two 0x00
 * value separaed by 0x01
 */	

/* nvram path */
#define NVRAM_PATH     "/dev/mtdblock1"          /* ex:  /dev/mtd/nvram */

#define NVRAM_SPACE 0x8000 //32K

#define NVRAM_TMP_PATH "/tmp/nvram"		  /* ex:  /tmp/nvram     */
#define NVRAM_DEFAULT  "/etc/default"             /* ex:  /etc/default   */


#define END_SYMBOL	    0x00		  	
#define DIVISION_SYMBOL	    0x01		  

/* NVRAM_HEADER MAGIC*/ 
#define NVRAM_MAGIC 		    0x004E4F52		 /* RON */

/* used 12bytes, 28bytes reserved */
#define NVRAM_HEADER_SIZE   40       		 
/* max size in flash*/
//#define NVRAM_SIZE          65535		  /* nvram size 64k bytes*/
#define NVRAM_SIZE              0x10000     /* nvram size 64k bytes */

/* each line max size*/
#define NVRAM_BUFF_SIZE           4096		 

/* errorno */
#define NVRAM_SUCCESS       	    0
#define NVRAM_FLASH_ERR           1 
#define NVRAM_MAGIC_ERR	    2
#define NVRAM_LEN_ERR	    3
#define NVRAM_CRC_ERR	    4
#define NVRAM_SHADOW_ERR	    5

/*
 * nvram header struct 		            
 * magic    = 0x004E4F52 (RON)             
 * len      = 0~65495                      
 * crc      = use crc-32                    
 * reserved = reserved 	                    
 */
 
typedef struct nvram_header_s{
	unsigned long magic;
	unsigned long len;
	unsigned long crc;
	unsigned long reserved;
	
}nvram_header_t;


/* Copy data from flash to NVRAM_TMP_PATH
 * @return	0 on success and errorno on failure     
 */
extern int nvram_load();


/*
 * Write data from NVRAM_TMP_PATH to flash   
 * @return	0 on success and errorno on failure     
 */
extern int nvram_commit();

/*
 * Get the value of an NVRAM variable
 * @param	name	name of variable to get
 * @return	value of variable or NULL if undefined
 */
#define nvram_get_def(name) nvram_get_fun(name,NVRAM_DEFAULT)
#define NVRAM_GET_CONFIG(name) nvram_get_fun(name,NVRAM_TMP_PATH)
//#define nvram_safe_get(msg) (nvram_get(msg)?:"")
extern char* nvram_safe_get(const char *name);
extern char* nvram_get(const char *name);
char* nvram_get_fun(const char *name,char *path);
extern char*  nvram_getall(char *data,int bytes);

/*
 * Match an NVRAM variable
 * @param	name	name of variable to match
 * @param	match	value to compare against value of variable
 * @return	TRUE if variable is defined and its value is string equal to match or FALSE otherwise
 */
static inline int nvram_match(char *name, char *match) {
    int ret;
	char *value = nvram_get(name);
	ret = (value && !strcmp(value, match));
	if(value)
	    free(value);
	
	return ret;
}

/*
 * IN_Match an NVRAM variable
 * @param	name	name of variable to match
 * @param	match	value to compare against value of variable
 * @return	TRUE if variable is defined and its value is not string equal to invmatch or FALSE otherwise
 */
static inline int nvram_invmatch(char *name, char *invmatch) {
	int ret;
	char *value = nvram_get(name);
	ret = (value && strcmp(value, invmatch));
	if(value)
	    free(value);
	
	return ret;
}

/*
 * Set the value of an NVRAM variable
 * @param	name	name of variable to set
 * @param	value	value of variable
 * @return	0 on success and errorno on failure
 * NOTE: use nvram_commit to commit this change to flash.
 */
extern int nvram_set(const char* name,const char* value);
extern void nvram_factory_default(void);

#endif
