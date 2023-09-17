#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#define NVRAM_SIZE 100000      //MAX of nvram file;
#define NVRAM_TMP_PATH "/var/nvram"
char* value_parser_file(char *name)
{
    char *s,*sp;
    char buf[NVRAM_SIZE];
    int fd;
    unsigned int file_size;
//    if((fd=open(NVRAM_TMP_PATH, O_RDONLY))<0)
//    {
//        printf("Open file error!\n");
//        return " ";				
//    }
if((fd=open("/var/nvram","r"))<0)
{
	return " ";
}
read(fd,buf,128);
printf("L<%d> value_parser_file buf=%s\n",__LINE__,buf);
    memset(buf,0,sizeof(buf));
printf("L<%d> value_parser_file lseek=%ld\n",__LINE__,lseek(fd,0,SEEK_END));
    file_size = lseek(fd,0,SEEK_END);
    lseek(fd,0,SEEK_SET);
    printf("file zise:%d\n",file_size);
    if (file_size>NVRAM_SIZE)
    {
        printf("To value_parser_file function,the file size of nvram is big than the buf size!\n");
        close(fd);
        return " ";
    }
    if(read(fd,buf,file_size)<0)
    {
        printf("Read file nvram error!\n");
        close(fd);
        return " ";
    }
    close(fd);
    s=buf;
    printf("nvram:%s\n",s);
    printf("name:%s\n",name);
    printf("name:%d\n",strlen(name));
    
	while(*s) 
	{
		if (!strncmp(s, name, strlen(name)) && *(s+strlen(name))=='=') 
		{
			//sp=malloc(strlen(s)-strlen(name));
			//memcpy(sp,(s+strlen(name)+1),(strlen(s)-strlen(name)));						
			sp=s+strlen(name)+1;
			printf("sp:%s\n",sp);
			return sp;
		}
		while(*s++);
	}
	return " ";
}
