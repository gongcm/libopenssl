#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "libopenssl.h"

#define cert "../certs/client/client.crt"
#define private_key "../certs/client/rsa_private.key"

int main ()
{
   // ssl test
   int ret = -1;
   ssl_ctx * mctx;
   struct sockaddr_in addr;
   static char buf[4096];
   int sockfd = -1;
   const char * ip = "39.102.202.24";
   const int port = 5683;
   const char * str = "hello test tls";
   const char * f = "../register.txt";
   int size = -1;
   FILE * fp = fopen(f,"r+b");

   if(fp){
      size = fread(buf,sizeof(buf),1,fp);
      printf("fread %d bytes,buf %s \n",size,buf);
      fclose(fp);
   }


   //1. 初始化 ssl
   ssl_library_init(&mctx,CLINET);

   //2. 加载证书 ssl,单向认证客户端不加载证书
   ssl_load_certfile(mctx,cert,private_key);

   //3. tcp socket
   sockfd = socket(AF_INET,SOCK_STREAM,0);
   if(sockfd < 0) perror("socket");

   //4. bind local address

   //5. connect
   bzero((char *) &addr, sizeof(addr));
   addr.sin_family = AF_INET;
   addr.sin_addr.s_addr = inet_addr(ip);
   addr.sin_port = htons(port); 

   sleep(1);
     /* connect to the server */    
   if(connect(sockfd, (struct sockaddr *) &addr,sizeof(addr)) < 0) {
      perror("can't connect to server");
      exit(1);
   }

   //6. ssl session 会话
   ssl_session * session = ssl_new_session(mctx,sockfd);
   printf("ssl_new_session successful \n");

   //7. ssl connect 
   ssl_session_connect(session);
   printf("ssl_client_connect \n");
   usleep(500 * 1000);

   //8. 传送数据
   ret = ssl_write(session,buf,strlen(buf));
   printf("ssl write %d bytes \n",ret);

   memset(buf,0,sizeof(buf));
   ret = ssl_read(session,buf,sizeof(buf),-1);
   printf("ssl_read %d bytes,buf %s\n",ret,buf);
  
   //close(accept_fd);
   close(sockfd);

   //9.结束会话
   ssl_free_session(session);

   //10 退出ssl
   ssl_library_exit(mctx);
   return(0);
}