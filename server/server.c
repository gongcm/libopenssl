#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/select.h>

#include "libopenssl.h"

#define cert "../certs/server/server.crt"
#define private_key "../certs/server/rsa_private.key"

int main()
{
   int ret = -1;
   // ssl test
   ssl_ctx *mctx;
   struct sockaddr_in addr;
   struct sockaddr_in saddr;
   static char buf[4096];
   int sockfd = -1;
   const int port = 5683;
   const char *str = "hello test tls";
   const char *local_host = "localhost";
   int size = -1;
   socklen_t len;

   //1. c初始化
   ssl_library_init(&mctx,SERVER);

   //2. 加载证书
   ssl_load_certfile(mctx,cert,private_key);

   //3. tcp socket
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0)
      perror("socket");

   //4. bind local address
   //getaddrinfo(local_host,)
   memset(&saddr, 0, sizeof(saddr));
   saddr.sin_family = AF_INET;
   saddr.sin_port = htons(port);
   saddr.sin_addr.s_addr = htonl(INADDR_ANY);
   if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr)) < 0)
   {
      printf("tcp bind failed \n");
      perror("Bind：");
      return -1;
   }

   //5. listen
   if (listen(sockfd, 10) < 0)
   {
      perror("listen: ");
      return -2;
   }



   while (1)
   {
      
      //6.accept
      int accept_fd = accept(sockfd, (struct sockaddr *)&addr, &len);
      if (accept_fd < 0)
      {
         perror("accept :");
         return -1;
      }

      //7. 创建一个新ssl 会话
      ssl_session * session =  ssl_new_session(mctx,accept_fd);

      //8. accept

      ssl_session_accept(session);

      //8. 数据传输
      ret = ssl_read(session, buf, sizeof(buf),-1);
      printf("ssl read %d bytes,%s \n",ret,buf);
      ssl_write(session, str, strlen(str));

      //9 关闭 sockfd，会话
      close(accept_fd);
      ssl_free_session(session);
   }
   

   //ssl_server_accept(mctx, accept_fd);


   close(sockfd);

   ssl_library_exit(mctx);
   return (0);
}