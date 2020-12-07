#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/x509v3.h>

#include "libopenssl.h"

#undef log_printf
#define log_printf(format, args...) printf("%s[%d] " format, __FUNCTION__, __LINE__, ##args)

//TLSv1_2_client_method()
#define SSL_CLIENT_METHOD_VER TLSv1_2_client_method()
#define SSL_SERVER_METHOD_VER TLSv1_2_server_method()

struct ssl_context
{
    SSL_CTX *sslContext;
    X509 * certificate;
};

struct ssl_session_t{
    int fd;
    SSL *ssl;
};


void dump_x509(SSL * ssl)
{
    X509 *cert = NULL;
    cert = SSL_get_peer_certificate(ssl);
    if(!cert){
        ERR_print_errors_fp(stdout);
        printf("SSL_get_peer_certificate failed \n");
        return;
    }

    log_printf("SUBJECT %s \n", X509_NAME_oneline(X509_get_subject_name(cert), 0, 0));
    log_printf("issuer %s \n", X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0));
    log_printf("SUBJECT %s \n", X509_NAME_oneline(X509_get_subject_name(cert), 0, 0));

    X509_free(cert);
}

int ssl_library_init(ssl_ctx ** ctx,int flag)
{
    ssl_ctx *mctx = NULL;

    if(!ctx){
        log_printf("ctx null \n");
        return -1;
    }

    // Register the error strings for libcrypto & libssl
    SSL_load_error_strings();
    // Register the available ciphers and digests
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    mctx = (ssl_ctx *)malloc(sizeof(ssl_ctx));
    if (!mctx)
    {
        log_printf("malloc failed \n");
        return -1;
    }

    mctx->sslContext = SSL_CTX_new(flag == CLINET ? SSL_CLIENT_METHOD_VER : SSL_SERVER_METHOD_VER);
    if (mctx->sslContext == NULL)
    {
        log_printf("SSL_CTX_new failed \n");
        return -1;
    }
    *ctx = mctx;
    return 0;
}



int ssl_library_exit(ssl_ctx *mctx)
{
    if (!mctx)
    {
        log_printf(" mctx null \n");
        return -1;
    }

    if (mctx->sslContext)
        SSL_CTX_free(mctx->sslContext);

    free(mctx);
    return 0;
}

int ssl_load_certfile(ssl_ctx *mctx, char *public_cert, char *private_cert)
{
    int ret = 0;

    if (!mctx)
        return -1;

    if (public_cert)
    {
        /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
        if (SSL_CTX_use_certificate_file(mctx->sslContext, public_cert, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stdout);
            return -1;
        }
    }

    if (private_cert)
    {

        /* 载入用户私钥 */
        if (SSL_CTX_use_PrivateKey_file(mctx->sslContext, private_cert, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stdout);
            return -1;
        }
        /* 检查用户私钥是否正确 */
        if (!SSL_CTX_check_private_key(mctx->sslContext))
        {
            ERR_print_errors_fp(stdout);
            return -1;
        }
    }

    return ret;
}

ssl_session *  ssl_new_session(ssl_ctx * mctx,int sockfd)
{
    ssl_session * session = NULL;
    
    if(!mctx){
        log_printf("mctx null \n");
        return NULL;
    }

    session =(ssl_session *)malloc(sizeof(ssl_session));
    if(!session){
        log_printf("ssl session malloc null \n");
        return NULL;
    }

    session->ssl = SSL_new(mctx->sslContext);
    if (!session->ssl)
    {
        log_printf("SSL_new failed \n");
        return NULL;
    }

    session->fd = sockfd;

    return session;
}

void ssl_free_session(ssl_session * session)
{
    if(session && session->ssl) SSL_free(session->ssl);
    if(session) free(session);
}

int ssl_session_connect(ssl_session * session)
{
    int ret = -1;

    if (!session)
    {
        log_printf("mctx null \n");
        return -1;
    }

    if (!session->ssl || (session->fd < 0))
    {
        log_printf("ssl null \n");
        return -1;
    }

    // Connect the SSL struct to our connection
    if (!SSL_set_fd(session->ssl,session->fd))
    {
        log_printf("SSL_set_fd failed \n");
        return -1;
    }

    ret = SSL_connect(session->ssl);
    if (ret < 0)
    {
        log_printf("SSL_connect failed \n");
        return -1;
    }

    dump_x509(session->ssl);

    return 0;
}

int ssl_session_accept(ssl_session *session)
{
    int ret = -1;
    int acceptfd = -1;

    if (!session)
    {
        log_printf("mctx null \n");
        return -1;
    }

    if (!session->ssl)
    {
        log_printf("ssl null \n");
        return -1;
    }

    acceptfd = session->fd;

    // Connect the SSL struct to our connection
    if (!SSL_set_fd(session->ssl, acceptfd))
    {
        log_printf("SSL_set_fd failed \n");
        return -1;
    }

    ret = SSL_accept(session->ssl);
    if (ret < 0)
    {
        ERR_print_errors_fp(stdout);
        log_printf("SSL_accept failed \n");
        return -1;
    }

    dump_x509(session->ssl);
    return 0;
}

int ssl_write(ssl_session * sesion,char * buffer,int len)
{
    int retLen       = 0;
    int sendLen      = 0;
    SSL * ssl        = sesion->ssl; 
    int bufLen       = len;
    const char *pBuf = buffer;
    
    
    if(!ssl)
    {
        return -1;
    }
    
    /* 发消息给服务器 */
    
    while(bufLen > 0)
    {
        retLen = SSL_write(ssl, pBuf + sendLen, bufLen);
    
        if (retLen < 0)
        {
            // 发送被中断，或将被阻塞，或要求重发，就重新发送
            if (errno == EINTR  || errno == EWOULDBLOCK || errno == EAGAIN)
            {
                continue;
            }
            printf("send false！errno:%d, %s !\n", errno, strerror(errno));
            return -1;
        }
        else
        {
            sendLen += retLen;
            bufLen  -= retLen;
            
            printf("send ok, len = %d\n", retLen );
        }
    }
    
    return sendLen;

}

int ssl_read(ssl_session * sesion,char * buffer,int len,int timeout)
{
    int selectRet;
    int ret = 0;

    int size = 0;
    struct timeval tv;
    struct timeval * val = NULL;
    fd_set fs_read;
    int fd = sesion->fd;
    SSL * ssl = sesion->ssl;
    
    if(!ssl)
        return -2;

    if(timeout > 0){
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
        val = &tv;
    }

    FD_ZERO(&fs_read);
    FD_SET(fd, &fs_read);
    
    // 使用select接收数据，等待超时60时
    selectRet = select(fd + 1, &fs_read, NULL, NULL, val);
    if (selectRet < 0)
    {
        printf("recv: select false\n");
        return -1;
    }
    else if (0 == selectRet)
    {
        return 0;
    }

    size = SSL_read(ssl,buffer,len);

    return size;
}