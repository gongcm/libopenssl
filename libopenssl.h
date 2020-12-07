

#define SERVER 0
#define CLINET 1

struct ssl_context;
typedef struct ssl_context ssl_ctx;

struct ssl_session_t;
typedef struct ssl_session_t ssl_session;


// flag CLIENT or SERVER
int ssl_library_init(ssl_ctx ** ctx,int flag);
int ssl_library_exit(ssl_ctx *mctx);

int ssl_load_certfile(ssl_ctx *mctx,char *public_cert, char *private_cert);

ssl_session *  ssl_new_session(ssl_ctx * mctx,int sockfd);
void ssl_free_session(ssl_session * session);

int ssl_session_connect(ssl_session * session);
int ssl_session_accept(ssl_session *session);

int ssl_write(ssl_session * sesion,char * buffer,int len);

// timeout < 0 ,block
int ssl_read(ssl_session * sesion,char * buffer,int len,int timeout);