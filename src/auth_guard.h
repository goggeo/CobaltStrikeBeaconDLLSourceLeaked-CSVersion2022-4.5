// auth_guard.h-在macOS下交叉编译必要的头文件，包含了Windows和Linux的授权守卫逻辑和必要的头文件定义
// 全局授权/安全模式守卫 —— 默认关闭高危功能，除非满足“编译期 + 运行期”双重授权。
// 使用方式：在各高危函数入口加 REQUIRE_AUTH_* 宏（见文末示例）

#ifndef AUTH_GUARD_H_
#define AUTH_GUARD_H_

// ==== 构建期安全开关 ====
// 未定义 AUTHORIZED_BUILD 时，默认 SAFE_MODE=1：全部高危操作短路。
// 仅当构建时 -DAUTHORIZED_BUILD 并在运行期通过令牌校验时才放行。
#ifndef AUTHORIZED_BUILD
  #define SAFE_MODE 1
#else
  #define SAFE_MODE 0 #不允许高危操作
#endif

// ==== 依赖声明 ====
// 这些符号来自你现有工程（如 commands.cpp / jobs / callbacks 等）。
// 如果命名不同，请自行修改为你项目中的版本。
#ifdef __cplusplus
extern "C" {
#endif
void post_error_na(int code); // 统一错误上报（已存在于工程中）
#ifdef __cplusplus
}
#endif

// ==== 运行期授权令牌校验 ====
// 要求设置环境变量 REDTEAM_AUTH，内容与 expected 相同才视为授权。
#ifdef _WIN32
  #include <windows.h>
  #include <string.h>
  static inline int auth_is_authorized_runtime()
  {
      // TODO：替换为你的团队预共享令牌（≥16字节，建议随机并定期轮换）
      const char* expected = "REPLACE_WITH_YOUR_TEAM_TOKEN";
      char buf[256] = {0};
      DWORD len = GetEnvironmentVariableA("REDTEAM_AUTH", buf, sizeof(buf));
      if (len == 0 || len >= sizeof(buf)) return 0; // 未设置或溢出 → 未授权
      return (strcmp(buf, expected) == 0) ? 1 : 0;
  }
#else
  // 非 Windows 情况（如构建辅助工具），也给出实现，避免编译错误。
  #include <stdlib.h>
  #include <string.h>
  static inline int auth_is_authorized_runtime()
  {
      const char* expected = "REPLACE_WITH_YOUR_TEAM_TOKEN";
      const char* v = getenv("REDTEAM_AUTH");
      if (!v) return 0;
      return (strcmp(v, expected) == 0) ? 1 : 0;
  }
#endif

// ==== 统一短路宏 ====
// 未授权：上报通用错误码 0x50，避免透露原因（编译期或运行期不满足）。
#define REQUIRE_AUTH_OR_RETURN_VOID() do {               \
    if (SAFE_MODE || !auth_is_authorized_runtime()) {    \
        post_error_na(0x50);                             \
        return;                                          \
    }                                                    \
} while (0)

#define REQUIRE_AUTH_OR_RETURN_SOCKET(invalid_socket) do { \
    if (SAFE_MODE || !auth_is_authorized_runtime()) {      \
        post_error_na(0x50);                               \
        return (invalid_socket);                           \
    }                                                      \
} while (0)

#define REQUIRE_AUTH_OR_RETURN_BOOL() do {               \
    if (SAFE_MODE || !auth_is_authorized_runtime()) {    \
        post_error_na(0x50);                             \
        return 0;                                        \
    }                                                    \
} while (0)

#define REQUIRE_AUTH_OR_RETURN_INT(errcode) do {         \
    if (SAFE_MODE || !auth_is_authorized_runtime()) {    \
        post_error_na(0x50);                             \
        return (errcode);                                \
    }                                                    \
} while (0)

// ==== 可选：编译时误配检测（双保险）====
// 如果你在 Debug 构建里不小心同时定义/取消定义，给出明确编译错误。
// #if SAFE_MODE==0
//   #warning "授权构建已启用：确保运行时提供 REDTEAM_AUTH 正确令牌。"
// #endif

#endif // AUTH_GUARD_H_