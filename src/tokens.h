
#ifdef _WIN32
#include <Windows.h>
#else
// Define BOOL for non-Windows platforms
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#endif

void token_guard_start();
void token_guard_stop();

void token_guard_start_maybe(BOOL ignoreToken);
void token_guard_stop_maybe(BOOL ignoreToken);