#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "commands.h"

#define MAXPATH 32768
#define MAX_RECURSION_DEPTH 100  // 添加：防止栈溢出的递归深度限制

void walk_parent(char * parent, WIN32_FIND_DATA * ffd, RCALLBACK callback, int depth);

// 改进：添加路径长度检查和错误处理
BOOL safe_path_combine(char* dest, size_t dest_size, const char* parent, const char* child) {
    size_t parent_len = strlen(parent);
    size_t child_len = strlen(child);
    
    // 检查路径总长度（+2用于反斜杠和空终止符）
    if (parent_len + child_len + 2 >= dest_size) {
        return FALSE;
    }
    
    _snprintf(dest, dest_size, "%s\\%s", parent, child);
    return TRUE;
}

void walk_parent_child(char * parent, char * folder, WIN32_FIND_DATA * ffd, RCALLBACK callback, int depth) {
    // 改进：检查递归深度
    if (depth >= MAX_RECURSION_DEPTH) {
        return;
    }
    
    char * folderz = (char *)malloc(MAXPATH);
    if (folderz == NULL) {
        return; // 改进：添加内存分配失败检查
    }
    
    // 改进：使用安全的路径组合函数
    if (!safe_path_combine(folderz, MAXPATH, parent, folder)) {
        free(folderz);
        return;
    }
    
    walk_parent(folderz, ffd, callback, depth + 1);
    free(folderz);
}

void walk_parent(char * parent, WIN32_FIND_DATA * ffd, RCALLBACK callback, int depth) {
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char * search_pattern = NULL;
    
    // 改进：检查递归深度
    if (depth >= MAX_RECURSION_DEPTH) {
        return;
    }
    
    // 改进：检查输入参数
    if (parent == NULL || ffd == NULL || callback == NULL) {
        return;
    }
    
    search_pattern = (char *)malloc(MAXPATH);
    if (search_pattern == NULL) {
        return; // 改进：添加内存分配失败检查
    }
    
    // 改进：安全的字符串格式化
    if (_snprintf(search_pattern, MAXPATH, "%s\\*", parent) < 0) {
        free(search_pattern);
        return;
    }
    
    hFind = FindFirstFile(search_pattern, ffd);
    free(search_pattern);
    
    if (INVALID_HANDLE_VALUE == hFind) {
        return;
    }
    
    do {
        // 改进：检查文件名长度，防止缓冲区溢出
        if (strlen(ffd->cFileName) >= MAX_PATH) {
            continue;
        }
        
        if (ffd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // 改进：更安全的字符串比较
            if (strcmp(ffd->cFileName, ".") != 0 && strcmp(ffd->cFileName, "..") != 0) {
                // 改进：避免不必要的内存分配
                walk_parent_child(parent, ffd->cFileName, ffd, callback, depth);
                callback(parent, ffd->cFileName, TRUE);
            }
        }
        else {
            callback(parent, ffd->cFileName, FALSE);
        }
    } while (FindNextFile(hFind, ffd) != 0);
    
    // 改进：确保句柄始终被关闭
    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
    }
}

// 改进：添加错误处理和输入验证
void recurse(char * start, RCALLBACK callback) {
    WIN32_FIND_DATA ffd;
    
    // 改进：输入验证
    if (start == NULL || callback == NULL) {
        return;
    }
    
    // 改进：检查起始路径长度
    if (strlen(start) >= MAXPATH - 10) { // 预留空间给通配符和子路径
        return;
    }
    
    memset(&ffd, 0, sizeof(WIN32_FIND_DATA)); // 改进：初始化结构体
    walk_parent(start, &ffd, callback, 0);
}