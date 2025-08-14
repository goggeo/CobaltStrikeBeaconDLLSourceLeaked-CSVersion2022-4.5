cmake_minimum_required(VERSION 3.10)
project(TokensDLL)

set(CMAKE_CXX_STANDARD 17)

# 设置为DLL
add_library(tokens SHARED
    tokens.cpp
    tokens_dll.cpp
)

# 链接必要的库
target_link_libraries(tokens
    advapi32
    kernel32
    user32
    netapi32
)

# 设置输出目录
set_target_properties(tokens PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

# 添加编译定义
target_compile_definitions(tokens PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
)