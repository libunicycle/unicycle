// SPDX-License-Identifier: MIT

#pragma once

#include "compiler.h"
#include "stdio.h"

#define __SHOUT_0()                                       \
    do {                                                  \
        printf("SHOUT at (%s:%d)\n", __FILE__, __LINE__); \
    } while (0)
#define __SHOUT_VARARG(msg, ...)                                                   \
    do {                                                                           \
        printf("SHOUT at (%s:%d): " #msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define SHOUT(...)                                                                                                               \
    GET_MACRO(_0, ##__VA_ARGS__, __SHOUT_VARARG, __SHOUT_VARARG, __SHOUT_VARARG, __SHOUT_VARARG, __SHOUT_VARARG, __SHOUT_VARARG, \
              __SHOUT_0)                                                                                                         \
    (__VA_ARGS__)

#define __SHOUT_IF_1(cond)                                               \
    do {                                                                 \
        if (cond)                                                        \
            printf("SHOUT at (%s:%d): %s\n", __FILE__, __LINE__, #cond); \
    } while (0)
#define __SHOUT_IF_VARARG(cond, msg, ...)                                                        \
    do {                                                                                         \
        if (cond)                                                                                \
            printf("SHOUT at (%s:%d): %s " #msg "\n", __FILE__, __LINE__, #cond, ##__VA_ARGS__); \
    } while (0)
#define SHOUT_IF(...)                                                                                                           \
    GET_MACRO(_0, ##__VA_ARGS__, __SHOUT_IF_VARARG, __SHOUT_IF_VARARG, __SHOUT_IF_VARARG, __SHOUT_IF_VARARG, __SHOUT_IF_VARARG, \
              __SHOUT_IF_1, void)                                                                                               \
    (__VA_ARGS__)

#define __PANIC_0()                                       \
    do {                                                  \
        printf("PANIC at (%s:%d)\n", __FILE__, __LINE__); \
        __builtin_trap();                                 \
    } while (0)

#define __PANIC_VARARG(msg, ...)                                                   \
    do {                                                                           \
        printf("PANIC at (%s:%d): " #msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        __builtin_trap();                                                          \
    } while (0)
#define PANIC(...)                                                                                                               \
    GET_MACRO(_0, ##__VA_ARGS__, __PANIC_VARARG, __PANIC_VARARG, __PANIC_VARARG, __PANIC_VARARG, __PANIC_VARARG, __PANIC_VARARG, \
              __PANIC_0)                                                                                                         \
    (__VA_ARGS__)

#define __PANIC_IF_1(cond)                                               \
    do {                                                                 \
        if (cond) {                                                      \
            printf("PANIC at (%s:%d): %s\n", __FILE__, __LINE__, #cond); \
            __builtin_trap();                                            \
        }                                                                \
    } while (0)
#define __PANIC_IF_VARARG(cond, msg, ...)                                                        \
    do {                                                                                         \
        if (cond) {                                                                              \
            printf("PANIC at (%s:%d): %s " #msg "\n", __FILE__, __LINE__, #cond, ##__VA_ARGS__); \
            __builtin_trap();                                                                    \
        }                                                                                        \
    } while (0)
#define PANIC_IF(...)                                                                                                           \
    GET_MACRO(_0, ##__VA_ARGS__, __PANIC_IF_VARARG, __PANIC_IF_VARARG, __PANIC_IF_VARARG, __PANIC_IF_VARARG, __PANIC_IF_VARARG, \
              __PANIC_IF_1, void)                                                                                               \
    (__VA_ARGS__)

#define __BUILD_PANIC_0 _Static_assert(false, "")
#define __BUILD_PANIC_1(msg) _Static_assert(false, msg)
#define __BUILD_PANIC_IF_1(cond) _Static_assert(!(cond), "")
#define __BUILD_PANIC_IF_2(cond, msg) _Static_assert(!(cond), msg)

#define BUILD_PANIC(...) GET_MACRO(_0, ##__VA_ARGS__, void, void, void, void, void, __BUILD_PANIC_1, __BUILD_PANIC_0)(__VA_ARGS__)
#define BUILD_PANIC_IF(...) GET_MACRO(_0, ##__VA_ARGS__, void, void, void, void, __BUILD_PANIC_IF_2, __BUILD_PANIC_IF_1, void)(__VA_ARGS__)
