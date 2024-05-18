#ifndef STX_H
#define STX_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/*
//  I will keep this here as a lookup for my own sake, C primitives are hard :(
typedef uint8_t u8;
typedef int32_t b32;
typedef int32_t i32;
typedef uint32_t u32;
typedef uint64_t u64;
typedef float f32;
typedef double f64;
typedef uintptr_t uptr;
typedef unsigned char byte;
typedef ptrdiff_t size;
typedef size_t usize;
*/

// This is interesting, can be used in many ways for optimizations.
// Leaving this here because I don't _fully_ understand the implications.

// #define assert(c) while (!(c)) __builtin_unreachable()

// Useful macros
#define count_of(a) (size_t)(sizeof(a) / sizeof(*(a)))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
// #define new(a, t, n) (t *)alloc(a, sizeof(t), n)

#define memset(d, c, n) __builtin_memset(d, c, n)
#define memcpy(d, s, n) __builtin_memcpy(d, s, n)
#define memccpy(a, b, n) __builtin_memccpy(a, b, n)
#define memmove(a, b, n) __builtin_memmove(a, b, n)
#define memcmp(a, b, n) __builtin_memcmp(a, b, n)
#define memeql(a, b, n) !__builtin_memcmp(a, b, n)

// Nice utility to check the timing of a function
#define CHECK_TIME(x, msg)                    \
  {                                           \
    struct timespec start, end;               \
    timespec_get(&start, TIME_UTC);           \
    x;                                        \
    timespec_get(&end, TIME_UTC);             \
    long f = (end.tv_nsec) - (start.tv_nsec); \
    printf("%s %ld ns\n", msg, f);            \
  }

#endif