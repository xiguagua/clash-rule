#include "alloc_counter.h"

#if defined(__APPLE__)

#include <stdint.h>

// 未公开的 libmalloc 钩子（堆栈日志使用的同一个），公共 SDK 头文件中未声明。
typedef void (malloc_logger_t)(unsigned type, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                               uintptr_t result, unsigned num_hot_frames_to_skip);
extern malloc_logger_t *malloc_logger;

#define CLASH_RULE_MALLOC_LOG_TYPE_ALLOCATE 0x02

static __thread uint64_t allocation_count = 0;

static void count_allocation(unsigned type, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                             uintptr_t result, unsigned num_hot_frames_to_skip) {
    (void)arg1;
    (void)arg2;
    (void)arg3;
    (void)result;
    (void)num_hot_frames_to_skip;
    if (type & CLASH_RULE_MALLOC_LOG_TYPE_ALLOCATE) {
        allocation_count++;
    }
}

void clash_rule_alloc_tracking_begin(void) {
    allocation_count = 0;
    malloc_logger = count_allocation;
}

uint64_t clash_rule_alloc_tracking_end(void) {
    malloc_logger = NULL;
    return allocation_count;
}

#endif
