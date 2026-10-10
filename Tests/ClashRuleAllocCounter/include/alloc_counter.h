#ifndef CLASH_RULE_ALLOC_COUNTER_H
#define CLASH_RULE_ALLOC_COUNTER_H

#include <stdint.h>

void clash_rule_alloc_tracking_begin(void);
uint64_t clash_rule_alloc_tracking_end(void);

#endif /* CLASH_RULE_ALLOC_COUNTER_H */
