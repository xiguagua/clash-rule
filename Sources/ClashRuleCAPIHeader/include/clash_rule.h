#ifndef CLASH_RULE_H
#define CLASH_RULE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 与 Swift 导出函数使用相同的 void* ABI 表示。 */
typedef void *clash_rule_engine_t;

typedef int32_t clash_rule_status;
enum clash_rule_status_code {
    CLASH_RULE_STATUS_OK = 0,
    CLASH_RULE_STATUS_NO_MATCH = 1,
    CLASH_RULE_STATUS_INVALID_ARGUMENT = 2,
    CLASH_RULE_STATUS_BUFFER_TOO_SMALL = 3
};

enum clash_rule_error_code {
    CLASH_RULE_ERROR_NONE = 0,
    CLASH_RULE_ERROR_UNKNOWN_RULE_TYPE = 1,
    CLASH_RULE_ERROR_MALFORMED_LINE = 2,
    CLASH_RULE_ERROR_INVALID_ARGUMENT = 3,
    CLASH_RULE_ERROR_INVALID_PORT = 4,
    CLASH_RULE_ERROR_INVALID_ADDRESS = 5,
    CLASH_RULE_ERROR_UNKNOWN_FLAG = 6,
    CLASH_RULE_ERROR_POLICY_TABLE_FULL = 7,
    CLASH_RULE_ERROR_UNKNOWN_RULE_SET = 8,
    CLASH_RULE_ERROR_CIRCULAR_RULE_SET = 9,
    CLASH_RULE_ERROR_RULE_SET_LOAD_FAILED = 10,
    CLASH_RULE_ERROR_INVALID_RULE_SET_RESOLVER = 11,
    CLASH_RULE_ERROR_API_ARGUMENT = 12
};

typedef struct clash_rule_error {
    int32_t code;
    size_t line;
    size_t column;
} clash_rule_error;

typedef struct clash_rule_request {
    const uint8_t *domain;
    size_t domain_length;

    uint8_t has_target_address;
    uint64_t target_address_high;
    uint64_t target_address_low;
    uint16_t target_port;

    uint8_t has_source_address;
    uint64_t source_address_high;
    uint64_t source_address_low;
    uint16_t source_port;

    const uint8_t *process_name;
    size_t process_name_length;
    const uint8_t *process_path;
    size_t process_path_length;

    /* 0 = 未指定，1 = TCP，2 = UDP。 */
    uint8_t network_protocol;
    uint8_t has_dscp;
    uint8_t dscp;

    /* 大写 ASCII 国家码按大端打包，例如 "US" = 0x00005553。 */
    uint32_t country_code;
} clash_rule_request;

/*
 * 编译规则文本。rule_data 在调用期间借用；空规则可传 NULL 和长度 0。
 * 最小版不接收外部 RULE-SET resolver；解析失败时返回 NULL 并填写 out_error。
 */
clash_rule_engine_t clash_rule_engine_create(
    const uint8_t *rule_data,
    size_t rule_length,
    clash_rule_error *out_error);

/* NULL 安全。多个 match/policy_name 可并发调用；销毁不能与同一 handle 的调用并发执行。 */
void clash_rule_engine_destroy(clash_rule_engine_t engine);

/*
 * 执行一次匹配。domain/process 的指针仅在调用期间借用；长度为 0 时可传 NULL。
 * 地址按 128 位大端数值拆成 high/low；IPv4 放在 low 的低 32 位。
 * 成功命中返回 OK；未命中返回 NO_MATCH；输出指针或请求字段非法时返回 INVALID_ARGUMENT。
 * out_policy_id/out_rule_index 在无匹配时写 0。
 */
clash_rule_status clash_rule_engine_match(
    clash_rule_engine_t engine,
    const clash_rule_request *request,
    uint16_t *out_policy_id,
    uint32_t *out_rule_index);

/*
 * 查询已 intern 的 policy 名称的 UTF-8 字节数（不含 NUL）。
 * out_name=NULL 且 capacity=0 时只查询长度；缓冲区不足时不写入并返回 BUFFER_TOO_SMALL。
 */
clash_rule_status clash_rule_engine_policy_name(
    clash_rule_engine_t engine,
    uint16_t policy_id,
    uint8_t *out_name,
    size_t capacity,
    size_t *out_length);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CLASH_RULE_H */
