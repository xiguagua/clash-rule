#include <clash_rule.h>
#include <string.h>

int32_t clash_rule_capi_smoke_test(void) {
    static const uint8_t rules[] =
        "DOMAIN,example.com,Proxy\n"
        "MATCH,DIRECT\n";
    clash_rule_error error = {0};
    clash_rule_engine_t engine = clash_rule_engine_create(rules, sizeof(rules) - 1, &error);
    if (engine == NULL || error.code != CLASH_RULE_ERROR_NONE) return 1;

    static const uint8_t domain[] = "example.com";
    clash_rule_request request = {0};
    request.domain = domain;
    request.domain_length = sizeof(domain) - 1;

    uint16_t policy_id = UINT16_MAX;
    uint32_t rule_index = UINT32_MAX;
    if (clash_rule_engine_match(engine, &request, &policy_id, &rule_index) != CLASH_RULE_STATUS_OK) {
        clash_rule_engine_destroy(engine);
        return 2;
    }
    if (policy_id != 0 || rule_index != 0) {
        clash_rule_engine_destroy(engine);
        return 3;
    }

    size_t name_length = 0;
    if (clash_rule_engine_policy_name(engine, policy_id, NULL, 0, &name_length) != CLASH_RULE_STATUS_OK ||
        name_length != 5) {
        clash_rule_engine_destroy(engine);
        return 4;
    }
    uint8_t short_name[4] = {0xA5, 0xA5, 0xA5, 0xA5};
    if (clash_rule_engine_policy_name(engine, policy_id, short_name, sizeof(short_name), &name_length) !=
            CLASH_RULE_STATUS_BUFFER_TOO_SMALL ||
        name_length != 5 || short_name[0] != 0xA5) {
        clash_rule_engine_destroy(engine);
        return 5;
    }
    uint8_t name[5] = {0};
    if (clash_rule_engine_policy_name(engine, policy_id, name, sizeof(name), &name_length) != CLASH_RULE_STATUS_OK ||
        memcmp(name, "Proxy", sizeof(name)) != 0) {
        clash_rule_engine_destroy(engine);
        return 6;
    }

    clash_rule_engine_destroy(engine);

    /* 安全性验证 1：Double-destroy 必须安全防御，不崩溃 */
    clash_rule_engine_destroy(engine);

    /* 安全性验证 2：UAF 访问已释放的句柄必须被识别并返回 INVALID_ARGUMENT */
    if (clash_rule_engine_match(engine, &request, &policy_id, &rule_index) != CLASH_RULE_STATUS_INVALID_ARGUMENT) {
        return 8;
    }
    if (clash_rule_engine_policy_name(engine, policy_id, name, sizeof(name), &name_length) != CLASH_RULE_STATUS_INVALID_ARGUMENT) {
        return 9;
    }

    /* 安全性验证 3：NULL 句柄必须安全处理 */
    if (clash_rule_engine_match(NULL, &request, &policy_id, &rule_index) != CLASH_RULE_STATUS_INVALID_ARGUMENT) {
        return 10;
    }
    clash_rule_engine_destroy(NULL);

    static const uint8_t invalid_rules[] = "DOMAIN,example.com\n";
    engine = clash_rule_engine_create(invalid_rules, sizeof(invalid_rules) - 1, &error);
    if (engine != NULL || error.code != CLASH_RULE_ERROR_MALFORMED_LINE || error.line != 1) {
        if (engine != NULL) clash_rule_engine_destroy(engine);
        return 7;
    }
    return 0;
}
