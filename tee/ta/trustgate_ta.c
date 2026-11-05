/*
 * TrustGate 可信锚 TA：审计链权威（HMAC 密钥 + 单调序号 + 链头）。
 *
 * 设计依据 docs/06-T2可信锚实现方案.md §3（决策 D1/D3）：
 *   - TA 内只放"盖章 + 数序号"，策略求值留在 host 锚进程（P4 最小 TCB）；
 *   - 状态 {key, seq, head} 存 TA 私有持久存储，每次 chain_append 立即
 *     写盘（每条落盘，论断不留断电时间窗）；
 *   - 存储后端必须为 RPMB（构建侧配置，见 user_ta_header_defines.h 与
 *     tee/README.md），否则"旧状态不可整块回滚"不成立。
 *
 * 语义与 trustgate/audit.py + tee/bridge/tg_bridge.c 逐字节对齐：
 *   hash = sha256(prev_hex_ascii || "|" || seq十进制_ascii || "|" || payload)
 *   记录 mac = HMAC-SHA256(key, hash_hex_ascii)
 *   检查点 mac = HMAC-SHA256(key, "seq|head_hex" ascii)
 * canonical payload 由 host 侧 Python 唯一权威产出，本 TA 把它当作不透明
 * 字节，不解析 JSON。
 *
 * 输出布局（与 tg_bridge.c 一致，小端）：
 *   chain_append: u32 seq | char prev[64] | char hash[64] | char mac[64]
 *   checkpoint:   u32 seq | char head[64] | char mac[64]
 *   seal:         char mac[64]；export_key: 32 字节原始密钥
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdint.h>
#include "user_ta_header_defines.h"

#define TG_OBJ_ID "tg.chain"
#define TG_OBJ_ID_LEN (sizeof(TG_OBJ_ID) - 1)

#define TG_KEY_LEN 32
#define TG_HEAD_LEN 32
#define TG_HEX_LEN 64
/* 持久对象布局：[key 32][seq 4 LE][head 32] */
#define TG_BLOB_LEN (TG_KEY_LEN + 4 + TG_HEAD_LEN)

enum {
    TG_CMD_SEAL = 1,
    TG_CMD_CHAIN_APPEND = 2,
    TG_CMD_CHECKPOINT = 3,
    TG_CMD_EXPORT_KEY = 4,
};

static uint8_t g_key[TG_KEY_LEN];
static uint32_t g_seq;
static uint8_t g_head[TG_HEAD_LEN];
static int g_loaded = 0;

static void bin2hex(const uint8_t *in, size_t len, char *out) {
    static const char d[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        out[i * 2] = d[in[i] >> 4];
        out[i * 2 + 1] = d[in[i] & 15];
    }
    out[len * 2] = 0;
}

static void u32dec(uint32_t v, char *out, size_t *len) {
    char tmp[12];
    size_t n = 0, i;
    if (v == 0) {
        out[0] = '0';
        *len = 1;
        return;
    }
    while (v) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    for (i = 0; i < n; i++)
        out[i] = tmp[n - 1 - i];
    *len = n;
}

static TEE_Result sha256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_Result res;
    size_t outlen = 32;
    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
        return res;
    res = TEE_DigestDoFinal(op, in, inlen, out, &outlen);
    TEE_FreeOperation(op);
    return res == TEE_SUCCESS && outlen == 32 ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

static TEE_Result hmac(const uint8_t *msg, size_t msglen, uint8_t out[32]) {
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle key = TEE_HANDLE_NULL;
    TEE_Attribute attr;
    TEE_Result res;
    size_t outlen = 32;
    res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, 32 * 8);
    if (res != TEE_SUCCESS)
        return res;
    res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, 32 * 8, &key);
    if (res != TEE_SUCCESS)
        goto out_op;
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, g_key, TG_KEY_LEN);
    res = TEE_PopulateTransientObject(key, &attr, 1);
    if (res != TEE_SUCCESS)
        goto out_key;
    res = TEE_SetOperationKey(op, key);
    if (res != TEE_SUCCESS)
        goto out_key;
    res = TEE_MACCompute(op, msg, msglen, out, &outlen);
out_key:
    TEE_FreeTransientObject(key);
out_op:
    TEE_FreeOperation(op);
    return res == TEE_SUCCESS && outlen == 32 ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

/* 从持久存储加载状态；不存在则以随机密钥 + 创世状态创建。 */
static TEE_Result state_load(void) {
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    TEE_Result res;
    uint8_t blob[TG_BLOB_LEN];
    size_t n = 0;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, TG_OBJ_ID, TG_OBJ_ID_LEN,
                                   TEE_DATA_FLAG_ACCESS_READ, &obj);
    if (res == TEE_SUCCESS) {
        res = TEE_ReadObjectData(obj, blob, sizeof(blob), &n);
        TEE_CloseObject(obj);
        if (res != TEE_SUCCESS || n != sizeof(blob))
            return TEE_ERROR_CORRUPT_OBJECT;
        memcpy(g_key, blob, TG_KEY_LEN);
        g_seq = (uint32_t)blob[TG_KEY_LEN] | ((uint32_t)blob[TG_KEY_LEN + 1] << 8) |
                ((uint32_t)blob[TG_KEY_LEN + 2] << 16) | ((uint32_t)blob[TG_KEY_LEN + 3] << 24);
        memcpy(g_head, blob + TG_KEY_LEN + 4, TG_HEAD_LEN);
        g_loaded = 1;
        return TEE_SUCCESS;
    }
    if (res != TEE_ERROR_ITEM_NOT_FOUND)
        return res;

    /* 首次运行：生成密钥，从创世状态（head=0，对应 GENESIS 的 64 个 '0'）开始。 */
    TEE_GenerateRandom(g_key, TG_KEY_LEN);
    g_seq = 0;
    memset(g_head, 0, sizeof(g_head));
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, TG_OBJ_ID, TG_OBJ_ID_LEN,
                                     TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, NULL, 0, &obj);
    if (res != TEE_SUCCESS)
        return res;
    memcpy(blob, g_key, TG_KEY_LEN);
    blob[TG_KEY_LEN] = 0;
    blob[TG_KEY_LEN + 1] = 0;
    blob[TG_KEY_LEN + 2] = 0;
    blob[TG_KEY_LEN + 3] = 0;
    memcpy(blob + TG_KEY_LEN + 4, g_head, TG_HEAD_LEN);
    res = TEE_WriteObjectData(obj, blob, sizeof(blob));
    TEE_CloseObject(obj);
    if (res != TEE_SUCCESS)
        return res;
    g_loaded = 1;
    return TEE_SUCCESS;
}

/* 每次链推进后立即写盘（决策 D1：每条落盘，断电不丢序号）。 */
static TEE_Result state_save(void) {
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    TEE_Result res;
    uint8_t blob[TG_BLOB_LEN];
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, TG_OBJ_ID, TG_OBJ_ID_LEN,
                                   TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE, &obj);
    if (res != TEE_SUCCESS)
        return res;
    memcpy(blob, g_key, TG_KEY_LEN);
    blob[TG_KEY_LEN] = (uint8_t)(g_seq & 0xff);
    blob[TG_KEY_LEN + 1] = (uint8_t)((g_seq >> 8) & 0xff);
    blob[TG_KEY_LEN + 2] = (uint8_t)((g_seq >> 16) & 0xff);
    blob[TG_KEY_LEN + 3] = (uint8_t)((g_seq >> 24) & 0xff);
    memcpy(blob + TG_KEY_LEN + 4, g_head, TG_HEAD_LEN);
    res = TEE_WriteObjectData(obj, blob, sizeof(blob));
    TEE_CloseObject(obj);
    return res;
}

TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4],
                                    void **sess_ctx) {
    (void)param_types;
    (void)params;
    (void)sess_ctx;
    return state_load();
}

void TA_CloseSessionEntryPoint(void *sess_ctx) { (void)sess_ctx; }

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_types,
                                      TEE_Param params[4]) {
    (void)sess_ctx;
    if (!g_loaded)
        return TEE_ERROR_ITEM_NOT_FOUND;

    switch (cmd) {
    case TG_CMD_SEAL: {
        uint8_t mac[32];
        char *out;
        if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
            TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT ||
            params[1].memref.size < TG_HEX_LEN + 1)
            return TEE_ERROR_BAD_PARAMETERS;
        if (hmac(params[0].memref.buffer, params[0].memref.size, mac) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        out = params[1].memref.buffer;
        bin2hex(mac, 32, out);
        params[1].memref.size = TG_HEX_LEN;
        return TEE_SUCCESS;
    }
    case TG_CMD_CHAIN_APPEND: {
        uint8_t digest[32];
        uint8_t mac[32];
        char hash_hex[TG_HEX_LEN + 1];
        char mac_hex[TG_HEX_LEN + 1];
        char prev_hex[TG_HEX_LEN + 1];
        uint8_t *out;
        uint32_t seq_out;
        TEE_Result res;
        if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
            TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT ||
            params[1].memref.size < 4 + 64 * 3)
            return TEE_ERROR_BAD_PARAMETERS;

        bin2hex(g_head, TG_HEAD_LEN, prev_hex);
        {
            /* digest = sha256(prev_hex | seq | payload) */
            char seqdec[12];
            size_t seqdeclen = 0;
            size_t plen = params[0].memref.size;
            size_t total = TG_HEX_LEN + 1 + 12 + 1 + plen;
            uint8_t *buf = TEE_Malloc(total, 0);
            char *p;
            if (!buf)
                return TEE_ERROR_OUT_OF_MEMORY;
            u32dec(g_seq, seqdec, &seqdeclen);
            p = (char *)buf;
            memcpy(p, prev_hex, TG_HEX_LEN);
            p += TG_HEX_LEN;
            *p++ = '|';
            memcpy(p, seqdec, seqdeclen);
            p += seqdeclen;
            *p++ = '|';
            memcpy(p, params[0].memref.buffer, plen);
            res = sha256(buf, total, digest);
            TEE_Free(buf);
            if (res != TEE_SUCCESS)
                return res;
        }
        bin2hex(digest, 32, hash_hex);
        if (hmac((const uint8_t *)hash_hex, TG_HEX_LEN, mac) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        bin2hex(mac, 32, mac_hex);

        /* 原子推进：序号 +1、链头前进、立即落盘。 */
        seq_out = g_seq;
        memcpy(g_head, digest, TG_HEAD_LEN);
        g_seq += 1;
        res = state_save();
        if (res != TEE_SUCCESS)
            return res;

        out = params[1].memref.buffer;
        memcpy(out, &seq_out, 4);
        memcpy(out + 4, prev_hex, TG_HEX_LEN);
        memcpy(out + 4 + 64, hash_hex, TG_HEX_LEN);
        memcpy(out + 4 + 128, mac_hex, TG_HEX_LEN);
        params[1].memref.size = 4 + 64 * 3;
        return TEE_SUCCESS;
    }
    case TG_CMD_CHECKPOINT: {
        char head_hex[TG_HEX_LEN + 1];
        char msg[12 + 1 + TG_HEX_LEN + 1];
        char msglen12[12];
        size_t msglen = 0, seqlen = 0;
        uint8_t mac[32];
        uint8_t *out;
        if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT ||
            params[0].memref.size < 4 + 64 * 2)
            return TEE_ERROR_BAD_PARAMETERS;
        bin2hex(g_head, TG_HEAD_LEN, head_hex);
        u32dec(g_seq, msglen12, &seqlen);
        memcpy(msg, msglen12, seqlen);
        msglen = seqlen;
        msg[msglen++] = '|';
        memcpy(msg + msglen, head_hex, TG_HEX_LEN);
        msglen += TG_HEX_LEN;
        if (hmac((const uint8_t *)msg, msglen, mac) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        out = params[0].memref.buffer;
        memcpy(out, &g_seq, 4);
        memcpy(out + 4, head_hex, TG_HEX_LEN);
        bin2hex(mac, 32, (char *)out + 4 + 64);
        params[0].memref.size = 4 + 64 * 2;
        return TEE_SUCCESS;
    }
    case TG_CMD_EXPORT_KEY: {
        if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT ||
            params[0].memref.size < TG_KEY_LEN)
            return TEE_ERROR_BAD_PARAMETERS;
        memcpy(params[0].memref.buffer, g_key, TG_KEY_LEN);
        params[0].memref.size = TG_KEY_LEN;
        return TEE_SUCCESS;
    }
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
