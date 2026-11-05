/*
 * TrustGate TEE 桥接进程（docs/06-T2可信锚实现方案.md §3）。
 *
 * 在锚进程（trustgate/anchor.py 的 TeeAnchorCore）与 OP-TEE TA 之间转发
 * 链权威请求：seal / chain_append / checkpoint / export_key。stdio 上跑
 * JSON Lines，协议与锚进程一侧的 TeeBridge 类对应。
 *
 * 两种构建形态：
 *   - 真桥（默认）：链接 libteec，调用 UUID 为 TA_UUID 的 trustgate_ta，
 *     密钥、单调序号与链头都在 TA 内的 RPMB 安全存储里。
 *   - 软模拟（-DSOFT_TA）：不链接 libteec，用普通文件模拟 TA 语义，
 *     **仅供开发与单元测试**。它绝不能出现在实验数据路径里——论文数据
 *     必须来自真桥（tee/README.md 的诚实边界）。
 *
 * 语义与 trustgate/audit.py + trustgate/anchor.py 的 AnchorCore 完全对齐：
 *   GENESIS      = 64 个 '0' 字符（head 的初始十六进制形态）
 *   chain_append hash = sha256(prev_hex_ascii || "|" || seq十进制_ascii
 *                                  || "|" || canonical_payload_bytes)
 *   记录 mac     = HMAC-SHA256(key, hash_hex_ascii)
 *   检查点 mac   = HMAC-SHA256(key, seq十进制_ascii || "|" || head_hex_ascii)
 * canonical payload 由 host 侧 Python 唯一权威产出（audit.canonical_payload），
 * 本程序把它当作不透明字节，不做任何 JSON 解析——这是刻意设计。
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef SOFT_TA
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#else
#include <tee_client_api.h>
#endif

/* 与 tee/ta/user_ta_header_defines.h 保持一致。 */
#define TG_TA_UUID_0 0x7c1c3f20
#define TG_TA_UUID_1 0x5a6b
#define TG_TA_UUID_2 0x4c7d
#define TG_TA_UUID_3                                            \
    {                                                           \
        0x8e, 0x9f, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f        \
    }

#define TG_STATE_KEY_LEN 32
#define TG_HEAD_LEN 32
#define TG_HEX_LEN 64

/* ---------------- SHA-256（软模拟需要；真桥的哈希在 TA 内完成） ---------------- */

#ifdef SOFT_TA

static uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

typedef struct {
    uint32_t h[8];
    uint64_t bits;
    uint8_t buf[64];
    size_t buflen;
} sha256_ctx;

static void sha256_transform(sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64], a, b, d, e, f, g, h, t1, t2, s0, s1;
    uint32_t x = c->h[2];
    uint32_t cc = c->h[3];
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (i = 16; i < 64; i++) {
        s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0];
    b = c->h[1];
    d = cc;
    e = c->h[4];
    f = c->h[5];
    g = c->h[6];
    h = c->h[7];
    for (i = 0; i < 64; i++) {
        s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        t1 = h + s1 + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        t2 = s0 + ((a & b) ^ (a & x) ^ (b & x));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = x;
        x = b;
        b = a;
        a = t1 + t2;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += x;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += h;
}

static void sha256_init(sha256_ctx *c) {
    static const uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->h, H0, sizeof(H0));
    c->bits = 0;
    c->buflen = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len) {
    size_t i = 0;
    c->bits += (uint64_t)len * 8;
    while (i < len) {
        size_t take = 64 - c->buflen;
        if (take > len - i)
            take = len - i;
        memcpy(c->buf + c->buflen, data + i, take);
        c->buflen += take;
        i += take;
        if (c->buflen == 64) {
            sha256_transform(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->bits;
    uint8_t pad = 0x80;
    uint8_t z = 0;
    uint8_t lenbe[8];
    int i;
    sha256_update(c, &pad, 1);
    while (c->buflen != 56)
        sha256_update(c, &z, 1);
    for (i = 0; i < 8; i++)
        lenbe[i] = (uint8_t)(bits >> (56 - 8 * i));
    /* 长度追加不进 bits 计数，直接手工压进缓冲。 */
    memcpy(c->buf + c->buflen, lenbe, 8);
    c->buflen += 8;
    if (c->buflen == 64) {
        sha256_transform(c, c->buf);
        c->buflen = 0;
    }
    for (i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)c->h[i];
    }
}

static void hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen,
                        uint8_t out[32]) {
    uint8_t k[64], ipad[64], opad[64];
    sha256_ctx c;
    size_t i;
    memset(k, 0, sizeof(k));
    if (keylen > 64) {
        sha256_init(&c);
        sha256_update(&c, key, keylen);
        sha256_final(&c, k);
    } else {
        memcpy(k, key, keylen);
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, msglen);
    sha256_final(&c, out);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, out, 32);
    sha256_final(&c, out);
}

#endif /* SOFT_TA */

/* ---------------- 公共小工具 ---------------- */

static void bin2hex(const uint8_t *in, size_t len, char *out) {
    static const char d[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        out[i * 2] = d[in[i] >> 4];
        out[i * 2 + 1] = d[in[i] & 15];
    }
    out[len * 2] = 0;
}

static int hex2bin(const char *hex, uint8_t *out, size_t outlen) {
    size_t i;
    if (strlen(hex) != outlen * 2)
        return -1;
    for (i = 0; i < outlen; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1)
            return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* base64 解码（协议中的二进制字段一律 base64，避开 JSON 转义问题）。 */
static int b64_decode(const char *s, uint8_t *out, size_t outsz, size_t *outlen) {
    static const int8_t T[256] = {
        ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,  ['G'] = 6,
        ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13,
        ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19, ['U'] = 20,
        ['V'] = 21, ['W'] = 22, ['X'] = 23, ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27,
        ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34,
        ['j'] = 35, ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
        ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47, ['w'] = 48,
        ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55,
        ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61, ['+'] = 62,
        ['/'] = 63,
    };
    size_t n = 0;
    uint32_t acc = 0;
    int nbits = 0;
    const unsigned char *u = (const unsigned char *)s;
    while (*u) {
        if (*u == '=')
            break;
        if (*u == '\n' || *u == '\r') {
            u++;
            continue;
        }
        if (T[*u] < 0)
            return -1;
        acc = (acc << 6) | (uint32_t)T[*u];
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (n >= outsz)
                return -1;
            out[n++] = (uint8_t)(acc >> nbits);
        }
        u++;
    }
    *outlen = n;
    return 0;
}

/*
 * 从扁平 JSON 对象行中取字符串字段值。
 * 仅处理 \" 与 \\ 转义；协议里进入本函数的字段不是 op 就是 base64，
 * 值内不会出现其他转义序列（Python json.dumps 对 ASCII 不转义）。
 * 返回 0 成功，-1 未找到，-2 缓冲溢出。
 */
static int json_get_str(const char *line, const char *key, char *out, size_t outsz) {
    char pat[64];
    const char *p;
    size_t n = 0;
    int r = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (r < 0 || (size_t)r >= sizeof(pat))
        return -1;
    p = strstr(line, pat);
    if (!p)
        return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != ':')
        return -1;
    p++;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != '"')
        return -1;
    p++;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) {
            p++;
            if (n + 1 >= outsz)
                return -2;
            out[n++] = *p;
            p++;
            continue;
        }
        if (n + 1 >= outsz)
            return -2;
        out[n++] = *p;
        p++;
    }
    if (!*p)
        return -1;
    out[n] = 0;
    return 0;
}

static int json_get_u32(const char *line, const char *key, uint32_t *out) {
    char pat[64];
    const char *p;
    char *end;
    unsigned long v;
    int r = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (r < 0 || (size_t)r >= sizeof(pat))
        return -1;
    p = strstr(line, pat);
    if (!p)
        return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != ':')
        return -1;
    p++;
    while (*p == ' ' || *p == '\t')
        p++;
    v = strtoul(p, &end, 10);
    if (end == p)
        return -1;
    *out = (uint32_t)v;
    return 0;
}

/* ---------------- 链权威状态 ---------------- */

typedef struct {
    uint8_t key[TG_STATE_KEY_LEN];
    uint32_t seq;
    uint8_t head[TG_HEAD_LEN];
} tg_state;

static void state_genesis(tg_state *st) {
    memset(st->head, 0, sizeof(st->head));
    st->seq = 0;
}

static int state_init(tg_state *st, char *err, size_t errsz);
static int state_seal(tg_state *st, const uint8_t *data, size_t dlen, char mac_hex[TG_HEX_LEN + 1]);
static int state_append(tg_state *st, const uint8_t *payload, size_t plen,
                        uint32_t *seq, char prev_hex[TG_HEX_LEN + 1], char hash_hex[TG_HEX_LEN + 1],
                        char mac_hex[TG_HEX_LEN + 1]);
static int state_checkpoint(tg_state *st, uint32_t *seq, char head_hex[TG_HEX_LEN + 1],
                            char mac_hex[TG_HEX_LEN + 1]);
static int state_save(const tg_state *st, char *err, size_t errsz);

#ifdef SOFT_TA
/* 链推进算术（软模拟版；真桥的哈希与 HMAC 在 TA 内完成，布局见 trustgate_ta.c）：
 *   hash = sha256(prev_hex_ascii || "|" || seq十进制_ascii || "|" || payload)
 *   mac  = HMAC-SHA256(key, hash_hex_ascii)
 * 与 trustgate/audit.py 的 chain_record 逐字节一致。 */
static void chain_digest_mac(const tg_state *st, const uint8_t *payload, size_t plen,
                             uint8_t digest[32], uint8_t mac[32]) {
    char prev_hex[TG_HEX_LEN + 1];
    char seqdec[16];
    char hash_hex[TG_HEX_LEN + 1];
    sha256_ctx c;
    bin2hex(st->head, TG_HEAD_LEN, prev_hex);
    snprintf(seqdec, sizeof(seqdec), "%u", st->seq);
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)prev_hex, TG_HEX_LEN);
    sha256_update(&c, (const uint8_t *)"|", 1);
    sha256_update(&c, (const uint8_t *)seqdec, strlen(seqdec));
    sha256_update(&c, (const uint8_t *)"|", 1);
    sha256_update(&c, payload, plen);
    sha256_final(&c, digest);
    bin2hex(digest, 32, hash_hex);
    hmac_sha256(st->key, TG_STATE_KEY_LEN, (const uint8_t *)hash_hex, TG_HEX_LEN, mac);
}
#endif /* SOFT_TA */

#ifdef SOFT_TA

/* ---------------- 软模拟：状态落普通文件（仅供开发/测试！） ---------------- */

static char g_state_path[192];

static int soft_random(uint8_t *out, size_t len) {
#ifdef _WIN32
    /* /dev/urandom 是 Linux 专有，Windows 上不存在。软模拟仅供开发测试、
       不产生任何安全性质（tee/README.md 的诚实边界），退化为
       时间 + PID + 栈地址播种的 LCG 足以让各测试会话密钥互不相同。
       真桥的随机数由 TA 内 TEE_GenerateRandom 提供，不走这条路。 */
    static unsigned seed;
    size_t i;
    seed = (unsigned)time(NULL) ^ (unsigned)(uintptr_t)&seed ^ (unsigned)getpid();
    for (i = 0; i < len; i++) {
        seed = seed * 1103515245u + 12345u;
        out[i] = (uint8_t)(seed >> 16);
    }
    return 0;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    ssize_t r;
    if (fd < 0)
        return -1;
    r = read(fd, out, len);
    close(fd);
    return r == (ssize_t)len ? 0 : -1;
#endif
}

static int state_init(tg_state *st, char *err, size_t errsz) {
    const char *env = getenv("TG_TEE_SOFT_STATE");
    FILE *f;
    char line[1024];
    char key_hex[TG_HEX_LEN + 1];
    char head_hex[TG_HEX_LEN + 1];

    snprintf(g_state_path, sizeof(g_state_path), "%s",
             env ? env : ".trustgate/tee-soft-state.json");

    f = fopen(g_state_path, "r");
    if (!f) {
        /* 首次启动：生成密钥，从创世状态开始。 */
        state_genesis(st);
        if (soft_random(st->key, TG_STATE_KEY_LEN) != 0) {
            snprintf(err, errsz, "无法生成初始密钥");
            return -1;
        }
        return state_save(st, err, errsz);
    }
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        snprintf(err, errsz, "状态文件 %s 为空", g_state_path);
        return -1;
    }
    fclose(f);
    if (json_get_str(line, "key", key_hex, sizeof(key_hex)) != 0 ||
        json_get_str(line, "head", head_hex, sizeof(head_hex)) != 0 ||
        json_get_u32(line, "seq", &st->seq) != 0) {
        snprintf(err, errsz, "状态文件 %s 格式非法", g_state_path);
        return -1;
    }
    if (hex2bin(key_hex, st->key, TG_STATE_KEY_LEN) != 0 ||
        hex2bin(head_hex, st->head, TG_HEAD_LEN) != 0) {
        snprintf(err, errsz, "状态文件 %s 十六进制字段非法", g_state_path);
        return -1;
    }
    return 0;
}

static int state_save(const tg_state *st, char *err, size_t errsz) {
    char tmp[208];
    char key_hex[TG_HEX_LEN + 1];
    char head_hex[TG_HEX_LEN + 1];
    FILE *f;
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_state_path);
    f = fopen(tmp, "w");
    if (!f) {
        snprintf(err, errsz, "无法写入状态文件 %s", tmp);
        return -1;
    }
    bin2hex(st->key, TG_STATE_KEY_LEN, key_hex);
    bin2hex(st->head, TG_HEAD_LEN, head_hex);
    fprintf(f, "{\"key\":\"%s\",\"seq\":%u,\"head\":\"%s\"}\n", key_hex, st->seq, head_hex);
    if (fclose(f) != 0) {
        snprintf(err, errsz, "无法写入状态文件 %s", tmp);
        return -1;
    }
#ifdef _WIN32
    /* MSVCRT 的 rename() 不会替换已存在的目标（与 POSIX 的原子替换不同），
       先删除再改名。这不是原子操作——但软模拟仅供开发测试，无需崩溃一致性
       保证（真桥的状态写在 TA/RPMB 里，根本不经过这条路径）。 */
    remove(g_state_path);
#endif
    if (rename(tmp, g_state_path) != 0) {
        snprintf(err, errsz, "无法替换状态文件 %s", g_state_path);
        return -1;
    }
    return 0;
}

static int state_seal(tg_state *st, const uint8_t *data, size_t dlen, char mac_hex[TG_HEX_LEN + 1]) {
    uint8_t mac[32];
    hmac_sha256(st->key, TG_STATE_KEY_LEN, data, dlen, mac);
    bin2hex(mac, 32, mac_hex);
    return 0;
}

static int state_append(tg_state *st, const uint8_t *payload, size_t plen,
                        uint32_t *seq, char prev_hex[TG_HEX_LEN + 1], char hash_hex[TG_HEX_LEN + 1],
                        char mac_hex[TG_HEX_LEN + 1]) {
    uint8_t digest[32];
    uint8_t mac[32];
    char serr[160];
    bin2hex(st->head, TG_HEAD_LEN, prev_hex);
    chain_digest_mac(st, payload, plen, digest, mac);
    bin2hex(digest, 32, hash_hex);
    bin2hex(mac, 32, mac_hex);
    *seq = st->seq;
    memcpy(st->head, digest, 32);
    st->seq += 1;
    /* 每条立刻落盘（docs/06 决策 D1/D3 对应的软模拟镜像；真形态下由 TA 写 RPMB）。 */
    return state_save(st, serr, sizeof(serr));
}

static int state_checkpoint(tg_state *st, uint32_t *seq, char head_hex[TG_HEX_LEN + 1],
                            char mac_hex[TG_HEX_LEN + 1]) {
    char msg[96];
    uint8_t mac[32];
    bin2hex(st->head, TG_HEAD_LEN, head_hex);
    snprintf(msg, sizeof(msg), "%u|%s", st->seq, head_hex);
    hmac_sha256(st->key, TG_STATE_KEY_LEN, (const uint8_t *)msg, strlen(msg), mac);
    bin2hex(mac, 32, mac_hex);
    *seq = st->seq;
    return 0;
}

#else /* 真桥：TEEC 转发到 TA */

static TEEC_Context g_ctx;
static TEEC_Session g_sess;
static const TEEC_UUID g_uuid = {TG_TA_UUID_0, TG_TA_UUID_1, TG_TA_UUID_2, TG_TA_UUID_3};

enum {
    TG_CMD_SEAL = 1,
    TG_CMD_CHAIN_APPEND = 2,
    TG_CMD_CHECKPOINT = 3,
    TG_CMD_EXPORT_KEY = 4,
};

static int tee_invoke(uint32_t cmd, const void *in, size_t in_len, void *out, size_t out_len,
                      char *err, size_t errsz) {
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t origin = 0;
    memset(&op, 0, sizeof(op));
    if (in) {
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_PARAM_TYPE_MEMREF_INPUT,
                                         TEEC_PARAM_TYPE_MEMREF_OUTPUT, TEEC_PARAM_TYPE_NONE,
                                         TEEC_PARAM_TYPE_NONE);
        op.params[0].tmpref.buffer = (void *)in;
        op.params[0].tmpref.size = in_len;
        op.params[1].tmpref.buffer = out;
        op.params[1].tmpref.size = out_len;
    } else {
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_PARAM_TYPE_MEMREF_OUTPUT, TEEC_PARAM_TYPE_NONE,
                                         TEEC_PARAM_TYPE_NONE, TEEC_PARAM_TYPE_NONE);
        op.params[0].tmpref.buffer = out;
        op.params[0].tmpref.size = out_len;
    }
    res = TEEC_InvokeCommand(&g_sess, cmd, &op, &origin);
    if (res != TEEC_SUCCESS) {
        snprintf(err, errsz, "TEEC_InvokeCommand(0x%x) 失败: res=0x%x origin=0x%x", cmd, res,
                 origin);
        return -1;
    }
    return 0;
}

static int state_init(tg_state *st, char *err, size_t errsz) {
    TEEC_Result res;
    uint32_t origin = 0;
    (void)st;
    res = TEEC_InitializeContext(NULL, &g_ctx);
    if (res != TEEC_SUCCESS) {
        snprintf(err, errsz, "TEEC_InitializeContext 失败: 0x%x（/dev/tee0 不存在？）", res);
        return -1;
    }
    res = TEEC_OpenSession(&g_ctx, &g_sess, &g_uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        snprintf(err, errsz, "TEEC_OpenSession 失败: res=0x%x origin=0x%x（TA 未安装？）", res,
                 origin);
        TEEC_FinalizeContext(&g_ctx);
        return -1;
    }
    /* TA 在 OpenSession 时加载或创建 RPMB 状态，此处无需额外动作。 */
    return 0;
}

static int state_seal(tg_state *st, const uint8_t *data, size_t dlen, char mac_hex[TG_HEX_LEN + 1]) {
    char err[160];
    (void)st;
    if (tee_invoke(TG_CMD_SEAL, data, dlen, mac_hex, TG_HEX_LEN + 1, err, sizeof(err)) != 0)
        return -1;
    return 0;
}

static int state_append(tg_state *st, const uint8_t *payload, size_t plen,
                        uint32_t *seq, char prev_hex[TG_HEX_LEN + 1], char hash_hex[TG_HEX_LEN + 1],
                        char mac_hex[TG_HEX_LEN + 1]) {
    /* TA 输出布局（与 trustgate_ta.c 一致）：u32 seq | prev[64] | hash[64] | mac[64] */
    uint8_t buf[4 + 64 * 3];
    char err[160];
    (void)st;
    if (tee_invoke(TG_CMD_CHAIN_APPEND, payload, plen, buf, sizeof(buf), err, sizeof(err)) != 0)
        return -1;
    memcpy(seq, buf, 4);
    memcpy(prev_hex, buf + 4, 64);
    prev_hex[64] = 0;
    memcpy(hash_hex, buf + 68, 64);
    hash_hex[64] = 0;
    memcpy(mac_hex, buf + 132, 64);
    mac_hex[64] = 0;
    return 0;
}

static int state_checkpoint(tg_state *st, uint32_t *seq, char head_hex[TG_HEX_LEN + 1],
                            char mac_hex[TG_HEX_LEN + 1]) {
    uint8_t buf[4 + 64 * 2];
    char err[160];
    (void)st;
    if (tee_invoke(TG_CMD_CHECKPOINT, NULL, 0, buf, sizeof(buf), err, sizeof(err)) != 0)
        return -1;
    memcpy(seq, buf, 4);
    memcpy(head_hex, buf + 4, 64);
    head_hex[64] = 0;
    memcpy(mac_hex, buf + 68, 64);
    mac_hex[64] = 0;
    return 0;
}

static int state_save(const tg_state *st, char *err, size_t errsz) {
    (void)st;
    (void)err;
    (void)errsz;
    return 0; /* 真形态下持久化完全由 TA 负责 */
}

#endif /* SOFT_TA */

/* ---------------- JSONL 主循环 ---------------- */

#define LINE_MAX (1 << 20)
#define FIELD_MAX (512 * 1024)

static char g_line[LINE_MAX];
static char g_field[FIELD_MAX];
static uint8_t g_bin[FIELD_MAX];

int main(void) {
    tg_state st;
    char err[256] = {0};

    if (state_init(&st, err, sizeof(err)) != 0) {
        fprintf(stderr, "tg_bridge: init 失败: %s\n", err[0] ? err : "(未知)");
        return 1;
    }

    while (fgets(g_line, sizeof(g_line), stdin)) {
        char op[32];
        char resp[1024];
        int bad = 0;

        if (!strchr(g_line, '\n') && !feof(stdin)) {
            /* 行超出缓冲：丢弃余下内容，报错（正常请求的 payload 远小于 1MB）。 */
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;
            printf("{\"error\":\"请求行过长\"}\n");
            fflush(stdout);
            continue;
        }
        /* Windows 文本管道送 \r\n，剥掉行尾 \r 再解析。 */
        g_line[strcspn(g_line, "\r\n")] = 0;
        if (!g_line[0])
            continue;

        if (json_get_str(g_line, "op", op, sizeof(op)) != 0) {
            printf("{\"error\":\"缺少 op 字段\"}\n");
            fflush(stdout);
            continue;
        }

        if (strcmp(op, "init") == 0) {
            printf("{\"result\":{\"ok\":true}}\n");
        } else if (strcmp(op, "seal") == 0) {
            size_t dlen = 0;
            char mac_hex[TG_HEX_LEN + 1];
            if (json_get_str(g_line, "data_b64", g_field, sizeof(g_field)) != 0 ||
                b64_decode(g_field, g_bin, sizeof(g_bin), &dlen) != 0) {
                bad = 1;
            } else if (state_seal(&st, g_bin, dlen, mac_hex) != 0) {
                bad = 1;
            } else {
                snprintf(resp, sizeof(resp), "{\"result\":{\"mac\":\"%s\"}}", mac_hex);
                printf("%s\n", resp);
            }
        } else if (strcmp(op, "chain_append") == 0) {
            size_t plen = 0;
            uint32_t seq;
            char prev_hex[TG_HEX_LEN + 1], hash_hex[TG_HEX_LEN + 1], mac_hex[TG_HEX_LEN + 1];
            if (json_get_str(g_line, "payload_b64", g_field, sizeof(g_field)) != 0 ||
                b64_decode(g_field, g_bin, sizeof(g_bin), &plen) != 0) {
                bad = 1;
            } else if (state_append(&st, g_bin, plen, &seq, prev_hex, hash_hex, mac_hex) != 0) {
                bad = 1;
            } else {
                snprintf(resp, sizeof(resp),
                         "{\"result\":{\"seq\":%u,\"prev_hash\":\"%s\",\"hash\":\"%s\","
                         "\"mac\":\"%s\"}}",
                         seq, prev_hex, hash_hex, mac_hex);
                printf("%s\n", resp);
            }
        } else if (strcmp(op, "checkpoint") == 0) {
            uint32_t seq;
            char head_hex[TG_HEX_LEN + 1], mac_hex[TG_HEX_LEN + 1];
            if (state_checkpoint(&st, &seq, head_hex, mac_hex) != 0) {
                bad = 1;
            } else {
                snprintf(resp, sizeof(resp),
                         "{\"result\":{\"seq\":%u,\"head\":\"%s\",\"mac\":\"%s\"}}", seq, head_hex,
                         mac_hex);
                printf("%s\n", resp);
            }
        } else if (strcmp(op, "export_key") == 0) {
#ifdef SOFT_TA
            char key_hex[TG_HEX_LEN + 1];
            bin2hex(st.key, TG_STATE_KEY_LEN, key_hex);
            snprintf(resp, sizeof(resp), "{\"result\":{\"key\":\"%s\"}}", key_hex);
            printf("%s\n", resp);
#else
            uint8_t key[TG_STATE_KEY_LEN];
            char err2[160];
            if (tee_invoke(TG_CMD_EXPORT_KEY, NULL, 0, key, sizeof(key), err2, sizeof(err2)) != 0) {
                bad = 1;
            } else {
                char key_hex[TG_HEX_LEN + 1];
                bin2hex(key, TG_STATE_KEY_LEN, key_hex);
                snprintf(resp, sizeof(resp), "{\"result\":{\"key\":\"%s\"}}", key_hex);
                printf("%s\n", resp);
            }
#endif
        } else {
            printf("{\"error\":\"未知 op %s\"}\n", op);
            fflush(stdout);
            continue;
        }

        if (bad)
            printf("{\"error\":\"%s 执行失败\"}\n", op);
        fflush(stdout);
    }

#ifndef SOFT_TA
    TEEC_CloseSession(&g_sess);
    TEEC_FinalizeContext(&g_ctx);
#endif
    return 0;
}
