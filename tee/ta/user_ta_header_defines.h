/*
 * TrustGate 可信锚 TA 的二进制属性定义。
 * UUID 必须与 tee/bridge/tg_bridge.c 的 TG_TA_UUID_* 完全一致。
 */
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#define TA_UUID                                                                \
    {                                                                          \
        0x7c1c3f20, 0x5a6b, 0x4c7d, {                                          \
            0x8e, 0x9f, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f                   \
        }                                                                      \
    }

#define TA_FLAGS TA_FLAG_EXEC_DDR
#define TA_STACK_SIZE (4 * 1024)
#define TA_DATA_SIZE (64 * 1024)

/*
 * 存储后端的 RPMB 选择不在此硬编码：代码用 TEE_STORAGE_PRIVATE，
 * 由构建侧决定后端（OP-TEE ≥3.13 可给本 TA 设 gpd.ta.storageID=RPMB 属性；
 * 旧版本直接以 CFG_RPMB_FS=y 构建 optee_os）。见 tee/README.md「RPMB 配置」。
 * 无论哪条路径，不落在 RPMB 上的构建**不得**用于论文实验。
 */

#endif /* USER_TA_HEADER_DEFINES_H */
