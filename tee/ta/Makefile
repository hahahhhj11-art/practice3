# TrustGate TA 的构建入口。由 ../Makefile 递归调用，也可直接：
#   make -C tee/ta TA_DEV_KIT_DIR=$OPTEE_DIR/optee_os/out/arm/export-ta_arm64
CFG_TEE_TA_LOG_LEVEL ?= 2
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

BINARY := 7c1c3f20-5a6b-4c7d-8e9f-0a1b2c3d4e5f

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
