# TrustGate TEE 组件构建（docs/06-T2可信锚实现方案.md §3）
#
# 产物                    形态            用途
# bridge/tg_bridge_soft   host gcc        软模拟桥：不链 libteec，状态落普通文件，
#                                         **仅供开发与单元测试**，不得进实验数据
# bridge/tg_bridge        aarch64 + TEEC  真桥：跑在 QEMU guest（或真机）内
# ta/<uuid>.ta            aarch64 TA 开发包 真 TA：装进 guest 的 /lib/optee_armtz/
#
# 真桥与真 TA 必须在目标机（QEMU guest 的 aarch64 Linux，或开发板）上构建，
# 典型用法见 tee/README.md。

SOFT_BIN := bridge/tg_bridge_soft
REAL_BIN := bridge/tg_bridge

CROSS_COMPILE ?= aarch64-linux-gnu-

.PHONY: all soft bridge ta clean

all: soft

soft: $(SOFT_BIN)

$(SOFT_BIN): bridge/tg_bridge.c
	@mkdir -p bridge
	gcc -O2 -Wall -Wextra -DSOFT_TA -o $@ $<

bridge: $(REAL_BIN)

$(REAL_BIN): bridge/tg_bridge.c
	@test -n "$(TEEC_DIR)" || { \
		echo "需要 TEEC_DIR（optee_client 安装前缀，含 include/ 与 lib/）"; exit 1; }
	@mkdir -p bridge
	$(CROSS_COMPILE)gcc -O2 -Wall -Wextra -I$(TEEC_DIR)/include \
		-o $@ $< -L$(TEEC_DIR)/lib -lteec

ta:
	@test -n "$(TA_DEV_KIT_DIR)" || { \
		echo "需要 TA_DEV_KIT_DIR（OP-TEE TA 开发包，如 optee_os/out/arm/export-ta_arm64）"; \
		exit 1; }
	$(MAKE) -C ta TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

clean:
	rm -f $(SOFT_BIN) $(REAL_BIN)
	rm -f ta/*.o ta/*.d ta/*.ta ta/*.elf
