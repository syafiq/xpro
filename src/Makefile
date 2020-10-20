# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := xpro_kern
USER_TARGETS := statread xdp_loader trace_read syncdb xdp_uspace sync usp_tmp

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

# Extend with another COMMON_OBJS
COMMON_OBJS += $(COMMON_DIR)/common_libbpf.o

include $(COMMON_DIR)/common.mk
