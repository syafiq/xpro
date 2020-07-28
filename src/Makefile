# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := xdp_prog_kern
USER_TARGETS := xdp_stats xdp_loader trace_read

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

# Extend with another COMMON_OBJS
COMMON_OBJS += $(COMMON_DIR)/common_libbpf.o

include $(COMMON_DIR)/common.mk
