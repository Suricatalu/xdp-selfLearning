# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := af_xdp_kern
USER_TARGETS := af_xdp_user af_xdp_lib_sample
LDLIBS += -lpthread
LIB_OBJS     := af_xdp_lib.o
COMMON_DIR := ../common

include $(COMMON_DIR)/common.mk
$(USER_TARGETS): $(LIB_OBJS)
COMMON_OBJS := $(COMMON_DIR)/common_params.o
COMMON_OBJS += $(COMMON_DIR)/common_user_bpf_xdp.o