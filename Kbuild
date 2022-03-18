# SPDX-License-Identifier: GPL-2.0
################################################################################
#
#  Kbuild: Linux kernel Makefile for inangoplug-pp-acceleration-module
#  Copyright (C) 2021,2022 Inango Systems Ltd.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of version 2 of the GNU General Public
#  License as published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
################################################################################

TARGET_ACCELERATION_MODULE := ovs_hw_acceleration
obj-m := $(TARGET_ACCELERATION_MODULE).o

ccflags-y += -Wno-unused -I$(KERNEL_SRC)/net/openvswitch

$(TARGET_ACCELERATION_MODULE)-y := acceleration_module.o am_db_api.o ovs_dp_to_am.o
