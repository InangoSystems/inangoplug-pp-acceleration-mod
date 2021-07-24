# SPDX-License-Identifier: GPL-2.0
################################################################################
#  
#  Makefile: contains inangoplug-pp-acceleration-module build rules
#  Copyright (C) 2021 Inango Systems Ltd. 
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

TARGET_ACCEL_MODULE := ovs_hw_acceleration

KERNEL_SRC ?= $(KERNEL_DIR)

# Target objects
$(TARGET_ACCEL_MODULE)-y += $(TARGET_ACCEL_MODULE).o

prefix ?= /usr
includedir ?= $(prefix)/include

compile:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD)

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules_install
	install -d $(DESTDIR)$(includedir)
	install -m 644 acceleration_module.h $(DESTDIR)$(includedir)
	install -m 644 acceleration_module_proto.h $(DESTDIR)$(includedir)
	install -m 644 ppcu_api.h $(DESTDIR)$(includedir)
	install -m 644 am_db_api.h $(DESTDIR)$(includedir)

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c

