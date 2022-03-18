/* SPDX-License-Identifier: GPL-2.0 */
/*
 * am_private.h: Header with private functions and definitions of AM
 * Copyright (C) 2021, 2022 Inango Systems Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef __AM_PRIVATE_H__
#define __AM_PRIVATE_H__

#define MAX_SESSIONS_PER_STATISTIC_REQUEST 50
#define STATS_THREAD_SLEEP_PERIOD_MSEC (5 * 1000) // 5 seconds
#define OUTDATED_STATS_THRESHOLD_JIFFIES (msecs_to_jiffies(3*1000)) // 3 seconds

#ifdef AM_DEBUG_LOG_ENABLE
 #define AM_LOG_DBG(format, ...) printk(KERN_INFO "AM:%s:%d " format, __func__, __LINE__,##__VA_ARGS__ )
#else
 #define AM_LOG_DBG(format, ...)
#endif

#ifdef AM_LOG_ENABLE
 #define AM_LOG(format, ...) printk(KERN_DEFAULT "AM: " format, ##__VA_ARGS__ )
 #define AM_LOG_ERR(format, ...) printk(KERN_ERR "AM: " format, ##__VA_ARGS__ )
#else
 #define AM_LOG(format, ...)
 #define AM_LOG_ERR(format, ...)
#endif

#define STATS_ADD(sum, lhs, rhs)                                               \
	do {                                                                   \
		(sum).packets = (lhs).packets + (rhs).packets;                 \
		(sum).bytes = (lhs).bytes + (rhs).bytes;                       \
	} while (0)

#define STATS_SUB(diff, lhs, rhs)                                              \
	do {                                                                   \
		(diff).packets = (lhs).packets - (rhs).packets;                \
		(diff).bytes = (lhs).bytes - (rhs).bytes;                      \
	} while (0)

#endif
