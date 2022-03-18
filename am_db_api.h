// SPDX-License-Identifier: GPL-2.0
/*
 * am_db_api.h: definitions of database related function of PP AM
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

#ifndef __AM_DB_API_H__
#define __AM_DB_API_H__

#include "acceleration_module.h"

#define PP_AM_DB_MAX_SESSION (35 * 1024)

struct pp_am_pp_session_stats {
	u64 bytes;
	u64 packets;
};

struct pp_am_db_session_entry {
	u32 pp_session_handle;
	struct pp_am_stats stats;
	struct pp_am_pp_session_stats last_pp_stats;
	bool is_proactive;
	// Id of prev flow associated with same PP session
	u32 prev;
	// Id of next flow associated with same PP session
	u32 next;
};

struct pp_am_db_pp_entry {
	u32 pp_session;
	// Contains id of last flow in chain (if any) due to algorithm of associating flows
	u32 am_id;
};

struct update_stats_data {
	u32 pp_session;
	struct pp_am_stats stats;
	bool update_last_used;
	bool updated_out;
};

pp_am_status_ret pp_am_db_init(void);

pp_am_status_ret pp_am_db_flow_add(struct pp_am_db_session_entry *flow,
				   u32 *am_id);
pp_am_status_ret pp_am_db_flow_rm(struct pp_am_db_session_entry *flow,
				  u32 am_id);
pp_am_status_ret pp_am_db_flow_set(struct pp_am_db_session_entry *flow,
				   u32 am_id);
pp_am_status_ret pp_am_db_flow_get(struct pp_am_db_session_entry *flow,
				   u32 am_id);

pp_am_status_ret pp_am_db_pp_session_add(struct pp_am_db_pp_entry *pp_entry);
pp_am_status_ret pp_am_db_pp_session_rm(struct pp_am_db_pp_entry *pp_entry);
pp_am_status_ret pp_am_db_pp_session_set(struct pp_am_db_pp_entry *pp_entry);
pp_am_status_ret pp_am_db_pp_session_get(struct pp_am_db_pp_entry *pp_entry);

// Removes relations between previously associated flows
pp_am_status_ret pp_am_db_flow_chain_cleanup(u32 am_id, pp_am_flow_chain_traverse_order order);

// find all flows assosiated with given PP session and update stats in them
pp_am_status_ret pp_am_db_update_stats(u32 pp_session,
				       struct pp_am_stats stats,
				       bool update_last_used);

// NOTE: does NOT aquire lock!
// Make sure to aquire lock on DB before calling it!
int update_stats_unsafe(void *data);

size_t for_each_pp_entry_that_needs_update(
	void (*func)(struct pp_am_db_pp_entry *entry), size_t requested_amount,
	u32 *last_handle);

// call given function while holding locks on both flows and PP sessions
int with_db_locked(int (*func)(void *data), void *data);

#endif
