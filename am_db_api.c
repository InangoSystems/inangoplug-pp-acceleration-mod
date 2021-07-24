/* SPDX-License-Identifier: GPL-2.0 */
/*
 * am_db_api.c: AM internal DB API implementation
 * Copyright (C) 2021 Inango Systems Ltd.
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

#include "am_db_api.h"
#include "am_private.h"

#include <linux/jiffies.h>

struct flow_entry {
	struct pp_am_db_session_entry data;
	bool busy;
	u32 next_free;
};

static struct flow_entry *flows;
static u32 flows_size;
static u32 flows_capacity;
static u32 next_free_flow_position;
static struct spinlock flows_lock;

static struct pp_am_db_pp_entry *pp_entries;
static u32 pp_size;
static u32 pp_capacity;
static struct spinlock pp_sessions_lock;

// NOTE: use these function when you need to lock both spinlocks
// DO NOT lock both spinlocks in one function manually
static void lock_flows_and_pp_sessions(void);
static void unlock_flows_and_pp_sessions(void);

static bool is_eligible_for_update(u32 pp_session, u64 current_time,
				   u64 threshold);
static pp_am_status_ret
update_stats_single_flow_unsafe(struct pp_am_db_session_entry *flow,
				struct pp_am_stats new_pp_stats,
				bool update_last_used);

pp_am_status_ret pp_am_db_init()
{
	int i;

	flows = NULL;
	flows = (struct flow_entry *)kzalloc(
		sizeof(struct flow_entry) * PP_AM_DB_MAX_SESSION,
		GFP_KERNEL);
	if (flows == NULL)
		return PP_AM_GENERIC_FAIL;

	flows_size = 0;
	next_free_flow_position = 1;
	flows_capacity = PP_AM_DB_MAX_SESSION - 1;
	for (i = 1; i < PP_AM_DB_MAX_SESSION - 1; i++) {
		flows[i].next_free = i + 1;
	}
	flows[PP_AM_DB_MAX_SESSION - 1].next_free = 1;

	spin_lock_init(&flows_lock);

	pp_entries = NULL;
	pp_entries = (struct pp_am_db_pp_entry *)kzalloc(
		sizeof(struct pp_am_db_pp_entry) * PP_AM_DB_MAX_SESSION,
		GFP_KERNEL);
	if (pp_entries == NULL)
		return PP_AM_GENERIC_FAIL;
	for (i = 0; i < PP_AM_DB_MAX_SESSION; i++) {
		pp_entries[i].pp_session = PP_AM_DB_MAX_SESSION;
		pp_entries[i].am_id = PP_AM_DB_MAX_SESSION;
	}

	pp_size = 0;
	pp_capacity = PP_AM_DB_MAX_SESSION;

	spin_lock_init(&pp_sessions_lock);

	return PP_AM_OK;
}

pp_am_status_ret pp_am_db_flow_add(struct pp_am_db_session_entry *flow,
				   u32 *am_id)
{
	pp_am_status_ret rc = PP_AM_OK;

	AM_LOG_DBG("add flow, pp_session_handle = %u; flows_size: %u\n",
		   flow->pp_session_handle, flows_size);

	spin_lock(&flows_lock);

	if (flows_size == flows_capacity) {
		AM_LOG_ERR(
			"flows_size == flows_capacity. Unable add flow. No sessions left\n");
		rc = PP_AM_NO_SESSIONS_LEFT;
		goto func_exit;
	}

	if (flows[next_free_flow_position].busy) {
		*am_id = PP_AM_DB_MAX_SESSION;
		AM_LOG_ERR(
			"No free elements. Unable add flow. No sessions left\n");
		rc = PP_AM_NO_SESSIONS_LEFT;
		goto func_exit;
	}

	*am_id = next_free_flow_position;
	flows[next_free_flow_position].data = *flow;
	flows[next_free_flow_position].busy = true;
	next_free_flow_position = flows[next_free_flow_position].next_free;
	flows_size++;

	AM_LOG_DBG(
		"add flow, am_id = %u, pp_session_handle = %u, next_free_flow_position: %u \n",
		*am_id, flow->pp_session_handle, next_free_flow_position);
	rc = PP_AM_OK;

func_exit:
	spin_unlock(&flows_lock);
	return rc;
}
EXPORT_SYMBOL(pp_am_db_flow_add);

pp_am_status_ret pp_am_db_flow_rm(struct pp_am_db_session_entry *flow,
				  u32 am_id)
{
	pp_am_status_ret rc = PP_AM_OK;

	if (am_id <= 0 || am_id >= PP_AM_DB_MAX_SESSION || flows_size <= 0)
		return PP_AM_GENERIC_FAIL;

	spin_lock(&flows_lock);

	// Nothing to remove, it was requested to remove already removed element
	if (!flows[am_id].busy) {
		AM_LOG_DBG(
			"we were asked to remove flow that doesn't exist; am_id = %u, flows_size: %u\n",
			am_id, flows_size);
		rc = PP_AM_OK;
		goto func_exit;
	}

	flows[am_id].next_free = next_free_flow_position;
	next_free_flow_position = am_id;

	// reset to default values
	flows[am_id].busy = false;
	flows[am_id].data.pp_session_handle = PP_AM_DB_MAX_SESSION;
	flows[am_id].data.stats.bytes = 0;
	flows[am_id].data.stats.packets = 0;

	flows_size--;

	AM_LOG_DBG(
		"delete flow, am_id = %u, pp_session_handle = %u, flows_size: %u\n",
		am_id, flow->pp_session_handle, flows_size);

	rc = PP_AM_OK;

func_exit:
	spin_unlock(&flows_lock);
	return rc;
}
EXPORT_SYMBOL(pp_am_db_flow_rm);

pp_am_status_ret pp_am_db_flow_set(struct pp_am_db_session_entry *flow,
				   u32 am_id)
{
	pp_am_status_ret rc = PP_AM_OK;

	AM_LOG_DBG(
		"set flow, am_id = %u, pp_session_handle = %u ; stats={bytes: %llu, packets: %llu, last_used: %llu}\n",
		am_id, flow->pp_session_handle, flow->stats.bytes,
		flow->stats.packets, flow->stats.last_used);

	if (am_id <= 0 || am_id >= PP_AM_DB_MAX_SESSION)
		return PP_AM_GENERIC_FAIL;

	spin_lock(&flows_lock);

	if (!flows[am_id].busy) {
		AM_LOG_ERR("unable to reset element that wasn't set: %u\n",
			   am_id);
		rc = PP_AM_GENERIC_FAIL;
		goto func_exit;
	}

	memcpy(&flows[am_id].data, flow, sizeof(struct pp_am_db_session_entry));

	rc = PP_AM_OK;

func_exit:
	spin_unlock(&flows_lock);
	return rc;
}
EXPORT_SYMBOL(pp_am_db_flow_set);

pp_am_status_ret pp_am_db_flow_get(struct pp_am_db_session_entry *flow,
				   u32 am_id)
{
	pp_am_status_ret rc = PP_AM_OK;

	if (am_id <= 0 || am_id >= PP_AM_DB_MAX_SESSION)
		return PP_AM_GENERIC_FAIL;

	spin_lock(&flows_lock);

	if (!flows[am_id].busy) {
		AM_LOG_ERR("unable to get element that wasn't set: %u\n",
			   am_id);
		rc = PP_AM_GENERIC_FAIL;
		goto func_exit;
	}

	memcpy(flow, &flows[am_id].data, sizeof(struct pp_am_db_session_entry));

	rc = PP_AM_OK;

func_exit:
	spin_unlock(&flows_lock);
	return rc;
}
EXPORT_SYMBOL(pp_am_db_flow_get);

pp_am_status_ret pp_am_db_flow_chain_cleanup(u32 am_id, pp_am_flow_chain_traverse_order order)
{
	pp_am_status_ret rc = PP_AM_OK;
	struct flow_entry *flow;
	u32 next_am_id;
	AM_LOG_DBG("%s: Cleanup chain for am_id=%u", __func__, am_id);

	spin_lock(&flows_lock);
	while (am_id) {
		if (am_id <= 0 || am_id >= PP_AM_DB_MAX_SESSION || !flows[am_id].busy) {
			AM_LOG_ERR("%s: Failed to get flow: am_id=%u", __func__, am_id);
			rc = PP_AM_GENERIC_FAIL;
			goto func_exit;
		}
		flow = &flows[am_id];
		AM_LOG_DBG("%s: Cleanup flow: am_id=%u, next=%u, prev=%u", __func__, am_id, flow->data.next, flow->data.prev);
		if (order == TRAVERSE_BACKWARD) {
			next_am_id = flow->data.prev;
		} else {
			next_am_id = flow->data.next;
		}
		flow->data.pp_session_handle = PP_AM_DB_MAX_SESSION;
		flow->data.last_pp_stats.bytes = 0;
		flow->data.last_pp_stats.packets = 0;
		flow->data.prev = 0;
		flow->data.next = 0;
		am_id = next_am_id;
	}

func_exit:
	spin_unlock(&flows_lock);
	return rc;
}
EXPORT_SYMBOL(pp_am_db_flow_chain_cleanup);

pp_am_status_ret pp_am_db_pp_session_add(struct pp_am_db_pp_entry *pp_entry)
{
	struct pp_am_db_pp_entry *tmp;

	AM_LOG_DBG("add pp session, am_id = %u, pp_session = %u \n",
		   pp_entry->am_id, pp_entry->pp_session);

	if (pp_entry->pp_session <= 0 ||
	    pp_entry->pp_session >= PP_AM_DB_MAX_SESSION)
		return PP_AM_GENERIC_FAIL;

	spin_lock(&pp_sessions_lock);

	tmp = &pp_entries[pp_entry->pp_session];
	memcpy(tmp, pp_entry, sizeof(struct pp_am_db_pp_entry));
	pp_size++;

	spin_unlock(&pp_sessions_lock);

	return PP_AM_OK;
}
EXPORT_SYMBOL(pp_am_db_pp_session_add);

pp_am_status_ret pp_am_db_pp_session_rm(struct pp_am_db_pp_entry *pp_entry)
{
	struct pp_am_db_pp_entry *db_entry;
	AM_LOG_DBG("delete pp session, am_id = %u, pp_session = %u \n",
		   pp_entry->am_id, pp_entry->pp_session);

	if (pp_entry->pp_session <= 0 ||
	    pp_entry->pp_session >= PP_AM_DB_MAX_SESSION)
		return PP_AM_GENERIC_FAIL;

	spin_lock(&pp_sessions_lock);

	db_entry = &pp_entries[pp_entry->pp_session];
	db_entry->am_id = PP_AM_DB_MAX_SESSION;

	pp_size--;

	spin_unlock(&pp_sessions_lock);

	return PP_AM_OK;
}
EXPORT_SYMBOL(pp_am_db_pp_session_rm);

pp_am_status_ret pp_am_db_pp_session_set(struct pp_am_db_pp_entry *pp_entry)
{
	struct pp_am_db_pp_entry *db_entry;

	AM_LOG_DBG("set pp session, am_id = %u, pp_session = %u \n",
		   pp_entry->am_id, pp_entry->pp_session);

	if (pp_entry->pp_session <= 0 ||
	    pp_entry->pp_session >= PP_AM_DB_MAX_SESSION)
		return PP_AM_GENERIC_FAIL;

	spin_lock(&pp_sessions_lock);

	db_entry = &pp_entries[pp_entry->pp_session];
	memcpy(db_entry, pp_entry, sizeof(struct pp_am_db_pp_entry));

	spin_unlock(&pp_sessions_lock);

	return PP_AM_OK;
}
EXPORT_SYMBOL(pp_am_db_pp_session_set);

pp_am_status_ret pp_am_db_pp_session_get(struct pp_am_db_pp_entry *pp_entry)
{
	if (pp_entry->pp_session <= 0 ||
	    pp_entry->pp_session >= PP_AM_DB_MAX_SESSION)
		return PP_AM_GENERIC_FAIL;

	spin_lock(&pp_sessions_lock);

	memcpy(pp_entry, &pp_entries[pp_entry->pp_session],
	       sizeof(struct pp_am_db_pp_entry));

	spin_unlock(&pp_sessions_lock);

	return PP_AM_OK;
}
EXPORT_SYMBOL(pp_am_db_pp_session_get);

pp_am_status_ret pp_am_db_update_stats(u32 pp_session, struct pp_am_stats stats,
				       bool update_last_used)
{
	struct update_stats_data data = {
		.pp_session = pp_session,
		.stats = stats,
		.update_last_used = update_last_used,
	};
	return with_db_locked(update_stats_unsafe, &data);
}
EXPORT_SYMBOL(pp_am_db_update_stats);

// NOTE: does NOT aquire lock!
// Make sure to aquire lock on DB before calling it!
int update_stats_unsafe(void *data)
{
	u32 am_id = 0;
	struct pp_am_db_session_entry flow = { 0 };
	u32 pp_session = ((struct update_stats_data*)data)->pp_session;
	struct pp_am_stats stats = ((struct update_stats_data*)data)->stats;
	const bool update_last_used = ((struct update_stats_data*)data)->update_last_used;

	if (pp_session <= 0 || pp_session >= PP_AM_DB_MAX_SESSION)
		return PP_AM_GENERIC_FAIL;

	// Flows are updated backwards (using prev field) because PP session stores handle to the last flow in chain.
	// It is enforced by algorithm of associating flows in chain.
	for (am_id = pp_entries[pp_session].am_id; am_id;
	     am_id = flows[am_id].data.prev) {
		if (!flows[am_id].busy) {
			AM_LOG_ERR("%s: am_id=%u, busy=%d\n", __func__, am_id,
				   flows[am_id].busy);
			continue;
		}
		update_stats_single_flow_unsafe(&flows[am_id].data, stats, update_last_used);
	}

	return PP_AM_OK;
}
EXPORT_SYMBOL(update_stats_unsafe);

size_t for_each_pp_entry_that_needs_update(
	void (*func)(struct pp_am_db_pp_entry *entry), size_t requested_amount,
	u32 *last_handle)
{
	size_t eligible_session_amount = 0;
	u32 current_session = *last_handle;
	u64 current_time = get_jiffies_64();

	lock_flows_and_pp_sessions();
	if (pp_size < requested_amount)
		requested_amount = pp_size;
	AM_LOG_DBG("%s: requested size=%u\n", __func__, requested_amount);
	while (eligible_session_amount < requested_amount) {
		if ((pp_entries[current_session].am_id !=
		     PP_AM_DB_MAX_SESSION) &&
		    (pp_entries[current_session].am_id != 0)) {
			AM_LOG_DBG("%s: testing current_session %u / flow %u\n",
				   __func__, current_session,
				   pp_entries[current_session].am_id);
			if (is_eligible_for_update(current_session,
						   current_time,
						   OUTDATED_STATS_THRESHOLD_JIFFIES)) {
				AM_LOG_DBG(
					"%s: current_session %u / flow %u is eligible\n",
					__func__, current_session,
					pp_entries[current_session].am_id);
				func(&pp_entries[current_session]);
				eligible_session_amount++;
			}
		}
		current_session++;
		if (current_session == PP_AM_DB_MAX_SESSION)
			current_session = 0;
		if (current_session == *last_handle)
			break;
	}
	unlock_flows_and_pp_sessions();

	*last_handle = current_session;
	return eligible_session_amount;
}
EXPORT_SYMBOL(for_each_pp_entry_that_needs_update);

int with_db_locked(int (*func)(void *data), void *data)
{
	int rc = 0;
	lock_flows_and_pp_sessions();
	rc = func(data);
	unlock_flows_and_pp_sessions();
	return rc;
}
EXPORT_SYMBOL(with_db_locked);

static pp_am_status_ret
update_stats_single_flow_unsafe(struct pp_am_db_session_entry *flow,
				struct pp_am_stats new_pp_stats,
				bool update_last_used)
{
	struct pp_am_pp_session_stats pp_stats_diff;

	if (PP_AM_DB_MAX_SESSION != flow->pp_session_handle) {
		STATS_SUB(pp_stats_diff, new_pp_stats, flow->last_pp_stats);

		if ((pp_stats_diff.bytes != 0) ||
		    (pp_stats_diff.packets != 0)) {
			STATS_ADD(flow->stats, flow->stats, pp_stats_diff);
			flow->last_pp_stats.packets = new_pp_stats.packets;
			flow->last_pp_stats.bytes = new_pp_stats.bytes;
			if (update_last_used)
				flow->stats.last_used = new_pp_stats.last_used;

			AM_LOG_DBG(
				"%s: Updated flow stats: pp_session_handle=%u, new_stats={bytes: %llu, packets: %llu} ; diff={bytes: %llu, packets: %llu} ; current_stats={bytes: %llu, packets: %llu}",
				__func__, flow->pp_session_handle,
				new_pp_stats.bytes, new_pp_stats.packets,
				pp_stats_diff.bytes, pp_stats_diff.packets,
				flow->stats.bytes, flow->stats.packets);
		} else {
			AM_LOG_DBG(
				"%s: Flow stats not changed: pp_session_handle=%u, new_stats={bytes: %llu, packets: %llu}",
				__func__, flow->pp_session_handle,
				new_pp_stats.bytes, new_pp_stats.packets);
		}
	} else {
		AM_LOG_DBG("%s: Session not found: pp_session_handle=%u",
			   __func__, flow->pp_session_handle);
	}

	return PP_AM_OK;
}

static bool is_eligible_for_update(u32 pp_session, u64 current_time,
				   u64 threshold)
{
	u32 am_id = 0;
	struct flow_entry *flow;

	if (pp_session <= 0 || pp_session >= PP_AM_DB_MAX_SESSION)
		return false;

	am_id = pp_entries[pp_session].am_id;

	flow = &flows[am_id];
	if (!flow->busy)
		return false;
	AM_LOG_DBG("%s: current_time=%llu previous=%llu threshold=%lu\n",
		   __func__, current_time, flow->data.stats.last_used,
		   OUTDATED_STATS_THRESHOLD_JIFFIES);
	if ((current_time - flow->data.stats.last_used) > threshold)
		return true;

	return false;
}

static void lock_flows_and_pp_sessions()
{
	spin_lock(&flows_lock);
	spin_lock(&pp_sessions_lock);
}

static void unlock_flows_and_pp_sessions()
{
	spin_unlock(&pp_sessions_lock);
	spin_unlock(&flows_lock);
}
