// SPDX-License-Identifier: GPL-2.0
/*
 * acceleration_module.c: extension of PP API
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <net/genetlink.h>

#include "acceleration_module.h"
#include "am_db_api.h"
#include "ppcu_api.h"
#include "am_private.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Inango Systems Ltd.");
MODULE_DESCRIPTION("Extension to PP API");
MODULE_VERSION("0.1");

pp_am_set_am_id_by_ufid_t pp_am_set_am_id_by_ufid;
EXPORT_SYMBOL(pp_am_set_am_id_by_ufid);

void pp_am_set_am_id_by_ufid_callback(pp_am_set_am_id_by_ufid_t callback)
{
	pp_am_set_am_id_by_ufid = callback;
}
EXPORT_SYMBOL(pp_am_set_am_id_by_ufid_callback);

enum PP_AM_NETLINK_ATTRIBUTE {
	PP_AM_ATTR_UNSPEC,
	PP_AM_ATTR_MSG,
	PP_AM_ATTR_MAX,
};

static struct nla_policy pp_am_genl_policy[PP_AM_ATTR_MAX] = {
	[PP_AM_ATTR_MSG] = { .type = NLA_NUL_STRING },
};

static struct genl_family pp_am_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "PP_Accel_Mod",
	.version = 1,
	.maxattr = PP_AM_ATTR_MAX - 1,
};

enum PP_AM_NETLINK_CMD {
	PP_AM_CMD_UNSPEC,
	PP_AM_CMD_TEST,
	PP_AM_CMD_MAX,
};

static int pp_am_test(struct sk_buff *skb, struct genl_info *info);

static struct genl_ops pp_am_ops[] = { {
	.cmd = PP_AM_CMD_TEST,
	.flags = 0,
	.policy = pp_am_genl_policy,
	.doit = pp_am_test,
	.dumpit = NULL,
} };

static pp_am_status_ret dummy_session_create (struct pm_am_session *request);
static pp_am_status_ret dummy_session_delete(Uint32 session_handle,
        struct pp_am_pp_session_stats *session_stats);
static pp_am_status_ret dummy_get_session_info(Uint32 session_handle,
        struct pp_am_pp_session_stats *session_stats);
static pp_am_status_ret dummy_skb_preprocess(pp_am_skb_process_action action,
        u32 ufid[4], u32 pp_am_id, struct sk_buff *skb);
static pp_am_status_ret dummy_skb_postprocess(pp_am_skb_process_action action, u8 local,
        u32 ufid[4], u32 pp_am_id, struct sk_buff *skb);
static pp_am_status_ret dummy_send_multicast_event(pp_am_port_event_type type, struct pp_am_multicast_event_msg *msg);
static bool dummy_can_accelerate_ports(const unsigned int *ports, const size_t ports_len);

static struct acceleration_module_ops default_fops = {
    .session_create = dummy_session_create,
    .session_delete = dummy_session_delete,
    .get_session_info = dummy_get_session_info,
    .pp_am_skb_preprocess = dummy_skb_preprocess,
    .pp_am_skb_postprocess = dummy_skb_postprocess,
    .send_multicast_event = dummy_send_multicast_event,
    .can_accelerate_ports = dummy_can_accelerate_ports,
};

static struct acceleration_module_ops * fops = &(struct acceleration_module_ops) {0};

static int pp_am_test(struct sk_buff *skb, struct genl_info *info)
{
	int rc = 0;
	struct sk_buff *response_msg = NULL;
	void *msg_head = NULL;
	int flags = 0;
	const char *user_data;
	int size;

	AM_LOG(KERN_INFO "Acceleration module example function called!\n");

	if (info->attrs != NULL) {
		user_data = nla_data(info->attrs[PP_AM_ATTR_MSG]);
		size = nla_len(info->attrs[PP_AM_ATTR_MSG]);
		AM_LOG_DBG(
			"Acceleration module: input_size=%d, message=\"%s\"\n",
			size, user_data);
	}

	response_msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (response_msg == NULL) {
		rc = -ENOMEM;
		goto failure;
	}

	msg_head = genlmsg_put(response_msg, 0, info->snd_seq, &pp_am_family,
			       flags, PP_AM_CMD_TEST);
	if (msg_head == NULL) {
		rc = -ENOMEM;
		goto failure;
	}

	rc = nla_put_string(response_msg, PP_AM_ATTR_MSG,
			    "Test message from PP AM");
	if (rc != 0)
		goto failure;

	genlmsg_end(response_msg, msg_head);

	rc = genlmsg_unicast(genl_info_net(info), response_msg,
			     info->snd_portid);
	if (rc != 0)
		goto failure;

	return 0;

failure:
	return rc;
}

pp_am_status_ret pp_am_flow_key_to_am_ip_addr(struct pp_am_flow_key *flow_key, 
					  struct pp_am_ip_addr *ip_addr)
{
	if (flow_key == NULL || ip_addr == NULL) {
		AM_LOG_ERR("%s: Failed to convert value: flow_key=%p, ip_addr=%p\n", 
			__func__, flow_key, ip_addr);
		return PP_AM_GENERIC_FAIL;
	}
	
	ip_addr->eth_proto = flow_key->eth.type;
	if (flow_key->eth.type == htons(ETH_P_IP))
		ip_addr->ipv4.s_addr =
			flow_key->ipv4.addr.dst;
	else if (flow_key->eth.type == htons(ETH_P_IPV6))
		ip_addr->ipv6 = flow_key->ipv6.addr.dst;

	return PP_AM_OK;
}
EXPORT_SYMBOL(pp_am_flow_key_to_am_ip_addr);

pp_am_status_ret pp_am_create_session(struct pm_am_session *session,
				      u32 *pp_am_id)
{
	struct pp_am_db_session_entry entry = { 0 };
	pp_am_status_ret rc = PP_AM_OK;

	if (session == NULL || pp_am_id == NULL) {
		AM_LOG_ERR("%s: Failed to create session: session=%p, pp_am_id=%p\n",
			__func__, session, pp_am_id);
		return PP_AM_GENERIC_FAIL;
	}

	*pp_am_id = PP_AM_DB_MAX_SESSION;

	if (session->proactive_session && fops->session_create) {
		rc = fops->session_create(session);
		if (rc != PP_AM_OK)
			AM_LOG_ERR("%s: Failed to create PP session: rc=%d\n", __func__, rc);
	}

	return rc;
}
EXPORT_SYMBOL(pp_am_create_session);

pp_am_status_ret pp_am_modify_session(struct pm_am_session *old_session, 
					  struct pm_am_session *session,
				      u32 *pp_am_id)
{
	struct pp_am_db_session_entry flow = { 0 };
	struct pp_am_stats stats = { 0 };
	pp_am_status_ret ret = PP_AM_OK;

	if (session == NULL || pp_am_id == NULL)
		return PP_AM_GENERIC_FAIL;

	if (*pp_am_id == PP_AM_DB_MAX_SESSION)
		return PP_AM_OK;

	if (pp_am_db_flow_get(&flow, *pp_am_id) != PP_AM_OK)
		return PP_AM_GENERIC_FAIL;

	if (*pp_am_id != PP_AM_DB_MAX_SESSION && flow.pp_session_handle != PP_AM_DB_MAX_SESSION) {
		struct pp_am_db_pp_entry pp_entry = { 0 };
		struct pp_am_pp_session_stats session_stats;
		pp_entry.pp_session = flow.pp_session_handle;

		if (fops->session_delete &&
		    fops->session_delete(flow.pp_session_handle,
					&session_stats) != PP_AM_OK)
			return PP_AM_GENERIC_FAIL;

		stats.bytes = session_stats.bytes;
		stats.packets = session_stats.packets;
		stats.last_used = get_jiffies_64();
		if (pp_am_db_update_stats(flow.pp_session_handle, stats, true) != PP_AM_OK) {
			AM_LOG_ERR(
				"%s: Failed to update stats for session %u via DB",
				__func__, flow.pp_session_handle);
			return PP_AM_GENERIC_FAIL;
		}

		pp_am_db_flow_chain_cleanup(flow.prev, TRAVERSE_BACKWARD);
		pp_am_db_flow_chain_cleanup(flow.next, TRAVERSE_FORWARD);

		if (pp_am_db_pp_session_rm(&pp_entry) != PP_AM_OK)
			return PP_AM_GENERIC_FAIL;
	}

	if (flow.is_proactive) {
		if (session->routing != PP_AM_MULTICAST) {
			pp_am_status_ret rc = PP_AM_OK;
			if (fops->session_create) {
				rc = fops->session_create(session);
				if (rc != PP_AM_OK)
					ret = rc;
			}
		}
	}

	// we should run this regardless of return code of session_create above
	flow.pp_session_handle = PP_AM_DB_MAX_SESSION;
	if (pp_am_db_flow_set(&flow, *pp_am_id) != PP_AM_OK) {
		// only change return code if it wasn't changed before
		// we need to preserve return code of session_create
		if (ret == PP_AM_OK)
			ret = PP_AM_GENERIC_FAIL;
	}

	return ret;
}
EXPORT_SYMBOL(pp_am_modify_session);

pp_am_status_ret pp_am_delete_session(struct pm_am_session *session, u32 pp_am_id,
				      struct pp_am_stats *stats_out)
{
	struct pp_am_db_session_entry flow = {0};

	if (session == NULL || stats_out == NULL || pp_am_id == 0)
		return PP_AM_GENERIC_FAIL;

	AM_LOG_DBG("Removing session pp_am_id: %u", pp_am_id);

	if (pp_am_id == PP_AM_DB_MAX_SESSION) {
		if (session->routing == PP_AM_MULTICAST) {
			memset(stats_out, 0, sizeof(*stats_out));
			return PP_AM_OK;
		} else {
			return PP_AM_GENERIC_FAIL;
		}
	}

	if (pp_am_db_flow_get(&flow, pp_am_id) != PP_AM_OK)
		return PP_AM_GENERIC_FAIL;

	AM_LOG_DBG("%s: Removing session: pp_session_handle=%u, pp_am_id=%u, next=%u, prev=%u; stats: p: %llu b: %llu, old: %u ;",
			__func__, flow.pp_session_handle, pp_am_id, flow.next, flow.prev, flow.stats.packets, flow.stats.bytes, jiffies_to_msecs(get_jiffies_64() - flow.stats.last_used));

	pp_am_db_flow_chain_cleanup(flow.prev, TRAVERSE_BACKWARD);
	pp_am_db_flow_chain_cleanup(flow.next, TRAVERSE_FORWARD);

	if (flow.pp_session_handle != PP_AM_DB_MAX_SESSION) {
		struct pp_am_db_pp_entry pp_entry;
		struct pp_am_pp_session_stats session_stats;
		struct pp_am_stats stats;
		pp_am_status_ret rc;

		if (fops->session_delete)
			rc = fops->session_delete(flow.pp_session_handle, &session_stats);

		stats.bytes = session_stats.bytes;
		stats.packets = session_stats.packets;
		stats.last_used = get_jiffies_64();

		if (rc == PP_AM_OK) {
			if (pp_am_db_update_stats(flow.pp_session_handle, stats, true) != PP_AM_OK) {
				AM_LOG_ERR(
						"%s: Failed to update stats for session %u via DB",
						__func__, flow.pp_session_handle);
				return PP_AM_GENERIC_FAIL;
			}
		}

		pp_entry.pp_session = flow.pp_session_handle;
		pp_entry.am_id = pp_am_id;
		if (pp_am_db_pp_session_rm(&pp_entry) != PP_AM_OK)
			return PP_AM_GENERIC_FAIL;
	}

	if (pp_am_db_flow_rm(&flow, pp_am_id) != PP_AM_OK)
		return PP_AM_GENERIC_FAIL;

	return PP_AM_OK;
}
EXPORT_SYMBOL(pp_am_delete_session);

pp_am_status_ret pp_am_get_session_stats(struct pp_am_flow_id *ufid,
					 u32 pp_am_id,
					 struct pp_am_stats *stats_out)
{
	struct pp_am_db_session_entry flow;
	if (stats_out == NULL || pp_am_id == 0) {
		AM_LOG_ERR(
			"%s: Failed to update stats: ufid=%p, pp_am_id=%u, stats_out=%p",
			__func__, ufid, pp_am_id, stats_out);
		return PP_AM_GENERIC_FAIL;
	}

	// Case of absent AM session for flow
	if (pp_am_id == PP_AM_DB_MAX_SESSION) {
		memset(stats_out, 0, sizeof(struct pp_am_stats));
		return PP_AM_OK;
	}

	if (pp_am_db_flow_get(&flow, pp_am_id) != PP_AM_OK) {
		AM_LOG_ERR("%s: Flow not found: pp_am_id=%u", __func__,
			   pp_am_id);
		return PP_AM_GENERIC_FAIL;
	}

	*stats_out = flow.stats;

	AM_LOG_DBG(
		"%s: returned stats for session %u / flow %u: %llu bytes / %llu packets (lasted used in %u ms)",
		__func__, flow.pp_session_handle, pp_am_id, stats_out->bytes,
		stats_out->packets, jiffies_to_msecs(stats_out->last_used));

	return PP_AM_OK;
}
EXPORT_SYMBOL(pp_am_get_session_stats);

pp_am_status_ret pp_am_skb_preprocess(pp_am_skb_process_action action,
				      u32 ufid[4], u32 pp_am_id,
				      struct sk_buff *skb)
{
	return fops->pp_am_skb_preprocess(action, ufid, pp_am_id, skb);
}
EXPORT_SYMBOL(pp_am_skb_preprocess);

pp_am_status_ret pp_am_skb_postprocess(pp_am_skb_process_action action,
				       u8 local, u32 ufid[4], u32 pp_am_id,
				       struct sk_buff *skb)
{
	return fops->pp_am_skb_postprocess(action, local, ufid, pp_am_id, skb);
}
EXPORT_SYMBOL(pp_am_skb_postprocess);

pp_am_status_ret pp_am_port_event(pp_am_port_event_type type, struct pp_am_multicast_event_msg *msg)
{
	pp_am_status_ret rc = PP_AM_OK;
	if (msg == NULL || type == PP_AM_UNKNOWN_PORT_EVENT)
		return PP_AM_GENERIC_FAIL;

	rc = fops->send_multicast_event(type, msg);
	if (rc != PP_AM_OK) {
		AM_LOG("%s: Failed to send multicast event: rc=%d\n", __func__, rc);
		return rc;
	}
	return PP_AM_OK;
}
EXPORT_SYMBOL(pp_am_port_event);

bool can_accelerate_ports(const unsigned int *ports, const size_t ports_len)
{

	return fops->can_accelerate_ports(ports, ports_len);
}
EXPORT_SYMBOL(can_accelerate_ports);

static pp_am_status_ret dummy_session_create (struct pm_am_session *request)
{
    return PP_AM_OK;
}

static pp_am_status_ret dummy_session_delete(Uint32 session_handle,
        struct pp_am_pp_session_stats *session_stats)
{
    return PP_AM_OK;
}

static pp_am_status_ret dummy_get_session_info(Uint32 session_handle,
        struct pp_am_pp_session_stats *session_stats)
{
    return PP_AM_OK;
}

static pp_am_status_ret dummy_skb_preprocess(pp_am_skb_process_action action,
        u32 ufid[4], u32 pp_am_id, struct sk_buff *skb)
{
    return PP_AM_OK;
}

static pp_am_status_ret dummy_skb_postprocess(pp_am_skb_process_action action,
        u8 local, u32 ufid[4], u32 pp_am_id, struct sk_buff *skb)
{
    return PP_AM_OK;
}

static pp_am_status_ret dummy_send_multicast_event(pp_am_port_event_type type, struct pp_am_multicast_event_msg *msg)
{
    return PP_AM_OK;
}

static bool dummy_can_accelerate_ports(const unsigned int *ports, const size_t ports_len)
{
    return true;
}

pp_am_status_ret acceleration_module_register(struct acceleration_module_ops *ops)
{
    if (ops == NULL) {
        return PP_AM_GENERIC_FAIL;
    }
    memcpy(fops, ops, sizeof(default_fops));
    return PP_AM_OK;
}
EXPORT_SYMBOL(acceleration_module_register);

pp_am_status_ret acceleration_module_unregister(void)
{
    memcpy(fops, &default_fops, sizeof(default_fops));
    return PP_AM_OK;
}
EXPORT_SYMBOL(acceleration_module_unregister);

static int __init acceleration_module_init(void)
{
	pp_am_set_am_id_by_ufid = NULL;

	AM_LOG("Acceleration module welcomes you!\n");
	if (pp_am_db_init() != PP_AM_OK)
		return PP_AM_GENERIC_FAIL;
	if (genl_register_family_with_ops(&pp_am_family, pp_am_ops) != PP_AM_OK)
		return PP_AM_GENERIC_FAIL;

    memcpy(fops, &default_fops, sizeof(default_fops));

	return PP_AM_OK;
}

static void acceleration_module_exit(void)
{
	pp_am_set_am_id_by_ufid = NULL;
	AM_LOG("Acceleration module is out\n");
}

module_init(acceleration_module_init);
module_exit(acceleration_module_exit);
