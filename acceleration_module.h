/* SPDX-License-Identifier: GPL-2.0 */
/*
 * acceleration_module.h: public interfaces of PP AM
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

#ifndef __ACCELERATION_MODULE_H__
#define __ACCELERATION_MODULE_H__

#include "acceleration_module_proto.h"

#define PP_AM_EGRESS_PORTS_MAX 52

#define PP_AM_ZERO_UFID ((u32[PP_AM_MAX_UFID_LENGTH]){0, 0, 0, 0})
#define PP_AM_SIZEOF_UFID sizeof(PP_AM_ZERO_UFID)

typedef enum {
	PP_AM_OK,
	PP_AM_NO_SESSIONS_LEFT,
	PP_AM_UNSUPPORTED_PARAM,
	PP_AM_GENERIC_FAIL,
	PP_AM_STATS_NOT_UPDATED,
	PP_AM_NO_SUCH_SESSION,
} pp_am_status_ret;

typedef enum {
	PP_AM_UNDEFINED = 0, // NOP
	PP_AM_SET_OUTPUT,
	PP_AM_SET_DROP,
	PP_AM_SET_FLOOD,
	PP_AM_SET_SKIP,
	PP_AM_SET_FORWARD_UDP,
} pp_am_skb_process_action;

typedef enum {
	PP_AM_UNKNOWN_ROUTING_TYPE = 0,
	PP_AM_BROADCAST,
	PP_AM_UNICAST,
	PP_AM_MULTICAST,
	PP_AM_UNKNOWN_UNICAST,
} pp_am_routing_type;

typedef enum {
	TRAVERSE_BACKWARD,
	TRAVERSE_FORWARD,
} pp_am_flow_chain_traverse_order;

struct pp_am_exact_match {
	struct pp_am_flow_key ingress;
	unsigned int ingress_port;
	struct pp_am_flow_key egress;
	unsigned int egress_ports[PP_AM_EGRESS_PORTS_MAX];
	size_t egress_ports_len;
};

struct pm_am_session {
	struct pp_am_exact_match match;
	struct pp_am_flow_id ufid;
	struct pp_am_flow_mask *wildcard;
	struct pp_am_flow_actions *actions;
	long long int idle_timeout;
	long long int hard_timeout;
	bool proactive_session;
	pp_am_routing_type routing;
};

struct pp_am_stats {
	u64 packets;
	u64 bytes;
	u64 last_used;
};

typedef enum pp_am_port_event_type {
        PP_AM_UNKNOWN_PORT_EVENT,
        PP_AM_MULTICAST_JOIN,
        PP_AM_MULTICAST_LEAVE,
} pp_am_port_event_type;

struct pp_am_ip_addr {
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	};
	u16 eth_proto;
};

struct pp_am_multicast_event_msg {
	int ifindex;
	struct pp_am_ip_addr ip;
};

struct pp_am_db_session_entry;
struct pp_am_ip_addr;

typedef int (*pp_am_set_am_id_by_ufid_t)(u32 ufid[PP_AM_MAX_UFID_LENGTH], u32 am_id, u32 *old_am_id);
extern pp_am_set_am_id_by_ufid_t pp_am_set_am_id_by_ufid;

pp_am_status_ret pp_am_create_session(struct pm_am_session *session, u32 *pp_am_id);
pp_am_status_ret pp_am_modify_session(struct pm_am_session *old_session,
					  struct pm_am_session *session, u32 *pp_am_id);
pp_am_status_ret pp_am_delete_session(struct pm_am_session *session, u32 pp_am_id,
				      struct pp_am_stats *stats_out);
pp_am_status_ret pp_am_get_session_stats(struct pp_am_flow_id *ufid,u32 pp_am_id,
					 struct pp_am_stats *stats_out);
pp_am_status_ret pp_am_skb_preprocess(pp_am_skb_process_action action,
				      u32 ufid[4], u32 pp_am_id, struct sk_buff *skb);
pp_am_status_ret pp_am_skb_postprocess(pp_am_skb_process_action action,
				       u32 ufid[4], u32 pp_am_id, struct sk_buff *skb);
void pp_am_set_am_id_by_ufid_callback(pp_am_set_am_id_by_ufid_t callback);
pp_am_status_ret pp_am_port_event(pp_am_port_event_type type, struct pp_am_multicast_event_msg *msg);

pp_am_status_ret pp_am_cleanup_flow_chain(u32 pp_am_id, pp_am_flow_chain_traverse_order traverse_order);
pp_am_status_ret pp_am_flow_key_to_am_ip_addr(struct pp_am_flow_key *flow_key, 
					  struct pp_am_ip_addr *ip_addr);

#endif
