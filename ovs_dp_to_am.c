/*
 * ################################################################################
 * #
 * #  translate_dp_am.c: this code implement method of translation
 * #                     ingress to egress flow key.
 * #  Copyright (C) 2021,2022 Inango Systems Ltd.
 * #
 * #  This program is free software; you can redistribute it and/or
 * #  modify it under the terms of the GNU General Public License
 * #  as published by the Free Software Foundation; either version 2
 * #  of the License, or (at your option) any later version.
 * #
 * #  This program is distributed in the hope that it will be useful,
 * #  but WITHOUT ANY WARRANTY; without even the implied warranty of
 * #  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * #  GNU General Public License for more details.
 * #
 * #  You should have received a copy of the GNU General Public License
 * #  along with this program; if not, write to the Free Software
 * #  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * #
 * ################################################################################
 */

#include <linux/openvswitch.h>
#include <linux/etherdevice.h>
#include <net/mpls.h>

#include "ovs_dp_to_am.h"
#include "flow_netlink.h"

static void tr_set_udp(struct sw_flow_key *f_key, const struct ovs_key_udp *key,
		       const struct ovs_key_udp *mask)
{
	__be16 src, dst;

	src = OVS_MASKED(f_key->tp.src, key->udp_src, mask->udp_src);
	dst = OVS_MASKED(f_key->tp.dst, key->udp_dst, mask->udp_dst);

	if (likely(src != f_key->tp.src)) {
		f_key->tp.src = src;
	}
	if (likely(dst != f_key->tp.dst)) {
		f_key->tp.dst = dst;
	}
}

static void tr_set_tcp(struct sw_flow_key *f_key, const struct ovs_key_tcp *key,
		       const struct ovs_key_tcp *mask)
{
	__be16 src, dst;

	src = OVS_MASKED(f_key->tp.src, key->tcp_src, mask->tcp_src);
	if (likely(src != f_key->tp.src)) {
		f_key->tp.src = src;
	}
	dst = OVS_MASKED(f_key->tp.dst, key->tcp_dst, mask->tcp_dst);
	if (likely(dst != f_key->tp.dst)) {
		f_key->tp.dst = dst;
	}
}

static void tr_set_ipv6(struct sw_flow_key *f_key,
			const struct ovs_key_ipv6 *key,
			const struct ovs_key_ipv6 *mask)
{
	struct ipv6hdr nh_6;
	__be16 *nh = (__be16 *)&nh_6;
	__be32 *nhl = (__be32 *)&nh_6;

	if (tr_is_ipv6_mask_nonzero(mask->ipv6_src)) {
		__be32 *saddr = (__be32 *)&f_key->ipv6.addr.src;
		__be32 masked[4];

		tr_mask_ipv6_addr(saddr, key->ipv6_src, mask->ipv6_src, masked);

		if (unlikely(memcmp(saddr, masked, sizeof(masked)))) {
			memcpy(&f_key->ipv6.addr.src, masked,
			       sizeof(f_key->ipv6.addr.src));
		}
	}
	if (tr_is_ipv6_mask_nonzero(mask->ipv6_dst)) {
		__be32 *daddr = (__be32 *)&f_key->ipv6.addr.dst;
		__be32 masked[4];

		tr_mask_ipv6_addr(daddr, key->ipv6_dst, mask->ipv6_dst, masked);

		if (unlikely(memcmp(daddr, masked, sizeof(masked)))) {
			memcpy(&f_key->ipv6.addr.dst, masked,
			       sizeof(f_key->ipv6.addr.dst));
		}
	}
	if (mask->ipv6_tclass) {
		*nh = htons(f_key->ip.tos << 4);
		ipv6_change_dsfield(&nh_6, ~mask->ipv6_tclass,
				    key->ipv6_tclass);
		f_key->ip.tos = ipv6_get_dsfield(&nh_6);
	}
	if (mask->ipv6_label) {
		*nhl &= ~htonl(IPV6_FLOWINFO_FLOWLABEL);
		*nhl |= f_key->ipv6.label;

		tr_set_ipv6_fl(&nh_6, ntohl(key->ipv6_label),
			       ntohl(mask->ipv6_label));
		f_key->ipv6.label =
			*(__be32 *)&nh_6 & htonl(IPV6_FLOWINFO_FLOWLABEL);
	}
	if (mask->ipv6_hlimit) {
		OVS_SET_MASKED(f_key->ip.ttl, key->ipv6_hlimit,
			       mask->ipv6_hlimit);
	}
}

static void tr_set_ipv4(struct sw_flow_key *f_key,
			const struct ovs_key_ipv4 *key,
			const struct ovs_key_ipv4 *mask)
{
	__be32 new_addr;

	if (mask->ipv4_src) {
		new_addr = OVS_MASKED(f_key->ipv4.addr.src, key->ipv4_src,
				      mask->ipv4_src);

		if (unlikely(new_addr != f_key->ipv4.addr.src)) {
			f_key->ipv4.addr.src = new_addr;
		}
	}
	if (mask->ipv4_dst) {
		new_addr = OVS_MASKED(f_key->ipv4.addr.dst, key->ipv4_dst,
				      mask->ipv4_dst);

		if (unlikely(new_addr != f_key->ipv4.addr.dst)) {
			f_key->ipv4.addr.dst = new_addr;
		}
	}
	if (mask->ipv4_tos) {
		f_key->ip.tos =
			(f_key->ip.tos & ~mask->ipv4_tos) | key->ipv4_tos;
	}
	if (mask->ipv4_ttl) {
		f_key->ip.ttl = OVS_MASKED(f_key->ip.ttl, key->ipv4_ttl,
					   mask->ipv4_ttl);
	}
}

static int tr_set_nsh(struct sw_flow_key *f_key, const struct nlattr *a)
{
	struct ovs_key_nsh key;
	struct ovs_key_nsh mask;
	int err, i;

	// TODO: nsh_key_from_nlattr should be properly exported from OVS before supporting NSH tunnels
	// err = nsh_key_from_nlattr(a, &key, &mask);
	if (err)
		return err;

	f_key->nsh.base.flags = OVS_MASKED(f_key->nsh.base.flags,
					   key.base.flags, mask.base.flags);
	f_key->nsh.base.ttl =
		OVS_MASKED(f_key->nsh.base.ttl, key.base.ttl, mask.base.ttl);
	f_key->nsh.base.path_hdr =
		OVS_MASKED(f_key->nsh.base.path_hdr, key.base.path_hdr,
			   mask.base.path_hdr);

	switch (f_key->nsh.base.mdtype) {
	case NSH_M_TYPE1:
		for (i = 0; i < NSH_MD1_CONTEXT_SIZE; i++) {
			f_key->nsh.context[i] =
				OVS_MASKED(f_key->nsh.context[i],
					   key.context[i], mask.context[i]);
		}
		break;
	case NSH_M_TYPE2:
		memset(f_key->nsh.context, 0, sizeof(f_key->nsh.context));
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

#define get_mask(a, type) ((const type)nla_data(a) + 1)

static int tr_masked_set_action(struct sw_flow_key *f_key,
				const struct nlattr *a)
{
	int err = 0;

	switch (nla_type(a)) {
	case OVS_KEY_ATTR_PRIORITY: {
		OVS_SET_MASKED(f_key->phy.priority, nla_get_u32(a),
			       *get_mask(a, u32 *));
		break;
	}
	case OVS_KEY_ATTR_SKB_MARK: {
		OVS_SET_MASKED(f_key->phy.skb_mark, nla_get_u32(a),
			       *get_mask(a, u32 *));
		break;
	}
	case OVS_KEY_ATTR_ETHERNET: {
		tr_ether_addr_copy_masked(
			f_key->eth.src,
			((struct ovs_key_ethernet *)nla_data(a))->eth_src,
			(get_mask(a, struct ovs_key_ethernet *))->eth_src);
		tr_ether_addr_copy_masked(
			f_key->eth.dst,
			((struct ovs_key_ethernet *)nla_data(a))->eth_dst,
			(get_mask(a, struct ovs_key_ethernet *))->eth_dst);
		break;
	}
	case OVS_KEY_ATTR_NSH:
		// TODO NSH Tunnel isn't supported yet
		// err = tr_set_nsh(f_key, a);
		break;

	case OVS_KEY_ATTR_IPV4:
		tr_set_ipv4(f_key, nla_data(a),
			    get_mask(a, struct ovs_key_ipv4 *));
		break;

	case OVS_KEY_ATTR_IPV6:
		tr_set_ipv6(f_key, nla_data(a),
			    get_mask(a, struct ovs_key_ipv6 *));
		break;

	case OVS_KEY_ATTR_TCP:
		tr_set_tcp(f_key, nla_data(a),
			   get_mask(a, struct ovs_key_tcp *));
		break;

	case OVS_KEY_ATTR_UDP:
		tr_set_udp(f_key, nla_data(a),
			   get_mask(a, struct ovs_key_udp *));
		break;

	case OVS_KEY_ATTR_SCTP: {
		f_key->tp.src = OVS_MASKED(
			f_key->tp.src,
			((struct ovs_key_sctp *)nla_data(a))->sctp_src,
			get_mask(a, struct ovs_key_sctp *)->sctp_src);
		f_key->tp.dst = OVS_MASKED(
			f_key->tp.dst,
			((struct ovs_key_sctp *)nla_data(a))->sctp_dst,
			get_mask(a, struct ovs_key_sctp *)->sctp_dst);
		break;
	}
	case OVS_KEY_ATTR_MPLS:
		f_key->mpls.lse[0] =
			OVS_MASKED(f_key->mpls.lse[0], *(__be32 *)nla_data(a),
				   *get_mask(a, __be32 *));
		break;

	case OVS_KEY_ATTR_CT_STATE:
	case OVS_KEY_ATTR_CT_ZONE:
	case OVS_KEY_ATTR_CT_MARK:
	case OVS_KEY_ATTR_CT_LABELS:
	case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4:
	case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6:
		err = -EINVAL;
		break;
	}

	return err;
}

int translate_to_egr_prop(struct datapath *dp,
			  const struct sw_flow_actions *acts,
			  const struct sw_flow_key *ingr_key,
			  struct pm_am_session *session)
{
	const struct nlattr *a;
	int rem;
	struct sw_flow_key *egr_key =
		(struct sw_flow_key *)&session->match.egress;

	if (!dp)
		return -EINVAL;

	memcpy(egr_key, ingr_key, sizeof(struct sw_flow_key));

	if (!acts || !acts->actions || acts->actions_len == 0)
		return 0;

	for (a = acts->actions, rem = acts->actions_len; rem > 0;
	     a = nla_next(a, &rem)) {
		int err = 0;

		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_OUTPUT: {
			struct net_device *port =
				ovs_get_net_device(dp, nla_get_u32(a));
			if (port && session->match.egress_ports_len <
					    PP_AM_EGRESS_PORTS_MAX) {
				session->match.egress_ports
					[session->match.egress_ports_len] =
					port->ifindex;
				session->match.egress_ports_len++;
			} else {
				return -EINVAL;
			}
			break;
		}
		case OVS_ACTION_ATTR_MULTICAST_OUTPUT: {
			struct ovs_action_mcast_output *mcast_output =
				nla_data(a);
			struct net_device *port =
				ovs_get_net_device(dp, nla_get_u32(a));
			if (port && session->match.egress_ports_len <
					    PP_AM_EGRESS_PORTS_MAX) {
				session->match.egress_ports
					[session->match.egress_ports_len] =
					port->ifindex;
				session->match.egress_ports_len++;
			} else {
				return -EINVAL;
			}
			break;
		}
		case OVS_ACTION_ATTR_PUSH_MPLS: {
			const struct ovs_action_push_mpls *mpls = nla_data(a);
			u32 num_labels =
				hweight_long(egr_key->mpls.num_labels_mask);
			memmove(egr_key->mpls.lse + 1, egr_key->mpls.lse,
				num_labels);
			egr_key->mpls.lse[0] = mpls->mpls_lse;
			egr_key->mpls.num_labels_mask =
				GENMASK(num_labels + 1, 0);
			egr_key->eth.type = mpls->mpls_ethertype;
			break;
		}
		case OVS_ACTION_ATTR_POP_MPLS: {
			const __be16 ethertype = nla_get_be16(a);
			u32 num_labels =
				hweight_long(egr_key->mpls.num_labels_mask);
			memmove(egr_key->mpls.lse, egr_key->mpls.lse + 1,
				num_labels - 1);
			egr_key->mpls.num_labels_mask =
				GENMASK(num_labels - 1, 0);
			if (eth_p_mpls(egr_key->eth.type))
				egr_key->eth.type = ethertype;
			break;
		}
		case OVS_ACTION_ATTR_PUSH_VLAN:
			if (egr_key->eth.vlan.tci == 0 &&
			    egr_key->eth.vlan.tpid == 0) {
				egr_key->eth.vlan.tci =
					((struct ovs_action_push_vlan *)
						 nla_data(a))
						->vlan_tci;
				egr_key->eth.vlan.tpid =
					((struct ovs_action_push_vlan *)
						 nla_data(a))
						->vlan_tpid;
			} else {
				invalidate_flow_key(egr_key);
			}
			break;

		case OVS_ACTION_ATTR_POP_VLAN:
			egr_key->eth.vlan.tci = 0;
			egr_key->eth.vlan.tpid = 0;
			break;

		case OVS_ACTION_ATTR_SET_MASKED:
		case OVS_ACTION_ATTR_SET_TO_MASKED:
			err = tr_masked_set_action(egr_key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_PUSH_ETH: {
			err = -ENOTSUPP;
			break;
		}
		case OVS_ACTION_ATTR_POP_ETH:
			err = -ENOTSUPP;
			break;

		case OVS_ACTION_ATTR_PUSH_NSH: {
			err = -ENOTSUPP;
			break;
		}

		case OVS_ACTION_ATTR_POP_NSH: {
			err = -ENOTSUPP;
			break;
		}
		case OVS_ACTION_ATTR_USERSPACE:
			err = -ENOTSUPP;
			break;
		default:
			err = -ENOTSUPP;
			break;
		}

		if (unlikely(err)) {
			return err;
		}
	}

	return 0;
}

int translate_to_am_session(struct datapath *dp, struct sw_flow *flow,
			    struct pm_am_session *session)
{
	int err;
	struct net_device *port = NULL;

	if (!dp || !flow || !session)
		return -EINVAL;

	memset(session, 0, sizeof(struct pm_am_session));

	err = translate_to_egr_prop(dp, flow->sf_acts, &flow->key, session);

	memcpy(&session->match.ingress, &flow->key,
	       sizeof(struct pp_am_flow_key));

	port = ovs_get_net_device(dp, flow->key.phy.in_port);
	if (port)
		session->match.ingress_port = port->ifindex;

	session->wildcard = (struct pp_am_flow_mask *)flow->mask;
	memcpy(&session->ufid, &flow->id, sizeof(struct pp_am_flow_id));
	session->idle_timeout = -1;
	session->hard_timeout = -1;
	session->actions = (struct pp_am_flow_actions *)flow->sf_acts;
	session->proactive_session = false;
	session->routing = flow->flow_type;

	return err;
}

int translate_to_am_session_old_acts(struct datapath *dp, struct sw_flow *flow,
				     struct pm_am_session *session,
				     struct sw_flow_actions *old_acts)
{
	int err;
	struct net_device *port = NULL;

	if (!dp || !flow || !session)
		return -EINVAL;

	memset(session, 0, sizeof(struct pm_am_session));

	err = translate_to_egr_prop(dp, old_acts, &flow->key, session);

	memcpy(&session->match.ingress, &flow->key,
	       sizeof(struct pp_am_flow_key));

	port = ovs_get_net_device(dp, flow->key.phy.in_port);
	if (port)
		session->match.ingress_port = port->ifindex;

	session->wildcard = (struct pp_am_flow_mask *)flow->mask;
	memcpy(&session->ufid, &flow->id, sizeof(struct pp_am_flow_id));
	session->idle_timeout = -1;
	session->hard_timeout = -1;
	session->actions = (struct pp_am_flow_actions *)old_acts;
	session->proactive_session = false;
	session->routing = flow->flow_type;

	return err;
}
