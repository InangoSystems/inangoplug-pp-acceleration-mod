/*
 * ################################################################################
 * #
 * #  translate_dp_am.h: this code implement method of translation
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

#ifndef TRANSLATE_DP_AM_H
#define TRANSLATE_DP_AM_H 1

#include "acceleration_module.h"
#include "datapath.h"

#define LIST_OUTPUT_DEV_MAX 100

struct s_prop_ingress {
	struct sw_flow_key *ingress_key;
	struct net_device *in_dev;
};

struct s_prop_egress {
	struct sw_flow_key egress_key;
	struct net_device *out_dev[LIST_OUTPUT_DEV_MAX];
	unsigned int len;
	bool to_drop_flag;
};

int translate_to_egr_prop(struct datapath *dp,
			  const struct sw_flow_actions *acts,
			  const struct sw_flow_key *ingr_key,
			  struct pm_am_session *session);

int translate_to_am_session(struct datapath *dp, struct sw_flow *flow,
			    struct pm_am_session *session);

int translate_to_am_session_old_acts(struct datapath *dp, struct sw_flow *flow,
				     struct pm_am_session *session,
				     struct sw_flow_actions *old_acts);

static inline void invalidate_flow_key(struct sw_flow_key *key)
{
	key->mac_proto |= SW_FLOW_KEY_INVALID;
}

static inline bool tr_is_ipv6_mask_nonzero(const __be32 addr[4])
{
	return !!(addr[0] | addr[1] | addr[2] | addr[3]);
}

static inline void tr_mask_ipv6_addr(const __be32 old[4], const __be32 addr[4],
				     const __be32 mask[4], __be32 masked[4])
{
	masked[0] = OVS_MASKED(old[0], addr[0], mask[0]);
	masked[1] = OVS_MASKED(old[1], addr[1], mask[1]);
	masked[2] = OVS_MASKED(old[2], addr[2], mask[2]);
	masked[3] = OVS_MASKED(old[3], addr[3], mask[3]);
}

static inline void tr_set_ipv6_fl(struct ipv6hdr *nh, u32 fl, u32 mask)
{
	/* Bits 21-24 are always unmasked, so this retains their values. */
	OVS_SET_MASKED(nh->flow_lbl[0], (u8)(fl >> 16), (u8)(mask >> 16));
	OVS_SET_MASKED(nh->flow_lbl[1], (u8)(fl >> 8), (u8)(mask >> 8));
	OVS_SET_MASKED(nh->flow_lbl[2], (u8)fl, (u8)mask);
}

static inline void tr_ether_addr_copy_masked(u8 *dst_, const u8 *src_,
					     const u8 *mask_)
{
	u16 *dst = (u16 *)dst_;
	const u16 *src = (const u16 *)src_;
	const u16 *mask = (const u16 *)mask_;

	OVS_SET_MASKED(dst[0], src[0], mask[0]);
	OVS_SET_MASKED(dst[1], src[1], mask[1]);
	OVS_SET_MASKED(dst[2], src[2], mask[2]);
}

#endif /* translate_dp_am.h */
