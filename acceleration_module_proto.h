/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2007-2017 Nicira, Inc.
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

/*
 * Includes Inango Systems Ltd’s changes/modifications dated: 2021.
 * Changed/modified portions - Copyright (c) 2021 , Inango Systems Ltd.
 */

#ifndef __AM_PROTO_H__
#define __AM_PROTO_H__

#include <linux/netlink.h>
#include <linux/types.h>
#include <linux/in6.h>

/* Data structures from OVS */

#define PP_AM_CT_LABELS_LEN_32 4
#define PP_AM_CT_LABELS_LEN (PP_AM_CT_LABELS_LEN_32 * sizeof(u32))
#define PP_AM_NSH_MD1_CONTEXT_SIZE 4
#define PP_AM_ETH_ALEN 6
#define PP_AM_MAX_UFID_LENGTH 4 /* 128 bits */

struct pp_am_ip_tunnel_key {
	u64 tun_id;
	union {
		struct {
			u32 src;
			u32 dst;
		} ipv4;
		struct {
			struct in6_addr src;
			struct in6_addr dst;
		} ipv6;
	} u;
	u16 tun_flags;
	u8 tos; /* TOS for IPv4, TC for IPv6 */
	u8 ttl; /* TTL for IPv4, HL for IPv6 */
	u32 label; /* Flow Label for IPv6 */
	u16 tp_src;
	u16 tp_dst;
};

struct pp_am_key_ct_labels {
	union {
		u8 ct_labels[PP_AM_CT_LABELS_LEN];
		u32 ct_labels_32[PP_AM_CT_LABELS_LEN_32];
	};
};

struct pp_am_nsh_key_base {
	u8 flags;
	u8 ttl;
	u8 mdtype;
	u8 np;
	u32 path_hdr;
};

struct pp_am_vlan_head {
	u16 tpid; /* Vlan type. Generally 802.1q or 802.1ad.*/
	u16 tci; /* 0 if no VLAN, VLAN_TAG_PRESENT set otherwise. */
};

struct pp_am_key_nsh {
	struct pp_am_nsh_key_base base;
	u32 context[PP_AM_NSH_MD1_CONTEXT_SIZE];
};

struct pp_am_flow_key {
	u8 tun_opts[255];
	u8 tun_opts_len;
	struct pp_am_ip_tunnel_key tun_key; /* Encapsulating tunnel key. */
	struct {
		u32 priority; /* Packet QoS priority. */
		u32 skb_mark; /* SKB mark. */
		u16 in_port; /* Input switch port (or DP_MAX_PORTS). */
	} __packed phy; /* Safe when right after 'tun_key'. */
	u8 mac_proto; /* MAC layer protocol (e.g. Ethernet). */
	u8 tun_proto; /* Protocol of encapsulating tunnel. */
	u32 ovs_flow_hash; /* Datapath computed hash value.  */
	u32 recirc_id; /* Recirculation ID.  */
	struct {
		u8 src[PP_AM_ETH_ALEN];
		u8 dst[PP_AM_ETH_ALEN];
		struct pp_am_vlan_head vlan;
		struct pp_am_vlan_head cvlan;
		u16 type;
	} eth;
	/* Filling a hole of two bytes. */
	u8 ct_state;
	u8 ct_orig_proto; /* CT original direction tuple IP protocol. */
	union {
		struct {
			u32 top_lse; /* top label stack entry */
		} mpls;
		struct {
			u8 proto; /* IP protocol or lower 8 bits of ARP opcode. */
			u8 tos;
			u8 ttl;
			u8 frag; /* One of OVS_FRAG_TYPE_*. */
		} ip;
	};
	u16 ct_zone; /* Conntrack zone. */
	struct {
		u16 src; /* TCP/UDP/SCTP source port. */
		u16 dst; /* TCP/UDP/SCTP destination port. */
		u16 flags; /* TCP flags. */
	} tp;
	union {
		struct {
			struct {
				u32 src;
				u32 dst;
			} addr;
			union {
				struct {
					u32 src;
					u32 dst;
				} ct_orig; /* Conntrack original direction fields. */
				struct {
					u8 sha[PP_AM_ETH_ALEN]; /* ARP source hardware address. */
					u8 tha[PP_AM_ETH_ALEN]; /* ARP target hardware address. */
				} arp;
			};
		} ipv4;
		struct {
			struct {
				struct in6_addr src;
				struct in6_addr dst;
			} addr;
			u32 label; /* IPv6 flow label. */
			union {
				struct {
					struct in6_addr src;
					struct in6_addr dst;
				} ct_orig; /* Conntrack original direction fields. */
				struct {
					struct in6_addr
						target; /* ND target address. */
					u8 sll[PP_AM_ETH_ALEN]; /* ND source link layer address. */
					u8 tll[PP_AM_ETH_ALEN]; /* ND target link layer address. */
				} nd;
			};
		} ipv6;
		struct pp_am_key_nsh nsh; /* network service header */
	};
	struct {
		/* Connection tracking fields not packed above. */
		struct {
			u16 src; /* CT orig tuple tp src port. */
			u16 dst; /* CT orig tuple tp dst port. */
		} orig_tp;
		u32 mark;
		struct pp_am_key_ct_labels labels;
	} ct;

} __aligned(BITS_PER_LONG / 8);

struct pp_am_flow_key_range {
	unsigned short int start;
	unsigned short int end;
};

struct pp_am_flow_mask {
	int ref_count;
	struct rcu_head rcu;
	struct pp_am_flow_key_range range;
	struct pp_am_flow_key key;
};

struct pp_am_flow_id {
	u32 ufid_len;
	union {
		u32 ufid[PP_AM_MAX_UFID_LENGTH];
		struct pp_am_flow_key *unmasked_key;
	};
};

struct pp_am_flow_actions {
	struct rcu_head rcu;
	size_t orig_len; /* From flow_cmd_new netlink actions size */
	u32 actions_len;
	struct nlattr actions[];
};

#endif