/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ppcu_api.h: PP command unit platform independent API.
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

#ifndef __PPCU_API_H__
#define __PPCU_API_H__

#include "acceleration_module.h"

struct sk_buff;
struct pp_am_pp_session_stats;
struct pp_am_ip_addr;

struct acceleration_module_ops {
    pp_am_status_ret (*session_create)(struct pm_am_session *request);
    pp_am_status_ret (*session_modify_multicast)(struct pm_am_session *old_session,
        struct pm_am_session *session);
    pp_am_status_ret (*session_delete)(Uint32 session_handle,
        struct pp_am_pp_session_stats *session_stats);
    pp_am_status_ret (*session_delete_multicast)(struct pm_am_session *session);
    pp_am_status_ret (*add_multicast_members)(struct pm_am_session *session);
    pp_am_status_ret (*get_session_info)(Uint32 session_handle,
        struct pp_am_pp_session_stats *session_stats);
    pp_am_status_ret (*pp_am_skb_postprocess)(pp_am_skb_process_action action,
        u32 ufid[4], u32 pp_am_id, struct sk_buff *skb);
    pp_am_status_ret (*pp_am_skb_preprocess)(pp_am_skb_process_action action,
        u32 ufid[4], u32 pp_am_id, struct sk_buff *skb);
};

pp_am_status_ret acceleration_module_register(struct acceleration_module_ops *ops);
pp_am_status_ret acceleration_module_unregister(void);

#endif
