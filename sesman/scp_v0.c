/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2015
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 *
 * @file scp_v0.c
 * @brief scp version 0 implementation
 * @author Jay Sorg, Simone Fedele
 *
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "sesman.h"

#include "libscp_v0.h"
#include "libscp_session.h"

extern struct config_sesman *g_cfg; /* in sesman.c */

/**************************************************************************//**
 * Handles a gateway request
 *
 * This is simply a request to authenticate the user
 *
 * @param c Connection info
 * @param s Session info
 */
static void
handle_gateway_request(struct SCP_CONNECTION *c, struct SCP_SESSION *s)
{
    int errorcode = 0;
    tbus data = auth_userpass(s->username, s->password, &errorcode);

    if (!data)
    {
        log_message(LOG_LEVEL_INFO, "Username or password error "
                    "for user: %s", s->username);
    }
    else
    {
        if (1 == access_login_allowed(s->username))
        {
            /* the user is member of the correct groups. */
            log_message(LOG_LEVEL_INFO, "Access permitted for user: %s",
                        s->username);
        }
        else
        {
            errorcode = 32 + 3;
            log_message(LOG_LEVEL_INFO, "Username okey but group problem "
                        "for user: %s", s->username);
        }
        auth_end(data);
    }

    scp_v0s_replyauthentication(c, errorcode);
}


/**************************************************************************//**
 * Handles a reconnection request
 *
 * @param c Connection info
 * @param s Session info from client
 * @param s_item Session info held by sesman
 */
static void
handle_reconnection_request(struct SCP_CONNECTION *c, struct SCP_SESSION *s,
                            struct session_item *s_item)
{
    int errorcode = 0;
    tbus data = auth_userpass(s->username, s->password, &errorcode);
    if (!data)
    {
        log_message(LOG_LEVEL_INFO, "Can't reconnect: Username or "
                    "password error for user: %s", s->username);
        scp_v0s_deny_connection(c);
    }
    else
    {
        if (0 != s->client_ip)
        {
            log_message( LOG_LEVEL_INFO, "++ reconnected session: "
                         "username %s, display :%d.0, session_pid %d"
                         ", ip %s",
                         s->username, s_item->display, s_item->sl.pid,
                         s->client_ip);
        }
        else
        {
            log_message(LOG_LEVEL_INFO, "++ reconnected session: "
                        "username %s, display :%d.0, session_pid %d",
                        s->username, s_item->display, s_item->sl.pid);
        }

        scp_v0s_allow_connection(c, s_item->display, s_item->guid);
        /* Run a user script for the reconnection
         *
         * Ideally we would use s->data for this, but this would need
         * a context switch to the subprocess for the session (TBA) */
        session_reconnect(s->display, s->username, data);
        auth_end(data);
    }
}


/**************************************************************************//**
 * Handles a new session request
 *
 * See session_start() for more information on why user authentication is not
 * performed at this level.
 *
 * @param c Connection info
 * @param s Session info
 */
static void
handle_new_session_request(struct SCP_CONNECTION *c, struct SCP_SESSION *s)
{
    int display = 0;

    display = session_start(c, s);
    if (display == 0)
    {
        scp_v0s_deny_connection(c);
    }
    else
    {
        scp_v0s_allow_connection(c, display, s->guid);
    }
}

/******************************************************************************/
void
scp_v0_process(struct SCP_CONNECTION *c, struct SCP_SESSION *s)
{
    if (s->type == SCP_GW_AUTHENTICATION)
    {
        /* g_writeln("SCP_GW_AUTHENTICATION message received"); */
        handle_gateway_request(c, s);
    }
    else
    {
        /* See if there's already a session we can reconnect to */
        struct session_item *s_item;
        s_item = session_get_bydata(s->username, s->width, s->height,
                                    s->bpp, s->type, s->client_ip);

        if (s_item != 0)
        {
            handle_reconnection_request(c, s, s_item);
        }
        else
        {
            /* This is a new session */
            handle_new_session_request(c, s);
        }
    }
}
