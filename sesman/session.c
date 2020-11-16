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
 * @file session.c
 * @brief Session management code
 * @author Jay Sorg, Simone Fedele
 *
 */

#if defined(HAVE_CONFIG_H)
#include "config_ac.h"
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <errno.h>

#include "sesman.h"
#include "libscp_types.h"
#include "xauth.h"
#include "xrdp_sockets.h"
#include "session_leader.h"

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

extern struct config_sesman *g_cfg; /* in sesman.c */
extern int g_sck; /* in sesman.c */
static struct session_chain *g_sessions;
static int g_session_count;

extern tbus g_term_event; /* in sesman.c */

/******************************************************************************/
/* convert from SCP_SESSION_TYPE namespace to SESMAN_SESSION_TYPE namespace */
static bool_t cvt_from_scp_sesstype(int from,
                                    enum sesman_sesstype_t *to)
{
    bool_t result = 1;
    switch (from)
    {
        case SCP_SESSION_TYPE_XVNC:
            *to = SESMAN_SESSION_TYPE_XVNC;
            break;
        case SCP_SESSION_TYPE_XRDP:
            *to = SESMAN_SESSION_TYPE_XRDP;
            break;
        case SCP_SESSION_TYPE_XORG:
            *to = SESMAN_SESSION_TYPE_XORG;
            break;
        default:
            result = 0;
    }

    return result;
}



/******************************************************************************/
struct session_item *
session_get_bydata(const char *name, int width, int height, int bpp,
                   int scptype, const char *client_ip)
{
    struct session_chain *tmp;
    enum SESMAN_CFG_SESS_POLICY policy = g_cfg->sess.policy;
    enum sesman_sesstype_t type;

    if (!cvt_from_scp_sesstype(scptype, &type))
    {
        return 0;
    }

    tmp = g_sessions;

#if 0
    log_message(LOG_LEVEL_INFO,
            "session_get_bydata: search policy %d U %s W %d H %d bpp %d T %d IP %s",
            policy, name, width, height, bpp, type, client_ip);
#endif

    while (tmp != 0)
    {
#if 0
        log_message(LOG_LEVEL_INFO,
            "session_get_bydata: try %p U %s W %d H %d bpp %d T %d IP %s",
            tmp->item,
            tmp->item->name,
            tmp->item->width, tmp->item->height,
            tmp->item->bpp, tmp->item->type,
            tmp->item->client_ip);
#endif

        if (g_strncmp(name, tmp->item.name, 255) == 0 &&
            (!(policy & SESMAN_CFG_SESS_POLICY_D) ||
             (tmp->item.width == width && tmp->item.height == height)) &&
            (!(policy & SESMAN_CFG_SESS_POLICY_I) ||
             (g_strncmp_d(client_ip, tmp->item.client_ip, ':', 255) == 0)) &&
            (!(policy & SESMAN_CFG_SESS_POLICY_C) ||
             (g_strncmp(client_ip, tmp->item.client_ip, 255) == 0)) &&
            tmp->item.bpp == bpp &&
            tmp->item.type == type)
        {
            return &tmp->item;
        }

        tmp = tmp->next;
    }

    return 0;
}

/**************************************************************************//**
 * Authenticates and starts a new session
 *
 * @param c Connection info
 * @param s Session info
 * @return display number which is started, or 0 for fail
 */
int
session_start(struct SCP_CONNECTION *c, struct SCP_SESSION *s)
{
    int result = 0;
    int r;
    bool_t auth_result = 0;
    struct session_chain *temp = 
        (struct session_chain *)g_malloc(sizeof(struct session_chain), 0);
    struct session_leader_t *sl = NULL;
    enum sesman_sesstype_t sesstype;
    int display = 0;
    const char *client_ip = (0 != s->client_ip) ? s->client_ip : "unknown";

    if (temp)
    {
        sl = &temp->item.sl;
        INIT_SL(sl);
    }

    if (temp == NULL)
    {
        log_message(LOG_LEVEL_ERROR, "cannot create new chain element"
                    " - user %s, ip %s", s->username, client_ip);
    }
    else if (!cvt_from_scp_sesstype(s->type, &sesstype))
    {
        log_message(LOG_LEVEL_ERROR, "Unrecognised SCP session type %d"
                    " - user %s, ip %s", s->type, s->username, client_ip);
    }
    else if (g_session_count >= g_cfg->sess.max_sessions)
    {
        log_message(LOG_LEVEL_INFO, "max concurrent session limit exceeded"
                    " - user %s, ip %s", s->username, client_ip);
    }
    else if ((session_leader_start(sl, NULL, session_leader_main)) < 0)
    {
        log_message(LOG_LEVEL_ERROR, "cannot create new session leader [%s]"
                    " - user %s, ip %s",
                    g_get_strerror(),
                    s->username, client_ip);
    }
    else if (session_leader_authenticate_user(sl, s->username,
                                              s->password, s->client_ip,
                                              &auth_result) < 0)
    {
        log_message(LOG_LEVEL_ERROR, "authentication failed unexpectedly"
                    " - user %s, ip %s", s->username, client_ip);
    }
    else if (!auth_result)
    {
        log_message(LOG_LEVEL_INFO, "++ did not create session (access denied)"
                    " - user %s, ip %s", s->username, client_ip);
    }
    else
    {
        char guid_str[64];

        g_bytes_to_hexstr(s->guid, 16, guid_str, sizeof(guid_str));

        r = session_leader_start_session(sl, sesstype,
                                         s->directory, s->program,
                                         s->width, s->height, s->bpp,
                                         guid_str, &display);
        if (r < 0)
        {
            if (abs(r) == ENOENT)
            {
                log_message(LOG_LEVEL_ERROR,
                            "X server -- no display in range is available"
                            " - user %s, ip %s", s->username, client_ip);
            }
            else
            {
                log_message(LOG_LEVEL_ERROR, "failed to start session"
                            " - user %s, ip %s", s->username, client_ip);
            }
        }
    }

    if (result > 0)
    {
        struct tm stime;
        time_t ltime;
        temp->item.display = display;
        temp->item.width = s->width;
        temp->item.height = s->height;
        temp->item.bpp = s->bpp;
        g_strncpy(temp->item.client_ip, s->client_ip, 255);   /* store client ip data */
        g_strncpy(temp->item.name, s->username, 255);
        g_memcpy(temp->item.guid, s->guid, 16);
        
        ltime = g_time1();
        localtime_r(&ltime, &stime);
        temp->item.connect_time.year = (tui16)(stime.tm_year + 1900);
        temp->item.connect_time.month = (tui8)(stime.tm_mon + 1);
        temp->item.connect_time.day = (tui8)stime.tm_mday;
        temp->item.connect_time.hour = (tui8)stime.tm_hour;
        temp->item.connect_time.minute = (tui8)stime.tm_min;
        zero_time(&(temp->item.disconnect_time));
        zero_time(&(temp->item.idle_time));

        temp->item.type = sesstype;
        temp->item.status = SESMAN_SESSION_STATUS_ACTIVE;

        temp->next = g_sessions;
        g_sessions = temp;
        g_session_count++;

        result = display;

        log_message(LOG_LEVEL_INFO, "++ created session (access granted)"
                    " - user %s, ip %s", s->username, client_ip);
    }
    else
    {
        g_free(temp);
    }

    return result;
}

/******************************************************************************/
void
session_reconnect(int display, char *username, long data)
{
    int pid;

    pid = g_fork();

    if (pid == -1)
    {
    }
    else if (pid == 0)
    {
        env_set_user(username,
                     0,
                     display,
                     g_cfg->env_names,
                     g_cfg->env_values);
        auth_set_env(data);

        if (g_file_exist(g_cfg->reconnect_sh))
        {
            g_execlp3(g_cfg->reconnect_sh, g_cfg->reconnect_sh, 0);
        }

        g_exit(0);
    }
}

/******************************************************************************/
int
session_kill(int pid)
{
    struct session_chain *tmp;
    struct session_chain *prev;

    tmp = g_sessions;
    prev = 0;

    while (tmp != 0)
    {
        if (tmp->item.sl.pid == pid)
        {
            /* deleting the session */
            session_leader_kill(&tmp->item.sl);
            log_message(LOG_LEVEL_INFO, "++ terminated session:  username %s, display :%d.0, session_pid %d, ip %s", tmp->item.name, tmp->item.display, tmp->item.sl.pid, tmp->item.client_ip);

            if (prev == 0)
            {
                /* prev does no exist, so it's the first element - so we set
                   g_sessions */
                g_sessions = tmp->next;
            }
            else
            {
                prev->next = tmp->next;
            }

            g_free(tmp);
            g_session_count--;
            return SESMAN_SESSION_KILL_OK;
        }

        /* go on */
        prev = tmp;
        tmp = tmp->next;
    }

    return SESMAN_SESSION_KILL_NOTFOUND;
}

/******************************************************************************/
void
session_sigkill_all(void)
{
    struct session_chain *tmp;

    tmp = g_sessions;

    while (g_sessions != 0)
    {
        session_leader_kill(&g_sessions->item.sl);
        tmp = g_sessions->next;
        g_free(g_sessions);
        g_sessions = tmp;
    }
}

/******************************************************************************/
struct session_item *
session_get_bypid(int pid)
{
    struct session_chain *tmp;
    struct session_item *dummy;

    dummy = g_new0(struct session_item, 1);

    if (0 == dummy)
    {
        log_message(LOG_LEVEL_ERROR, "session_get_bypid: out of memory");
        return 0;
    }

    tmp = g_sessions;

    while (tmp != 0)
    {
        if (tmp->item.sl.pid == pid)
        {
            g_memcpy(dummy, &tmp->item, sizeof(struct session_item));
            return dummy;
        }

        /* go on */
        tmp = tmp->next;
    }

    g_free(dummy);
    return 0;
}

/******************************************************************************/
struct SCP_DISCONNECTED_SESSION *
session_get_byuser(const char *user, int *cnt, unsigned char flags)
{
    struct session_chain *tmp;
    struct SCP_DISCONNECTED_SESSION *sess;
    int count;
    int index;

    count = 0;

    tmp = g_sessions;

    while (tmp != 0)
    {
        LOG_DEVEL(LOG_LEVEL_DEBUG, "user: %s", user);

        if ((NULL == user) || (!g_strncasecmp(user, tmp->item.name, 256)))
        {
            LOG_DEVEL(LOG_LEVEL_DEBUG, "session_get_byuser: status=%d, flags=%d, "
                    "result=%d", (tmp->item.status), flags,
                    ((tmp->item.status) & flags));

            if ((tmp->item.status) & flags)
            {
                count++;
            }
        }

        /* go on */
        tmp = tmp->next;
    }

    if (count == 0)
    {
        (*cnt) = 0;
        return 0;
    }

    /* malloc() an array of disconnected sessions */
    sess = g_new0(struct SCP_DISCONNECTED_SESSION, count);

    if (sess == 0)
    {
        (*cnt) = 0;
        return 0;
    }

    tmp = g_sessions;
    index = 0;

    while (tmp != 0)
    {
/* #warning FIXME: we should get only disconnected sessions! */
        if ((NULL == user) || (!g_strncasecmp(user, tmp->item.name, 256)))
        {
            if ((tmp->item.status) & flags)
            {
                (sess[index]).SID = tmp->item.sl.pid;
                (sess[index]).type = tmp->item.type;
                (sess[index]).height = tmp->item.height;
                (sess[index]).width = tmp->item.width;
                (sess[index]).bpp = tmp->item.bpp;
/* #warning FIXME: setting idle times and such */
                /*(sess[index]).connect_time.year = tmp->item->connect_time.year;
                (sess[index]).connect_time.month = tmp->item->connect_time.month;
                (sess[index]).connect_time.day = tmp->item->connect_time.day;
                (sess[index]).connect_time.hour = tmp->item->connect_time.hour;
                (sess[index]).connect_time.minute = tmp->item->connect_time.minute;
                (sess[index]).disconnect_time.year = tmp->item->disconnect_time.year;
                (sess[index]).disconnect_time.month = tmp->item->disconnect_time.month;
                (sess[index]).disconnect_time.day = tmp->item->disconnect_time.day;
                (sess[index]).disconnect_time.hour = tmp->item->disconnect_time.hour;
                (sess[index]).disconnect_time.minute = tmp->item->disconnect_time.minute;
                (sess[index]).idle_time.year = tmp->item->idle_time.year;
                (sess[index]).idle_time.month = tmp->item->idle_time.month;
                (sess[index]).idle_time.day = tmp->item->idle_time.day;
                (sess[index]).idle_time.hour = tmp->item->idle_time.hour;
                (sess[index]).idle_time.minute = tmp->item->idle_time.minute;*/
                (sess[index]).conn_year = tmp->item.connect_time.year;
                (sess[index]).conn_month = tmp->item.connect_time.month;
                (sess[index]).conn_day = tmp->item.connect_time.day;
                (sess[index]).conn_hour = tmp->item.connect_time.hour;
                (sess[index]).conn_minute = tmp->item.connect_time.minute;
                (sess[index]).idle_days = tmp->item.idle_time.day;
                (sess[index]).idle_hours = tmp->item.idle_time.hour;
                (sess[index]).idle_minutes = tmp->item.idle_time.minute;

                index++;
            }
        }

        /* go on */
        tmp = tmp->next;
    }

    (*cnt) = count;
    return sess;
}

/******************************************************************************/
int
cleanup_sockets(int display)
{
    log_message(LOG_LEVEL_DEBUG, "cleanup_sockets:");
    char file[256];
    int error;

    error = 0;

    g_snprintf(file, 255, CHANSRV_PORT_OUT_STR, display);
    if (g_file_exist(file))
    {
        log_message(LOG_LEVEL_DEBUG, "cleanup_sockets: deleting %s", file);
        if (g_file_delete(file) == 0)
        {
            log_message(LOG_LEVEL_DEBUG,
                       "cleanup_sockets: failed to delete %s", file);
            error++;
        }
    }

    g_snprintf(file, 255, CHANSRV_PORT_IN_STR, display);
    if (g_file_exist(file))
    {
        log_message(LOG_LEVEL_DEBUG, "cleanup_sockets: deleting %s", file);
        if (g_file_delete(file) == 0)
        {
            log_message(LOG_LEVEL_DEBUG,
                       "cleanup_sockets: failed to delete %s", file);
            error++;
        }
    }

    g_snprintf(file, 255, XRDP_CHANSRV_STR, display);
    if (g_file_exist(file))
    {
        log_message(LOG_LEVEL_DEBUG, "cleanup_sockets: deleting %s", file);
        if (g_file_delete(file) == 0)
        {
            log_message(LOG_LEVEL_DEBUG,
                       "cleanup_sockets: failed to delete %s", file);
            error++;
        }
    }

    g_snprintf(file, 255, CHANSRV_API_STR, display);
    if (g_file_exist(file))
    {
        log_message(LOG_LEVEL_DEBUG, "cleanup_sockets: deleting %s", file);
        if (g_file_delete(file) == 0)
        {
            log_message(LOG_LEVEL_DEBUG,
                       "cleanup_sockets: failed to delete %s", file);
            error++;
        }
    }

    return error;

}
