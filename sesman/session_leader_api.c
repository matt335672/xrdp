/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2013
 *
 * BSD process grouping by:
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland.
 * Copyright (c) 2000-2001 Markus Friedl.
 * Copyright (c) 2011-2015 Koichiro Iwao, Kyushu Institute of Technology.
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
 * @file session_leader_api.c
 * @brief Client/server functions for the session leader API
 *
 */

#if defined(HAVE_CONFIG_H)
#include "config_ac.h"
#endif

#include <errno.h>

#include "session_leader_api.h"
#include "xak.h"
#include "os_calls.h"
#include "log.h"

enum
{
    SL_API_AUTHENTICATE_USER = 0,
    SL_API_START_SESSION
};

#define ELEMENTS(x) (sizeof(x) / sizeof(x[0]))

/* Forward function definitions */
static int
dispatch_authenticate_user(xak_message *m, void *userdata,
                           xak_error *ret_error);
static int
dispatch_start_session(xak_message *m, void *userdata,
                       xak_error *ret_error);

static xak_dispatch_table_entry sl_dispatch_table[] =
{
    { SL_API_AUTHENTICATE_USER, dispatch_authenticate_user },
    { SL_API_START_SESSION, dispatch_start_session }
};

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
/*
 * FreeBSD bug
 * ports/157282: effective login name is not set by xrdp-sesman
 * http://www.freebsd.org/cgi/query-pr.cgi?pr=157282
 *
 * from:
 *  $OpenBSD: session.c,v 1.252 2010/03/07 11:57:13 dtucker Exp $
 *  with some ideas about BSD process grouping to xrdp
 *
 *  Extra process added for #1016. Needed to catch SIGCHLD from
 *  process group underneath
 */
static void
create_freebsd_intermediate_process(int child_fd)
{
    pid_t bsdsespid = g_fork();

    if (bsdsespid == -1)
    {
        log_message(LOG_LEVEL_ERROR,
                    "g_fork() failed - pid %d", g_getpid());
        g_exit(1);
    }

    if (bsdsespid > 0) /* Intermediate process */
    {
        g_sck_close(child_fd);
        g_waitpid(bsdsespid);
        g_exit(0);
    }

    /**
     * Create a new session and process group since the 4.4BSD
     * setlogin() affects the entire process group
     */
    if (g_setsid() < 0)
    {
        log_message(LOG_LEVEL_ERROR,
                    "setsid failed - pid %d", g_getpid());
    }

    if (g_setlogin(g_username) < 0)
    {
        log_message(LOG_LEVEL_ERROR,
                    "setlogin failed for user %s - pid %d",
                    g_username, g_getpid());
    }
}
#endif

/*****************************************************************************/

int
session_leader_start(struct session_leader_t *sl,
                     void (*sl_init)(void),
                     int (*sl_main)(xak_connection *, int))
{
    int fds[2];
    int result = -1;
    xak_connection *conn;

    if (g_stream_socketpair(fds) >= 0)
    {
        int pid = g_fork();

        if (pid < 0)
        {
            int e = errno; /* Save errno for the caller */
            g_sck_close(fds[0]);
            g_sck_close(fds[1]);
            errno = e;
        }
        else if (pid == 0)
        {
            /* Child process */
            g_sck_close(fds[0]);
            if (sl_init != NULL)
            {
                (*sl_init)();
            }
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
            create_freebsd_intermediate_process(fds[1]);
#endif
            conn = xak_connection_create(fds[1],
                                         ELEMENTS(sl_dispatch_table),
                                         sl_dispatch_table);
            if (conn != NULL)
            {
                result = (*sl_main)(conn, fds[1]);
            }
            else
            {
                result = 1;
            }
            g_exit(result);
        }
        else
        {
            conn = xak_connection_create(fds[0], 0, NULL);
            g_sck_close(fds[1]);
            if (conn != NULL)
            {
                sl->pid = pid;
                sl->fd = fds[0];
                sl->c = conn;
                result = 0;
            }
            else
            {
                int e = errno; /* Save errno for the caller */
                g_sck_close(fds[0]);
                errno = e;
            }
        }
    }

    return result;
}

/*****************************************************************************/
int
session_leader_authenticate_user(struct session_leader_t *sl,
                                 const char *username, const char *password,
                                 const char *client_ip,
                                 bool_t *caller_result)
{
    int r;
    xak_error error = XAK_ERROR_NULL;
    xak_message *reply = NULL;

    r = xak_call_method( sl->c, SL_API_AUTHENTICATE_USER,
                         &error, &reply,
                         "sss", username, password, client_ip);
    if (r < 0)
    {
        log_message(LOG_LEVEL_ERROR, "Failed to authenticate user: %s",
                    xak_error_message(&error, r));
    }
    else if ((r = xak_message_read(reply, "b", caller_result)) < 0)
    {
        log_message(LOG_LEVEL_ERROR, "Failed to parse message: %s",
                    g_strerror(abs(r)));
    }
    else
    {
        r = 0;
    }
    xak_error_free(&error);
    xak_message_unref(reply);

    return r;
}

/*****************************************************************************/
static
int dispatch_authenticate_user(xak_message *m, void *userdata,
                               xak_error *ret_error)
{
    const char *username;
    const char *password;
    const char *client_ip;
    int r;

    r = xak_message_read(m, "sss", &username, &password, &client_ip);
    if (r < 0)
    {
        LOG(LOG_LEVEL_ERROR, "Failed to read message: %s",
            g_strerror(abs(r)));
    }
    else
    {
        bool_t auth_result;
        struct sl_dispatch_table_t *dt =
            (struct sl_dispatch_table_t *)(userdata);
        r = dt->authenticate_user(username, password, client_ip, &auth_result);
        if (r < 0)
        {
            xak_error_setf(ret_error, "authenticate_user returned %s",
                           g_strerror(errno));
        }
        else
        {
            r = xak_reply_method_return(m, "b", auth_result);
        }
    }

    return r;
}

/*****************************************************************************/
int
session_leader_start_session(struct session_leader_t *sl,
                             enum sesman_sesstype_t sesstype,
                             const char *directory,
                             const char *program,
                             int width, int height, char bpp,
                             const char *guid_str,
                             int *display)
{
    int r;
    uint32_t rdisplay;

    xak_error error = XAK_ERROR_NULL;
    xak_message *reply = NULL;

    r = xak_call_method(sl->c, SL_API_START_SESSION,
                        &error, &reply,
                        "yqqysss",
                        (uint8_t)sesstype,
                        (uint16_t)width,
                        (uint16_t)height,
                        (uint8_t)bpp,
                        directory,
                        program,
                        guid_str);
    if (r < 0)
    {
        log_message(LOG_LEVEL_ERROR, "Failed to start session: %s",
                    xak_error_message(&error, r));
    }
    else if ((r = xak_message_read(reply, "u", &rdisplay)) < 0)
    {
        log_message(LOG_LEVEL_ERROR, "Failed to parse message: %s",
                    g_strerror(abs(r)));
    }
    else
    {
        *display = rdisplay;
    }
    xak_error_free(&error);
    xak_message_unref(reply);

    return r;
}

/*****************************************************************************/
static
int dispatch_start_session(xak_message *m, void *userdata,
                           xak_error *ret_error)
{
    int r;
    uint8_t sesstype;
    uint16_t width;
    uint16_t height;
    uint8_t bpp;
    const char *directory;
    const char *program;
    const char *guid_str;

    r = xak_message_read(m, "yqqysss",
                         &sesstype,
                         &width,
                         &height,
                         &bpp,
                         &directory,
                         &program,
                         &guid_str);
    if (r < 0)
    {
        LOG(LOG_LEVEL_ERROR, "Failed to read message: %s",
            g_strerror(abs(r)));
    }
    else
    {
        int ret_display;
        struct sl_dispatch_table_t *dt =
            (struct sl_dispatch_table_t *)(userdata);
        r = dt->start_session(sesstype, directory, program,
                              width, height, bpp, guid_str, &ret_display);
        if (r < 0)
        {
            xak_error_setf(ret_error, "authenticate_user returned %s",
                           g_strerror(errno));
        }
        else
        {
            r = xak_reply_method_return(m, "u", ret_display);
        }
    }

    return r;
}


/*****************************************************************************/
void
session_leader_kill(struct session_leader_t *sl)
{
}

/*****************************************************************************/
int
session_leader_srv_process_message(
    xak_connection *conn,
    const struct sl_dispatch_table_t *dispatch_table)
{
    int r = xak_connection_read(conn);
    while ( r >= 0 && xak_connection_queue_count(conn) > 0)
    {
        r = xak_connection_dispatch_message(conn);
    }
    return r;
}
