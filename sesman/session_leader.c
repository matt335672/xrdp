/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2015
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
 * @file session_leader.c
 * @brief Session leader main functions.
 *
 */

#if defined(HAVE_CONFIG_H)
#include "config_ac.h"
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#include <errno.h>

#include "os_calls.h"
#include "xrdp_sockets.h"
#include "list.h"
#include "config.h"
#include "auth.h"
#include "access.h"
#include "env.h"
#include "xauth.h"

#include "session_leader_api.h"

/**
 * Struct containing common strings used to start an X server
 */
struct x_server_config_strings_t
{
    char width[8];
    char height[8];
    char depth[8];
    char display[8];
    char authfile[256];
};


extern struct config_sesman *g_cfg; /* in sesman.c */

/* Session leader module statics */
static char *g_username;
static tbus g_authdata;
static char *g_client_ip;
static int g_x_server_pid;
static int g_window_manager_pid;
static int g_chansrv_pid;

/**
 * Creates a string consisting of all parameters that is hosted in the param list
 * @param self
 * @param outstr, allocate this buffer before you use this function
 * @param len the allocated len for outstr
 * @return
 */
static char *
dumpItemsToString(struct list *self, char *outstr, int len)
{
    int index;
    int totalLen = 0;

    g_memset(outstr, 0, len);
    if (self->count == 0)
    {
        g_writeln("List is empty");
    }

    for (index = 0; index < self->count; index++)
    {
        /* +1 = one space*/
        totalLen = totalLen + g_strlen((char *)list_get_item(self, index)) + 1;

        if (len > totalLen)
        {
            g_strcat(outstr, (char *)list_get_item(self, index));
            g_strcat(outstr, " ");
        }
    }

    return outstr ;
}

/******************************************************************************/
/**
 *
 * @brief checks if there's a server running on a display
 * @param display the display to check
 * @return 0 if there isn't a display running, nonzero otherwise
 *
 */
static int
x_server_running_check_ports(int display)
{
    char text[256];
    int x_running;
    int sck;

    g_sprintf(text, "/tmp/.X11-unix/X%d", display);
    x_running = g_file_exist(text);

    if (!x_running)
    {
        g_sprintf(text, "/tmp/.X%d-lock", display);
        x_running = g_file_exist(text);
    }

    if (!x_running) /* check 59xx */
    {
        if ((sck = g_tcp_socket()) != -1)
        {
            g_sprintf(text, "59%2.2d", display);
            x_running = g_tcp_bind(sck, text);
            g_tcp_close(sck);
        }
    }

    if (!x_running) /* check 60xx */
    {
        if ((sck = g_tcp_socket()) != -1)
        {
            g_sprintf(text, "60%2.2d", display);
            x_running = g_tcp_bind(sck, text);
            g_tcp_close(sck);
        }
    }

    if (!x_running) /* check 62xx */
    {
        if ((sck = g_tcp_socket()) != -1)
        {
            g_sprintf(text, "62%2.2d", display);
            x_running = g_tcp_bind(sck, text);
            g_tcp_close(sck);
        }
    }

    if (!x_running)
    {
        g_sprintf(text, XRDP_CHANSRV_STR, display);
        x_running = g_file_exist(text);
    }

    if (!x_running)
    {
        g_sprintf(text, CHANSRV_PORT_OUT_STR, display);
        x_running = g_file_exist(text);
    }

    if (!x_running)
    {
        g_sprintf(text, CHANSRV_PORT_IN_STR, display);
        x_running = g_file_exist(text);
    }

    if (!x_running)
    {
        g_sprintf(text, CHANSRV_API_STR, display);
        x_running = g_file_exist(text);
    }

    if (!x_running)
    {
        g_sprintf(text, XRDP_X11RDP_STR, display);
        x_running = g_file_exist(text);
    }

    return x_running;
}

/******************************************************************************/
/**
 *
 * @brief checks if there's a server running on a display
 * @param display the display to check
 * @return 0 if there isn't a display running, nonzero otherwise
 *
 */
static int
x_server_running(int display)
{
    char text[256];
    int x_running;

    g_sprintf(text, "/tmp/.X11-unix/X%d", display);
    x_running = g_file_exist(text);

    if (!x_running)
    {
        g_sprintf(text, "/tmp/.X%d-lock", display);
        x_running = g_file_exist(text);
    }

    return x_running;
}

/******************************************************************************/
static int
session_get_avail_display(void)
{
    int display;

    display = g_cfg->sess.x11_display_offset;

    while ((display - g_cfg->sess.x11_display_offset) <= g_cfg->sess.max_sessions)
    {
        if (!x_server_running_check_ports(display))
        {
            return display;
        }

        display++;
    }

    return 0;
}

/******************************************************************************/
static int
wait_for_xserver(int display)
{
    int i;

    /* give X a bit to start */
    /* wait up to 10 secs for x server to start */
    i = 0;

    while (!x_server_running(display))
    {
        i++;

        if (i > 40)
        {
            log_message(LOG_LEVEL_ERROR,
                        "X server for display %d startup timeout",
                        display);
            break;
        }

        g_sleep(250);
    }

    return 0;
}

/**************************************************************************//**
 * Implementation of session_leader_authenticate_user()
 *
 * @param username username
 * @param password password
 * @param client_ip IP address of client
 * @param[out] result of authentication
 * @return <0 for error (in errno)
 */
static bool_t
session_leader_authenticate_user_impl(const char *username,
                                      const char *password,
                                      const char *client_ip,
                                      bool_t *auth_result)
{
    int errorcode;

    g_username = g_strdup(username);
    g_client_ip = g_strdup(client_ip);

    if (g_username == NULL || g_client_ip == NULL)
    {
        return -1;
    }

    g_authdata = auth_userpass(username, password, &errorcode);
    if (!g_authdata)
    {
        log_message(LOG_LEVEL_INFO, "Authentication failed for user %s [%d]",
                    username, errorcode);
        *auth_result = 0;
        return 0;
    }


    if (1 != access_login_allowed(g_username))
    {
        log_message(LOG_LEVEL_INFO, "Group check failed for user %s",
                    username);
        *auth_result = 0;
        return 0;
    }

    log_message(LOG_LEVEL_INFO, "Authentication succeeded for user %s, pid %d",
                username, g_getpid());
    *auth_result = 1;
    return 0;
}

/******************************************************************************/

static int
window_manager_main(int display, const char *directory, const char *program)
{
    char text[256];

    env_set_user(g_username,
                     0,
                     display,
                     g_cfg->env_names,
                     g_cfg->env_values);
    wait_for_xserver(display);
    if (x_server_running(display))
    {
        if (directory[0] != 0)
        {
            g_set_current_dir(directory);
        }
        if (program[0] != 0)
        {
            log_message(LOG_LEVEL_DEBUG, 
                        "starting program with parameters: %s ",
                        program);
            if(g_strchr(program, ' ') != 0 || g_strchr(program, '\t') != 0)
            {
                const char *params[] = {"sh", "-c", program, NULL};
                g_execvp("/bin/sh", (char **)params);
            }
            else
            {
               g_execlp3(program, program, 0);
            }
            log_message(LOG_LEVEL_ALWAYS,
                        "error starting program %s for user %s - pid %d",
                        program, g_username, g_getpid());
        }
        /* try to execute user window manager if enabled */
        if (g_cfg->enable_user_wm)
        {
            g_snprintf(text, sizeof(text), "%s/%s",
                       g_getenv("HOME"), g_cfg->user_wm);
            if (g_file_exist(text))
            {
                g_execlp3(text, g_cfg->user_wm, 0);
                log_message(LOG_LEVEL_ALWAYS, "error starting user "
                            "wm for user %s - pid %d", g_username, g_getpid());
                /* logging parameters */
                log_message(LOG_LEVEL_DEBUG, "errno: %d, "
                            "description: %s", g_get_errno(), g_get_strerror());
                log_message(LOG_LEVEL_DEBUG, "execlp3 parameter "
                            "list:");
                log_message(LOG_LEVEL_DEBUG, "        argv[0] = %s",
                            text);
                log_message(LOG_LEVEL_DEBUG, "        argv[1] = %s",
                            g_cfg->user_wm);
            }
        }
        /* if we're here something happened to g_execlp3
           so we try running the default window manager */
        g_execlp3(g_cfg->default_wm, g_cfg->default_wm, 0);

        log_message(LOG_LEVEL_ALWAYS, "error starting default "
                     "wm for user %s - pid %d", g_username, g_getpid());
        /* logging parameters */
        log_message(LOG_LEVEL_DEBUG, "errno: %d, description: "
                    "%s", g_get_errno(), g_get_strerror());
        log_message(LOG_LEVEL_DEBUG, "execlp3 parameter list:");
        log_message(LOG_LEVEL_DEBUG, "        argv[0] = %s",
                    g_cfg->default_wm);
        log_message(LOG_LEVEL_DEBUG, "        argv[1] = %s",
                    g_cfg->default_wm);

        /* still a problem starting window manager just start xterm */
        g_execlp3("xterm", "xterm", 0);

        /* should not get here */
        log_message(LOG_LEVEL_ALWAYS, "error starting xterm "
                    "for user %s - pid %d", g_username, g_getpid());
        /* logging parameters */
        log_message(LOG_LEVEL_DEBUG, "errno: %d, description: "
                    "%s", g_get_errno(), g_get_strerror());
    }
    else
    {
        log_message(LOG_LEVEL_ERROR, "another Xserver might "
                    "already be active on display %d - see log", display);
    }

    log_message(LOG_LEVEL_DEBUG, "aborting connection...");
    return 1;
}

/******************************************************************************/
static int
fork_window_manager(int display, const char *directory, const char *program)
{
    int pid = g_fork();
    if (pid == 0)
    {
        int status = window_manager_main(display, directory, program);
        g_exit(status);
    }

    return pid;
}

/******************************************************************************/
static void
dump_x_server_params(const struct list *xserver_params)
{
    int i;
    /* should not get here */
    log_message(LOG_LEVEL_ALWAYS, "error starting X server "
                "- user %s - pid %d", g_username, g_getpid());

    /* logging parameters */
    log_message(LOG_LEVEL_DEBUG, "errno: %d, description: "
                "%s", g_get_errno(), g_get_strerror());
    log_message(LOG_LEVEL_DEBUG, "execve parameter list size: "
                "%d", (xserver_params)->count);

    for (i = 0; i < (xserver_params->count); i++)
    {
        log_message(LOG_LEVEL_DEBUG, "        argv[%d] = %s",
                    i, (char *)list_get_item(xserver_params, i));
    }
}

/******************************************************************************/

static void
exec_x_server_xorg(const struct x_server_config_strings_t *cfgstr)
{
    struct list *xserver_params = list_create();
    char **pp1 = NULL;
    char *xserver = NULL; /* absolute/relative path to executable */
    char execvpparams[2048];

    xserver_params->auto_free = 1;

    log_message(LOG_LEVEL_INFO, "starting Xorg session...");

#ifdef HAVE_SYS_PRCTL_H
    /*
     * Make sure Xorg doesn't run setuid root. Root access is not
     * needed. Xorg can fail when run as root and the user has no
     * console permissions.
     * PR_SET_NO_NEW_PRIVS requires Linux kernel 3.5 and newer.
     */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
    {
        log_message(LOG_LEVEL_WARNING,
                    "Failed to disable setuid on X server: %s",
                    g_get_strerror());
    }
#endif

    /* get path of Xorg from config */
    xserver = g_strdup((const char *)list_get_item(g_cfg->xorg_params, 0));

    /* these are the must have parameters */
    list_add_item(xserver_params, (tintptr) g_strdup(xserver));
    list_add_item(xserver_params, (tintptr) g_strdup(cfgstr->display));
    list_add_item(xserver_params, (tintptr) g_strdup("-auth"));
    list_add_item(xserver_params, (tintptr) g_strdup(cfgstr->authfile));

    /* additional parameters from sesman.ini file */
    list_append_list_strdup(g_cfg->xorg_params, xserver_params, 1);

    /* make sure it ends with a zero */
    list_add_item(xserver_params, 0);

    pp1 = (char **) xserver_params->items;

    dumpItemsToString(xserver_params, execvpparams, sizeof(execvpparams));
    log_message(LOG_LEVEL_INFO, "%s", execvpparams);

    /* some args are passed via env vars */
    g_setenv("XRDP_START_WIDTH", cfgstr->width, 1);
    g_setenv("XRDP_START_HEIGHT", cfgstr->height, 1);

    /* fire up Xorg */
    g_execvp(xserver, pp1);

    /* Shouldn't get here */
    dump_x_server_params(xserver_params);
    list_delete(xserver_params);
    g_free(xserver);
}

/******************************************************************************/
static void
exec_x_server_xvnc(const struct x_server_config_strings_t *cfgstr,
                   const char *guid_str,
                   const char *passwd_file)
{
    struct list *xserver_params = list_create();
    char **pp1 = NULL;
    char *xserver = NULL; /* absolute/relative path to executable */
    char geometry[32];
    char execvpparams[2048];

    xserver_params->auto_free = 1;
    g_snprintf(geometry, sizeof(geometry), "%sx%s",
             cfgstr->width, cfgstr->height);

    log_message( LOG_LEVEL_INFO, "starting Xvnc session...");
    env_check_password_file(passwd_file, guid_str);

    /* get path of Xvnc from config */
    xserver = g_strdup((const char *)list_get_item(g_cfg->vnc_params, 0));

    /* these are the must have parameters */
    list_add_item(xserver_params, (tintptr)g_strdup(xserver));
    list_add_item(xserver_params, (tintptr)g_strdup(cfgstr->display));
    list_add_item(xserver_params, (tintptr)g_strdup("-auth"));
    list_add_item(xserver_params, (tintptr)g_strdup(cfgstr->authfile));
    list_add_item(xserver_params, (tintptr)g_strdup("-geometry"));
    list_add_item(xserver_params, (tintptr)g_strdup(geometry));
    list_add_item(xserver_params, (tintptr)g_strdup("-depth"));
    list_add_item(xserver_params, (tintptr)g_strdup(cfgstr->depth));
    list_add_item(xserver_params, (tintptr)g_strdup("-rfbauth"));
    list_add_item(xserver_params, (tintptr)g_strdup(passwd_file));

    /* additional parameters from sesman.ini file */
    //config_read_xserver_params(SESMAN_SESSION_TYPE_XVNC,
    //                           xserver_params);
    list_append_list_strdup(g_cfg->vnc_params, xserver_params, 1);

    /* make sure it ends with a zero */
    list_add_item(xserver_params, 0);
    pp1 = (char **)xserver_params->items;
    dumpItemsToString(xserver_params, execvpparams, sizeof(execvpparams));
    log_message(LOG_LEVEL_INFO, "%s", execvpparams);
    g_execvp(xserver, pp1);

    /* Shouldn't get here */
    dump_x_server_params(xserver_params);
    list_delete(xserver_params);
    g_free(xserver);
}

/******************************************************************************/
static void
exec_x_server_xrdp(const struct x_server_config_strings_t *cfgstr)
{
    struct list *xserver_params = list_create();
    char **pp1 = NULL;
    char *xserver = NULL; /* absolute/relative path to executable */
    char geometry[32];
    char execvpparams[2048];

    xserver_params->auto_free = 1;
    g_snprintf(geometry, sizeof(geometry), "%sx%s",
             cfgstr->width, cfgstr->height);

    log_message(LOG_LEVEL_INFO, "starting X11rdp session...");

    /* get path of X11rdp from config */
    xserver = g_strdup((const char *)list_get_item(g_cfg->rdp_params, 0));

    /* these are the must have parameters */
    list_add_item(xserver_params, (tintptr)g_strdup(xserver));
    list_add_item(xserver_params, (tintptr)g_strdup(cfgstr->display));
    list_add_item(xserver_params, (tintptr)g_strdup("-auth"));
    list_add_item(xserver_params, (tintptr)g_strdup(cfgstr->authfile));
    list_add_item(xserver_params, (tintptr)g_strdup("-geometry"));
    list_add_item(xserver_params, (tintptr)g_strdup(geometry));
    list_add_item(xserver_params, (tintptr)g_strdup("-depth"));
    list_add_item(xserver_params, (tintptr)g_strdup(cfgstr->depth));

    /* additional parameters from sesman.ini file */
    //config_read_xserver_params(SESMAN_SESSION_TYPE_XRDP,
    //                           xserver_params);
    list_append_list_strdup(g_cfg->rdp_params, xserver_params, 1);

    /* make sure it ends with a zero */
    list_add_item(xserver_params, 0);
    pp1 = (char **)xserver_params->items;
    dumpItemsToString(xserver_params, execvpparams, sizeof(execvpparams));
    log_message(LOG_LEVEL_INFO, "%s", execvpparams);
    g_execvp(xserver, pp1);

    /* Shouldn't get here */
    dump_x_server_params(xserver_params);
    list_delete(xserver_params);
    g_free(xserver);
}

/******************************************************************************/

static int
x_server_main(int display, enum sesman_sesstype_t type,
              int width, int height, char bpp, const char *guid_str)
{
    char *passwd_file = NULL;
    char text[256];
    const char *xauthority;

    struct x_server_config_strings_t cfgstr;

    if (type == SESMAN_SESSION_TYPE_XVNC)
    {
        env_set_user(g_username,
                     &passwd_file,
                     display,
                     g_cfg->env_names,
                     g_cfg->env_values);
    }
    else
    {
        env_set_user(g_username,
                     0,
                     display,
                     g_cfg->env_names,
                     g_cfg->env_values);
    }


    g_snprintf(text, sizeof(text), "%d", g_cfg->sess.max_idle_time);
    g_setenv("XRDP_SESMAN_MAX_IDLE_TIME", text, 1);
    g_snprintf(text, sizeof(text), "%d", g_cfg->sess.max_disc_time);
    g_setenv("XRDP_SESMAN_MAX_DISC_TIME", text, 1);
    g_snprintf(text, sizeof(text), "%d", g_cfg->sess.kill_disconnected);
    g_setenv("XRDP_SESMAN_KILL_DISCONNECTED", text, 1);
    g_setenv("XRDP_SOCKET_PATH", XRDP_SOCKET_PATH, 1);

    /* prepare the X server string arguments */
    g_snprintf(cfgstr.width, sizeof(cfgstr.width), "%d", width);
    g_snprintf(cfgstr.height, sizeof(cfgstr.height), "%d", height);
    g_snprintf(cfgstr.depth, sizeof(cfgstr.depth), "%d", bpp);
    g_snprintf(cfgstr.display, sizeof(cfgstr.display), "%d", display);

    xauthority = g_getenv("XAUTHORITY");
    if (xauthority == NULL)
    {
        xauthority = ".Xauthority";
    }
    g_snprintf(cfgstr.authfile, sizeof(cfgstr.authfile), "%s", xauthority);

    /* Add the entry in XAUTHORITY file */
    if (add_xauth_cookie(display, cfgstr.authfile) != 0)
    {
        /* Error should already be logged */
    }
    else if (type == SESMAN_SESSION_TYPE_XORG)
    {
        exec_x_server_xorg(&cfgstr);
    }
    else if (type == SESMAN_SESSION_TYPE_XVNC)
    {
        exec_x_server_xvnc(&cfgstr, guid_str, passwd_file);
    }
    else if (type == SESMAN_SESSION_TYPE_XRDP)
    {
        exec_x_server_xrdp(&cfgstr);
    }
    else
    {
        log_message(LOG_LEVEL_ALWAYS, "bad session type - "
                    "user %s - pid %d", g_username, g_getpid());
    }

    if (passwd_file)
    {
        g_free(passwd_file);
    }

    return 1;
}
/******************************************************************************/
static int
fork_x_server(int display, enum sesman_sesstype_t type,
               int width, int height, char bpp, const char *guid_str)
{
    int pid = g_fork();
    if (pid == 0)
    {
        int status = x_server_main(display, type, width, height, bpp, guid_str);
        g_exit(status);
    }

    return pid;
}


/******************************************************************************/
static int
chansrv_main(int display)
{
    struct list *chansrv_params;
    char exe_path[262];

    chansrv_params = list_create();
    chansrv_params->auto_free = 1;

    /* building parameters */
    g_snprintf(exe_path, sizeof(exe_path), "%s/xrdp-chansrv",
               XRDP_SBIN_PATH);

    list_add_item(chansrv_params, (intptr_t) g_strdup(exe_path));
    list_add_item(chansrv_params, 0); /* mandatory */

    env_set_user(g_username, 0, display,
                 g_cfg->env_names,
                 g_cfg->env_values);

    /* executing chansrv */
    g_execvp(exe_path, (char **) (chansrv_params->items));
    /* should not get here */
    log_message(LOG_LEVEL_ALWAYS, "error starting chansrv "
                "- user %s - pid %d", g_username, g_getpid());
    list_delete(chansrv_params);
    return 1;
}

/******************************************************************************/
static int
fork_chansrv(int display)
{
    int pid = g_fork();
    if (pid == 0)
    {
        int status = chansrv_main(display);
        g_exit(status);
    }

    return pid;
}

/**************************************************************************//**
 * Implementation of session_leader_authenticate_user()
 *
 * @param sesstype session type
 * @param width Initial screen width
 * @param height Initial screen height
 * @param bpp bits-per-pixel
 * @param guid_str stringified GUID for session
 * @param[out] display Returned display number
 *
 * @return 0 if operation completed normally, -1 for error
 */
static int
session_leader_start_session_impl(enum sesman_sesstype_t sesstype,
                                  const char *directory,
                                  const char *program,
                                  int width, int height, char bpp,
                                  const char *guid_str,
                                  int *ret_display)
{
    bool_t success = 0;

    int display = session_get_avail_display();
    if (display == 0)
    {
        errno = ENOENT;
    }
    else
    {
        log_message(LOG_LEVEL_INFO, "Calling auth_start_session for"
                    " user %s, pid %d", g_username, g_getpid());
        auth_start_session(g_authdata, display);
        auth_set_env(g_authdata);

        g_x_server_pid = fork_x_server(display, sesstype, width, height,
                                        bpp, guid_str);
        if (g_x_server_pid < 0)
        {
            log_message(LOG_LEVEL_ERROR, "Unable to fork() X server [%s]", g_get_strerror());
        }
        else
        {
            wait_for_xserver(display);
            g_window_manager_pid = fork_window_manager(display, directory,
                                                        program);
            if (g_window_manager_pid < 0)
            {
                log_message(LOG_LEVEL_ERROR, "Unable to fork() window manager [%s]", g_get_strerror());
                g_sigterm(g_x_server_pid);
            }
            else
            {
                g_chansrv_pid = fork_chansrv(display);
                if (g_window_manager_pid < 0)
                {
                    log_message(LOG_LEVEL_WARNING, "Unable to fork() chansrv [%s]", g_get_strerror());
                }
                success = 1;
            }
        }
    }

    if (success)
    {
        *ret_display = display;
    }
    return success;
}

int
session_leader_main(xak_connection *conn, int sck)
{
    int robjs_count;
    tbus robjs[8];
    tbus sck_obj;

    struct sl_dispatch_table_t dtable = {0};

    /* Initialise the dispatch table for incoming messages */
    dtable.start_session = session_leader_start_session_impl;
    dtable.authenticate_user = session_leader_authenticate_user_impl;

    sck_obj = g_create_wait_obj_from_socket(sck, 0);
    robjs_count = 0;
    robjs[robjs_count++] = sck_obj;

    while(1)
    {
        /* status = */ g_obj_wait(robjs, robjs_count, 0, 0, -1);
        if (g_is_wait_obj_set(sck_obj))
        {
            session_leader_srv_process_message(conn, &dtable);
        }
    }
#if 0
    log_message(LOG_LEVEL_ALWAYS, "waiting for window manager "
                "(pid %d) to exit", window_manager_pid);
    g_waitpid(window_manager_pid);
    log_message(LOG_LEVEL_ALWAYS, "window manager (pid %d) did "
                "exit, cleaning up session", window_manager_pid);
    log_message(LOG_LEVEL_INFO, "calling auth_stop_session and "
                "auth_end from pid %d", g_getpid());
    auth_stop_session(g_authdata);
    auth_end(g_authdata);
    g_sigterm(display_pid);
    g_sigterm(chansrv_pid);
    cleanup_sockets(display);
    g_deinit();
    g_exit(0);
#endif

    return 0;
}
