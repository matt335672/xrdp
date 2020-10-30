/*
 * sesadmin.c - an sesman administration tool
 * (c) 2008 Simone Fedele
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "arch.h"
#include "tcp.h"
#include "parse.h"
#include "log.h"

#include <stdio.h>
#include <unistd.h>

#include "libscp_types.h"
#include "libscp_init.h"
#include "libscp_connection.h"
#include "libscp_session.h"
#include "libscp_v1c_mng.h"

void cmndList(struct SCP_CONNECTION *c);
void cmndHelp(void);

int main(int argc, char **argv)
{
    struct SCP_SESSION *s;
    struct SCP_CONNECTION *c;
    enum SCP_CLIENT_STATES_E e;
    int idx;
    int sock;
    struct log_config *logging = log_config_init_for_console();

    const char *cmnd = "";
    const char *serv = "localhost";
    const char *port = "3350";

    logging = log_config_init_for_console();
    log_start_from_param(logging);
    log_config_free(logging);

    for (idx = 1; idx < argc; idx++)
    {
        if (0 == g_strncmp(argv[idx], "-u=", 3))
        {
            /* Now ignored */
        }
        else if (0 == g_strncmp(argv[idx], "-p=", 3))
        {
            /* Now ignored */
        }
        else if (0 == g_strncmp(argv[idx], "-s=", 3))
        {
            serv = argv[idx] + 3;
        }
        else if (0 == g_strncmp(argv[idx], "-i=", 3))
        {
            port = argv[idx] + 3;
        }
        else if (0 == g_strncmp(argv[idx], "-c=", 3))
        {
            cmnd = argv[idx] + 3;
        }
        else
        {
            LOG(LOG_LEVEL_WARNING, "Unrecognised argument '%s'", argv[idx]);
        }
    }

    if (0 == g_strncmp(cmnd, "", 1))
    {
        cmndHelp();
        return 0;
    }

    scp_init();

    sock = g_tcp_socket();
    if (sock < 0)
    {
        LOG(LOG_LEVEL_DEBUG, "Socket open error, g_tcp_socket() failed");
        return 1;
    }

    s = scp_session_create();
    c = scp_connection_create(sock);

    LOG(LOG_LEVEL_DEBUG, "Connecting to %s:%s", serv, port);

    if (0 != g_tcp_connect(sock, serv, port))
    {
        LOG(LOG_LEVEL_DEBUG, "g_tcp_connect() error");
        return 1;
    }

    scp_session_set_type(s, SCP_SESSION_TYPE_MANAGE);
    scp_session_set_version(s, 1);

    e = scp_v1c_mng_connect(c, s);

    if (SCP_CLIENT_STATE_OK != e)
    {
        LOG(LOG_LEVEL_DEBUG, "libscp error connecting: %s %d", s->errstr, (int)e);
    }

    if (0 == g_strncmp(cmnd, "list", 5))
    {
        cmndList(c);
    }
    else
    {
        cmndHelp();
    }

    g_tcp_close(sock);
    scp_session_destroy(s);
    scp_connection_destroy(c);
    log_end();

    return 0;
}

void cmndHelp(void)
{
    fprintf(stderr, "sesadmin - a console sesman administration tool\n");
    fprintf(stderr, "syntax: sesadmin [] COMMAND [OPTIONS]\n\n");
    fprintf(stderr, "-s=<hostname>: sesman host (default is localhost)\n");
    fprintf(stderr, "-i=<port>    : sesman port (default 3350)\n");
    fprintf(stderr, "-c=<command> : command to execute on the server [MANDATORY]\n");
    fprintf(stderr, "               it can be one of those:\n");
    fprintf(stderr, "               list\n");
}

static void
print_session(const struct SCP_DISCONNECTED_SESSION *s)
{
    printf("Session ID: %d\n", s->SID);
    printf("\tSession type: %d\n", s->type);
    printf("\tScreen size: %dx%d, color depth %d\n",
           s->width, s->height, s->bpp);
    printf("\tIdle time: %d day(s) %d hour(s) %d minute(s)\n",
           s->idle_days, s->idle_hours, s->idle_minutes);
    printf("\tConnected: %04d/%02d/%02d %02d:%02d\n",
           s->conn_year, s->conn_month, s->conn_day, s->conn_hour,
           s->conn_minute);
}

void cmndList(struct SCP_CONNECTION *c)
{
    struct SCP_DISCONNECTED_SESSION *dsl;
    enum SCP_CLIENT_STATES_E e;
    int scnt;
    int idx;

    e = scp_v1c_mng_get_session_list(c, &scnt, &dsl);

    if (e != SCP_CLIENT_STATE_LIST_OK)
    {
        printf("Error getting session list.\n");
        return;
    }

    if (scnt > 0)
    {
        for (idx = 0; idx < scnt; idx++)
        {
            print_session(&dsl[idx]);
        }
    }
    else
    {
        printf("No sessions.\n");
    }

    g_free(dsl);
}

void cmndKill(struct SCP_CONNECTION *c, struct SCP_SESSION *s)
{

}
