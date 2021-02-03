/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2012
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
 * @file libscp_connection.c
 * @brief SCP_CONNECTION handling code
 * @author Simone Fedele
 *
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "libscp_connection.h"
#include "string_calls.h"
#include "xrdp_sockets.h"

int
scp_port_to_unix_domain_path(const char *port, char *buff,
                             unsigned int bufflen)
{
    int result;
    if (port[0] == '/')
    {
        result = g_snprintf(buff, bufflen, "%s", port);
    }
    else
    {
        if (port[0] == '\0')
        {
            port = SCP_LISTEN_PORT_BASE_STR;
        }
        result = g_snprintf(buff, bufflen, SESMAN_RUNTIME_PATH "/%s", port);
    }

    return result;
}
