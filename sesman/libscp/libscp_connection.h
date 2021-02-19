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
 * @file libscp_connection.h
 * @brief SCP_CONNECTION handling code
 * @author Simone Fedele
 *
 */

#ifndef LIBSCP_CONNECTION_H
#define LIBSCP_CONNECTION_H

#include "libscp.h"

/**
 *
 * @brief Maps SCP_CLIENT_TYPES_E to a string
 * @param e
 *
 * @return Pointer to a string
 *
 */
const char *scp_client_state_to_str(SCP_CLIENT_STATES_E e);

/**
 *
 * @brief Maps a port definition to a UNIX domain socket path
 * @param port Port definition (e.g. from sesman.ini)
 * @param buff Buffer for result
 * @param bufflen Length of buff
 *
 * @return Number of chars needed for result, excluding the '\0'
 *
 */
int
scp_port_to_unix_domain_path(const char *port, char *buff,
                             unsigned int bufflen);

#endif
