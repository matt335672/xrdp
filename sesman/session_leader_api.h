/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2013
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
 * @file session_leader_api.h
 * @brief Client/server functions for the session leader API
 * @author Jay Sorg, Simone Fedele
 *
 */


#ifndef SESSION__LEADER_H
#define SESSION__LEADER_H

#include "arch.h"

/* Dont need the details of this one */
typedef struct xak_connection xak_connection;

struct session_leader_t
{
    int pid;
    int fd;
    xak_connection *c;
};

/* Initialiser for a session_leader_t */
#define INIT_SL(sl) { (sl)->pid = -1 ; (sl)->fd = -1; (sl)->c = NULL; }

enum sesman_sesstype_t
{
    SESMAN_SESSION_TYPE_XRDP = 1,
    SESMAN_SESSION_TYPE_XVNC,
    SESMAN_SESSION_TYPE_XORG
};

struct sl_dispatch_table_t
{
    bool_t (*authenticate_user)(const char *username, const char *password,
                                const char *client_ip,
                                bool_t *auth_result);

    int (*start_session)(enum sesman_sesstype_t sesstype,
                         const char *directory,
                         const char *program,
                         int width, int height, char bpp,
                         const char *guid_str,
                         int *ret_display);
};

/**
 *
 * @brief starts a session leader process
 *
 * This is a client-side function
 *
 * @param sl session leader data block
 * @param sl_init Session leader init function. Called from sub-process
 *                before main to close file descriptors inherited from the
 *                parent. Can ~e NULL;
 * @param sl_main Session leader main function (called from sub-process)
 * @return <0 for error or 0 for OK
 */
int
session_leader_start(struct session_leader_t *sl,
                     void (*sl_init)(void),
                     int (*sl_main)(xak_connection *conn, int sck));

/**
 *
 * @brief Authenticate a user in the session leader
 *
 * This is a client-side function
 *
 * If authentication fails, the session leader has exited and cannot be used
 * again
 *
 * @param sl session leader
 * @param username username
 * @param password password
 * @param client_ip IP address of client
 * @param[out] result Address of result variable
 * @return 0 if operation completed normally, -1 for error
 */
int
session_leader_authenticate_user(struct session_leader_t *sl,
                                 const char *username, const char *password,
                                 const char *client_ip,
                                 bool_t *result);

/**
 *
 * @brief Start a session in the session leader
 *
 * This is a client-side function
 *
 * On a successful return, display is always set to a non-zero value.
 *
 * If the call fails, the session leader has exited and cannot be used
 * again
 *
 * @param sl session leader
 * @param sesstype session type
 * @param width Initial screen width
 * @param height Initial screen height
 * @param bpp bits-per-pixel
 * @param guid_str stringified GUID for session
 * @param[out] display Returned display number
 *
 * @return 0 if operation completed normally, <0 for an error. The absolute
 *           value of the return is an errno value. ENOENT is used to
 *           indicate no displays are available.
 */
int
session_leader_start_session(struct session_leader_t *sl,
                             enum sesman_sesstype_t sesstype,
                             const char *directory,
                             const char *program,
                             int width, int height, char bpp,
                             const char *guid_str,
                             int *display);
/**
 *
 * @brief kills a session leader
 *
 * This is a client-side function
 *
 * @param  sl session leader
 *
 */
void
session_leader_kill(struct session_leader_t *sl);

/*
 * Read an incoming message and process it
 *
 * This is a server-side function
 *
 * Note that the return from this function has nothing to do with the
 * value actually returned to the caller. A success here means that a
 * message was successfully sent to the caller.
 *
 * @param sck Incoming socket
 * @param dispatch_table Table of callbacks for incoming functions
 *
 * @return 0 for success, or -1 for error (error in errno)
 */

int
session_leader_srv_process_message(
    xak_connection *conn,
    const struct sl_dispatch_table_t *dispatch_table);

#endif /* SESSION_LEADER_H */
