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
 * @file login_records.h
 * @brief Update operating system records in utmpx, wtmp, etc
 * @author Matt Burt
 *
 */

#ifndef LOGIN_RECORDS_H
#define LOGIN_RECORDS_H

struct login_info;
struct g_exit_status;

/**
 * Inform utmpx/wtmp, etc a session has started
 *
 * @param user Name of user
 * @param display Display number
 * @param pid PID of session
 */
void
login_records_start_session(const struct login_info *login_info,
                            unsigned int display, int pid);


/**
 * Inform utmpx/wtmp, etc a session has ended
 *
 * @param display Display number
 * @param pid PID of session
 * @param e exit status of session
 */
void
login_records_end_session(unsigned int display, int pid,
                          const struct g_exit_status *e);

#endif // LOGIN_RECORDS_H
