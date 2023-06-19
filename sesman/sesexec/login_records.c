/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Matt Burt 2023
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
 * @file login_records.c
 * @brief Update operating system records in utmpx, wtmp, etc
 * @author Matt Burt
 *
 */

/* Linux needs _GNU_SOURCE to see the ut_exit members */
#if defined (__linux) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#if defined(HAVE_CONFIG_H)
#include "config_ac.h"
#endif

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "login_records.h"

#ifdef USE_UTMPX
#include <utmpx.h>
#include <sys/time.h>

#include "login_info.h"
#include "os_calls.h"
#endif

#if defined(USE_UTMPX)
/******************************************************************************/
/* This is like strncpy(), but based on memcpy(), so compilers and static
 * analyzers do not complain when sizeof(destination) is the same as 'n' and
 * result is not terminated by zero.
 *
 * Use this function to copy string to logs with fixed sizes (wtmp/utmp. ...)
 * where string terminator is optional.
 *
 * Taken from util-linux/include/strutils.h (public domain)
 */
static inline void *__attribute__((nonnull (1)))
str2memcpy(void *dest, const char *src, size_t n)
{
    size_t bytes = strlen(src) + 1;

    if (bytes > n)
    {
        bytes = n;
    }

    memcpy(dest, src, bytes);
    return dest;
}

/******************************************************************************/
/***
 * Update the utmpx file
 *
 * @param login_info Info about logged-in user. NULL if session is ending
 * @param display Display number
 * @param pid PID of session
 * @param e exit status, or NULL if session is starting
 */
static void
update_utmpx(const struct login_info *login_info,
             unsigned int display, int pid,
             const struct g_exit_status *e)
{
    char idbuff[16];

    struct utmpx ut = {0};
    struct timeval now;

    /* Use the display number in hex for the very limited ut_id field */
    snprintf(idbuff, sizeof(idbuff), ":%x", display);

    /* POSIX fields */
    if (login_info != NULL)
    {
        snprintf(ut.ut_user, sizeof(ut.ut_user), "%s", login_info->username);
    }
    str2memcpy(ut.ut_id, idbuff, sizeof(ut.ut_id));
    snprintf(ut.ut_line, sizeof(ut.ut_line), ":%u", display);
    ut.ut_pid = pid;
    ut.ut_type = (login_info != NULL) ? USER_PROCESS : DEAD_PROCESS;
    // Linux has some compatibility code which means this cannot be
    // done in a single step.
    gettimeofday(&now, NULL);
    ut.ut_tv.tv_sec = now.tv_sec;
    ut.ut_tv.tv_usec = now.tv_usec;

    /* Optional fields */
#ifdef HAVE_UTMPX_UT_HOST
    if (login_info != NULL)
    {
        snprintf(ut.ut_host, sizeof(ut.ut_host), "%s", login_info->ip_addr);
    }
#endif

#ifdef HAVE_UTMPX_UT_EXIT
    if (e != NULL && e->reason == E_XR_STATUS_CODE)
    {
        ut.ut_exit.e_exit = e->val;
    }
    else if (e != NULL && e->reason == E_XR_SIGNAL)
    {
        ut.ut_exit.e_termination = e->val;
    }
#endif

    setutxent();
    pututxline(&ut);
    endutxent();
}
#endif // USE_UTMPX

/******************************************************************************/
#if !defined(USE_UTMPX)
/* Dummy definition for systems not using utmpx */
static void
update_utmpx(const struct login_info *login_info,
             unsigned int display, int pid,
             const struct g_exit_status *e)
{
}
#endif

/******************************************************************************/
void
login_records_start_session(const struct login_info *login_info,
                            unsigned int display, int pid)
{
    update_utmpx(login_info, display, pid, NULL);
}

/******************************************************************************/
void
login_records_end_session(unsigned int display, int pid,
                          const struct g_exit_status *e)
{
    update_utmpx(NULL, display, pid, e);
}
