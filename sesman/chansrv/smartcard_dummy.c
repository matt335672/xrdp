/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Laxmikant Rashinkar 2013 LK.Rashinkar@gmail.com
 * Copyright (C) Jay Sorg 2013 jay.sorg@gmail.com
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
 *
 */

/**
 * @file sesman/chansrv/smartcard_dummy.c
 *
 * smartcard redirection support
 *
 * This file is compiled if smartcard support is not required
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "log.h"
#include "smartcard.h"

int
scard_get_wait_objs(tbus *objs, int *count, int *timeout)
{
    return 0;
}

int
scard_check_wait_objs(void)
{
    return 0;
}

int
scard_init(void)
{
    LOG(LOG_LEVEL_WARNING, "This build does not support smartcards");
    return 1;  // Tells the caller not to use this module
}

int
scard_deinit(void)
{
    return 0;
}

void
scard_device_announce(tui32 device_id)
{
}
