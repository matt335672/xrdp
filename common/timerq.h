/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2025
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
 * @file common/timerq.h
 * @brief Implementation of a timer queue (declarations)
 * @author Matt Burt
  */

#ifndef TIMERQ_H
#define TIMERQ_H

#include "arch.h"

struct timerq;

/**
 * Initialise a timer queue
 * @return pointer to queue, or NULL of no memory
 */
struct timerq *
timerq_init(void);

/**
 * Add an event to a timer queue
 * @param timerq Timer queue
 * @param trigger_time number of milliseconds in future to trigger event
 * @param closure Pointer to pass to the timer event
 * @param callback Callback for event
 *
 * @return Event ID ( >= 0) or -1 for no memory
 */
long
timerq_add_event(struct timerq *timerq,
                 int trigger_time,
                 void *closure,
                 int (*callback)(void *closure, struct timerq *timerq));

/**
 * Remove an event from a timer queue
 * @param timerq Timer queue
 * @param event_id Event ID returned from timerq_add_event
 */
void
timerq_cancel_event(struct timerq *timerq,
                    long event_id);

/**
 * Delete a timer queue
 * @param timerq Timer queue
 * Any queued events are canceled without being fired
 */
void
timerq_delete(struct timerq *timerq);

/**
 * Fire events on a timer queue
 * @param timerq Timer queue
 * @return First non-zero value from any of the callbacks
 * Callbacks are fired for any events which have become due
 */
int
timerq_fire_events(struct timerq *timerq);

/**
 * Get the time remaining until the next event is due on a timer queue
 * @param timerq Timer queue
 * @return milliseconds to next event (>= 0), or -1 if there are no events
 */
int
timerq_time_to_next_event(struct timerq *timerq);

#endif // TIMERQ_H
