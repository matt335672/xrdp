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

#if defined(HAVE_CONFIG_H)
#include "config_ac.h"
#endif

#include "os_calls.h"
#include "list.h"
#include "timerq.h"

struct timerq
{
    /**
     * Store events in reverse order, so the next one due to fire is the
     * last on the list. This makes removal easier */
    struct list *events;
    void *closure1;
    long next_event_id;
};

struct event
{
    unsigned int add_time;  // Time event was added from_g_get_elapsed_ms()
    int trigger_time;
    void *closure2;
    int (*callback)(void *closure1, void *closure2, struct timerq *timerq);
    long id;
};

/******************************************************************************/
struct timerq *
timerq_init(void *closure1)
{
    struct timerq *tq = (struct timerq *)malloc(sizeof(*tq));
    if (tq != NULL)
    {
        tq->events = list_create();
        if (tq->events != NULL)
        {
            tq->events->auto_free = 1;
            tq->closure1 = closure1;
            tq->next_event_id = 1;
        }
        else
        {
            free(tq);
            tq = NULL;
        }
    }
    return tq;
}

/******************************************************************************/
long
timerq_add_event(struct timerq *timerq,
                 int trigger_time,
                 void *closure2,
                 int (*callback)(void *closure1, void *closure2,
                                 struct timerq *timerq))
{
    long rv = -1;

    if (trigger_time < 0)
    {
        trigger_time = 0;
    }

    if (timerq != NULL)
    {
        struct event *event = (struct event *)malloc(sizeof(*event));
        if (event != NULL)
        {
            unsigned int now = g_get_elapsed_ms();

            // Fill in the new event
            event->add_time = now;
            event->trigger_time = trigger_time;
            event->closure2 = closure2;
            event->callback = callback;
            event->id = timerq->next_event_id++;

            // The list is in fire order, so the last event in the list
            // is the first to fire. This order makes it easy to remove
            // events when they fire.
            //
            // Find an event in the list which is going to fire before this one
            int i;
            struct event *b;
            for (i = 0; i < timerq->events->count; ++i)
            {
                b = (struct event *)list_get_item(timerq->events, i);
                int b_trigger = b->trigger_time - (int)(now - b->add_time);
                if (trigger_time > b_trigger)
                {
                    break; // Insert event before event 'b'
                }
            }

            if (list_insert_item(timerq->events, i, (tintptr)event))
            {
                rv = event->id;
            }
            else
            {
                free(event);
            }
        }
    }

    return rv;
}

/******************************************************************************/
void
timerq_cancel_event(struct timerq *timerq,
                    long event_id)
{
    if (timerq != NULL)
    {
        int i;
        for (i = 0; i < timerq->events->count; ++i)
        {
            struct event *event = (struct event *)list_get_item(timerq->events, i);
            if (event->id == event_id)
            {
                list_remove_item(timerq->events, i);
                break;
            }
        }
    }
}

/******************************************************************************/
void
timerq_delete(struct timerq *timerq)
{
    if (timerq != NULL)
    {
        free(timerq->events);
        free(timerq);
    }
}

/******************************************************************************/
int
timerq_fire_events(struct timerq *timerq)
{
    int rv = 0;

    while (timerq != NULL && timerq->events->count > 0)
    {
        // Look at the last event on the queue (which is the first to fire)
        int i = (timerq->events->count - 1);
        struct event *event = (struct event *)list_get_item(timerq->events, i);

        unsigned int now = g_get_elapsed_ms();
        if (event->trigger_time > (int)(now - event->add_time))
        {
            // This event isn't ready, and as this is the soonest one
            // to trigger we don't have to look further.
            break;
        }

        // Remove the event before the callback (potentially)
        // messes with the queue
        void *closure2 = event->closure2;
        int (*callback)(void *, void *, struct timerq *) = event->callback;
        list_remove_item(timerq->events, i);

        // Call the callback.
        int callback_rv = (*callback)(timerq->closure1, closure2, timerq);
        if (rv == 0)
        {
            rv = callback_rv;
        }
    }

    return rv;
}

/******************************************************************************/
int
timerq_time_to_next_event(struct timerq *timerq)
{
    int rv = -1;
    if (timerq != NULL && timerq->events->count > 0)
    {
        int i = (timerq->events->count - 1);
        // Look at the last event on the queue (which is the first to fire)
        struct event *event = (struct event *)list_get_item(timerq->events, i);
        unsigned int now = g_get_elapsed_ms();
        int remaining = event->trigger_time - (int)(now - event->add_time);
        // If the event is overdue, return a zero time remaining
        rv = (remaining < 0) ? 0 : remaining;
    }
    return rv;
}
