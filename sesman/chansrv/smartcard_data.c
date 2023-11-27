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
 * @file sesman/chansrv/smartcard_data.c
 *
 * smartcard redirection support
 *
 * This file implements state data storage, primarily for converting
 * data types used by [MS-RDPESC] into 32-bit ints.
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "arch.h"
#include "list.h"
#include "log.h"
#include "os_calls.h"

#include "smartcard_data.h"

struct card_mapping
{
    unsigned int app_context;  /* application context, always 4 byte */
    unsigned int app_hcard;  /* application card handle, always 4 byte */
    struct redir_scardhandle hcard; /* redirector card handle */
};

struct context_mapping
{
    unsigned int app_context;  /* application context, always 4 byte */
    struct redir_scardcontext context; /* Redirector context */
};

#define MAX_CB_DATA_KEYS 5 // Increase as required
struct scard_client
{
    unsigned int client_id;
    struct list *contexts;
    struct list *cards;
    void *cb_data[MAX_CB_DATA_KEYS];
};

static unsigned int g_autoinc = 0; /* general purpose autoinc */

static struct list *g_scard_clients = 0;

/*****************************************************************************/
int
scard_data_init(void)
{
    return 0;
}

/*****************************************************************************/
int
scard_data_deinit(void)
{
    return 0;
}

/*****************************************************************************/
/**
 * Destroys a particular client without disturbing the clients list
 * @param client to destroy
 */
static void
destroy_client(struct scard_client *client)
{
    if (client != NULL)
    {
        list_delete(client->contexts);
        list_delete(client->cards);
        free(client);
    }
}

/*****************************************************************************/
struct scard_client *
scdata_create_client(void)
{
    struct scard_client *client = g_new0(struct scard_client, 1);
    if (client != NULL)
    {
        client->client_id = ++g_autoinc;
        if ((client->contexts = list_create()) == NULL)
        {
            destroy_client(client);
            client = NULL;
        }
        else if ((client->cards = list_create()) == NULL)
        {
            destroy_client(client);
            client = NULL;
        }
        else
        {
            client->contexts->auto_free = 1;
            client->cards->auto_free = 1;

            if (g_scard_clients == NULL &&
                    (g_scard_clients = list_create()) == NULL)
            {
                destroy_client(client);
                client = NULL;
            }
            else if (!list_add_item(g_scard_clients, (tbus)client))
            {
                destroy_client(client);
                client = NULL;
            }
        }
    }
    return client;
}

/*****************************************************************************/
void
scdata_destroy_client(struct scard_client *client)
{
    if (g_scard_clients != NULL)
    {
        int index = list_index_of(g_scard_clients, (tintptr)client);
        if (index >= 0)
        {
            list_remove_item(g_scard_clients, index);
            destroy_client(client);
        }
    }
}

/*****************************************************************************/
unsigned int
scdata_get_client_id(struct scard_client *client)
{
    return (client != NULL) ? client->client_id : 0;
}

/*****************************************************************************/
struct scard_client *
scdata_get_client_from_id(unsigned int client_id)
{
    if (g_scard_clients != NULL)
    {
        int index;
        for (index = 0 ; index < g_scard_clients->count ; ++index)
        {
            struct scard_client *sc;
            sc = (struct scard_client *)list_get_item(g_scard_clients, index);

            if (sc->client_id == client_id)
            {
                return sc;
            }
        }
    }

    return NULL;
}

/*****************************************************************************/
void *
scdata_get_client_cb_data(struct scard_client *client, unsigned char key)
{
    void *rv = NULL;

    if (key >= MAX_CB_DATA_KEYS)
    {
        LOG(LOG_LEVEL_ERROR,
            "Key value %d out-of-range for scdata_get_client_cb_data()", key);
    }
    else
    {
        rv = client->cb_data[key];
    }

    return rv;
}

/*****************************************************************************/
void
scdata_set_client_cb_data(struct scard_client *client,
                          unsigned char key,
                          void *value)
{
    if (key >= MAX_CB_DATA_KEYS)
    {
        LOG(LOG_LEVEL_ERROR,
            "Key value %d out-of-range for scdata_set_client_cb_data()", key);
    }
    else
    {
        client->cb_data[key] = value;
    }
}

/*****************************************************************************/
int
scdata_add_context_mapping(struct scard_client *client,
                           const struct redir_scardcontext *Context,
                           unsigned int *app_context)
{
    int rv = 0;

    struct context_mapping *cm;
    if ((cm = g_new0(struct context_mapping, 1)) != NULL)
    {
        cm->app_context = ++g_autoinc;
        cm->context = *Context;
        if (list_add_item(client->contexts, (tintptr)cm))
        {
            *app_context = cm->app_context;
            rv = 1;
        }
    }

    if (!rv)
    {
        LOG(LOG_LEVEL_ERROR, "Out of memory adding context mapping");
    }

    return rv;
}


/*****************************************************************************/
/**
 * Local procedure to look up a context mapping
 * @param client client
 * @param app_context Application context to look up
 * @param[out] index Index of context in the global list (may be NULL)
 * @return Context mapping type, or NULL for no mapping
 */
static struct context_mapping *
find_cm(struct scard_client *client, unsigned int app_context, int *index)
{
    int i;
    for (i = 0 ; i < client->contexts->count; ++i)
    {
        struct context_mapping *cm;
        cm = (struct context_mapping *)list_get_item(client->contexts, i);
        if (cm->app_context == app_context)
        {
            if (index != NULL)
            {
                *index = i;
            }
            return cm;
        }
    }
    return NULL;
}

/*****************************************************************************/
/**
 * Local procedure to look up a card mapping
 * @param client client
 * @param app_hcard Application card handle to look up
 * @param[out] index Index of card in the context mapping card list
 * @return card mapping type, or NULL for no mapping
 */
static struct card_mapping *
find_crdm(struct scard_client *client, unsigned int app_hcard, int *index)
{
    int i;
    for (i = 0 ; i < client->cards->count; ++i)
    {
        struct card_mapping *crdm;
        crdm = (struct card_mapping *)list_get_item(client->cards, i);
        if (crdm->app_hcard == app_hcard)
        {
            if (index != NULL)
            {
                *index = i;
            }
            return crdm;
        }
    }
    return NULL;
}

/*****************************************************************************/
void
scdata_remove_context_mapping(struct scard_client *client,
                              unsigned int app_context)
{
    int i;
    struct context_mapping *cm;
    if ((cm = find_cm(client, app_context, &i)) != NULL)
    {
        list_remove_item(client->contexts, i);
    }
}

/*****************************************************************************/
int
scdata_lookup_context_mapping(struct scard_client *client,
                              unsigned int app_context,
                              struct redir_scardcontext *Context)
{
    int rv = 0;

    struct context_mapping *cm;
    if ((cm = find_cm(client, app_context, NULL)) != NULL)
    {
        *Context = cm->context;
        rv = 1;
    }
    return rv;
}

/*****************************************************************************/
unsigned int
scdata_context_mapping_count(struct scard_client *client)
{
    return client->contexts->count;
}

/*****************************************************************************/
unsigned int
scdata_get_all_context_mapping(struct scard_client *client,
                               unsigned int max_entries,
                               unsigned int indexes[])
{
    int i;
    for (i = 0 ; i < client->contexts->count && i < (int)max_entries; ++i)
    {
        struct context_mapping *cm;
        cm = (struct context_mapping *)list_get_item(client->contexts, i);
        indexes[i] = cm->app_context;
    }

    return client->contexts->count;
}

/*****************************************************************************/
int
scdata_add_card_mapping(struct scard_client *client,
                        unsigned int app_context,
                        const struct redir_scardhandle *hCard,
                        unsigned int *app_hcard)
{
    int rv = 0;

    struct card_mapping *crdm;
    if ((crdm = g_new0(struct card_mapping, 1)) != NULL)
    {
        crdm->app_context = app_context;
        crdm->app_hcard = (++g_autoinc);
        crdm->hcard = *hCard;
    }
    if (list_add_item(client->cards, (tintptr)crdm))
    {
        *app_hcard = crdm->app_hcard;
        rv = 1;
    }
    else
    {
        free(crdm);
    }

    return rv;
}

/*****************************************************************************/
void
scdata_remove_card_mapping(struct scard_client *client,
                           unsigned int app_hcard)
{
    int i;
    struct card_mapping *crdm;
    if ((crdm = find_crdm(client, app_hcard, &i)) != NULL)
    {
        list_remove_item(client->cards, i);
    }
}

/*****************************************************************************/
int
scdata_lookup_card_mapping(struct scard_client *client,
                           unsigned int app_hcard,
                           struct redir_scardhandle *hCard)
{
    int rv = 0;

    struct card_mapping *crdm;
    if ((crdm = find_crdm(client, app_hcard, NULL)) != NULL)
    {
        *hCard = crdm->hcard;
        rv = 1;
    }
    return rv;
}

/*****************************************************************************/
unsigned int
scdata_card_mapping_count(struct scard_client *client,
                          unsigned int app_context)
{
    unsigned int rv = 0;
    int i;
    for (i = 0 ; i < client->cards->count; ++i)
    {
        struct card_mapping *crdm;
        crdm = (struct card_mapping *)list_get_item(client->cards, i);
        if (crdm->app_context == app_context)
        {
            ++rv;
        }
    }
    return rv;
}

/*****************************************************************************/
unsigned int
scdata_get_all_card_mapping(struct scard_client *client,
                            unsigned int app_context,
                            unsigned int max_entries,
                            unsigned int indexes[])
{
    unsigned int rv = 0;
    int i;
    for (i = 0 ; i < client->cards->count; ++i)
    {
        struct card_mapping *crdm;
        crdm = (struct card_mapping *)list_get_item(client->cards, i);
        if (crdm->app_context == app_context)
        {
            if (rv < max_entries)
            {
                indexes[rv] = crdm->app_hcard;
            }
            ++rv;
        }
    }
    return rv;
}
