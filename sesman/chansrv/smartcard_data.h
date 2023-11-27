/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Laxmikant Rashinkar 2013 LK.Rashinkar@gmail.com
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

/*
 * @file smartcard_data.h
 *
 * Definitions used to manage state date held by the smartcard interface.
 */

#ifndef _SMARTCARD_DATA_H
#define _SMARTCARD_DATA_H

struct scard_client;

/*****************************************************************************/
struct redir_scardcontext  /* 2.2.1.1 */
{
    unsigned int cbContext;
    char pbContext[16];
};

struct redir_scardhandle   /* 2.2.1.2 */
{
    struct redir_scardcontext Context;
    unsigned int cbHandle;
    char pbHandle[16];
};

int
scard_data_init(void);

int
scard_data_deinit(void);

/**
 * Add a client to the database
 *
 * Returns the client
 */
struct scard_client *
scdata_create_client(void);

/**
 * Remove a client from the database, freeing memory
 *
 * @param client_id ID of client
 */
void
scdata_destroy_client(struct scard_client *client);

/**
 * Gets the unique ID for the client
 *
 * @param client Client
 * @return Unique non-repeating ID for the client (>0)
 *
 * The ID is used to locate the client over time, when there is the
 * possibility the client has gone away (e.g. when an I/O completes)
 */
unsigned int
scdata_get_client_id(struct scard_client *client);

/**
 * Gets the client for a unique client ID
 *
 * @param client_id Result of a previous scdata_get_client_id() call
 * @return Client, or NULL if the client has gone away.
 */
struct scard_client *
scdata_get_client_from_id(unsigned int client_id);

/**
 * Add callback data to a client
 *struct scard_client *client);
 * Data added in this way can be read back with scard_get_client_cb_data()
 * @param client Client
 * @param key Key for data
 * @param value Value to set for key
 */
void
scdata_set_client_cb_data(struct scard_client *client,
                          unsigned char key,
                          void *value);

/**
 * Retrieve callback data from a client
 *
 * Gets a value previously added with scard_set_client_cb_data()
 * @param client Client
 * @param key Key for data
 * @return Value for key, or NULL
 */
void *
scdata_get_client_cb_data(struct scard_client *client, unsigned char key);

/**
 * Add a context mapping for a client
 * @param client Client
 * @param Context REDIR_SCARDCONTEXT ([MS-RDPESC]) for the mapping
 * @param[out] app_context Application level context value
 * @return != 0 for success
 */
int
scdata_add_context_mapping(struct scard_client *client,
                           const struct redir_scardcontext *Context,
                           unsigned int *app_context);

/**
 * Remove a context mapping for a client
 * @param client Client
 * @param app_context Application level context value
 */
void
scdata_remove_context_mapping(struct scard_client *client,
                              unsigned int app_context);

/**
 * Lookup a context mapping for a client
 * @param client Client
 * @param app_context Application level context value
 * @param[out] Context REDIR_SCARDCONTEXT for the application level context
 * @return != 0 for success
 */
int
scdata_lookup_context_mapping(struct scard_client *client,
                              unsigned int app_context,
                              struct redir_scardcontext *Context);

/**
 * Gets the number of entries in the context mapping for a client
 * @param client Client
 * @return Number of entries for the client
 */
unsigned int
scdata_context_mapping_count(struct scard_client *client);

/**
 * Gets the indexes in the context mapping for a client
 * @param client Client
 * @param max_entries Max number of entries to return
 * @param[out] indexes Returned context mapping indexes
 * @return Number of entries written to indexes
 */
unsigned int
scdata_get_all_context_mapping(struct scard_client *client,
                               unsigned int max_entries,
                               unsigned int indexes[]);


/**
 * Add a card handle mapping for a client
 * @param client Client
 * @param app_context App context accessing the card
 * @param hCard REDIR_SCARDHANDLE ([MS-RDPESC]) for the mapping
 * @param[out] app_hcard Application level card handle value
 * @return != 0 for success
 */
int
scdata_add_card_mapping(struct scard_client *client,
                        unsigned int app_context,
                        const struct redir_scardhandle *hCard,
                        unsigned int *app_hcard);

/**
 * Remove a card handle mapping for a client
 * @param client Client
 * @param app_context App context accessing the card
 * @param app_hcard Application level card handle
 */
void
scdata_remove_card_mapping(struct scard_client *client,
                           unsigned int app_hcard);

/**
 * Lookup a card handle mapping for a client
 * @param client Client
 * @param app_context App context accessing the card
 * @param app_hcard Application level card handle
 * @param[out] hCard REDIR_SCARDCONTEXT for the application level card handle
 * @return != 0 for success
 */
int
scdata_lookup_card_mapping(struct scard_client *client,
                           unsigned int app_hcard,
                           struct redir_scardhandle *hCard);

/**
 * Gets the number of entries in the card handle mapping for a client
 * @param client Client
 * @param app_context App context accessing the card
 * @return Number of entries for the client
 */
unsigned int
scdata_card_mapping_count(struct scard_client *client,
                          unsigned int app_context);

/**
 * Gets the indexes in the context mapping for a client
 * @param client Client
 * @param app_context App context accessing the card
 * @param max_entries Max number of entries to return
 * @param[out] indexes Returned context mapping indexes
 * @return Number of entries written to indexes
 */
unsigned int
scdata_get_all_card_mapping(struct scard_client *client,
                            unsigned int app_context,
                            unsigned int max_entries,
                            unsigned int indexes[]);

#endif /* end #ifndef _SMARTCARD_DATA_H */
