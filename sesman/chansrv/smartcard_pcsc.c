/**
 * xrdp: A Remote Desktop Protocol server.
 *
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

/*
 * smartcard redirection support, PCSC daemon standin
 * this will act like pcsc daemon
 * pcsc lib and daemon write struct on unix domain socket for communication
 *
 * Currently this file implements some of the PDUs detailed in [MS-RDPESC].
 *
 * The PDUs use DCE IDL structs. These are required to be re-interpreted
 * in DCE NDR (Netword Data Representation)
 *
 * For more information on this subject see DCE publication C706
 * "DCE 1.1: Remote Procedure Call" 1997. In particular:-
 * Section 4.2 : Describes the IDL
 * Section 14 : Describes the NDR
 */

#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include <stddef.h>
#include <stdio.h>

#define JAY_TODO_CONTEXT    0
#define JAY_TODO_WIDE       1

#include "ms-erref.h"
#include "ms-rdpesc.h"
#include "os_calls.h"
#include "string_calls.h"
#include "smartcard.h"
#include "log.h"
#include "irp.h"
#include "devredir.h"
#include "trans.h"
#include "chansrv.h"
#include "list.h"
#include "xrdp_sockets.h"

#include "pcsc/xrdp_pcsc.h"

extern int g_display_num; /* in chansrv.c */

/**
 * Key values used with scard_client_set_cb_data() /
 * scard_client_get_cb_data()
 */
enum scdata_keys
{
    SCDATA_PCSC_CLIENT = 0
};

#define GET_PCSC_CLIENT(scard_client) \
    (struct pcsc_uds_client *) \
    scard_client_get_cb_data(scard_client, SCDATA_PCSC_CLIENT)


// TODO: Stuff to remove
struct pcsc_context
{
    struct
    {
        unsigned int cbContext;
        char pbContext[16];
    } context;
    unsigned int app_context;
};

struct pcsc_card
{
    unsigned int card_bytes;
    char card[16];
};

struct pcsc_uds_client;
struct pcsc_card *
get_pcsc_card_by_app_card(struct pcsc_uds_client *a, unsigned int b, struct pcsc_context **c)
{
    return 0;
}
struct pcsc_uds_client *
get_uds_client_by_id(int id)
{
    return 0;
}
struct pcsc_context *
get_pcsc_context_by_app_context(struct pcsc_uds_client *a, unsigned int b)
{
    return 0;
}

/*****************************************************************************/
struct pcsc_uds_client
{
    struct trans *con;     /* the connection to the app */
    //struct list *contexts; /* list of struct pcsc_context */
    //struct pcsc_context *connect_context;
    struct scard_client *scard_client; /* other end for the connection */
};

static struct list *g_uds_clients = 0; /* struct pcsc_uds_client */

static struct trans *g_lis = 0;
static char g_pcsclite_ipc_file[XRDP_SOCKETS_MAXPATH];

/*****************************************************************************/
/* got a new unix domain socket connection */
static struct pcsc_uds_client *
create_uds_client(struct trans *con)
{
    struct pcsc_uds_client *uds_client;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "create_uds_client:");
    if (con == 0)
    {
        return 0;
    }
    uds_client = g_new0(struct pcsc_uds_client, 1);
    if (uds_client == 0)
    {
        return 0;
    }
    if ((uds_client->scard_client = scard_client_new()) == NULL)
    {
        free(uds_client);
        return 0;
    }

    /*
     * Set callback data on the scard client so that scard client
     * callbacks can find the pcsc client to send a reply */
    scard_client_set_cb_data(uds_client->scard_client,
                             SCDATA_PCSC_CLIENT,
                             uds_client);
    uds_client->con = con;
    con->callback_data = uds_client;
    return uds_client;
}

/*****************************************************************************/
static void
free_uds_client(struct pcsc_uds_client *uds_client)
{
    if (uds_client != NULL)
    {
        scard_client_destroy(uds_client->scard_client);
        free(uds_client);
    }
}

/*****************************************************************************/
int
scard_pcsc_get_wait_objs(tbus *objs, int *count, int *timeout)
{
    struct pcsc_uds_client *uds_client;
    int index;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_pcsc_get_wait_objs:");
    if (g_lis != 0)
    {
        trans_get_wait_objs(g_lis, objs, count);
    }
    if (g_uds_clients != 0)
    {
        for (index = 0; index < g_uds_clients->count; index++)
        {
            uds_client = (struct pcsc_uds_client *)
                         list_get_item(g_uds_clients, index);
            if (uds_client != 0)
            {
                trans_get_wait_objs(uds_client->con, objs, count);
            }
        }
    }
    return 0;
}

/*****************************************************************************/
int
scard_pcsc_check_wait_objs(void)
{
    struct pcsc_uds_client *uds_client;
    int index;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_pcsc_check_wait_objs:");
    if (g_lis != 0)
    {
        if (trans_check_wait_objs(g_lis) != 0)
        {
            LOG(LOG_LEVEL_ERROR,
                "scard_pcsc_check_wait_objs: g_lis trans_check_wait_objs error");
        }
    }
    if (g_uds_clients != 0)
    {
        index = 0;
        while (index < g_uds_clients->count)
        {
            uds_client = (struct pcsc_uds_client *)
                         list_get_item(g_uds_clients, index);
            if (uds_client != 0)
            {
                if (trans_check_wait_objs(uds_client->con) != 0)
                {
                    free_uds_client(uds_client);
                    list_remove_item(g_uds_clients, index);
                    continue;
                }
            }
            index++;
        }
    }
    return 0;
}

/*****************************************************************************/
static int
send_establish_context_return(struct scard_client *client,
                              unsigned int ReturnCode,
                              unsigned int app_context)
{
    struct pcsc_uds_client *uds_client = GET_PCSC_CLIENT(client);

    struct trans *con = uds_client->con;
    struct stream *out_s = trans_get_out_s(con, 64);
    if (out_s == NULL)
    {
        return 1;
    }

    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, ReturnCode);
    out_uint32_le(out_s, app_context);
    s_mark_end(out_s);
    unsigned int bytes = (unsigned int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_ESTABLISH_CONTEXT);
    return trans_force_write(con);
}

/*****************************************************************************/
/* returns error */
int
scard_process_establish_context(struct trans *con, struct stream *in_s)
{
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;
    struct establish_context_call *call_data;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_establish_context:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4, "Reading SCARD_ESTABLISH_CONTEXT"))
    {
        return send_establish_context_return(scard_client,
                                             XSCARD_F_INTERNAL_ERROR, 0);
    }

    /* Allocate a block to describe the call */
    if ((call_data = g_new0(struct establish_context_call, 1)) == NULL)
    {
        return send_establish_context_return(scard_client,
                                             XSCARD_E_NO_MEMORY, 0);
    }

    call_data->callback = send_establish_context_return;
    in_uint32_le(in_s, call_data->dwScope);

    LOG_DEVEL(LOG_LEVEL_DEBUG,
              "scard_process_establish_context: dwScope 0x%8.8x",
              call_data->dwScope);
    scard_send_establish_context(scard_client, call_data);
    return 0;
}

/*****************************************************************************/
static int
send_long_return(struct scard_client *client,
                 enum pcsc_message_code msg_code,
                 unsigned int ReturnCode)
{
    struct pcsc_uds_client *uds_client = GET_PCSC_CLIENT(client);
    struct trans *con = uds_client->con;
    struct stream *out_s = trans_get_out_s(con, 64);
    if (out_s == NULL)
    {
        return 1;
    }
    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, ReturnCode);
    s_mark_end(out_s);
    unsigned int bytes = (unsigned int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, msg_code);
    return trans_force_write(con);
}

/*****************************************************************************/
static int
send_release_context_return(struct scard_client *client,
                            unsigned int ReturnCode)
{
    return send_long_return(client, SCARD_RELEASE_CONTEXT, ReturnCode);
}

/*****************************************************************************/
/* returns error */
int
scard_process_release_context(struct trans *con, struct stream *in_s)
{
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;
    struct release_context_call *call_data;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_release_context:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4, "Reading SCARD_RELEASE_CONTEXT"))
    {
        return send_release_context_return(scard_client,
                                           XSCARD_F_INTERNAL_ERROR);
    }

    /* Allocate a block to describe the call */
    if ((call_data = g_new0(struct release_context_call, 1)) == NULL)
    {
        return send_release_context_return(scard_client,
                                           XSCARD_E_NO_MEMORY);
    }


    call_data->callback = send_release_context_return;
    in_uint32_le(in_s, call_data->app_context);
    scard_send_release_context(scard_client, call_data);
    return 0;
}

/*****************************************************************************/
static int
send_long_and_multistring_return(struct scard_client *client,
                                 enum pcsc_message_code msg_code,
                                 unsigned int ReturnCode,
                                 unsigned int cBytes,
                                 const char *msz)
{
    struct pcsc_uds_client *uds_client = GET_PCSC_CLIENT(client);
    struct trans *con = uds_client->con;
    struct stream *out_s = trans_get_out_s(con, 64 + cBytes);
    if (out_s == NULL)
    {
        return 1;
    }

    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, ReturnCode);
    out_uint32_le(out_s, cBytes);
    // The string can be a NULL too in the IDL (even if cBytes is > 0).
    // This is context dependent, and the receiver needs to cater for this
    if (msz != NULL)
    {
        out_uint8a(out_s, msz, cBytes);
    }
    s_mark_end(out_s);
    unsigned int bytes = (unsigned int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, msg_code);
    return trans_force_write(con);
}

/*****************************************************************************/
static int
send_list_readers_return(struct scard_client *client,
                         unsigned int ReturnCode,
                         unsigned int cBytes,
                         const char *msz)
{
    return send_long_and_multistring_return(client, SCARD_LIST_READERS,
                                            ReturnCode, cBytes, msz);
}


/*****************************************************************************/
/* returns error */
int
scard_process_list_readers(struct trans *con, struct stream *in_s)
{
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;
    struct list_readers_call *call_data;

    unsigned int hContext;
    unsigned int cBytes;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_list_readers:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4 + 4, "Reading SCARD_LIST_READERS(1)"))
    {
        return send_list_readers_return(scard_client,
                                        XSCARD_F_INTERNAL_ERROR, 0, NULL);
    }
    in_uint32_le(in_s, hContext);
    in_uint32_le(in_s, cBytes);

    if (!s_check_rem_and_log(in_s, cBytes + 4 + 4,
                             "Reading SCARD_LIST_READERS(2)"))
    {
        return send_list_readers_return(scard_client,
                                        XSCARD_F_INTERNAL_ERROR, 0, NULL);
    }

    unsigned int call_data_size =
        offsetof(struct list_readers_call, mszGroups) +
        cBytes * sizeof(call_data->mszGroups[0]);

    call_data = (struct list_readers_call *)malloc(call_data_size);
    if (call_data == NULL)
    {
        return send_list_readers_return(scard_client,
                                        XSCARD_E_NO_MEMORY, 0, NULL);
    }

    call_data->callback = send_list_readers_return;
    call_data->app_context = hContext;
    in_uint32_le(in_s, call_data->fmszReadersIsNULL);
    in_uint32_le(in_s, call_data->cchReaders);
    call_data->cBytes = cBytes;
    in_uint8a(in_s, call_data->mszGroups, cBytes);

    scard_send_list_readers(scard_client, call_data);
    return 0;
}

/*****************************************************************************/
/**
 * Counts the number of non-NULL strings in a multistring
 *
 * [MS-RDPESC] A multistring is "A series of null-terminated character
 * strings terminated by a final null character stored in a contiguous
 * block of memory."
 *
 * The string is guaranteed to have at least the returned number of NULL
 * characters in it
 */
unsigned int
count_multistring_elements(const char *str, unsigned int len)
{
    unsigned int rv = 0;

    if (str != NULL)
    {
        while (len > 0)
        {
            // Look for a terminator
            const char *p = (const char *)memchr(str, '\0', len);
            if (!p || p == str)
            {
                // No terminator, or an empty string encountered */
                break;
            }

            ++rv;
            ++p; // Skip terminator
            len -= (p - str);
            str = p;
        }
    }

    return rv;
}


/*****************************************************************************/
static int
send_connect_return(struct scard_client *client,
                    unsigned int ReturnCode,
                    unsigned int hCard,
                    unsigned int dwActiveProtocol)
{
    struct pcsc_uds_client *uds_client = GET_PCSC_CLIENT(client);
    struct trans *con = uds_client->con;
    struct stream *out_s = trans_get_out_s(con, 64);
    if (out_s == NULL)
    {
        return 1;
    }

    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, ReturnCode);
    out_uint32_le(out_s, hCard);
    out_uint32_le(out_s, dwActiveProtocol);
    s_mark_end(out_s);
    unsigned int bytes = (unsigned int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_CONNECT);
    return trans_force_write(con);
}

/*****************************************************************************/
/* returns error */
int
scard_process_connect(struct trans *con, struct stream *in_s)
{
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;
    struct connect_call *call_data;

    unsigned int hContext;
    unsigned int dwShareMode;
    unsigned int dwPreferredProtocols;
    unsigned int reader_len;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_connect:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4 + 4 + 4 + 4, "Reading SCARD_CONNECT(1)"))
    {
        return send_connect_return(scard_client, XSCARD_F_INTERNAL_ERROR, 0, 0);
    }

    in_uint32_le(in_s, hContext);
    in_uint32_le(in_s, dwShareMode);
    in_uint32_le(in_s, dwPreferredProtocols);
    in_uint32_le(in_s, reader_len);

    if (!s_check_rem_and_log(in_s, reader_len, "Reading SCARD_CONNECT(2)"))
    {
        return send_connect_return(scard_client, XSCARD_F_INTERNAL_ERROR, 0, 0);
    }

    // Add the terminator to the string for the call
    unsigned int call_data_size =
        offsetof(struct connect_call, szReader) +
        (reader_len + 1) * sizeof(call_data->szReader[0]);

    call_data = (struct connect_call *)malloc(call_data_size);
    if (call_data == NULL)
    {
        return send_connect_return(scard_client, XSCARD_E_NO_MEMORY, 0, 0);
    }

    //LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_connect: rs.reader_name %s dwShareMode 0x%8.8x "
    //          "dwPreferredProtocols 0x%8.8x", rs.reader_name, rs.dwShareMode,
    //          rs.dwPreferredProtocols);

    call_data->callback = send_connect_return;
    call_data->app_context = hContext;
    call_data->dwShareMode = dwShareMode;
    call_data->dwPreferredProtocols = dwPreferredProtocols;
    in_uint8a(in_s, call_data->szReader, reader_len);
    call_data->szReader[reader_len] = '\0';

    scard_send_connect(scard_client, call_data);
    return 0;
}
/*****************************************************************************/
/* returns error */
int
scard_process_disconnect(struct trans *con, struct stream *in_s)
{
    int hCard;
    int dwDisposition;
    struct pcsc_uds_client *uds_client;
    void *user_data = 0;
    struct pcsc_context *lcontext;
    struct pcsc_card *lcard;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_disconnect:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    in_uint32_le(in_s, hCard);
    in_uint32_le(in_s, dwDisposition);
    //user_data = (void *) (tintptr) (uds_client->uds_client_id);
    lcard = get_pcsc_card_by_app_card(uds_client, hCard, &lcontext);
    if ((lcontext == 0) || (lcard == 0))
    {
        LOG(LOG_LEVEL_ERROR, "scard_process_disconnect: "
            "get_pcsc_card_by_app_card failed");
        return 1;
    }
    scard_send_disconnect(user_data, lcontext->context.pbContext,
                          lcontext->context.cbContext,
                          lcard->card, lcard->card_bytes, dwDisposition);
    return 0;
}

/*****************************************************************************/
int
scard_function_disconnect_return(void *user_data,
                                 struct stream *in_s,
                                 int len, int status)
{
    int bytes;
    int uds_client_id = 0;
    struct stream *out_s;
    struct pcsc_uds_client *uds_client;
    struct trans *con;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_disconnect_return:");
    LOG_DEVEL(LOG_LEVEL_DEBUG, "  status 0x%8.8x", status);
    //uds_client_id = (int) (tintptr) user_data;
    uds_client = (struct pcsc_uds_client *)
                 get_uds_client_by_id(uds_client_id);
    if (uds_client == 0)
    {
        LOG(LOG_LEVEL_ERROR, "scard_function_disconnect_return: "
            "get_uds_client_by_id failed to find uds_client_id %d",
            uds_client_id);
        return 1;
    }
    con = uds_client->con;
    out_s = trans_get_out_s(con, 8192);
    if (out_s == NULL)
    {
        return 1;
    }
    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, status); /* XSCARD_S_SUCCESS status */
    s_mark_end(out_s);
    bytes = (int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_DISCONNECT);
    return trans_force_write(con);
}

/*****************************************************************************/
/* returns error */
int
scard_process_begin_transaction(struct trans *con, struct stream *in_s)
{
    int hCard;
    struct pcsc_uds_client *uds_client;
    void *user_data = 0;
    struct pcsc_card *lcard;
    struct pcsc_context *lcontext;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_begin_transaction:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    in_uint32_le(in_s, hCard);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_begin_transaction: hCard 0x%8.8x", hCard);
    //user_data = (void *) (tintptr) (uds_client->uds_client_id);
    lcard = get_pcsc_card_by_app_card(uds_client, hCard, &lcontext);
    if ((lcard == 0) || (lcontext == 0))
    {
        LOG(LOG_LEVEL_ERROR, "scard_process_begin_transaction: "
            "get_pcsc_card_by_app_card failed");
        return 1;
    }
    scard_send_begin_transaction(user_data,
                                 lcontext->context.pbContext,
                                 lcontext->context.cbContext,
                                 lcard->card, lcard->card_bytes);
    return 0;
}

/*****************************************************************************/
/* returns error */
int
scard_function_begin_transaction_return(void *user_data,
                                        struct stream *in_s,
                                        int len, int status)
{
    struct stream *out_s;
    int bytes;
    int uds_client_id;
    struct pcsc_uds_client *uds_client;
    struct trans *con;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_begin_transaction_return:");
    LOG_DEVEL(LOG_LEVEL_DEBUG, "  status 0x%8.8x", status);
    uds_client_id = (int) (tintptr) user_data;
    uds_client = (struct pcsc_uds_client *)
                 get_uds_client_by_id(uds_client_id);
    if (uds_client == 0)
    {
        LOG(LOG_LEVEL_ERROR, "scard_function_begin_transaction_return: "
            "get_uds_client_by_id failed to find uds_client_id %d",
            uds_client_id);
        return 1;
    }
    con = uds_client->con;
    out_s = trans_get_out_s(con, 8192);
    if (out_s == NULL)
    {
        return 1;
    }
    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, status); /* XSCARD_S_SUCCESS status */
    s_mark_end(out_s);
    bytes = (int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_BEGIN_TRANSACTION);
    return trans_force_write(con);
}

/*****************************************************************************/
/* returns error */
int
scard_process_end_transaction(struct trans *con, struct stream *in_s)
{
    int hCard;
    int dwDisposition;
    struct pcsc_uds_client *uds_client;
    void *user_data = 0;
    struct pcsc_card *lcard;
    struct pcsc_context *lcontext;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_end_transaction:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    in_uint32_le(in_s, hCard);
    in_uint32_le(in_s, dwDisposition);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_end_transaction: hCard 0x%8.8x", hCard);
    //user_data = (void *) (tintptr) (uds_client->uds_client_id);
    lcard = get_pcsc_card_by_app_card(uds_client, hCard, &lcontext);
    if ((lcard == 0) || (lcontext == 0))
    {
        LOG(LOG_LEVEL_ERROR, "scard_process_end_transaction: "
            "get_pcsc_card_by_app_card failed");
        return 1;
    }
    scard_send_end_transaction(user_data,
                               lcontext->context.pbContext,
                               lcontext->context.cbContext,
                               lcard->card, lcard->card_bytes,
                               dwDisposition);
    return 0;
}

/*****************************************************************************/
/* returns error */
int
scard_function_end_transaction_return(void *user_data,
                                      struct stream *in_s,
                                      int len, int status)
{
    struct stream *out_s;
    int bytes;
    int uds_client_id;
    struct pcsc_uds_client *uds_client;
    struct trans *con;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_end_transaction_return:");
    LOG_DEVEL(LOG_LEVEL_DEBUG, "  status 0x%8.8x", status);
    uds_client_id = (int) (tintptr) user_data;
    uds_client = (struct pcsc_uds_client *)
                 get_uds_client_by_id(uds_client_id);
    if (uds_client == 0)
    {
        LOG(LOG_LEVEL_ERROR, "scard_function_end_transaction_return: "
            "get_uds_client_by_id failed to find uds_client_id %d",
            uds_client_id);
        return 1;
    }
    con = uds_client->con;

    out_s = trans_get_out_s(con, 8192);
    if (out_s == NULL)
    {
        return 1;
    }
    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, status); /* XSCARD_S_SUCCESS status */
    s_mark_end(out_s);
    bytes = (int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_END_TRANSACTION);
    return trans_force_write(con);
}

/*****************************************************************************/
/* returns error */
int
scard_function_get_attrib_return(void *user_data,
                                 struct stream *in_s,
                                 int len, int status)
{
    return 0;
}

/*****************************************************************************/
struct pcsc_transmit
{
    int uds_client_id;
    struct xrdp_scard_io_request recv_ior;
    int cbRecvLength;
};

/*****************************************************************************/
/* returns error */
int
scard_process_transmit(struct trans *con, struct stream *in_s)
{
    int hCard;
    int recv_bytes;
    int send_bytes;
    char *send_data;
    struct xrdp_scard_io_request send_ior;
    struct xrdp_scard_io_request recv_ior;
    struct pcsc_uds_client *uds_client;
    struct pcsc_card *lcard;
    struct pcsc_context *lcontext;
    struct pcsc_transmit *pcscTransmit;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_transmit:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_transmit:");
    in_uint32_le(in_s, hCard);
    in_uint32_le(in_s, send_ior.dwProtocol);
    in_uint32_le(in_s, send_ior.cbPciLength);
    in_uint32_le(in_s, send_ior.extra_bytes);
    in_uint8p(in_s, send_ior.extra_data, send_ior.extra_bytes);
    in_uint32_le(in_s, send_bytes);
    in_uint8p(in_s, send_data, send_bytes);
    in_uint32_le(in_s, recv_ior.dwProtocol);
    in_uint32_le(in_s, recv_ior.cbPciLength);
    in_uint32_le(in_s, recv_ior.extra_bytes);
    in_uint8p(in_s, recv_ior.extra_data, recv_ior.extra_bytes);
    in_uint32_le(in_s, recv_bytes);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_transmit: send dwProtocol %d cbPciLength %d "
              "recv dwProtocol %d cbPciLength %d send_bytes %d ",
              send_ior.dwProtocol, send_ior.cbPciLength, recv_ior.dwProtocol,
              recv_ior.cbPciLength, send_bytes);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_transmit: recv_bytes %d", recv_bytes);
    lcard = get_pcsc_card_by_app_card(uds_client, hCard, &lcontext);
    if ((lcard == 0) || (lcontext == 0))
    {
        LOG(LOG_LEVEL_ERROR, "scard_process_transmit: "
            "get_pcsc_card_by_app_card failed");
        return 1;
    }

    pcscTransmit = (struct pcsc_transmit *)
                   g_malloc(sizeof(struct pcsc_transmit), 1);
    pcscTransmit->uds_client_id = 0; //uds_client->uds_client_id;
    pcscTransmit->recv_ior = recv_ior;
    pcscTransmit->cbRecvLength = recv_bytes;

    scard_send_transmit(pcscTransmit,
                        lcontext->context.pbContext,
                        lcontext->context.cbContext,
                        lcard->card, lcard->card_bytes,
                        send_data, send_bytes, recv_bytes,
                        &send_ior, &recv_ior);
    return 0;
}

/*****************************************************************************/
/* returns error */
int
scard_function_transmit_return(void *user_data,
                               struct stream *in_s,
                               int len, int status)
{
    struct stream *out_s;
    int bytes;
    int val;
    int cbRecvLength;
    char *recvBuf;
    struct xrdp_scard_io_request recv_ior;
    struct pcsc_uds_client *uds_client;
    struct trans *con;
    struct pcsc_transmit *pcscTransmit;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_transmit_return:");
    LOG_DEVEL(LOG_LEVEL_DEBUG, "  status 0x%8.8x", status);
    pcscTransmit = (struct pcsc_transmit *) user_data;
    recv_ior = pcscTransmit->recv_ior;
    uds_client = (struct pcsc_uds_client *)
                 get_uds_client_by_id(pcscTransmit->uds_client_id);
    g_free(pcscTransmit);

    if (uds_client == 0)
    {
        LOG(LOG_LEVEL_ERROR, "scard_function_transmit_return: "
            "get_uds_client_by_id failed");
        return 1;
    }
    con = uds_client->con;
    cbRecvLength = 0;
    recvBuf = 0;
    if (status == 0)
    {
        in_uint8s(in_s, 20);
        in_uint32_le(in_s, val);
        if (val != 0)
        {
            /* pioRecvPci */
            in_uint8s(in_s, 8);
            in_uint32_le(in_s, recv_ior.dwProtocol);
            in_uint32_le(in_s, recv_ior.cbPciLength);
            recv_ior.cbPciLength += 8;
            in_uint32_le(in_s, recv_ior.extra_bytes);
            if (recv_ior.extra_bytes > 0)
            {
                in_uint8p(in_s, recv_ior.extra_data, recv_ior.extra_bytes);
            }
        }

        in_uint8s(in_s, 4);
        in_uint32_le(in_s, val);
        if (val != 0)
        {
            in_uint32_le(in_s, cbRecvLength);
            in_uint8p(in_s, recvBuf, cbRecvLength);
        }

    }
    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_transmit_return: cbRecvLength %d", cbRecvLength);
    out_s = trans_get_out_s(con, 8192);
    if (out_s == NULL)
    {
        return 1;
    }
    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, recv_ior.dwProtocol);
    out_uint32_le(out_s, recv_ior.cbPciLength);
    out_uint32_le(out_s, recv_ior.extra_bytes);
    out_uint8a(out_s, recv_ior.extra_data, recv_ior.extra_bytes);
    out_uint32_le(out_s, cbRecvLength);
    out_uint8a(out_s, recvBuf, cbRecvLength);
    out_uint32_le(out_s, status); /* XSCARD_S_SUCCESS status */
    s_mark_end(out_s);
    bytes = (int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_TRANSMIT);
    return trans_force_write(con);
}

/*****************************************************************************/
/* returns error */
int
scard_process_control(struct trans *con, struct stream *in_s)
{
    int hCard;
    int send_bytes;
    int recv_bytes;
    int control_code;
    char *send_data;
    struct pcsc_uds_client *uds_client;
    void *user_data = 0;
    struct pcsc_context *lcontext;
    struct pcsc_card *lcard;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_control:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_control:");

    in_uint32_le(in_s, hCard);
    in_uint32_le(in_s, control_code);
    in_uint32_le(in_s, send_bytes);
    in_uint8p(in_s, send_data, send_bytes);
    in_uint32_le(in_s, recv_bytes);

    //user_data = (void *) (tintptr) (uds_client->uds_client_id);
    lcard = get_pcsc_card_by_app_card(uds_client, hCard, &lcontext);
    if ((lcard == 0) || (lcontext == 0))
    {
        LOG(LOG_LEVEL_ERROR, "scard_process_control: "
            "get_pcsc_card_by_app_card failed");
        return 1;
    }
    scard_send_control(user_data, lcontext->context.pbContext,
                       lcontext->context.cbContext,
                       lcard->card, lcard->card_bytes,
                       send_data, send_bytes, recv_bytes,
                       control_code);

    return 0;
}

/*****************************************************************************/
/* returns error */
int
scard_function_control_return(void *user_data,
                              struct stream *in_s,
                              int len, int status)
{
    struct stream *out_s;
    int bytes;
    int cbRecvLength;
    char *recvBuf;
    int uds_client_id;
    struct pcsc_uds_client *uds_client;
    struct trans *con;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_control_return:");
    LOG_DEVEL(LOG_LEVEL_DEBUG, "  status 0x%8.8x", status);
    uds_client_id = (int) (tintptr) user_data;
    uds_client = (struct pcsc_uds_client *)
                 get_uds_client_by_id(uds_client_id);
    if (uds_client == 0)
    {
        LOG(LOG_LEVEL_ERROR, "scard_function_control_return: "
            "get_uds_client_by_id failed to find uds_client_id %d",
            uds_client_id);
        return 1;
    }
    con = uds_client->con;
    cbRecvLength = 0;
    recvBuf = 0;
    if (status == 0)
    {
        in_uint8s(in_s, 28);
        in_uint32_le(in_s, cbRecvLength);
        in_uint8p(in_s, recvBuf, cbRecvLength);
    }
    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_control_return: cbRecvLength %d", cbRecvLength);
    out_s = trans_get_out_s(con, 8192);
    if (out_s == NULL)
    {
        return 1;
    }
    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, cbRecvLength);
    out_uint8a(out_s, recvBuf, cbRecvLength);
    out_uint32_le(out_s, status); /* XSCARD_S_SUCCESS status */
    s_mark_end(out_s);
    bytes = (int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_CONTROL);
    return trans_force_write(con);
}

/*****************************************************************************/
struct pcsc_status
{
    int uds_client_id;
    int cchReaderLen;
};


/*****************************************************************************/
static int
send_status_return(struct scard_client *client,
                   unsigned int ReturnCode,
                   unsigned int dwState,
                   unsigned int dwProtocol,
                   unsigned int cBytes,
                   const char *mszReaderNames,
                   unsigned int cbAtrLen,
                   const char *pbAtr)
{
    struct pcsc_uds_client *uds_client = GET_PCSC_CLIENT(client);
    struct trans *con = uds_client->con;

    // The PCSC client just wants the friendly name of the
    // reader, but we have a multistring. Terminate the returned
    // string after the first result.
    if (mszReaderNames == NULL)
    {
        mszReaderNames = "";
    }
    const char *p = (const char *)memchr(mszReaderNames, '\0', cBytes);
    if (p != NULL)
    {
        cBytes = p - mszReaderNames;
    }

    struct stream *out_s = trans_get_out_s(con, 64 + cBytes + cbAtrLen);
    if (out_s == NULL)
    {
        return 1;
    }

    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, ReturnCode);
    out_uint32_le(out_s, dwState); // TODO change to bitmask
    out_uint32_le(out_s, dwProtocol);
    out_uint32_le(out_s, cBytes);
    out_uint32_le(out_s, cbAtrLen);
    out_uint8a(out_s, mszReaderNames, cBytes);
    out_uint8a(out_s, pbAtr, cbAtrLen);
    s_mark_end(out_s);
    unsigned int bytes = (unsigned int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_STATUS);
    return trans_force_write(con);
}
/*****************************************************************************/
/* returns error */
int
scard_process_status(struct trans *con, struct stream *in_s)
{
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;
    struct status_call *call_data;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_status:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4, "Reading SCARD_STATUS"))
    {
        return send_status_return(scard_client,
                                  XSCARD_F_INTERNAL_ERROR,
                                  0, 0, 0, NULL, 0, NULL);
    }

    /* Allocate a block to describe the call */
    if ((call_data = g_new0(struct status_call, 1)) == NULL)
    {
        return send_status_return(scard_client,
                                  XSCARD_E_NO_MEMORY,
                                  0, 0, 0, NULL, 0, NULL);
    }

    call_data->callback = send_status_return;
    in_uint32_le(in_s, call_data->app_hcard);

    scard_send_status(scard_client, call_data);
    return 0;
}

#if 0
#define MS_SCARD_UNKNOWN    0
#define MS_SCARD_ABSENT     1
#define MS_SCARD_PRESENT    2
#define MS_SCARD_SWALLOWED  3
#define MS_SCARD_POWERED    4
#define MS_SCARD_NEGOTIABLE 5
#define MS_SCARD_SPECIFIC   6
#endif

#define PC_SCARD_UNKNOWN    0x0001 /**< Unknown state */
#define PC_SCARD_ABSENT     0x0002 /**< Card is absent */
#define PC_SCARD_PRESENT    0x0004 /**< Card is present */
#define PC_SCARD_SWALLOWED  0x0008 /**< Card not powered */
#define PC_SCARD_POWERED    0x0010 /**< Card is powered */
#define PC_SCARD_NEGOTIABLE 0x0020 /**< Ready for PTS */
#define PC_SCARD_SPECIFIC   0x0040 /**< PTS has been set */

#if 0
static int g_ms2pc[] = { PC_SCARD_UNKNOWN, PC_SCARD_ABSENT,
                         PC_SCARD_PRESENT, PC_SCARD_SWALLOWED,
                         PC_SCARD_POWERED, PC_SCARD_NEGOTIABLE,
                         PC_SCARD_SPECIFIC
                       };
#endif

/*****************************************************************************/
/* returns error */
int
scard_process_get_status_change(struct trans *con, struct stream *in_s)
{
    int index;
    int hContext;
    int dwTimeout;
    int cReaders;
    READER_STATE *rsa;
    struct pcsc_uds_client *uds_client;
    void *user_data = 0;
    struct pcsc_context *lcontext;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_get_status_change:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    in_uint32_le(in_s, hContext);
    in_uint32_le(in_s, dwTimeout);
    in_uint32_le(in_s, cReaders);
    if ((cReaders < 0) || (cReaders > 16))
    {
        LOG(LOG_LEVEL_ERROR, "scard_process_get_status_change: bad cReaders %d", cReaders);
        return 1;
    }
    rsa = (READER_STATE *) g_malloc(sizeof(READER_STATE) * cReaders, 1);

    for (index = 0; index < cReaders; index++)
    {
        in_uint8a(in_s, rsa[index].reader_name, 100);
        LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_get_status_change: reader_name %s",
                  rsa[index].reader_name);
        in_uint32_le(in_s, rsa[index].current_state);
        LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_get_status_change: current_state %d",
                  rsa[index].current_state);
        in_uint32_le(in_s, rsa[index].event_state);
        LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_get_status_change: event_state %d",
                  rsa[index].event_state);
        in_uint32_le(in_s, rsa[index].atr_len);
        LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_get_status_change: atr_len %d",
                  rsa[index].atr_len);
        in_uint8a(in_s, rsa[index].atr, 36);
    }

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_get_status_change: hContext 0x%8.8x dwTimeout "
              "%d cReaders %d", hContext, dwTimeout, cReaders);

    //user_data = (void *) (tintptr) (uds_client->uds_client_id);
    lcontext = get_pcsc_context_by_app_context(uds_client, hContext);
    if (lcontext == 0)
    {
        LOG(LOG_LEVEL_ERROR, "scard_process_get_status_change: "
            "get_pcsc_context_by_app_context failed");
        g_free(rsa);
        return 1;
    }
    scard_send_get_status_change(user_data,
                                 lcontext->context.pbContext,
                                 lcontext->context.cbContext,
                                 1, dwTimeout, cReaders, rsa);
    g_free(rsa);

    return 0;
}

/*****************************************************************************/
int
scard_function_get_status_change_return(void *user_data,
                                        struct stream *in_s,
                                        int len, int status)
{
    int bytes;
    int index;
    int cReaders;
    tui32 current_state;
    tui32 event_state;
    tui32 atr_len; /* number of bytes in atr[] */
    tui8 atr[36];
    struct stream *out_s;
    int uds_client_id;
    struct pcsc_uds_client *uds_client;
    struct trans *con;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_get_status_change_return:");
    LOG_DEVEL(LOG_LEVEL_DEBUG, "  status 0x%8.8x", status);
    uds_client_id = (int) (tintptr) user_data;
    uds_client = (struct pcsc_uds_client *)
                 get_uds_client_by_id(uds_client_id);
    if (uds_client == 0)
    {
        LOG(LOG_LEVEL_ERROR, "scard_function_get_status_change_return: "
            "get_uds_client_by_id failed to find uds_client_id %d",
            uds_client_id);
        return 1;
    }
    con = uds_client->con;

    out_s = trans_get_out_s(con, 8192);
    if (out_s == NULL)
    {
        return 1;
    }
    s_push_layer(out_s, iso_hdr, 8);
    if (status != 0)
    {
        out_uint32_le(out_s, 0); /* cReaders */
        out_uint32_le(out_s, status); /* XSCARD_S_SUCCESS status */
    }
    else
    {
        in_uint8s(in_s, 28);
        in_uint32_le(in_s, cReaders);
        LOG_DEVEL(LOG_LEVEL_DEBUG, "  cReaders %d", cReaders);
        out_uint32_le(out_s, cReaders);
        if (cReaders > 0)
        {
            for (index = 0; index < cReaders; index++)
            {
                in_uint32_le(in_s, current_state);
                out_uint32_le(out_s, current_state);
                in_uint32_le(in_s, event_state);
                out_uint32_le(out_s, event_state);
                in_uint32_le(in_s, atr_len);
                out_uint32_le(out_s, atr_len);
                in_uint8a(in_s, atr, 36);
                out_uint8a(out_s, atr, 36);
            }
        }
        out_uint32_le(out_s, status); /* XSCARD_S_SUCCESS status */
    }

    s_mark_end(out_s);
    bytes = (int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_ESTABLISH_CONTEXT);
    return trans_force_write(con);
}

/*****************************************************************************/
/* returns error */
int
scard_process_cancel(struct trans *con, struct stream *in_s)
{
    int hContext;
    struct pcsc_uds_client *uds_client;
    void *user_data = 0;
    struct pcsc_context *lcontext;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_cancel:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    in_uint32_le(in_s, hContext);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_cancel: hContext 0x%8.8x", hContext);
    //user_data = (void *) (tintptr) (uds_client->uds_client_id);
    lcontext = get_pcsc_context_by_app_context(uds_client, hContext);
    if (lcontext == 0)
    {
        LOG(LOG_LEVEL_ERROR, "scard_process_cancel: "
            "get_pcsc_context_by_app_context failed");
        return 1;
    }
    scard_send_cancel(user_data, 0 /*&lcontext->context */);
    return 0;
}

/*****************************************************************************/
/* returns error */
int
scard_function_cancel_return(void *user_data,
                             struct stream *in_s,
                             int len, int status)
{
    int bytes;
    int uds_client_id;
    struct stream *out_s;
    struct pcsc_uds_client *uds_client;
    struct trans *con;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_cancel_return:");
    LOG_DEVEL(LOG_LEVEL_DEBUG, "  status 0x%8.8x", status);
    uds_client_id = (int) (tintptr) user_data;
    uds_client = (struct pcsc_uds_client *)
                 get_uds_client_by_id(uds_client_id);
    if (uds_client == 0)
    {
        LOG(LOG_LEVEL_ERROR, "scard_function_cancel_return: "
            "get_uds_client_by_id failed to find uds_client_id %d",
            uds_client_id);
        return 1;
    }
    con = uds_client->con;
    out_s = trans_get_out_s(con, 8192);
    if (out_s == NULL)
    {
        return 1;
    }
    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, status); /* XSCARD_S_SUCCESS status */
    s_mark_end(out_s);
    bytes = (int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_CANCEL);
    return trans_force_write(con);
}

/*****************************************************************************/
/* returns error */
int
scard_function_is_context_valid_return(void *user_data,
                                       struct stream *in_s,
                                       int len, int status)
{
    return 0;
}

/*****************************************************************************/
/* returns error */
int scard_function_reconnect_return(void *user_data,
                                    struct stream *in_s,
                                    int len, int status)
{
    return 0;
}

/*****************************************************************************/
/* returns error */
int
scard_process_msg(struct trans *con, struct stream *in_s, int command)
{
    int rv;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_msg: command 0x%4.4x", command);
    rv = 0;
    switch (command)
    {
        case SCARD_ESTABLISH_CONTEXT:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_ESTABLISH_CONTEXT");
            rv = scard_process_establish_context(con, in_s);
            break;
        case SCARD_RELEASE_CONTEXT:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_RELEASE_CONTEXT");
            rv = scard_process_release_context(con, in_s);
            break;

        case SCARD_LIST_READERS:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_LIST_READERS");
            rv = scard_process_list_readers(con, in_s);
            break;

        case SCARD_CONNECT:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_CONNECT");
            rv = scard_process_connect(con, in_s);
            break;

        case SCARD_RECONNECT:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_RECONNECT");
            break;

        case SCARD_DISCONNECT:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_DISCONNECT");
            rv = scard_process_disconnect(con, in_s);
            break;

        case SCARD_BEGIN_TRANSACTION:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_BEGIN_TRANSACTION");
            rv = scard_process_begin_transaction(con, in_s);
            break;

        case SCARD_END_TRANSACTION:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_END_TRANSACTION");
            rv = scard_process_end_transaction(con, in_s);
            break;

        case SCARD_TRANSMIT:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_TRANSMIT");
            rv = scard_process_transmit(con, in_s);
            break;

        case SCARD_CONTROL:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_CONTROL");
            rv = scard_process_control(con, in_s);
            break;

        case SCARD_STATUS:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_STATUS");
            rv = scard_process_status(con, in_s);
            break;

        case SCARD_GET_STATUS_CHANGE:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_GET_STATUS_CHANGE");
            rv = scard_process_get_status_change(con, in_s);
            break;

        case SCARD_CANCEL:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_CANCEL");
            rv = scard_process_cancel(con, in_s);
            break;

        case SCARD_CANCEL_TRANSACTION:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_CANCEL_TRANSACTION");
            break;

        case SCARD_GET_ATTRIB:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_GET_ATTRIB");
            break;

        case SCARD_SET_ATTRIB:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_SET_ATTRIB");
            break;

        default:
            LOG_DEVEL(LOG_LEVEL_WARNING, "scard_process_msg: unknown mtype 0x%4.4x", command);
            rv = 1;
            break;
    }
    return rv;
}

/*****************************************************************************/
/* returns error */
int
my_pcsc_trans_data_in(struct trans *trans)
{
    struct stream *s;
    int size;
    int command;
    int error;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "my_pcsc_trans_data_in:");
    if (trans == 0)
    {
        return 0;
    }
    s = trans_get_in_s(trans);
    in_uint32_le(s, size);
    in_uint32_le(s, command);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "my_pcsc_trans_data_in: size %d command %d", size, command);
    error = trans_force_read(trans, size);
    if (error == 0)
    {
        error = scard_process_msg(trans, s, command);
    }
    return error;
}

/*****************************************************************************/
/* got a new connection from libpcsclite */
int
my_pcsc_trans_conn_in(struct trans *trans, struct trans *new_trans)
{
    struct pcsc_uds_client *uds_client;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "my_pcsc_trans_conn_in:");

    if (trans == 0)
    {
        return 1;
    }

    if (trans != g_lis)
    {
        return 1;
    }

    if (new_trans == 0)
    {
        return 1;
    }

    uds_client = create_uds_client(new_trans);
    if (uds_client == 0)
    {
        return 1;
    }
    uds_client->con->trans_data_in = my_pcsc_trans_data_in;
    uds_client->con->header_size = 8;

    if (g_uds_clients == 0)
    {
        g_uds_clients = list_create();
    }
    list_add_item(g_uds_clients, (tbus)uds_client);

    return 0;
}

/*****************************************************************************/
/*
 * Get the name of the PC/SC socket
 *
 * We don't use XRDP_LIBPCSCLITE_SOCKET for this, as it complicates
 * restarting chansrv
 */
static void
get_libpcsclite_socket(void)
{
    const char *display_str = getenv("DISPLAY");
    int display = -1;
    if (display_str == NULL || display_str[0] == '\0')
    {
        LOG(LOG_LEVEL_ERROR, "No DISPLAY - can't create PC/SC socket");
    }
    else
    {
        display = g_get_display_num_from_display(display_str);
    }
    if (display >= 0)
    {
        snprintf(g_pcsclite_ipc_file, XRDP_SOCKETS_MAXPATH,
                 XRDP_LIBPCSCLITE_STR, g_getuid(), display);
    }
    else
    {
        g_pcsclite_ipc_file[0] = '\0';
    }
}


/*****************************************************************************/
int
scard_pcsc_init(void)
{
    int error;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_pcsc_init:");
    if (g_lis == 0)
    {
        get_libpcsclite_socket();
        g_lis = trans_create(2, 8192, 8192);
        error = trans_listen(g_lis, g_pcsclite_ipc_file);
        if (error != 0)
        {
            LOG(LOG_LEVEL_ERROR,
                "scard_pcsc_init: trans_listen failed for port %s",
                g_pcsclite_ipc_file);
            return 1;
        }
        g_lis->trans_conn_in = my_pcsc_trans_conn_in;
    }
    return 0;
}

/*****************************************************************************/
int
scard_pcsc_deinit(void)
{
    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_pcsc_deinit:");

    if (g_lis != 0)
    {
        trans_delete(g_lis);
        g_lis = 0;
    }

    g_file_delete(g_pcsclite_ipc_file);

    return 0;
}
