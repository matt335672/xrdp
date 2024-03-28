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
                              intptr_t closure,
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
    int rv = 0;
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_establish_context:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4, "Reading SCARD_ESTABLISH_CONTEXT"))
    {
        send_establish_context_return(scard_client, 0,
                                      XSCARD_F_INTERNAL_ERROR, 0);
        rv = 1;
    }
    else
    {
        unsigned int dwScope;
        in_uint32_le(in_s, dwScope);

        scard_send_establish_context(scard_client,
                                     send_establish_context_return,
                                     0,
                                     dwScope);
    }
    return rv;
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
                            intptr_t closure,
                            unsigned int ReturnCode)
{
    return send_long_return(client, SCARD_RELEASE_CONTEXT, ReturnCode);
}

/*****************************************************************************/
int
scard_process_release_context(struct trans *con, struct stream *in_s)
{
    int rv = 0;
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_release_context:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4, "Reading SCARD_RELEASE_CONTEXT"))
    {
        send_release_context_return(scard_client, 0, XSCARD_F_INTERNAL_ERROR);
        rv = 1;
    }
    else
    {
        unsigned int app_context;
        in_uint32_le(in_s, app_context);

        scard_send_release_context(scard_client,
                                   send_release_context_return,
                                   0,
                                   app_context);
    }
    return rv;
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
    if (msz == NULL)
    {
        out_uint32_le(out_s, 0);
    }
    else
    {
        out_uint32_le(out_s, cBytes);
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
                         intptr_t closure,
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
    int rv  = 0;
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    unsigned int hContext;
    unsigned int cBytes;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_list_readers:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4 + 4, "Reading SCARD_LIST_READERS(1)"))
    {
        send_list_readers_return(scard_client, 0,
                                 XSCARD_F_INTERNAL_ERROR, 0, NULL);
        rv = 1;
    }
    else
    {
        in_uint32_le(in_s, hContext);
        in_uint32_le(in_s, cBytes);

        if (!s_check_rem_and_log(in_s, cBytes,
                                 "Reading SCARD_LIST_READERS(2)"))
        {
            send_list_readers_return(scard_client, 0,
                                     XSCARD_F_INTERNAL_ERROR, 0, NULL);
            rv = 1;
        }
        else
        {
            char *mszGroups;
            in_uint8p(in_s,  mszGroups, cBytes);
            scard_send_list_readers(scard_client,
                                    send_list_readers_return, 0,
                                    hContext, cBytes, mszGroups);
        }
    }
    return rv;
}

/*****************************************************************************/
static int
send_connect_return(struct scard_client *client,
                    intptr_t closure,
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
    int rv = 0;
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    unsigned int hContext;
    unsigned int dwShareMode;
    unsigned int dwPreferredProtocols;
    unsigned int reader_len;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_connect:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4 + 4 + 4 + 4, "Reading SCARD_CONNECT(1)"))
    {
        send_connect_return(scard_client, 0, XSCARD_F_INTERNAL_ERROR, 0, 0);
        rv = 1;
    }
    else
    {
        in_uint32_le(in_s, hContext);
        in_uint32_le(in_s, dwShareMode);
        in_uint32_le(in_s, dwPreferredProtocols);
        in_uint32_le(in_s, reader_len);

        if (!s_check_rem_and_log(in_s, reader_len, "Reading SCARD_CONNECT(2)"))
        {
            send_connect_return(scard_client, 0,
                                XSCARD_F_INTERNAL_ERROR, 0, 0);
            rv = 1;
        }
        else
        {
            char *szReader;
            in_uint8p(in_s,  szReader, reader_len);
            scard_send_connect(scard_client, send_connect_return, 0,
                               hContext, dwShareMode,
                               dwPreferredProtocols, szReader);
        }
    }
    return rv;
}


/*****************************************************************************/
static int
send_is_valid_context_return(struct scard_client *client,
                             unsigned int ReturnCode)
{
    return send_long_return(client, SCARD_IS_VALID_CONTEXT, ReturnCode);
}

/*****************************************************************************/
/* returns error */
int
scard_process_common_context_long_return(struct trans *con,
        struct stream *in_s,
        enum common_context_code code)
{
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;
    struct common_context_long_return_call *call_data;

    int (*callback)(struct scard_client * client, unsigned int ReturnCode);

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_common_context_long_return:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    /* Which callback are we using for this function? */
    switch (code)
    {
        default:
            callback = send_is_valid_context_return;
    }

    if (!s_check_rem_and_log(in_s, 4, "Reading SCARD CONTEXT"))
    {
        return callback(scard_client, XSCARD_F_INTERNAL_ERROR);
    }

    /* Allocate a block to describe the call */
    if ((call_data = g_new0(struct common_context_long_return_call, 1)) == NULL)
    {
        return callback(scard_client, XSCARD_E_NO_MEMORY);
    }


    call_data->callback = callback;
    in_uint32_le(in_s, call_data->app_context);
    call_data->code = code;
    scard_send_common_context_long_return(scard_client, call_data);
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
send_reconnect_return(struct scard_client *client,
                      intptr_t closure,
                      unsigned int ReturnCode,
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
    out_uint32_le(out_s, dwActiveProtocol);
    s_mark_end(out_s);
    unsigned int bytes = (unsigned int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_RECONNECT);
    return trans_force_write(con);
}

/*****************************************************************************/
/* returns error */
int
scard_process_reconnect(struct trans *con, struct stream *in_s)
{
    int rv = 0;
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    unsigned int hCard;
    unsigned int dwShareMode;
    unsigned int dwPreferredProtocols;
    unsigned int dwInitialization;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_reconnect:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4 + 4 + 4 + 4, "Reading SCARD_RECONNECT"))
    {
        send_reconnect_return(scard_client, 0, XSCARD_F_INTERNAL_ERROR, 0);
        rv = 1;
    }
    else
    {
        in_uint32_le(in_s, hCard);
        in_uint32_le(in_s, dwShareMode);
        in_uint32_le(in_s, dwPreferredProtocols);
        in_uint32_le(in_s, dwInitialization);

        scard_send_reconnect(scard_client, send_reconnect_return, 0, hCard,
                             dwShareMode, dwPreferredProtocols,
                             dwInitialization);
    }
    return rv;
}

/*****************************************************************************/
static int
send_disconnect_return(struct scard_client *client,
                       intptr_t closure,
                       unsigned int ReturnCode)
{
    return send_long_return(client, SCARD_DISCONNECT, ReturnCode);
}

/*****************************************************************************/
/* returns error */
int
scard_process_disconnect(struct trans *con, struct stream *in_s)
{
    int rv = 0;
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    unsigned int hCard;
    unsigned int dwDisposition;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_disconnect:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 8, "Reading SCARD_DISCONNECT"))
    {
        send_disconnect_return(scard_client, 0, XSCARD_F_INTERNAL_ERROR);
        rv = 1;
    }
    else
    {
        in_uint32_le(in_s, hCard);
        in_uint32_le(in_s, dwDisposition);

        scard_send_disconnect(scard_client, send_disconnect_return, 0,
                              hCard, dwDisposition);
    }

    return rv;
}

/*****************************************************************************/
static int
send_begin_transaction_return(struct scard_client *client,
                              intptr_t closure,
                              unsigned int ReturnCode)
{
    return send_long_return(client, SCARD_BEGIN_TRANSACTION, ReturnCode);
}

/*****************************************************************************/
/* returns error */
int
scard_process_begin_transaction(struct trans *con, struct stream *in_s)
{
    int rv = 0;
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    unsigned int hCard;
    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_begin_transaction:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4, "Reading SCARD_BEGIN_TRANSACTION"))
    {
        send_begin_transaction_return(scard_client, 0, XSCARD_F_INTERNAL_ERROR);
        rv = 1;
    }
    else
    {
        in_uint32_le(in_s, hCard);
        scard_send_begin_transaction(scard_client,
                                     send_begin_transaction_return, 0, hCard);
    }
    return rv;
}

/*****************************************************************************/
static int
send_end_transaction_return(struct scard_client *client,
                            intptr_t closure,
                            unsigned int ReturnCode)
{
    return send_long_return(client, SCARD_END_TRANSACTION, ReturnCode);
}

/*****************************************************************************/
/* returns error */
int
scard_process_end_transaction(struct trans *con, struct stream *in_s)
{
    int rv = 0;
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    unsigned int hCard;
    unsigned int dwDisposition;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_end_transaction:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 8, "Reading SCARD_END_TRANSACTION"))
    {
        send_end_transaction_return(scard_client, 0, XSCARD_F_INTERNAL_ERROR);
        rv = 1;
    }
    else
    {
        in_uint32_le(in_s, hCard);
        in_uint32_le(in_s, dwDisposition);

        scard_send_end_transaction(scard_client, send_disconnect_return, 0,
                                   hCard, dwDisposition);
    }

    return rv;
}

/*****************************************************************************/
static int
send_transmit_return(struct scard_client *client,
                     intptr_t closure,
                     unsigned int ReturnCode,
                     const struct scard_io_request *pioRecvPci,
                     unsigned int cbRecvLength,
                     const char *pbRecvBuffer)
{
    struct pcsc_uds_client *uds_client = GET_PCSC_CLIENT(client);
    unsigned int stream_size = 64;
    if (pioRecvPci != NULL)
    {
        stream_size += pioRecvPci->cbExtraBytes;
    }
    if (pbRecvBuffer != NULL)
    {
        stream_size += cbRecvLength;
    }
    struct trans *con = uds_client->con;
    struct stream *out_s = trans_get_out_s(con, stream_size);
    if (out_s == NULL)
    {
        return 1;
    }

    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, ReturnCode);
    if (pioRecvPci != NULL)
    {
        out_uint32_le(out_s, 1);
        out_uint32_le(out_s, pioRecvPci->dwProtocol);
        out_uint32_le(out_s, pioRecvPci->cbExtraBytes);
    }
    else
    {
        out_uint32_le(out_s, 0);
        out_uint32_le(out_s, 0);
        out_uint32_le(out_s, 0);
    }
    out_uint32_le(out_s, cbRecvLength);
    if (pbRecvBuffer != NULL)
    {
        out_uint32_le(out_s, cbRecvLength);
        out_uint8a(out_s, pbRecvBuffer, cbRecvLength);
    }
    else
    {
        out_uint32_le(out_s, 0);
    }

    if (pioRecvPci != NULL)
    {
        out_uint8a(out_s, pioRecvPci->pbExtraBytes, pioRecvPci->cbExtraBytes);
    }

    s_mark_end(out_s);
    unsigned int bytes = (unsigned int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_TRANSMIT);
    return trans_force_write(con);
}

/*****************************************************************************/
int
scard_process_transmit(struct trans *con, struct stream *in_s)
{
    int rv = 0;
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    // Fixed fields provided by sender
    unsigned int hCard;
    unsigned int cbSendLength;
    unsigned int use_pioRecvPci;
    unsigned int fpbRecvBufferIsNULL;
    unsigned int cbRecvLength;

    struct scard_io_request ioSendPci;
    struct scard_io_request ioRecvPci;
    struct scard_io_request *pioRecvPci = NULL;
    const char *pbSendBuffer;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_transmit:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 9 * 4, "Reading SCARD_TRANSMIT(1)"))
    {
        send_transmit_return(scard_client, 0,
                             XSCARD_F_INTERNAL_ERROR, NULL, 0, NULL);
        rv = 1;
    }
    else
    {
        // Read all the fixed fields from the sender
        in_uint32_le(in_s, hCard);
        in_uint32_le(in_s, ioSendPci.dwProtocol);
        in_uint32_le(in_s, ioSendPci.cbExtraBytes);
        in_uint32_le(in_s, cbSendLength);
        in_uint32_le(in_s, use_pioRecvPci);
        in_uint32_le(in_s, ioRecvPci.dwProtocol);
        in_uint32_le(in_s, ioRecvPci.cbExtraBytes);
        in_uint32_le(in_s, fpbRecvBufferIsNULL);
        in_uint32_le(in_s, cbRecvLength);

        // Are we using the ioRecvPci?
        if (use_pioRecvPci)
        {
            pioRecvPci = &ioRecvPci;
        }
        else
        {
            pioRecvPci = NULL;
            ioRecvPci.dwProtocol = 0; // Ignore field
            ioRecvPci.cbExtraBytes = 0; // Ignore field
        }

        // Check the rest of the data we need is present
        unsigned int reqd_data = ioSendPci.cbExtraBytes +
                                 cbSendLength +
                                 ioRecvPci.cbExtraBytes;
        if (!s_check_rem_and_log(in_s, reqd_data, "Reading SCARD_TRANSMIT(2)"))
        {
            send_transmit_return(scard_client, 0,
                                 XSCARD_F_INTERNAL_ERROR, NULL, 0, NULL);
            rv = 1;
        }
        else
        {
            in_uint8p(in_s,  ioSendPci.pbExtraBytes, ioSendPci.cbExtraBytes);
            in_uint8p(in_s, pbSendBuffer, cbSendLength);
            in_uint8p(in_s,  ioRecvPci.pbExtraBytes, ioRecvPci.cbExtraBytes);

            scard_send_transmit(scard_client, send_transmit_return, 0,
                                hCard, &ioSendPci,
                                cbSendLength, pbSendBuffer,
                                pioRecvPci,
                                fpbRecvBufferIsNULL,
                                cbRecvLength);
        }
    }

    return rv;
}

/*****************************************************************************/
int
send_control_return(struct scard_client *client,
                    intptr_t closure,
                    unsigned int ReturnCode,
                    unsigned int cbOutBufferSize,
                    const char *pbRecvBuffer)
{
    struct pcsc_uds_client *uds_client = GET_PCSC_CLIENT(client);
    unsigned int stream_size = 64;

    if (ReturnCode == XSCARD_S_SUCCESS)
    {
        stream_size += cbOutBufferSize;
    }

    struct trans *con = uds_client->con;
    struct stream *out_s = trans_get_out_s(con, stream_size);
    if (out_s == NULL)
    {
        return 1;
    }

    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, ReturnCode);
    out_uint32_le(out_s, cbOutBufferSize);
    if (ReturnCode == XSCARD_S_SUCCESS)
    {
        out_uint8a(out_s, pbRecvBuffer, cbOutBufferSize);
    }
    s_mark_end(out_s);
    unsigned int bytes = (unsigned int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_CONTROL);
    return trans_force_write(con);
}

/*****************************************************************************/
/* returns error */
int
scard_process_control(struct trans *con, struct stream *in_s)
{
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    unsigned int hCard;
    unsigned int dwControlCode;
    unsigned int cbSendLength;
    unsigned int cbRecvLength;
    char *pbSendBuffer;

    int rv = 0;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_control:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4 + 4 + 4 + 4,
                             "Reading SCARD_CONTROL(1)"))
    {
        send_control_return(scard_client, 0,
                            XSCARD_F_INTERNAL_ERROR, 0, NULL);
        rv = 1;
    }
    else
    {
        in_uint32_le(in_s, hCard);
        in_uint32_le(in_s, dwControlCode);
        in_uint32_le(in_s, cbSendLength);
        in_uint32_le(in_s, cbRecvLength);

        if (!s_check_rem_and_log(in_s, cbSendLength,
                                 "Reading SCARD_CONTROL(2)"))
        {
            send_control_return(scard_client, 0,
                                XSCARD_F_INTERNAL_ERROR, 0, NULL);
            rv = 1;
        }
        else
        {
            in_uint8p(in_s, pbSendBuffer, cbSendLength);

            scard_send_control(scard_client, send_control_return, 0,
                               hCard, dwControlCode, cbSendLength,
                               pbSendBuffer, cbRecvLength);
        }
    }
    return rv;
}

/*****************************************************************************/
static int
send_status_return(struct scard_client *client,
                   intptr_t closure,
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
    int rv = 0;

    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_status:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4, "Reading SCARD_STATUS"))
    {
        send_status_return(scard_client, 0,
                           XSCARD_F_INTERNAL_ERROR,
                           0, 0, 0, NULL, 0, NULL);
        rv = 1;
    }
    else
    {
        unsigned int app_hcard;
        in_uint32_le(in_s, app_hcard);

        scard_send_status(scard_client, send_status_return, 0, app_hcard);
    }

    return rv;
}

/*****************************************************************************/
static int
send_get_status_change_return(struct scard_client *client,
                              intptr_t closure,
                              unsigned int ReturnCode,
                              unsigned int cReaders,
                              struct reader_state_return *rgReaderStates)
{
    struct pcsc_uds_client *uds_client = GET_PCSC_CLIENT(client);
    struct trans *con = uds_client->con;
    unsigned int stream_size = 64 + cReaders * 48;
    struct stream *out_s = trans_get_out_s(con, stream_size);
    if (out_s == NULL)
    {
        return 1;
    }

    unsigned int index;

    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, ReturnCode); /* XSCARD_S_SUCCESS status */
    out_uint32_le(out_s, cReaders); /* cReaders */
    for (index = 0 ; index < cReaders; ++index)
    {
        out_uint32_le(out_s, rgReaderStates[index].dwCurrentState);
        out_uint32_le(out_s, rgReaderStates[index].dwEventState);
        out_uint32_le(out_s, rgReaderStates[index].cbAtr);
        out_uint8a(out_s, rgReaderStates[index].rgbAtr, 36);
    }

    s_mark_end(out_s);
    unsigned int bytes = (unsigned int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_GET_STATUS_CHANGE);
    return trans_force_write(con);
}

/*****************************************************************************/
/* returns error */
int
scard_process_get_status_change(struct trans *con, struct stream *in_s)
{
    int rv = 0;
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_get_status_change:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    unsigned int hContext;
    unsigned int dwTimeout;
    unsigned int cReaders;
    struct reader_state *rsa = NULL;
    unsigned int *str_lengths = NULL;
    unsigned int str_space = 0;
    unsigned int index;

    if (!s_check_rem_and_log(in_s, 12, "Reading SCARD_GET_STATUS_CHANGE(1)"))
    {
        send_get_status_change_return(scard_client, 0,
                                      XSCARD_F_INTERNAL_ERROR, 0, NULL);
        rv = 1;
        goto done;
    }

    in_uint32_le(in_s, hContext);
    in_uint32_le(in_s, dwTimeout);
    in_uint32_le(in_s, cReaders);
    if (cReaders > 0)
    {
        rsa = (struct reader_state *) malloc(sizeof(rsa[0]) * cReaders);
        str_lengths = (unsigned int *)malloc(sizeof(unsigned int) * cReaders);
        if (rsa == NULL || str_lengths == NULL)
        {
            send_get_status_change_return(scard_client, 0,
                                          XSCARD_E_NO_MEMORY, 0, NULL);
            goto done;
        }
    }

    if (!s_check_rem_and_log(in_s, cReaders * 52,
                             "Reading SCARD_GET_STATUS_CHANGE(2)"))
    {
        send_get_status_change_return(scard_client, 0,
                                      XSCARD_F_INTERNAL_ERROR, 0, NULL);
        rv = 1;
        goto done;
    }

    // Read all the reader state variables (apart from the names)
    for (index = 0; index < cReaders; index++)
    {
        in_uint32_le(in_s, str_lengths[index]);
        str_space += str_lengths[index];
        in_uint32_le(in_s, rsa[index].dwCurrentState);
        in_uint32_le(in_s, rsa[index].dwEventState);
        in_uint32_le(in_s, rsa[index].cbAtr);
        in_uint8a(in_s, rsa[index].rgbAtr, 36);
    }

    if (!s_check_rem_and_log(in_s, str_space,
                             "Reading SCARD_GET_STATUS_CHANGE(3)"))
    {
        send_get_status_change_return(scard_client, 0,
                                      XSCARD_F_INTERNAL_ERROR, 0, NULL);
        rv = 1;
        goto done;
    }

    // Now read the reader names
    for (index = 0; index < cReaders; index++)
    {
        if (str_lengths[index] == 0)
        {
            rsa[index].szReader = NULL;
        }
        else
        {
            in_uint8p(in_s,  rsa[index].szReader, str_lengths[index]);
        }
    }

    scard_send_get_status_change(scard_client,
                                 send_get_status_change_return, 0,
                                 hContext, dwTimeout, cReaders, rsa);
done:
    free(rsa);
    free(str_lengths);
    return rv;
}

/*****************************************************************************/
static int
send_get_attrib_return(struct scard_client *client,
                       intptr_t closure,
                       unsigned int ReturnCode,
                       unsigned int cbAttrLen,
                       const char *pbAttr)
{
    struct pcsc_uds_client *uds_client = GET_PCSC_CLIENT(client);
    struct trans *con = uds_client->con;
    unsigned int stream_size = 64;
    if (cbAttrLen > 0 && pbAttr != NULL)
    {
        stream_size += cbAttrLen;
    }
    struct stream *out_s = trans_get_out_s(con, stream_size);
    if (out_s == NULL)
    {
        return 1;
    }

    s_push_layer(out_s, iso_hdr, 8);
    out_uint32_le(out_s, ReturnCode); /* XSCARD_S_SUCCESS status */
    out_uint32_le(out_s, cbAttrLen); /* cReaders */
    if (cbAttrLen > 0 && pbAttr != NULL)
    {
        out_uint8a(out_s, pbAttr, cbAttrLen);
    }

    s_mark_end(out_s);
    unsigned int bytes = (unsigned int) (out_s->end - out_s->data);
    s_pop_layer(out_s, iso_hdr);
    out_uint32_le(out_s, bytes - 8);
    out_uint32_le(out_s, SCARD_GET_STATUS_CHANGE);
    return trans_force_write(con);
}

/*****************************************************************************/
int
scard_process_get_attrib(struct trans *con, struct stream *in_s)
{
    int rv = 0;
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_get_attrib:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4 + 4 + 4 + 4, "Reading SCARD_GET_ATTRIB"))
    {
        send_get_attrib_return(scard_client, 0,
                               XSCARD_F_INTERNAL_ERROR, 0, NULL);
        rv = 1;
    }
    else
    {
        unsigned int app_hcard;
        unsigned int dwAttrId;
        unsigned int fpAttrIsNULL;
        unsigned int cbAttrLen;

        in_uint32_le(in_s, app_hcard);
        in_uint32_le(in_s, dwAttrId);
        in_uint32_le(in_s, fpAttrIsNULL);
        in_uint32_le(in_s, cbAttrLen);

        scard_send_get_attrib(scard_client, send_get_attrib_return, 0,
                              app_hcard, dwAttrId, fpAttrIsNULL, cbAttrLen);

    }
    return rv;
}


/*****************************************************************************/
static int
send_cancel_return(struct scard_client *client,
                   intptr_t closure,
                   unsigned int ReturnCode)
{
    return send_long_return(client, SCARD_CANCEL, ReturnCode);
}

/*****************************************************************************/
int
scard_process_cancel(struct trans *con, struct stream *in_s)
{
    int rv = 0;
    struct pcsc_uds_client *uds_client;
    struct scard_client *scard_client;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_process_cancel:");
    uds_client = (struct pcsc_uds_client *) (con->callback_data);
    scard_client = uds_client->scard_client;

    if (!s_check_rem_and_log(in_s, 4, "Reading SCARD_CANCEL"))
    {
        send_cancel_return(scard_client, 0, XSCARD_F_INTERNAL_ERROR);
        rv = 1;
    }
    else
    {
        unsigned int app_context;
        in_uint32_le(in_s, app_context);

        scard_send_cancel(scard_client,
                          send_cancel_return,
                          0,
                          app_context);
    }
    return rv;
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
            rv = scard_process_reconnect(con, in_s);
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

        case SCARD_GET_ATTRIB:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_GET_ATTRIB");
            rv = scard_process_get_attrib(con, in_s);
            break;

        case SCARD_SET_ATTRIB:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_SET_ATTRIB");
            break;

        case SCARD_IS_VALID_CONTEXT:
            LOG_DEVEL(LOG_LEVEL_INFO, "scard_process_msg: SCARD_IS_VALID_CONTEXT");
            rv = scard_process_common_context_long_return(
                     con, in_s, CCLR_IS_VALID_CONTEXT);
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
