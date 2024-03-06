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
 * @file sesman/chansrv/smartcard.c
 *
 * smartcard redirection support
 *
 * This file implements some of the PDUs detailed in [MS-RDPESC].
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

#include <string.h>
#include "os_calls.h"
#include "string_calls.h"
#include "smartcard.h"
#include "log.h"
#include "irp.h"
#include "devredir.h"
#include "smartcard_data.h"
#include "smartcard_pcsc.h" // TODO: Remove this coupling
#include "chansrv.h"
#include "ms-rdpesc.h"

/*
 * TODO
 *
 * o ensure that all wide calls are handled correctly
 *
 * o need to query client for build number and determine whether we should use
 *   SCREDIR_VERSION_XP or SCREDIR_VERSION_LONGHORN
 *
 * o need to call scard_release_resources()
 *
 * o why is win 7 sending SCARD_IOCTL_ACCESS_STARTED_EVENT first
 * 0000 00 01 00 00 04 00 00 00 e0 00 09 00 00 00 00 00 ................
 * 0010 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
 * 0020 28 b7 9d 02
 */

/*
 * Notes:
 *
 * XP and Server 2003 use version    SCREDIR_VERSION_XP       functions 5 - 58
 * Vista and Server 2008 use version SCREDIR_VERSION_LONGHORN functions 5 - 64
 * if TS Client's build number is >= 4,034 use SCREDIR_VERSION_LONGHORN
 */

/* [MS-RDPESC] 3.1.4 */
#define SCARD_IOCTL_ESTABLISH_CONTEXT        0x00090014 /* EstablishContext     */
#define SCARD_IOCTL_RELEASE_CONTEXT          0x00090018 /* ReleaseContext       */
#define SCARD_IOCTL_IS_VALID_CONTEXT         0x0009001C /* IsValidContext       */
#define SCARD_IOCTL_LIST_READER_GROUPS       0x00090020 /* ListReaderGroups     */
#define SCARD_IOCTL_LIST_READERSA            0x00090028 /* ListReaders ASCII    */
#define SCARD_IOCTL_LIST_READERSW            0x0009002C /* ListReaders Wide     */
#define SCARD_IOCTL_INTRODUCE_READER_GROUP   0x00090050 /* IntroduceReaderGroup */
#define SCARD_IOCTL_FORGET_READER_GROUP      0x00090058 /* ForgetReader         */
#define SCARD_IOCTL_INTRODUCE_READER         0x00090060 /* IntroduceReader      */
#define SCARD_IOCTL_FORGET_READER            0x00090068 /* IntroduceReader      */
#define SCARD_IOCTL_ADD_READER_TO_GROUP      0x00090070 /* AddReaderToGroup     */
#define SCARD_IOCTL_REMOVE_READER_FROM_GROUP 0x00090078 /* RemoveReaderFromGroup*/
#define SCARD_IOCTL_GET_STATUS_CHANGEA       0x000900A0 /* GetStatusChangeA     */
#define SCARD_IOCTL_GET_STATUS_CHANGEW       0x000900A4 /* GetStatusChangeW     */
#define SCARD_IOCTL_CANCEL                   0x000900A8 /* Cancel               */
#define SCARD_IOCTL_CONNECTA                 0x000900AC /* ConnectA             */
#define SCARD_IOCTL_CONNECTW                 0x000900B0 /* ConnectW             */
#define SCARD_IOCTL_RECONNECT                0x000900B4 /* Reconnect            */
#define SCARD_IOCTL_DISCONNECT               0x000900B8 /* Disconnect           */
#define SCARD_IOCTL_BEGINTRANSACTION         0x000900BC /* BeginTransaction     */
#define SCARD_IOCTL_ENDTRANSACTION           0x000900C0 /* EndTransaction       */
#define SCARD_IOCTL_STATE                    0x000900C4 /* State                */
#define SCARD_IOCTL_STATUSA                  0x000900C8 /* StatusA              */
#define SCARD_IOCTL_STATUSW                  0x000900CC /* StatusW              */
#define SCARD_IOCTL_TRANSMIT                 0x000900D0 /* Transmit             */
#define SCARD_IOCTL_CONTROL                  0x000900D4 /* Control              */
#define SCARD_IOCTL_GETATTRIB                0x000900D8 /* GetAttrib            */
#define SCARD_IOCTL_SETATTRIB                0x000900DC /* SetAttrib            */
#define SCARD_IOCTL_ACCESS_STARTED_EVENT     0x000900E0 /* SCardAccessStartedEvent */
#define SCARD_IOCTL_LOCATE_CARDS_BY_ATR      0x000900E8 /* LocateCardsByATR     */

/* scope used in EstablishContextCall */
#define SCARD_SCOPE_USER                     0x00000000
#define SCARD_SCOPE_TERMINAL                 0x00000001
#define SCARD_SCOPE_SYSTEM                   0x00000002

/* disposition - action to take on card */
#define SCARD_LEAVE_CARD                     0x00000000
#define SCARD_RESET_CARD                     0x00000001
#define SCARD_UNPOWER_CARD                   0x00000002
#define SCARD_EJECT_CARD                     0x00000003

#define MAX_SMARTCARDS                       16

/* Constants releated to referent IDs in NDR */
#define REFERENT_ID_BASE 0x20000
#define REFERENT_ID_INC 4

/* stores info about a smart card */
typedef struct smartcard
{
    tui32 DeviceId;
} SMARTCARD;

/* globals */
SMARTCARD   *smartcards[MAX_SMARTCARDS];
int          g_smartcards_inited = 0;
static tui32 g_device_id = 0;
static int   g_scard_index = 0;

/* externs */
extern tui32 g_completion_id;
extern int   g_rdpdr_chan_id;    /* in chansrv.c */


/******************************************************************************
**                   static functions local to this file                     **
******************************************************************************/
static struct stream *scard_make_new_ioctl(IRP *irp, tui32 ioctl,
        unsigned int ndr_size);
static int  scard_add_new_device(tui32 device_id);
static int  scard_get_free_slot(void);
static void scard_release_resources(void);
static void
scard_send_EstablishContext(struct stream *s,
                            struct establish_context_call *call_data);
static void
scard_send_CommonContextLongReturn(
    struct stream *s,
    struct common_context_long_return_call *call_data,
    const struct redir_scardcontext *context);

static void
scard_send_ListReaders(struct stream *s,
                       struct list_readers_call *call_data,
                       const struct redir_scardcontext *context);
static void scard_send_GetStatusChange(IRP *irp,
                                       char *context, int context_bytes,
                                       int wide,
                                       tui32 timeout, tui32 num_readers,
                                       READER_STATE *rsa);
static void
scard_send_Connect(struct stream *s,
                   struct connect_call *call_data,
                   const struct redir_scardcontext *context);

static void scard_send_Reconnect(IRP *irp,
                                 char *context, int context_bytes,
                                 char *card, int card_bytes,
                                 READER_STATE *rs);
static void
scard_send_HCardAndDisposition(struct stream *s,
                               struct hcard_and_disposition_call *call_data,
                               const struct redir_scardhandle *hCard);

static void
scard_send_Status(struct stream *s, struct status_call *call_data,
                  const struct redir_scardhandle *hCard);
static int
scard_send_Transmit(struct stream *s, struct transmit_call *call_data,
                    const struct redir_scardhandle *hCard);
static int scard_send_Control(IRP *irp, char *context, int context_bytes,
                              char *card, int card_bytes,
                              char *send_data, int send_bytes,
                              int recv_bytes, int control_code);
static int scard_send_GetAttrib(IRP *irp, char *card, int card_bytes,
                                READER_STATE *rs);

/******************************************************************************
**                    local callbacks into this module                       **
******************************************************************************/

static int
scard_function_establish_context_return(struct scard_client *client,
                                        void *vcall_data, struct stream *in_s,
                                        unsigned int len, unsigned int status);
static int
scard_function_common_context_return(struct scard_client *client,
                                     void *vcall_data, struct stream *in_s,
                                     unsigned int len, unsigned int status);

static int
scard_function_list_readers_return(struct scard_client *client,
                                   void *vcall_data, struct stream *in_s,
                                   unsigned int len, unsigned int status);

static void scard_handle_GetStatusChange_Return(struct stream *s, IRP *irp,
        tui32 DeviceId, tui32 CompletionId,
        tui32 IoStatus);

static int
scard_function_connect_return(struct scard_client *client,
                              void *vcall_data, struct stream *in_s,
                              unsigned int len, unsigned int status);

static void scard_handle_Reconnect_Return(struct stream *s, IRP *irp,
        tui32 DeviceId, tui32 CompletionId,
        tui32 IoStatus);

static int
scard_function_begin_transaction_return(struct scard_client *client,
                                        void *vcall_data, struct stream *in_s,
                                        unsigned int len, unsigned int status);

static int
scard_function_end_transaction_return(struct scard_client *client,
                                      void *vcall_data, struct stream *in_s,
                                      unsigned int len, unsigned int status);

static int
scard_function_status_return(struct scard_client *client,
                             void *vcall_data, struct stream *in_s,
                             unsigned int len, unsigned int status);

static int
scard_function_disconnect_return(struct scard_client *client,
                                 void *vcall_data, struct stream *in_s,
                                 unsigned int len, unsigned int status);

static int
scard_function_transmit_return(struct scard_client *client,
                               void *vcall_data, struct stream *in_s,
                               unsigned int len, unsigned int status);

static void scard_handle_Control_Return(struct stream *s, IRP *irp,
                                        tui32 DeviceId,
                                        tui32 CompletionId,
                                        tui32 IoStatus);

static void scard_handle_GetAttrib_Return(struct stream *s, IRP *irp,
        tui32 DeviceId,
        tui32 CompletionId,
        tui32 IoStatus);

/******************************************************************************
**                                                                           **
**          externally accessible functions, defined in smartcard.h          **
**                                                                           **
******************************************************************************/

/**
 *****************************************************************************/
void
scard_device_announce(tui32 device_id)
{
    LOG_DEVEL(LOG_LEVEL_DEBUG, "entered: device_id=%d", device_id);

    if (g_smartcards_inited)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "already init");
        return;
    }

    g_memset(&smartcards, 0, sizeof(smartcards));
    g_smartcards_inited = 1;
    g_device_id = device_id;
    g_scard_index = scard_add_new_device(device_id);

    if (g_scard_index < 0)
    {
        LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_add_new_device failed with DeviceId=%d", g_device_id);
    }
    else
    {
        LOG_DEVEL(LOG_LEVEL_DEBUG, "added smartcard with DeviceId=%d to list", g_device_id);
    }
}

/**
 *
 *****************************************************************************/
int
scard_get_wait_objs(tbus *objs, int *count, int *timeout)
{
    return scard_pcsc_get_wait_objs(objs, count, timeout);
}

/**
 *
 *****************************************************************************/
int
scard_check_wait_objs(void)
{
    return scard_pcsc_check_wait_objs();
}

/**
 *
 *****************************************************************************/
int
scard_init(void)
{
    LOG_DEVEL(LOG_LEVEL_INFO, "scard_init:");
    return scard_pcsc_init();
}

/**
 *
 *****************************************************************************/
int
scard_deinit(void)
{
    LOG_DEVEL(LOG_LEVEL_INFO, "scard_deinit:");
    scard_pcsc_deinit();
    scard_release_resources();
    g_smartcards_inited = 0;
    return 0;
}

/*****************************************************************************/
struct scard_client *
scard_client_new(void)
{
    /* Passthrough function */
    return scdata_create_client();
}

/*****************************************************************************/
void
scard_client_destroy(struct scard_client *client)
{
    /* TODO release resources */
    scdata_destroy_client(client);
}

/*****************************************************************************/
void
scard_client_set_cb_data(struct scard_client *client,
                         unsigned char key,
                         void *value)
{
    /* Passthrough function */
    scdata_set_client_cb_data(client, key, value);
}

/*****************************************************************************/
void *
scard_client_get_cb_data(struct scard_client *client, unsigned char key)
{
    /* Passthrough function */
    return scdata_get_client_cb_data(client, key);
}

/*****************************************************************************/
static void
scard_handle_irp_completion(struct stream *s, IRP *irp,
                            tui32 DeviceId, tui32 CompletionId,
                            tui32 IoStatus)
{
    struct common_call_private *call_data_private;
    struct scard_client *scard_client;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "entered");
    /* sanity check */
    if ((DeviceId != irp->DeviceId) || (CompletionId != irp->CompletionId))
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "DeviceId/CompletionId do not match those in IRP");
        return;
    }

    /* A pointer to a struct may be converted to a pointer
     * to its initial member */
    call_data_private = (struct common_call_private *)irp->user_data;

    /* Check the client is still here to process the return */
    scard_client = scdata_get_client_from_id(call_data_private->client_id);
    if (scard_client != NULL)
    {
        tui32 len;
        /* get OutputBufferLen */
        xstream_rd_u32_le(s, len);
        call_data_private->unmarshall_callback(scard_client, call_data_private,
                                               s, len, IoStatus);
    }
    devredir_irp_delete(irp);
}

/**
 *
 *****************************************************************************/
void
scard_send_establish_context(struct scard_client *client,
                             struct establish_context_call *call_data)
{
    IRP *irp;
    struct stream *s;

    /* Set up common_call_private data for the return */
    call_data->p.client_id = scdata_get_client_id(client);
    call_data->p.unmarshall_callback = scard_function_establish_context_return;

    /* setup up IRP */
    if ((irp = devredir_irp_new()) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        call_data->callback(client, XSCARD_E_NO_MEMORY, 0);
        free(call_data);
    }
    else
    {
        irp->scard_index = g_scard_index;
        irp->CompletionId = g_completion_id++;
        irp->DeviceId = g_device_id;
        irp->callback = scard_handle_irp_completion;
        /* Pass ownership of the call_data to the IRP */
        irp->user_data = call_data;
        irp->extra_destructor = devredir_irp_free_user_data;

        s = scard_make_new_ioctl(irp, SCARD_IOCTL_ESTABLISH_CONTEXT, 64);
        if (s == NULL)
        {
            LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl failed");
            call_data->callback(client, XSCARD_E_NO_MEMORY, 0);
            devredir_irp_delete(irp);
        }
        else
        {
            /* send IRP to client */
            scard_send_EstablishContext(s, call_data);
            free_stream(s);
        }
    }
}

/**
 * Sends one of several calls which take a context and return a uint32_t
 *****************************************************************************/
void
scard_send_common_context_long_return(
    struct scard_client *client,
    struct common_context_long_return_call *call_data)
{
    IRP *irp;
    struct stream *s;
    struct redir_scardcontext Context;
    int ioctl = 0;

    /* Set up common_call_private data for the return */
    call_data->p.client_id = scdata_get_client_id(client);
    call_data->p.unmarshall_callback = scard_function_common_context_return;

    /* Get the RDP-level context */
    if (!scdata_lookup_context_mapping(client,
                                       call_data->app_context, &Context))
    {
        call_data->callback(client, XSCARD_E_INVALID_HANDLE);
        free(call_data);
    }
    else
    {
        switch (call_data->code)
        {
            case CCLR_RELEASE_CONTEXT:
                ioctl = SCARD_IOCTL_RELEASE_CONTEXT;
                break;

            case CCLR_IS_VALID_CONTEXT:
                ioctl = SCARD_IOCTL_IS_VALID_CONTEXT;
                break;

            case CCLR_CANCEL:
                ioctl = SCARD_IOCTL_CANCEL;
                break;

            default:
                break;
        }
        if (ioctl == 0)
        {
            call_data->callback(client, XSCARD_E_INVALID_VALUE);
            free(call_data);
        }

        /* setup up IRP */
        else if ((irp = devredir_irp_new()) == NULL)
        {
            LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
            call_data->callback(client, XSCARD_E_NO_MEMORY);
            free(call_data);
        }
        else
        {
            irp->scard_index = g_scard_index;
            irp->CompletionId = g_completion_id++;
            irp->DeviceId = g_device_id;
            irp->callback = scard_handle_irp_completion;
            /* Pass ownership of the call_data to the IRP */
            irp->user_data = call_data;
            irp->extra_destructor = devredir_irp_free_user_data;

            s = scard_make_new_ioctl(irp, ioctl, 64);
            if (s == NULL)
            {
                LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl failed");
                call_data->callback(client, XSCARD_E_NO_MEMORY);
                devredir_irp_delete(irp);
            }
            else
            {
                /* send IRP to client */
                scard_send_CommonContextLongReturn(s, call_data, &Context);
                free_stream(s);
            }
        }
    }
}

/**
 *
 *****************************************************************************/
void
scard_send_list_readers(struct scard_client *client,
                        struct list_readers_call *call_data)
{
    IRP *irp;
    struct stream *s;
    struct redir_scardcontext Context;

    /* Set up common_call_private data for the return */
    call_data->p.client_id = scdata_get_client_id(client);
    call_data->p.unmarshall_callback = scard_function_list_readers_return;

    /* Lookup the context */
    if (!scdata_lookup_context_mapping(client, call_data->app_context,
                                       &Context))
    {
        call_data->callback(client, XSCARD_E_INVALID_HANDLE, 0, NULL);
        free(call_data);
    }
    /* setup up IRP */
    else if ((irp = devredir_irp_new()) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        call_data->callback(client, XSCARD_E_NO_MEMORY, 0, NULL);
        free(call_data);
    }
    else
    {
        unsigned int ioctl_size = 64;
        if (call_data->cBytes > 0)
        {
            ioctl_size += 2 * utf8_as_utf16_word_count(call_data->mszGroups,
                          call_data->cBytes);
        }

        irp->scard_index = g_scard_index;
        irp->CompletionId = g_completion_id++;
        irp->DeviceId = g_device_id;
        irp->callback = scard_handle_irp_completion;
        /* Pass ownership of the call_data to the IRP */
        irp->user_data = call_data;
        irp->extra_destructor = devredir_irp_free_user_data;

        s = scard_make_new_ioctl(irp, SCARD_IOCTL_LIST_READERSW, ioctl_size);
        if (s == NULL)
        {
            LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl failed");
            call_data->callback(client, XSCARD_E_NO_MEMORY, 0, NULL);
            devredir_irp_delete(irp);
        }
        else
        {
            /* send IRP to client */
            scard_send_ListReaders(s, call_data, &Context);
            free_stream(s);
        }
    }
}

/**
 * Send get change in status command
 *
 * @param  con          connection to client
 * @param  wide         TRUE if unicode string
 * @param  timeout      timeout in milliseconds, -1 for infinity
 * @param  num_readers  number of entries in rsa
 * @param  rsa          array of READER_STATEs
 *****************************************************************************/
int
scard_send_get_status_change(void *call_data, char *context, int context_bytes,
                             int wide, tui32 timeout, tui32 num_readers,
                             READER_STATE *rsa)
{
    IRP *irp;

    /* setup up IRP */
    if ((irp = devredir_irp_new()) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        return 1;
    }

    irp->scard_index = g_scard_index;
    irp->CompletionId = g_completion_id++;
    irp->DeviceId = g_device_id;
    irp->callback = scard_handle_GetStatusChange_Return;
    irp->user_data = call_data;

    /* send IRP to client */
    scard_send_GetStatusChange(irp, context, context_bytes, wide, timeout,
                               num_readers, rsa);

    return 0;
}

/**
 * Open a connection to the smart card located in the reader
 *
 * @param  con   connection to client
 * @param  wide  TRUE if unicode string
 *****************************************************************************/
void
scard_send_connect(struct scard_client *client,
                   struct connect_call *call_data)
{
    IRP *irp;
    struct stream *s;
    struct redir_scardcontext Context;

    /* Set up common_call_private data for the return */
    call_data->p.client_id = scdata_get_client_id(client);
    call_data->p.unmarshall_callback = scard_function_connect_return;

    /* Get the RDP-level context */
    if (!scdata_lookup_context_mapping(client,
                                       call_data->app_context, &Context))
    {
        call_data->callback(client, XSCARD_E_INVALID_HANDLE, 0, 0);
        free(call_data);
    }
    /* setup up IRP */
    else if ((irp = devredir_irp_new()) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        call_data->callback(client, XSCARD_E_NO_MEMORY, 0, 0);
        free(call_data);
    }
    else
    {
        unsigned int ioctl_size = 64;
        ioctl_size +=
            2 * utf8_as_utf16_word_count(call_data->szReader,
                                         strlen(call_data->szReader) + 1);

        irp->scard_index = g_scard_index;
        irp->CompletionId = g_completion_id++;
        irp->DeviceId = g_device_id;
        irp->callback = scard_handle_irp_completion;
        /* Pass ownership of the call_data to the IRP */
        irp->user_data = call_data;
        irp->extra_destructor = devredir_irp_free_user_data;

        s = scard_make_new_ioctl(irp, SCARD_IOCTL_CONNECTW, ioctl_size);
        if (s == NULL)
        {
            LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl failed");
            call_data->callback(client, XSCARD_E_NO_MEMORY, 0, 0);
            devredir_irp_delete(irp);
        }
        else
        {
            /* send IRP to client */
            scard_send_Connect(s, call_data, &Context);
            free_stream(s);
        }
    }
}

/**
 * The reconnect method re-establishes a smart card reader handle. On success,
 * the handle is valid once again.
 *
 * @param  con        connection to client
 * @param  sc_handle  handle to device
 * @param  rs         reader state where following fields are set
 *                        rs.shared_mode_flag
 *                        rs.preferred_protocol
 *                        rs.init_type
 *****************************************************************************/
int
scard_send_reconnect(void *call_data, char *context, int context_bytes,
                     char *card, int card_bytes, READER_STATE *rs)
{
    IRP *irp;

    /* setup up IRP */
    if ((irp = devredir_irp_new()) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        return 1;
    }

    irp->scard_index = g_scard_index;
    irp->CompletionId = g_completion_id++;
    irp->DeviceId = g_device_id;
    irp->callback = scard_handle_Reconnect_Return;
    irp->user_data = call_data;

    /* send IRP to client */
    scard_send_Reconnect(irp, context, context_bytes, card, card_bytes, rs);

    return 0;
}

/**
 *
 *****************************************************************************/
void
scard_send_begin_transaction(struct scard_client *client,
                             struct hcard_and_disposition_call *call_data)
{
    IRP *irp;
    struct stream *s;
    struct redir_scardhandle hCard;

    /* Set up common_call_private data for the return */
    call_data->p.client_id = scdata_get_client_id(client);
    call_data->p.unmarshall_callback = scard_function_begin_transaction_return;

    /* Get the RDP-level context */
    if (!scdata_lookup_card_mapping(client,
                                    call_data->app_hcard, &hCard))
    {
        call_data->callback(client, XSCARD_E_INVALID_HANDLE);
        free(call_data);
    }
    /* setup up IRP */
    else if ((irp = devredir_irp_new()) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        call_data->callback(client, XSCARD_E_NO_MEMORY);
        free(call_data);
    }
    else
    {
        irp->scard_index = g_scard_index;
        irp->CompletionId = g_completion_id++;
        irp->DeviceId = g_device_id;
        irp->callback = scard_handle_irp_completion;
        /* Pass ownership of the call_data to the IRP */
        irp->user_data = call_data;
        irp->extra_destructor = devredir_irp_free_user_data;

        s = scard_make_new_ioctl(irp, SCARD_IOCTL_BEGINTRANSACTION, 64);
        if (s == NULL)
        {
            LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl failed");
            call_data->callback(client, XSCARD_E_NO_MEMORY);
            devredir_irp_delete(irp);
        }
        else
        {
            /* send IRP to client */
            scard_send_HCardAndDisposition(s, call_data, &hCard);
            free_stream(s);
        }
    }
}

/**
 *
 *****************************************************************************/
void
scard_send_end_transaction(struct scard_client *client,
                           struct hcard_and_disposition_call *call_data)
{
    IRP *irp;
    struct stream *s;
    struct redir_scardhandle hCard;

    /* Set up common_call_private data for the return */
    call_data->p.client_id = scdata_get_client_id(client);
    call_data->p.unmarshall_callback = scard_function_end_transaction_return;

    /* Get the RDP-level context */
    if (!scdata_lookup_card_mapping(client,
                                    call_data->app_hcard, &hCard))
    {
        call_data->callback(client, XSCARD_E_INVALID_HANDLE);
        free(call_data);
    }
    /* setup up IRP */
    else if ((irp = devredir_irp_new()) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        call_data->callback(client, XSCARD_E_NO_MEMORY);
        free(call_data);
    }
    else
    {
        irp->scard_index = g_scard_index;
        irp->CompletionId = g_completion_id++;
        irp->DeviceId = g_device_id;
        irp->callback = scard_handle_irp_completion;
        /* Pass ownership of the call_data to the IRP */
        irp->user_data = call_data;
        irp->extra_destructor = devredir_irp_free_user_data;

        s = scard_make_new_ioctl(irp, SCARD_IOCTL_ENDTRANSACTION, 64);
        if (s == NULL)
        {
            LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl failed");
            call_data->callback(client, XSCARD_E_NO_MEMORY);
            devredir_irp_delete(irp);
        }
        else
        {
            /* send IRP to client */
            scard_send_HCardAndDisposition(s, call_data, &hCard);
            free_stream(s);
        }
    }
}

/**
 *
 *****************************************************************************/
void
scard_send_status(struct scard_client *client,
                  struct status_call *call_data)
{
    IRP *irp;
    struct stream *s;
    struct redir_scardhandle hCard;

    /* Set up common_call_private data for the return */
    call_data->p.client_id = scdata_get_client_id(client);
    call_data->p.unmarshall_callback = scard_function_status_return;

    /* Get the RDP-level context */
    if (!scdata_lookup_card_mapping(client,
                                    call_data->app_hcard, &hCard))
    {
        call_data->callback(client, XSCARD_E_INVALID_HANDLE,
                            0, 0, 0, NULL, 0, NULL);
        free(call_data);
    }
    /* setup up IRP */
    else if ((irp = devredir_irp_new()) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        call_data->callback(client, XSCARD_E_NO_MEMORY,
                            0, 0, 0, NULL, 0, NULL);
        free(call_data);
    }
    else
    {
        irp->scard_index = g_scard_index;
        irp->CompletionId = g_completion_id++;
        irp->DeviceId = g_device_id;
        irp->callback = scard_handle_irp_completion;
        /* Pass ownership of the call_data to the IRP */
        irp->user_data = call_data;
        irp->extra_destructor = devredir_irp_free_user_data;

        s = scard_make_new_ioctl(irp, SCARD_IOCTL_STATUSW, 64);
        if (s == NULL)
        {
            LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl failed");
            call_data->callback(client, XSCARD_E_NO_MEMORY,
                                0, 0, 0, NULL, 0, NULL);
            devredir_irp_delete(irp);
        }
        else
        {
            /* send IRP to client */
            scard_send_Status(s, call_data, &hCard);
            free_stream(s);
        }
    }
}

/**
 *
 *****************************************************************************/
void
scard_send_disconnect(struct scard_client *client,
                      struct hcard_and_disposition_call *call_data)
{
    IRP *irp;
    struct stream *s;
    struct redir_scardhandle hCard;

    /* Set up common_call_private data for the return */
    call_data->p.client_id = scdata_get_client_id(client);
    call_data->p.unmarshall_callback = scard_function_disconnect_return;

    /* Get the RDP-level context */
    if (!scdata_lookup_card_mapping(client,
                                    call_data->app_hcard, &hCard))
    {
        call_data->callback(client, XSCARD_E_INVALID_HANDLE);
        free(call_data);
    }
    /* setup up IRP */
    else if ((irp = devredir_irp_new()) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        call_data->callback(client, XSCARD_E_NO_MEMORY);
        free(call_data);
    }
    else
    {
        irp->scard_index = g_scard_index;
        irp->CompletionId = g_completion_id++;
        irp->DeviceId = g_device_id;
        irp->callback = scard_handle_irp_completion;
        /* Pass ownership of the call_data to the IRP */
        irp->user_data = call_data;
        irp->extra_destructor = devredir_irp_free_user_data;

        s = scard_make_new_ioctl(irp, SCARD_IOCTL_DISCONNECT, 64);
        if (s == NULL)
        {
            LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl failed");
            call_data->callback(client, XSCARD_E_NO_MEMORY);
            devredir_irp_delete(irp);
        }
        else
        {
            /* send IRP to client */
            scard_send_HCardAndDisposition(s, call_data, &hCard);
            free_stream(s);
        }
    }
}

/**
 * Local function to free a transmit_call struct
 *
 *****************************************************************************/
static void
free_transmit_call(struct transmit_call *call_data)
{
    free(call_data->pioSendPci);
    free(call_data->pioRecvPci);
    free(call_data);
}

/**
 * Local function to use as an IRP destructor if the IRP is carrying a
 * struct transmit_call
 *
 *****************************************************************************/
static void
irp_free_transmit_call_user_data(IRP *irp)
{
    struct transmit_call *call_data = (struct transmit_call *)irp->user_data;
    free_transmit_call(call_data);
}

/**
 *
 *****************************************************************************/
void
scard_send_transmit(struct scard_client *client,
                    struct transmit_call *call_data)
{
    IRP *irp;
    struct stream *s;
    struct redir_scardhandle hCard;

    /* Set up common_call_private data for the return */
    call_data->p.client_id = scdata_get_client_id(client);
    call_data->p.unmarshall_callback = scard_function_transmit_return;

    /* pioSendPci specified? */
    if (call_data->pioSendPci == NULL)
    {
        call_data->callback(client, XSCARD_E_INVALID_PARAMETER, NULL, 0, NULL);
        free_transmit_call(call_data);
    }
    /* Get the RDP-level context */
    else if (!scdata_lookup_card_mapping(client,
                                         call_data->app_hcard, &hCard))
    {
        call_data->callback(client, XSCARD_E_INVALID_HANDLE, NULL, 0, NULL);
        free_transmit_call(call_data);
    }
    /* setup up IRP */
    else if ((irp = devredir_irp_new()) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        call_data->callback(client, XSCARD_E_NO_MEMORY, NULL, 0, NULL);
        free_transmit_call(call_data);
    }
    else
    {
        unsigned int ioctl_length = 256;
        ioctl_length += call_data->cbSendLength;
        ioctl_length += call_data->pioSendPci->cbExtraBytes;
        if (call_data->pioRecvPci != NULL)
        {
            ioctl_length += call_data->pioRecvPci->cbExtraBytes;
        }
        irp->scard_index = g_scard_index;
        irp->CompletionId = g_completion_id++;
        irp->DeviceId = g_device_id;
        irp->callback = scard_handle_irp_completion;
        /* Pass ownership of the call_data to the IRP */
        irp->user_data = call_data;
        irp->extra_destructor = irp_free_transmit_call_user_data;

        s = scard_make_new_ioctl(irp, SCARD_IOCTL_TRANSMIT, ioctl_length);
        if (s == NULL)
        {
            LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl failed");
            call_data->callback(client, XSCARD_E_NO_MEMORY, NULL, 0, NULL);
            devredir_irp_delete(irp);
        }
        else
        {
            /* send IRP to client */
            scard_send_Transmit(s, call_data, &hCard);
            free_stream(s);
        }
    }
}

/**
 * Communicate directly with the smart card reader
 *****************************************************************************/
int
scard_send_control(void *call_data, char *context, int context_bytes,
                   char *card, int card_bytes,
                   char *send_data, int send_bytes,
                   int recv_bytes, int control_code)
{
    IRP *irp;

    /* setup up IRP */
    if ((irp = devredir_irp_new()) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        return 1;
    }

    irp->scard_index = g_scard_index;
    irp->CompletionId = g_completion_id++;
    irp->DeviceId = g_device_id;
    irp->callback = scard_handle_Control_Return;
    irp->user_data = call_data;

    /* send IRP to client */
    scard_send_Control(irp, context, context_bytes,
                       card, card_bytes,
                       send_data, send_bytes,
                       recv_bytes, control_code);

    return 0;
}

/**
 * Get reader attributes
 *****************************************************************************/
int
scard_send_get_attrib(void *call_data, char *card, int card_bytes,
                      READER_STATE *rs)
{
    IRP *irp;

    /* setup up IRP */
    if ((irp = devredir_irp_new()) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        return 1;
    }

    irp->scard_index = g_scard_index;
    irp->CompletionId = g_completion_id++;
    irp->DeviceId = g_device_id;
    irp->callback = scard_handle_GetAttrib_Return;
    irp->user_data = call_data;

    /* send IRP to client */
    scard_send_GetAttrib(irp, card, card_bytes, rs);

    return 0;
}

/******************************************************************************
**                                                                           **
**                   static functions local to this file                     **
**                                                                           **
******************************************************************************/

/**
 * Create a new stream and insert specified IOCTL
 *
 * @param  irp      information about the I/O
 * @param  ioctl    the IOCTL code
 * @param  ndr_size Expected additional size for the NDR type
 *
 * @return stream with IOCTL inserted in it, NULL on error
 *
 * @post In addition to the IOCTL, the NDR common type header from [MS-RPCE]
 *       2.2.6.1 is also inserted.
 * @post The iso_hdr of the stream contains the location where the
 *       size of the IOCTL has to be inserted.
 *****************************************************************************/
static struct stream *
scard_make_new_ioctl(IRP *irp, tui32 ioctl, unsigned int ndr_size)
{
    /*
     * format of device control request
     *
     * See [MS-RDPEFS] 2.2.1.4.5
     *
     * DeviceIoRequest
     * u16       RDPDR_CTYP_CORE
     * u16       PAKID_CORE_DEVICE_IOREQUEST
     * u32       DeviceId
     * u32       FileId
     * u32       CompletionId
     * u32       MajorFunction
     * u32       MinorFunction
     *
     * u32       OutputBufferLength SHOULD be 2048
     * u32       InputBufferLength
     * u32       IoControlCode
     * 20 bytes  padding
     * xx bytes  InputBuffer (variable). First 8 bytes are the NDR
     *           common type header
     */

    struct stream *s;

    make_stream(s);
    if (s == NULL)
    {
        return s;
    }
    init_stream(s, (int)((24 + 4 + 4 + 4 + 20) + 8 + ndr_size));
    if (s == NULL || s->data == NULL)
    {
        free_stream(s);
        return NULL;
    }

    devredir_insert_DeviceIoRequest(s,
                                    irp->DeviceId,
                                    irp->FileId,
                                    irp->CompletionId,
                                    IRP_MJ_DEVICE_CONTROL,
                                    IRP_MN_NONE);

    out_uint32_le(s, 2048);            /* OutputBufferLength               */
    s_push_layer(s, iso_hdr, 4);       /* InputBufferLength - insert later */
    out_uint32_le(s, ioctl);           /* Ioctl Code                       */
    out_uint8s(s, 20);                 /* padding                          */

    /* [MS-RPCE] 2.2.6.1 */
    out_uint32_le(s, 0x00081001);      /* len 8, LE, v1                */
    out_uint32_le(s, 0xcccccccc);      /* filler                       */

    return s;
}

/**
 * Create a new smart card device entry and insert it into smartcards[]
 *
 * @param  device_id  DeviceId of new card
 *
 * @return index into smartcards[] on success, -1 on failure
 *****************************************************************************/
static int
scard_add_new_device(tui32 device_id)
{
    int        index;
    SMARTCARD *sc;

    if ((index = scard_get_free_slot()) < 0)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "scard_get_free_slot failed");
        return -1;
    }

    sc = g_new0(SMARTCARD, 1);
    if (sc == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "system out of memory");
        return -1;
    }

    sc->DeviceId = device_id;
    smartcards[index] = sc;

    return index;
}

/**
 * Find first unused entry in smartcards
 *
 * @return index of first unused entry in smartcards or -1 if smartcards
 * is full
 *****************************************************************************/
static int
scard_get_free_slot(void)
{
    int i;

    for (i = 0; i < MAX_SMARTCARDS; i++)
    {
        if (smartcards[i] == NULL)
        {
            LOG_DEVEL(LOG_LEVEL_DEBUG, "found free slot at index %d", i);
            return i;
        }
    }

    LOG_DEVEL(LOG_LEVEL_ERROR, "too many smart card devices; rejecting this one");
    return -1;
}

/**
 * Release resources prior to shutting down
 *****************************************************************************/
static void
scard_release_resources(void)
{
    int i;

    for (i = 0; i < MAX_SMARTCARDS; i++)
    {
        if (smartcards[i] != NULL)
        {
            g_free(smartcards[i]);
            smartcards[i] = NULL;
        }
    }
}

/*****************************************************************************/
static void
out_align_s(struct stream *s, unsigned int boundary)
{
    unsigned int over = (unsigned int)(s->p - s->data) % boundary;
    if (over != 0)
    {
        out_uint8s(s, boundary - over);
    }
}

/*****************************************************************************/
static void
in_align_s(struct stream *s, unsigned int boundary)
{
    unsigned int over = (unsigned int)(s->p - s->data) % boundary;
    if (over != 0)
    {
        unsigned int seek = boundary - over;
        if (s_check_rem(s, seek))
        {
            in_uint8s(s, seek);
        }
    }
}

/*****************************************************************************/
/**
 * Outputs first part of a DEVREDIR_SCARDCONTEXT
 * @param s Stream
 * @param Context Context
 * @param[in,out] referent_id Next referent ID to use by reference. This is
 *                    incremented if a referent ID is actually used.
 *
 * This call will be followed by a call to
 * out_redir_scardcontext_part2(). The positioning of the call
 * depends on NDR rules.
 */
static void
out_redir_scardcontext_part1(struct stream *s,
                             const struct redir_scardcontext *Context,
                             unsigned int *referent_id)
{
    out_align_s(s, 4);
    out_uint32_le(s, Context->cbContext);
    out_uint32_le(s, *referent_id);
    *referent_id += REFERENT_ID_INC;
}

/*****************************************************************************/
/**
 * Outputs second part of a DEVREDIR_SCARDCONTEXT
 * @param s Stream
 * @param Context Context
 */
static void
out_redir_scardcontext_part2(struct stream *s,
                             const struct redir_scardcontext *Context)
{
    out_align_s(s, 4);
    out_uint32_le(s, Context->cbContext);
    out_uint8a(s, Context->pbContext, Context->cbContext);
}


/*****************************************************************************/
/**
 * Outputs first part of a DEVREDIR_SCARDHANDLE
 * @param s Stream
 * @param hCard Card Handle
 * @param[in,out] referent_id Next referent ID to use by reference. This is
 *                    incremented if a referent ID is actually used.
 *
 * This call will be followed by a call to
 * out_redir_scardhandle_part2(). The positioning of the call
 * depends on NDR rules.
 */
static void
out_redir_scardhandle_part1(struct stream *s,
                            const struct redir_scardhandle *hCard,
                            unsigned int *referent_id)
{
    out_redir_scardcontext_part1(s, &hCard->Context, referent_id);
    // Will already be aligned on a 4-boundary
    out_uint32_le(s, hCard->cbHandle);
    out_uint32_le(s, *referent_id);
    *referent_id += REFERENT_ID_INC;
}

/*****************************************************************************/
/**
 * Outputs second part of a DEVREDIR_SCARDHANDLE
 * @param s Stream
 * @param hCard Card handle
 */
static void
out_redir_scardhandle_part2(struct stream *s,
                            const struct redir_scardhandle *hCard)
{
    out_redir_scardcontext_part2(s, &hCard->Context);
    out_align_s(s, 4);
    out_uint32_le(s, hCard->cbHandle);
    out_uint8a(s, hCard->pbHandle, hCard->cbHandle);
}

/*****************************************************************************/
/**
 * Outputs first part of an scard_io_request
 * @param s Stream
 * @param ioreq I/O request
 * @param[in,out] referent_id Next referent ID to use by reference. This is
 *                    incremented if a referent ID is actually used.
 *
 * This call will be followed by a call to
 * out_scard_io_request_part2(). The positioning of the call
 * depends on NDR rules.
 */
static void
out_scard_io_request_part1(struct stream *s,
                           const struct scard_io_request *ioreq,
                           unsigned int *referent_id)
{
    out_align_s(s, 4);
    out_uint32_le(s, ioreq->dwProtocol);
    out_uint32_le(s, ioreq->cbExtraBytes);
    if (ioreq->cbExtraBytes > 0)
    {
        out_uint32_le(s, *referent_id);
        *referent_id += REFERENT_ID_INC;
    }
    else
    {
        out_uint32_le(s, 0);
    }
}

/*****************************************************************************/
/**
 * Outputs second part of an scard_io_request
 * @param s Stream
 * @param ioreq I/O request
 */
static void
out_scard_io_request_part2(struct stream *s,
                           const struct scard_io_request *ioreq)
{
    if (ioreq->cbExtraBytes > 0)
    {
        out_align_s(s, 4);
        out_uint32_le(s, ioreq->cbExtraBytes);
        out_uint8a(s, ioreq->pbExtraBytes, ioreq->cbExtraBytes);
    }
}

/*****************************************************************************/
/**
 * Outputs the pointed-to-data for this IDL pointer type:-
 *     [string] const wchar_t* str;
 *
 * It is assumed that the referent identifier for the string has already
 * been sent
 *
 * @param s Output stream
 * @param str UTF-8 string to output
 */
static void
out_conformant_and_varying_string(struct stream *s, const char *str)
{
    out_align_s(s, 4);
    unsigned int len = strlen(str) + 1;
    unsigned int num_chars = utf8_as_utf16_word_count(str, len);
    // Max number, offset and actual count ([C706] 14.3.3.4)
    out_uint32_le(s, num_chars);
    out_uint32_le(s, 0);
    out_uint32_le(s, num_chars);
    out_utf8_as_utf16_le(s, str, len);
}

/**
 *
 *****************************************************************************/
static void
scard_send_EstablishContext(struct stream *s,
                            struct establish_context_call *call_data)
{
    int            bytes;

    /* Private Header ([MS-RPCE] 2.2.6.2 */
    s_push_layer(s, mcs_hdr, 4); /* bytes, set later */
    out_uint32_le(s, 0x00000000);

    /* [MS-RDPESC] 2.2.2.1 EstablishContext_Call */
    out_uint32_le(s, call_data->dwScope);

    out_align_s(s, 8); // [MS-RPCE] 2.2.6.2 */
    s_mark_end(s);

    s_pop_layer(s, mcs_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 8;
    out_uint32_le(s, bytes);

    s_pop_layer(s, iso_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 28;
    out_uint32_le(s, bytes);

    bytes = (int) (s->end - s->data);

    /* send to client */
    send_channel_data(g_rdpdr_chan_id, s->data, bytes);
}

/**
 * Send release context / is valid context / cancel
 *****************************************************************************/
static void
scard_send_CommonContextLongReturn(
    struct stream *s,
    struct common_context_long_return_call *call_data,
    const struct redir_scardcontext *Context)
{
    /* see [MS-RDPESC] 3.1.4.2 */

    unsigned int ref_id = REFERENT_ID_BASE; /* Next referent ID to use */
    int            bytes;

    s_push_layer(s, mcs_hdr, 4); /* bytes, set later */
    out_uint32_le(s, 0x00000000);
    out_redir_scardcontext_part1(s, Context, &ref_id);
    out_redir_scardcontext_part2(s, Context);

    s_mark_end(s);

    s_pop_layer(s, mcs_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 8;
    out_uint32_le(s, bytes);

    s_pop_layer(s, iso_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 28;
    out_uint32_le(s, bytes);

    bytes = (int) (s->end - s->data);

    /* send to client */
    send_channel_data(g_rdpdr_chan_id, s->data, bytes);
}

/**
 *
 *****************************************************************************/
static void
scard_send_ListReaders(struct stream *s,
                       struct list_readers_call *call_data,
                       const struct redir_scardcontext *Context)
{
    /* see [MS-RDPESC] 2.2.2.4
     *
     * IDL:-
     *
     * typedef struct _REDIR_SCARDCONTEXT {
     *    [range(0,16)] unsigned long cbContext;
     *    [unique] [size_is(cbContext)] byte *pbContext;
     *    } REDIR_SCARDCONTEXT;
     *
     * struct _ListReaders_Call {
     *     REDIR_SCARDCONTEXT Context;
     *     [range(0, 65536)] unsigned long cBytes;
     *     [unique] [size_is(cBytes)] const byte *mszGroups;
     *     long fmszReadersIsNULL;
     *     unsigned long cchReaders;
     *     } ListReaders_Call;
     *
     * Type summary:-
     *
     * Context.cbContext  Unsigned 32-bit word
     * Context.pbContext  Embedded full pointer to conformant array of bytes
     * cBytes             Unsigned 32-bit word
     * mszGroups          Embedded full pointer to conformant array of bytes
     * fmszReaders        32-bit word
     * cchReaders         Unsigned 32-bit word
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        Context.cbContext
     * 4        Referent Identifier for pbContext
     * 8        cBytes
     * 12       Referent Identifier for mszGroups (or NULL)
     * 16       fmszReadersIsNULL
     * 20       cchReaders
     * 24       Conformant Array pointed to by pbContext
     * ??       Conformant Array pointed to by mszGroups
     *
     */

    unsigned int ref_id = REFERENT_ID_BASE; /* Next referent ID to use */
    int            bytes;
    int            val = 0;    // Referent Id for mszGroups (assume NULL)
    const char *mszGroups = call_data->mszGroups;
    unsigned int cBytes = call_data->cBytes;

    if (cBytes > 0)
    {
        // Get the length of the groups as a UTF-16 string
        cBytes = utf8_as_utf16_word_count(mszGroups, cBytes) * 2;
        val = 0x00020004;
    }

    /* Private Header ([MS-RPCE] 2.2.6.2 */
    s_push_layer(s, mcs_hdr, 4); /* bytes, set later */
    out_uint32_le(s, 0x00000000);

    // REDIR_SCARDCONTEXT Context;
    out_redir_scardcontext_part1(s, Context, &ref_id);
    // [range(0, 65536)] unsigned long cBytes;
    out_uint32_le(s, cBytes);
    // [unique] [size_is(cBytes)] const byte *mszGroups; (pointer)
    out_uint32_le(s, val);
    // long fmszReadersIsNULL;
    out_uint32_le(s, 0x000000);
    // unsigned long cchReaders;
    out_uint32_le(s, SCARD_AUTOALLOCATE);

    // At the end of the struct come the pointed-to structures

    // Context
    out_redir_scardcontext_part2(s, Context);

    // mszGroups is a Uni-dimensional conformant array of bytes
    if (cBytes > 0)
    {
        out_align_s(s, 4);
        out_uint32_le(s, cBytes);
        out_utf8_as_utf16_le(s, mszGroups, cBytes);
    }
    out_align_s(s, 8); // [MS-RPCE] 2.2.6.2 */
    s_mark_end(s);

    s_pop_layer(s, mcs_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 8;
    out_uint32_le(s, bytes);

    s_pop_layer(s, iso_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 28;
    out_uint32_le(s, bytes);

    bytes = (int) (s->end - s->data);

    /* send to client */
    LOG_DEVEL_HEXDUMP(LOG_LEVEL_TRACE, "scard_send_ListReaders:", s->data, bytes);
    send_channel_data(g_rdpdr_chan_id, s->data, bytes);
}

/**
 * Get change in status
 *
 * @param  irp          I/O resource pkt
 * @param  wide         TRUE if unicode string
 * @param  timeout      timeout in milliseconds, -1 for infinity
 * @param  num_readers  number of entries in rsa
 * @param  rsa          array of READER_STATEs
 *****************************************************************************/
static void
scard_send_GetStatusChange(IRP *irp, char *context, int context_bytes,
                           int wide, tui32 timeout,
                           tui32 num_readers, READER_STATE *rsa)
{
    /* see [MS-RDPESC] 2.2.2.11 for ASCII
     * see [MS-RDPESC] 2.2.2.12 for Wide char
     *
     * Here is a breakdown of the Wide-char variant
     *
     * IDL:-
     *
     * typedef struct _REDIR_SCARDCONTEXT {
     *    [range(0,16)] unsigned long cbContext;
     *    [unique] [size_is(cbContext)] byte *pbContext;
     *    } REDIR_SCARDCONTEXT;
     *
     * typedef struct _ReaderState_Common_Call {
     *    unsigned long dwCurrentState;
     *    unsigned long dwEventState;
     *    [range(0,36)] unsigned long cbAtr;
     *    byte rgbAtr[36];
     *    } ReaderState_Common_Call;
     *
     * typedef struct _ReaderStateW {
     *   [string] const wchar_t* szReader;
     *   ReaderState_Common_Call Common;
     *   } ReaderStateW;
     *
     * struct _GetStatusChangeW_Call {
     *    REDIR_SCARDCONTEXT Context;
     *    unsigned long dwTimeOut;
     *    [range(0,11)] unsigned long cReaders;
     *    [size_is(cReaders)] ReaderStateW* rgReaderStates;
     *    } GetStatusChangeW_Call;
     *
     * Type summary:-
     *
     * Context.cbContext  Unsigned 32-bit word
     * Context.pbContext  Embedded full pointer to conformant array of bytes
     * dwTimeOut          Unsigned 32-bit word
     * cReaders           Unsigned 32-bit word
     * rgReaderStates
     *                    Embedded full pointer to array of rgReaderStates
     * rgReaderStates.szReader
     *                    Embedded full pointer to conformant and varying
     *                    string of [Windows] wchar_t
     * rgReaderStates.Common.dwCurrentState
     *                    Unsigned 32-bit word
     * rgReaderStates.Common.dwEventState
     *                    Unsigned 32-bit word
     * rgReaderStates.Common.cbAtr
     *                    Unsigned 32-bit word
     * rgReaderStates.Common.rgbAtr[36]
     *                    Uni-dimensional fixed array
     *
     * NDR:-
     * Offset   Decription
     * 0        Context.cbContext
     * 4        Referent Identifier for pbContext
     * 8        dwTimeOut;
     * 12       cReaders;
     * 16       Referent Identifier for rgReaderStates
     * 20       Conformant Array pointed to by pbContext
     * ??       Conformant Array pointed to by rgReaderStates. Each element
     *          of this array has a pointer to a string for the name
     * ??       String names pointed to in the above array.
     */

    SMARTCARD     *sc;
    READER_STATE  *rs;
    struct stream *s;
    tui32          ioctl;
    int            bytes;
    unsigned int   i;

    if ((sc = smartcards[irp->scard_index]) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "smartcards[%d] is NULL", irp->scard_index);
        return;
    }

    ioctl = (wide) ? SCARD_IOCTL_GET_STATUS_CHANGEW :
            SCARD_IOCTL_GET_STATUS_CHANGEA;

    if ((s = scard_make_new_ioctl(irp, ioctl, 4096)) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl failed");
        return;
    }

    s_push_layer(s, mcs_hdr, 4); /* bytes, set later */
    out_uint32_le(s, 0x00000000);
    // REDIR_SCARDCONTEXT Context;
    out_uint32_le(s, context_bytes);
    out_uint32_le(s, 0x00020000);

    // unsigned long dwTimeOut;
    out_uint32_le(s, timeout);
    // [range(0,11)] unsigned long cReaders;
    out_uint32_le(s, num_readers);
    // [size_is(cReaders)] ReaderStateW* rgReaderStates;
    out_uint32_le(s, 0x00020004);

    // At the end of the struct come the pointed-to structures

    // Context field pbContext is a Uni-dimensional conformant array
    out_uint32_le(s, context_bytes);
    out_uint8a(s, context, context_bytes);

    // rgReaderState is a Uni-dimensional conformant array
    out_align_s(s, 4);
    out_uint32_le(s, num_readers);

    /* insert card reader state */
    for (i = 0; i < num_readers; i++)
    {
        rs = &rsa[i];
        //  [string] const wchar_t* szReader (wide)
        //  [string] const char_t* szReader (ASCII)
        out_uint32_le(s, 0x00020008 + (i * 4));
        //  unsigned long dwCurrentState;
        out_uint32_le(s, rs->current_state);
        //  unsigned long dwEventState;
        out_uint32_le(s, rs->event_state);
        //  [range(0,36)] unsigned long cbAtr;
        out_uint32_le(s, rs->atr_len);
        //  byte rgbAtr[36];
        out_uint8p(s, rs->atr, 33);
        out_uint8s(s, 3);
    }

    /* insert card reader names */
    for (i = 0; i < num_readers; i++)
    {
        rs = &rsa[i];
        out_conformant_and_varying_string(s, rs->reader_name);
    }

    s_mark_end(s);

    s_pop_layer(s, mcs_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 8;
    out_uint32_le(s, bytes);

    s_pop_layer(s, iso_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 28;
    out_uint32_le(s, bytes);

    bytes = (int) (s->end - s->data);

    /* send to client */
    LOG_DEVEL_HEXDUMP(LOG_LEVEL_TRACE, "scard_send_GetStatusChange:", s->data, bytes);
    send_channel_data(g_rdpdr_chan_id, s->data, bytes);
}

/**
 * Send connect command
 *
 * @param  irp  I/O resource pkt
 * @param  wide TRUE if unicode string
 * @param  rs   reader state
 *****************************************************************************/
static void
scard_send_Connect(struct stream *s, struct connect_call *call_data,
                   const struct redir_scardcontext *context)
{
    /* See [MS-RDPESC] 2.2.2.14
     *
     * IDL:-
     *
     * typedef struct _REDIR_SCARDCONTEXT {
     *    [range(0,16)] unsigned long cbContext;
     *    [unique] [size_is(cbContext)] byte *pbContext;
     *    } REDIR_SCARDCONTEXT;
     *
     * typedef struct _Connect_Common {
     *     REDIR_SCARDCONTEXT Context;
     *     unsigned long dwShareMode;
     *     unsigned long dwPreferredProtocols;
     * } Connect_Common;
     *
     * typedef struct _ConnectW_Call {
     *     [string] const wchar_t* szReader;
     *     Connect_Common Common;
     * } ConnectW_Call;
     *
     * Type summary:-
     *
     * szReader           Embedded full pointer to conformant and varying
     *                    string of [Windows] wchar_t
     * Common.Context.cbContext
     *                    Unsigned 32-bit word
     * Common.Context.pbContext
     *                    Embedded full pointer to conformant array of bytes
     * Common.dwShareMode Unsigned 32-bit word
     * Common.dwPreferredProtocols
     *                    Unsigned 32-bit word
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        Referent Identifier for szReader
     * 4        Context.cbContext
     * 8        Referent Identifier for pbContext
     * 12       dwShareMode
     * 16       dwPreferredProtocols
     * 20       Conformant and varying Array pointed to by szReader
     * ??       Conformant Array pointed to by pbContext
     *
     */
    unsigned int ref_id = REFERENT_ID_BASE; /* Next referent ID to use */
    int            bytes;

    s_push_layer(s, mcs_hdr, 4); /* bytes, set later */
    out_uint32_le(s, 0x00000000);
    // [string] const wchar_t* szReader;
    out_uint32_le(s, 0x00020000);

    // REDIR_SCARDCONTEXT Context;
    out_redir_scardcontext_part1(s, context, &ref_id);
    // unsigned long dwShareMode;
    out_uint32_le(s, call_data->dwShareMode);
    // unsigned long dwPreferredProtocols;
    out_uint32_le(s, call_data->dwPreferredProtocols);

    /* insert card reader name */
    out_conformant_and_varying_string(s, call_data->szReader);

    /* insert context data */
    out_redir_scardcontext_part2(s, context);

    out_align_s(s, 8); // [MS-RPCE] 2.2.6.2 */
    s_mark_end(s);

    s_pop_layer(s, mcs_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 8;
    out_uint32_le(s, bytes);

    s_pop_layer(s, iso_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 28;
    out_uint32_le(s, bytes);

    bytes = (int) (s->end - s->data);

    /* send to client */
    send_channel_data(g_rdpdr_chan_id, s->data, bytes);
}

/**
 * The reconnect method re-establishes a smart card reader handle. On success,
 * the handle is valid once again.
 *
 * @param  con        connection to client
 * @param  sc_handle  handle to device
 * @param  rs         reader state where following fields are set
 *                        rs.shared_mode_flag
 *                        rs.preferred_protocol
 *                        rs.init_type
 *****************************************************************************/
static void
scard_send_Reconnect(IRP *irp, char *context, int context_bytes,
                     char *card, int card_bytes, READER_STATE *rs)
{
    /* see [MS-RDPESC] 2.2.2.15 */
    /* see [MS-RDPESC] 3.1.4.36 */

    SMARTCARD     *sc;
    struct stream *s;
    int            bytes;

    if ((sc = smartcards[irp->scard_index]) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "smartcards[%d] is NULL", irp->scard_index);
        return;
    }

    if ((s = scard_make_new_ioctl(irp, SCARD_IOCTL_RECONNECT, 4096)) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl failed");
        return;
    }

    /*
     * command format
     *
     * ......
     *       20 bytes    padding
     * u32    4 bytes    len 8, LE, v1
     * u32    4 bytes    filler
     *       24 bytes    unused (s->p currently pointed here at unused[0])
     * u32    4 bytes    dwShareMode
     * u32    4 bytes    dwPreferredProtocols
     * u32    4 bytes    dwInitialization
     * u32    4 bytes    context length
     * u32    4 bytes    context
     * u32    4 bytes    handle length
     * u32    4 bytes    handle
     */

    xstream_seek(s, 24); /* TODO */

    out_uint32_le(s, rs->dwShareMode);
    out_uint32_le(s, rs->dwPreferredProtocols);
    out_uint32_le(s, rs->init_type);
    out_uint32_le(s, context_bytes);
    out_uint8a(s, context, context_bytes);
    out_uint32_le(s, card_bytes);
    out_uint8a(s, card, card_bytes);

    s_mark_end(s);

    s_pop_layer(s, iso_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 28;
    out_uint32_le(s, bytes);

    bytes = (int) (s->end - s->data);

    /* send to client */
    send_channel_data(g_rdpdr_chan_id, s->data, bytes);
}

/**
 * Lock smart card reader for exclusive access for specified smart
 * card reader handle.
 *
 * @param  con   connection to client
 *****************************************************************************/
static void
scard_send_HCardAndDisposition(struct stream *s,
                               struct hcard_and_disposition_call *call_data,
                               const struct redir_scardhandle *hCard)
{
    /* see [MS-RDPESC] 2.2.2.16 */
    int bytes;
    unsigned int ref_id = REFERENT_ID_BASE; /* Next referent ID to use */

    /* Private Header ([MS-RPCE] 2.2.6.2 */
    s_push_layer(s, mcs_hdr, 4); /* bytes, set later */
    out_uint32_le(s, 0x00000000);

    out_redir_scardhandle_part1(s, hCard, &ref_id);

    // unsigned long dwDisposition;
    out_uint32_le(s, call_data->dwDisposition);

    // Now add the data pointed to by the referents
    out_redir_scardhandle_part2(s, hCard);

    out_align_s(s, 8); // [MS-RPCE] 2.2.6.2 */
    s_mark_end(s);

    s_pop_layer(s, mcs_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 8;
    out_uint32_le(s, bytes);

    s_pop_layer(s, iso_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 28;
    out_uint32_le(s, bytes);

    bytes = (int) (s->end - s->data);

    /* send to client */
    send_channel_data(g_rdpdr_chan_id, s->data, bytes);
}

/**
 * Get the status of a connection for a valid smart card reader handle
 *
 * @param  con   connection to client
 * @param  wide  TRUE if unicode string
 *****************************************************************************/
static void
scard_send_Status(struct stream *s, struct status_call *call_data,
                  const struct redir_scardhandle *hCard)
{
    /* see [MS-RDPESC] 2.2.2.18
     *
     * IDL:-
     *
     * typedef struct _REDIR_SCARDCONTEXT {
     *    [range(0,16)] unsigned long cbContext;
     *    [unique] [size_is(cbContext)] byte *pbContext;
     *    } REDIR_SCARDCONTEXT;
     *
     * typedef struct _REDIR_SCARDHANDLE {
     *    REDIR_SCARDCONTEXT Context;
     *    [range(0,16)] unsigned long cbHandle;
     *    [size_is(cbHandle)] byte *pbHandle;
     *    } REDIR_SCARDHANDLE;
     *
     * typedef struct _Status_Call {
     *    REDIR_SCARDHANDLE hCard;
     *    long fmszReaderNamesIsNULL;
     *    unsigned long cchReaderLen;
     *    unsigned long cbAtrLen;
     *    } Status_Call;
     *
     * Type summary:-
     * hCard.Context.cbContext  Unsigned 32-bit word
     * hCard.Context.pbContext  Embedded full pointer to conformant
     *                          array of bytes
     * hCard.cbHandle  Unsigned 32-bit word
     * hCard.pbHandle  Embedded full pointer to conformant array of bytes
     * fmszReaderNamesIsNULL    32-bit word
     * cchReaderLen             32-bit word
     * cbAtrLen                 32-bit word
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        hCard.Context.cbContext
     * 4        hCard.Context.pbContext Referent Identifier
     * 8        hCard.cbHandle
     * 12       hCard.pbHandle Referent Identifier
     * 16       fmszReaderNamesIsNULL
     * 20       cchReaderLen
     * 24       cbAtrLen
     * 28       length of context in bytes
     * 32       Context data (up to 16 bytes)
     * ??       length of handle in bytes
     * ??       Handle data (up to 16 bytes)
     */
    int bytes;
    unsigned int ref_id = REFERENT_ID_BASE; /* Next referent ID to use */

    s_push_layer(s, mcs_hdr, 4); /* bytes, set later */
    out_uint32_le(s, 0x00000000);

    out_redir_scardhandle_part1(s, hCard, &ref_id);

    // Always ask for all the data
    // long fmszReaderNamesIsNULL;
    out_uint32_le(s, 0x000000);
    // unsigned long cchReaderLen;
    out_uint32_le(s, SCARD_AUTOALLOCATE);
    // unsigned long cchAtrLen;
    out_uint32_le(s, 0); // Unused by server end

    // Now add the data pointed to by the referents
    out_redir_scardhandle_part2(s, hCard);

    out_align_s(s, 8); // [MS-RPCE] 2.2.6.2 */

    s_mark_end(s);

    s_pop_layer(s, mcs_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 8;
    out_uint32_le(s, bytes);

    s_pop_layer(s, iso_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 28;
    out_uint32_le(s, bytes);

    bytes = (int) (s->end - s->data);

    LOG_DEVEL_HEXDUMP(LOG_LEVEL_TRACE, "", s->data, bytes);

    /* send to client */
    send_channel_data(g_rdpdr_chan_id, s->data, bytes);
}

/**
 * The Transmit_Call structure is used to send data to the smart card
 * associated with a valid context.
 *****************************************************************************/
static int
scard_send_Transmit(struct stream *s, struct transmit_call *call_data,
                    const struct redir_scardhandle *hCard)
{
    /* see [MS-RDPESC] 2.2.2.19
     *
     * IDL:-
     *
     * typedef struct _REDIR_SCARDCONTEXT {
     *    [range(0,16)] unsigned long cbContext;
     *    [unique] [size_is(cbContext)] byte *pbContext;
     *    } REDIR_SCARDCONTEXT;
     *
     * typedef struct _REDIR_SCARDHANDLE {
     *    REDIR_SCARDCONTEXT Context;
     *    [range(0,16)] unsigned long cbHandle;
     *    [size_is(cbHandle)] byte *pbHandle;
     *    } REDIR_SCARDHANDLE;
     *
     * typedef struct _SCardIO_Request {
     *    unsigned long dwProtocol;
     *    [range(0,1024)] unsigned long cbExtraBytes;
     *    [unique] [size_is(cbExtraBytes)] byte *pbExtraBytes;
     *    } SCardIO_Request;
     *
     * typedef struct _Transmit_Call {
     *    REDIR_SCARDHANDLE hCard;
     *    SCardIO_Request ioSendPci;
     *    [range(0,66560)] unsigned long cbSendLength;
     *    [size_is(cbSendLength)] const byte* pbSendBuffer;
     *    [unique] SCardIO_Request* pioRecvPci;
     *    long fpbRecvBufferIsNULL;
     *    unsigned long cbRecvLength;
     *    } Transmit_Call;
     *
     * Type summary:-
     * hCard.Context.cbContext  Unsigned 32-bit word
     * hCard.Context.pbContext  Embedded full ptr to conformant array of bytes
     * hCard.cbHandle           Unsigned 32-bit word
     * hCard.pbHandle           Embedded full ptr to conformant array of bytes
     * ioSendPci.dwProtocol     32-bit word
     * ioSendPci.cbExtraBytes   32-bit word
     * ioSendPci.pbExtraBytes   Embedded full ptr to conformant array of bytes
     * cbSendLength             32-bit word
     * pbSendBuffer             Embedded full ptr to conformant array of bytes
     * pioRecvPci               Embedded full ptr to struct
     * fpbRecvBufferIsNULL      32-bit word
     * cbRecvLength             32-bit word
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        hCard.Context.cbContext
     * 4        hCard.Context.pbContext Referent Identifier
     * 8        hCard.cbHandle
     * 12       hCard.pbHandle Referent Identifier
     * 16       ioSendPci.dwProtocol
     * 20       ioSendPci.cbExtraBytes
     * 24       ioSendPci.pbExtraBytes Referent Identifier
     * 28       cbSendLength
     * 32       pbSendBuffer referent identifier
     * 36       pioRecvPci referent identifier
     * 40       fpbRecvBufferIsNULL
     * 44       cbRecvLength
     * 48       length of context in bytes (hCard.Context.cbContext copy)
     * 52       Context data (up to 16 bytes)
     * ??       length of handle in bytes (hCard.cbHandle copy)
     * ??       Handle data (up to 16 bytes)
     * if (ioSendPci.pbExtraBytes != NULL)
     * | ??       Copy of ioSendPci.cbExtraBytes
     * | ??       ioSendPci.pbExtraBytes data
     * ??       Copy of cbSendLength
     * ??       pbSendBuffer data
     * if (pioRecvPci != NULL)
     * | ??     pioRecvPci.dwProtocol
     * | ??     pioRecvPci.cbExtraBytes
     * | ??     pioRecvPci.pbExtraBytes Referent identifier
     * if (pioRecvPci.pbExtraBytes != NULL)
     * | ??       Copy of pioRecvPci.cbExtraBytes
     * | ??       pioRecvPci.pbExtraBytes data
     */

    int            bytes;
    unsigned int ref_id = REFERENT_ID_BASE; /* Next referent ID to use */

    s_push_layer(s, mcs_hdr, 4); /* bytes, set later */
    out_uint32_le(s, 0x00000000);

    // REDIR_SCARDHANDLE hCard;
    out_redir_scardhandle_part1(s, hCard, &ref_id);
    // SCardIO_Request ioSendPci;
    out_scard_io_request_part1(s, call_data->pioSendPci, &ref_id);

    // [range(0,66560)] unsigned long cbSendLength;
    out_uint32_le(s, call_data->cbSendLength);
    // [size_is(cbSendLength)] const byte* pbSendBuffer;
    // This could be empty - check for that.
    if (call_data->cbSendLength > 0)
    {
        out_uint32_le(s, ref_id);
        ref_id += REFERENT_ID_INC;
    }
    else
    {
        out_uint32_le(s, 0);
    }
    // [unique] SCardIO_Request* pioRecvPci;
    if (call_data->pioRecvPci != NULL)
    {
        out_uint32_le(s, ref_id);
        ref_id += REFERENT_ID_INC;
    }
    else
    {
        out_uint32_le(s, 0);
    }
    // long fpbRecvBufferIsNULL;
    out_uint32_le(s, call_data->retrieve_length_only);
    // unsigned long cbRecvLength;
    out_uint32_le(s, call_data->cbRecvLength);

    // Now output all the pointed-to data
    out_redir_scardhandle_part2(s, hCard);
    out_scard_io_request_part2(s, call_data->pioSendPci);

    out_align_s(s, 4);
    if (call_data->cbSendLength > 0)
    {
        out_uint32_le(s, call_data->cbSendLength);
        out_uint8a(s, call_data->pbSendBuffer, call_data->cbSendLength);
    }

    if (call_data->pioRecvPci != NULL)
    {
        out_scard_io_request_part1(s, call_data->pioRecvPci, &ref_id);
        out_scard_io_request_part2(s, call_data->pioRecvPci);
    }

    out_align_s(s, 8); // [MS-RPCE] 2.2.6.2 */
    s_mark_end(s);

    s_pop_layer(s, mcs_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 8;
    out_uint32_le(s, bytes);

    s_pop_layer(s, iso_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 28;
    out_uint32_le(s, bytes);

    bytes = (int) (s->end - s->data);

    /* send to client */
    LOG_DEVEL_HEXDUMP(LOG_LEVEL_TRACE, "scard_send_Transmit:", s->data, bytes);
    send_channel_data(g_rdpdr_chan_id, s->data, bytes);

    return 0;
}

/**
 * Communicate directly with the smart card reader
 *****************************************************************************/
static int
scard_send_Control(IRP *irp, char *context, int context_bytes,
                   char *card, int card_bytes, char *send_data,
                   int send_bytes, int recv_bytes, int control_code)
{
    /* see [MS-RDPESC] 2.2.2.19 */

    SMARTCARD     *sc;
    struct stream *s;
    int            bytes;
    int            val;

    if ((sc = smartcards[irp->scard_index]) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "smartcards[%d] is NULL", irp->scard_index);
        return 1;
    }

    if ((s = scard_make_new_ioctl(irp, SCARD_IOCTL_CONTROL, 4096)) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl");
        return 1;
    }

    s_push_layer(s, mcs_hdr, 4); /* bytes, set later */
    out_uint32_le(s, 0x00000000);
    out_uint32_le(s, context_bytes);
    out_uint32_le(s, 0x00020000); /* map0 */
    out_uint32_le(s, card_bytes);
    out_uint32_le(s, 0x00020004); /* map1 */
    out_uint32_le(s, control_code);
    out_uint32_le(s, send_bytes);
    val = send_bytes > 0 ? 0x00020008 : 0;
    out_uint32_le(s, val);        /* map2 */
    out_uint32_le(s, 0x00000000);
    out_uint32_le(s, recv_bytes);
    out_uint32_le(s, context_bytes);
    out_uint8a(s, context, context_bytes);
    out_uint32_le(s, card_bytes);
    out_uint8a(s, card, card_bytes);
    if (send_bytes > 0)
    {
        out_uint32_le(s, send_bytes);
        out_uint8a(s, send_data, send_bytes);
    }
    else
    {
        out_uint32_le(s, 0x00000000);
    }

    s_mark_end(s);

    s_pop_layer(s, mcs_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 8;
    out_uint32_le(s, bytes);

    s_pop_layer(s, iso_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 28;
    out_uint32_le(s, bytes);

    bytes = (int) (s->end - s->data);

    LOG_DEVEL_HEXDUMP(LOG_LEVEL_TRACE, "", s->data, bytes);

    /* send to client */
    send_channel_data(g_rdpdr_chan_id, s->data, bytes);
    return 0;
}

/**
 * Get reader attributes
 *****************************************************************************/
static int
scard_send_GetAttrib(IRP *irp, char *card, int card_bytes, READER_STATE *rs)
{
    /* see [MS-RDPESC] 2.2.2.21 */

    SMARTCARD     *sc;
    struct stream *s;
    int            bytes;

    if ((sc = smartcards[irp->scard_index]) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "smartcards[%d] is NULL", irp->scard_index);
        return 1;
    }

    if ((s = scard_make_new_ioctl(irp, SCARD_IOCTL_GETATTRIB, 4096)) == NULL)
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "scard_make_new_ioctl");
        return 1;
    }

    /*
     * command format
     *
     * ......
     *       20 bytes    padding
     * u32    4 bytes    len 8, LE, v1
     * u32    4 bytes    filler
     *       24 bytes    unused (s->p currently pointed here at unused[0])
     * u32    4 bytes    dwAttribId
     *        4 bytes    unused
     * u32    4 bytes    dwAttrLen
     *        8 bytes    unused
     * u32    4 bytes    handle len
     * u32    4 bytes    handle
     */

    xstream_seek(s, 24); /* TODO */
    out_uint32_le(s, rs->dwAttribId);
    out_uint32_le(s, 0);
    out_uint32_le(s, rs->dwAttrLen);
    xstream_seek(s, 8);
    out_uint32_le(s, card_bytes);
    out_uint8a(s, card, card_bytes);

    s_mark_end(s);

    s_pop_layer(s, iso_hdr);
    bytes = (int) (s->end - s->p);
    bytes -= 28;
    out_uint32_le(s, bytes);

    bytes = (int) (s->end - s->data);

    /* send to client */
    send_channel_data(g_rdpdr_chan_id, s->data, bytes);
    return 0;
}

/******************************************************************************
**                                                                           **
**                    local callbacks into this module                       **
**                                                                           **
******************************************************************************/


/*****************************************************************************/
/* returns error */
static int
scard_function_establish_context_return(struct scard_client *client,
                                        void *vcall_data,
                                        struct stream *in_s,
                                        unsigned int len, unsigned int status)
{
    /* see [MS-RDPESC] 2.2.3.2
     *
     * IDL:-
     *
     * typedef struct _REDIR_SCARDCONTEXT {
     *    [range(0,16)] unsigned long cbContext;
     *    [unique] [size_is(cbContext)] byte *pbContext;
     *    } REDIR_SCARDCONTEXT;
     *
     * typedef struct _EstablishContext_Return {
     *     long ReturnCode;
     *     REDIR_SCARDCONTEXT Context;
     *     } EstablishContext_Return;
     *
     * Type summary:-
     *
     * ReturnCode         32-bit word
     * Context.cbContext  Unsigned 32-bit word
     * Context.pbContext  Embedded full pointer to conformant array of bytes
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        ReturnCode
     * 4        Context.cbContext
     * 8        Context.pbContext Referent Identifier
     * 12       length of context in bytes
     * 16       Context data (up to 16 bytes)
     */
    struct establish_context_call *call_data;
    call_data = (struct establish_context_call *)vcall_data;
    int ReturnCode = XSCARD_E_UNEXPECTED;
    struct redir_scardcontext Context = {0};
    unsigned int app_context = 0;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_establish_context_return:");
    LOG_DEVEL(LOG_LEVEL_DEBUG, "  status 0x%8.8x", status);

    if (status == 0)
    {
        if (s_check_rem_and_log(in_s, 8 + 8 + 4 + 4 + 4 + 4,
                                "[MS-RDPESC] EstablishContext_Return(1)"))
        {
            in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.1 */
            in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.2 */

            in_uint32_le(in_s, ReturnCode);
            in_uint32_le(in_s, Context.cbContext); // Context.cbContext
            in_uint8s(in_s, 4); // Context.pbContext Referent Identifier
            in_uint8s(in_s, 4); // Context.pbContext copy
            if (Context.cbContext > sizeof(Context.pbContext))
            {
                LOG(LOG_LEVEL_ERROR, "scard_function_establish_context_return:"
                    " opps context_bytes %u", Context.cbContext);
                Context.cbContext =  sizeof(Context.pbContext);
            }
            if (s_check_rem_and_log(in_s, Context.cbContext,
                                    "[MS-RDPESC] EstablishContext_Return(2)"))
            {
                in_uint8a(in_s, Context.pbContext, Context.cbContext);
            }
        }
        if (ReturnCode == XSCARD_S_SUCCESS)
        {
            if (!scdata_add_context_mapping(client, &Context, &app_context))
            {
                // TODO: Release context at client?
                ReturnCode = XSCARD_E_NO_MEMORY;
            }
        }
        LOG_DEVEL(LOG_LEVEL_DEBUG,
                  "scard_function_establish_context_return: "
                  "result %d app_context %d", ReturnCode, app_context);
    }

    return call_data->callback(client, ReturnCode, app_context);
}

/*****************************************************************************/
/* returns error */
static int
scard_function_common_context_return(struct scard_client *client,
                                     void *vcall_data,
                                     struct stream *in_s,
                                     unsigned int len, unsigned int status)
{
    /* see [MS-RDPESC] 2.2.3.3
     *
     * IDL:-
     * typedef struct _long_Return {
     *     long ReturnCode;
     * } long_Return;*
     *
     * Type summary:-
     *
     * ReturnCode         32-bit word
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        ReturnCode
     */
    struct common_context_long_return_call *call_data;
    call_data = (struct common_context_long_return_call *)vcall_data;
    int ReturnCode = XSCARD_E_UNEXPECTED;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_common_context_return:");
    LOG_DEVEL(LOG_LEVEL_DEBUG, "  status 0x%8.8x", status);

    if (status == 0)
    {
        if (s_check_rem_and_log(in_s, 8 + 8 + 4, "[MS-RDPESC] Long_Return"))
        {
            in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.1 */
            in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.2 */

            in_uint32_le(in_s, ReturnCode);
        }

        /* Special processing for message types */
        switch (call_data->code)
        {
            case CCLR_RELEASE_CONTEXT:
                if (ReturnCode == XSCARD_S_SUCCESS)
                {
                    scdata_remove_context_mapping(client,
                                                  call_data->app_context);
                }
                break;

            case CCLR_IS_VALID_CONTEXT:
            case CCLR_CANCEL:
                /* No special processing */
                break;
        }

        LOG_DEVEL(LOG_LEVEL_DEBUG,
                  "scard_function_common_context_return: "
                  "result %d", ReturnCode);
    }

    return call_data->callback(client, ReturnCode);
}

/*****************************************************************************/
static int
scard_function_list_readers_return(struct scard_client *client,
                                   void *vcall_data,
                                   struct stream *in_s,
                                   unsigned int len, unsigned int status)
{
    /* see [MS-RDPESC] 2.2.3.4
     *
     * IDL:-
     *
     * typedef struct _longAndMultiString_Return {
     *     long ReturnCode;
     *     [range(0,65536)] unsigned long cBytes;
     *     [unique] [size_is(cBytes)] byte *msz;
     *     } ListReaderGroups_Return, ListReaders_Return;
     *
     * Type summary:-
     *
     * ReturnCode         32-bit word
     * CBytes             Unsigned 32-bit word
     * msz                Embedded full pointer to conformant array of bytes
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        ReturnCode
     * 4        cBytes
     * 8        msz pointer Referent Identifier
     * 12       length of multistring in bytes
     * 16       Multistring data
     */
    struct list_readers_call *call_data;
    call_data = (struct list_readers_call *)vcall_data;
    unsigned int ReturnCode = XSCARD_E_UNEXPECTED;
    unsigned int utf8len = 0;
    char *msz_readers = NULL;
    int rv;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_list_readers_return:");
    LOG_DEVEL(LOG_LEVEL_DEBUG, "  status 0x%8.8x", status);

    if (status == 0)
    {
        unsigned int cBytes = 0;

        if (s_check_rem_and_log(in_s, 8 + 8 + 4 + 4 + 4 + 4,
                                "[MS-RDPESC] ListReaders_return(1)"))
        {
            in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.1 */
            in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.2 */

            in_uint32_le(in_s, ReturnCode);
            in_uint32_le(in_s, cBytes);
            in_uint8s(in_s, 4); // msz pointer Referent Identifier
            in_uint8s(in_s, 4); // copy of msz length
            // Get the length of the required UTF-8 string
            if (s_check_rem_and_log(in_s, cBytes,
                                    "[MS-RDPESC] ListReaders_return(2)"))
            {
                utf8len = in_utf16_le_fixed_as_utf8_length(in_s, cBytes / 2);
            }
        }

        // Now work out what the caller actually wanted
        if (ReturnCode == XSCARD_S_SUCCESS)
        {
            if ((msz_readers = (char *)malloc(utf8len)) == NULL)
            {
                LOG(LOG_LEVEL_ERROR, "scard_function_list_readers_return: "
                    "Can't allocate %u bytes of memory", utf8len);
                utf8len = 0;
                ReturnCode = XSCARD_E_NO_MEMORY;
            }
            else
            {
                in_utf16_le_fixed_as_utf8(in_s, cBytes / 2,
                                          msz_readers, utf8len);
            }
        }
    }

    rv = call_data->callback(client, ReturnCode, utf8len, msz_readers);
    free(msz_readers);
    return rv;
}

/**
 *
 *****************************************************************************/
static void
scard_handle_GetStatusChange_Return(struct stream *s, IRP *irp,
                                    tui32 DeviceId, tui32 CompletionId,
                                    tui32 IoStatus)
{
    tui32 len;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "entered");
    /* sanity check */
    if ((DeviceId != irp->DeviceId) || (CompletionId != irp->CompletionId))
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "DeviceId/CompletionId do not match those in IRP");
        return;
    }
    /* get OutputBufferLen */
    xstream_rd_u32_le(s, len);
    scard_function_get_status_change_return(irp->user_data, s, len, IoStatus);
    devredir_irp_delete(irp);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "leaving");
}


/*****************************************************************************/
static int
scard_function_connect_return(struct scard_client *client,
                              void *vcall_data,
                              struct stream *in_s,
                              unsigned int len, unsigned int status)
{
    /* see [MS-RDPESC] 2.2.3.8
     *
     * IDL:-
     *
     * typedef struct _REDIR_SCARDCONTEXT {
     *    [range(0,16)] unsigned long cbContext;
     *    [unique] [size_is(cbContext)] byte *pbContext;
     *    } REDIR_SCARDCONTEXT;
     *
     * typedef struct _REDIR_SCARDHANDLE {
     *    REDIR_SCARDCONTEXT Context;
     *    [range(0,16)] unsigned long cbHandle;
     *    [size_is(cbHandle)] byte *pbHandle;
     *    } REDIR_SCARDHANDLE;
     *
     * typedef struct _Connect_Return {
     *    long ReturnCode;
     *    REDIR_SCARDHANDLE hCard;
     *    unsigned long dwActiveProtocol;
     *    } Connect_Return;
     *
     * Type summary:-
     *
     * ReturnCode         32-bit word
     * hCard.Context.cbContext  Unsigned 32-bit word
     * hCard.Context.pbContext  Embedded full pointer to conformant
     *                          array of bytes
     * hCard.cbHandle  Unsigned 32-bit word
     * hCard.pbHandle  Embedded full pointer to conformant array of bytes
     * dwActiveProtocol   32-bit word
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        ReturnCode
     * 4        hCard.Context.cbContext
     * 8        hCard.Context.pbContext Referent Identifier
     * 12       hCard.cbHandle
     * 16       hCard.pbHandle Referent Identifier
     * 20       dwActiveProtocol
     * if (hCard.Context.pbContext Referent Identifier != NULL)
     * | 24       length of context in bytes
     * | 28       Context data (up to 16 bytes)
     * ??       length of handle in bytes
     * ??       Handle data (up to 16 bytes)
     */
    struct connect_call *call_data = (struct connect_call *)vcall_data;
    int ReturnCode = XSCARD_E_UNEXPECTED;
    struct redir_scardhandle hCard = {0};
    unsigned int app_hcard = 0;
    unsigned int dwActiveProtocol = 0;
    unsigned int context_ref_ident;
    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_connect_return:");
    LOG_DEVEL(LOG_LEVEL_DEBUG, "  status 0x%8.8x", status);

    if (status != 0)
    {
        goto done;
    }
    if (!s_check_rem_and_log(in_s, 8 + 8 + 4 + 4 + 4 + 4 + 4 + 4 + 4,
                             "[MS-RDPESC] EstablishContext_Return(1)"))
    {
        goto done;
    }
    in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.1 */
    in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.2 */

    in_uint32_le(in_s, ReturnCode);
    in_uint32_le(in_s, hCard.Context.cbContext);
    in_uint32_le(in_s, context_ref_ident);
    in_uint32_le(in_s, hCard.cbHandle);
    in_uint8s(in_s, 4); // hcard.pbHandle Referent Identifier
    in_uint32_le(in_s, dwActiveProtocol);
    if (context_ref_ident != 0) // pbContext may be NULL
    {
        in_uint8s(in_s, 4); // hCard.Context.cbContext copy
        if (!s_check_rem_and_log(in_s, hCard.Context.cbContext,
                                 "[MS-RDPESC] EstablishContext_Return(2)"))
        {
            goto done;
        }
        in_uint8a(in_s, hCard.Context.pbContext, hCard.Context.cbContext);
        in_align_s(in_s, 4);
    }
    in_uint8s(in_s, 4); // hCard.cbHandle copy
    if (!s_check_rem_and_log(in_s, hCard.cbHandle,
                             "[MS-RDPESC] EstablishContext_Return(3)"))
    {
        goto done;
    }
    in_uint8a(in_s, hCard.pbHandle, hCard.cbHandle);
    if (!scdata_add_card_mapping(client, call_data->app_context,
                                 &hCard, &app_hcard))
    {
        ReturnCode = XSCARD_E_NO_MEMORY;
    }

done:
    return call_data->callback(client,
                               ReturnCode, app_hcard, dwActiveProtocol);
}

/**
 *
 *****************************************************************************/
static void
scard_handle_Reconnect_Return(struct stream *s, IRP *irp,
                              tui32 DeviceId, tui32 CompletionId,
                              tui32 IoStatus)
{
    tui32 len;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "entered");

    /* sanity check */
    if ((DeviceId != irp->DeviceId) || (CompletionId != irp->CompletionId))
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "DeviceId/CompletionId do not match those in IRP");
        return;
    }

    /* get OutputBufferLen */
    xstream_rd_u32_le(s, len);
    scard_function_reconnect_return(irp->user_data, s, len, IoStatus);
    devredir_irp_delete(irp);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "leaving");
}

/*****************************************************************************/
/* returns error */
static int
scard_function_begin_transaction_return(struct scard_client *client,
                                        void *vcall_data, struct stream *in_s,
                                        unsigned int len, unsigned int status)
{
    /* see [MS-RDPESC] 2.2.3.3
     *
     * IDL:-
     * typedef struct _long_Return {
     *     long ReturnCode;
     * } long_Return;*
     *
     * Type summary:-
     *
     * ReturnCode         32-bit word
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        ReturnCode
     */
    struct hcard_and_disposition_call *call_data;
    call_data = (struct hcard_and_disposition_call *)vcall_data;
    int ReturnCode = XSCARD_E_UNEXPECTED;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_begin_transaction_return:");

    if (status == 0)
    {
        if (s_check_rem_and_log(in_s, 8 + 8 + 4,
                                "[MS-RDPESC] Long_Return"))
        {
            in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.1 */
            in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.2 */

            in_uint32_le(in_s, ReturnCode);
        }
        LOG_DEVEL(LOG_LEVEL_DEBUG,
                  "scard_function_begin_transaction_return: "
                  "result %d", ReturnCode);
    }

    return call_data->callback(client, ReturnCode);
}

/*****************************************************************************/
/* returns error */
static int
scard_function_end_transaction_return(struct scard_client *client,
                                      void *vcall_data, struct stream *in_s,
                                      unsigned int len, unsigned int status)
{
    /* see [MS-RDPESC] 2.2.3.3
     *
     * IDL:-
     * typedef struct _long_Return {
     *     long ReturnCode;
     * } long_Return;*
     *
     * Type summary:-
     *
     * ReturnCode         32-bit word
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        ReturnCode
     */
    struct hcard_and_disposition_call *call_data;
    call_data = (struct hcard_and_disposition_call *)vcall_data;
    int ReturnCode = XSCARD_E_UNEXPECTED;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_end_transaction_return:");

    if (status == 0)
    {
        if (s_check_rem_and_log(in_s, 8 + 8 + 4,
                                "[MS-RDPESC] Long_Return"))
        {
            in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.1 */
            in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.2 */

            in_uint32_le(in_s, ReturnCode);
        }
        LOG_DEVEL(LOG_LEVEL_DEBUG,
                  "scard_function_end_transaction_return: "
                  "result %d", ReturnCode);
    }

    return call_data->callback(client, ReturnCode);
}

/**
 *
 *****************************************************************************/
static int
scard_function_status_return(struct scard_client *client,
                             void *vcall_data, struct stream *in_s,
                             unsigned int len, unsigned int status)
{
    /* see [MS-RDPESC] 2.2.3.10
     *
     * IDL:-
     *
     * typedef struct _Status_Return {
     *     long ReturnCode;
     *     unsigned long cBytes;
     *     [unique] [size_is(cBytes)] byte *mszReaderNames;
     *     unsigned long dwState;
     *     unsigned long dwProtocol;
     *     byte pbAtr[32];
     *     [range(0,32)] unsigned long cbAtrLen;
     * } Status_Return;
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        ReturnCode
     * 4        cBytes
     * 8        Referent Identifier for mszReaderNames (could be NULL)
     * 12       dwState
     * 16       dwProtocol
     * 20       pbAtr
     * 52       cbAtrLen
     * if (mszReaderNames != NULL)
     * | 56       length of multistring in bytes (same as cBytes)
     * | 60       Multistring data
     */
    struct status_call *call_data;
    call_data = (struct status_call *)vcall_data;
    unsigned int ReturnCode = XSCARD_E_UNEXPECTED;
    unsigned int utf8len = 0;
    char *msz_readers = NULL;
    int rv;

    unsigned int cBytes = 0;
    unsigned int dwState = 0;
    unsigned int dwProtocol = 0;
    unsigned int cbAtrLen = 0;
    char atr[32] = {0};
    unsigned int readers_ref_ident;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_status_return:");
    LOG_DEVEL(LOG_LEVEL_DEBUG, "  status 0x%8.8x", status);

    if (status != 0)
    {
        goto done;
    }

    if (!s_check_rem_and_log(in_s, 8 + 8 + 4 + 4 + 4 + 4 + 4 + 32 + 4,
                             "[MS-RDPESC] Status_Return(1)"))
    {
        goto done;
    }
    in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.1 */
    in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.2 */

    in_uint32_le(in_s, ReturnCode);
    in_uint32_le(in_s, cBytes);
    in_uint32_le(in_s, readers_ref_ident);
    in_uint32_le(in_s, dwState);
    in_uint32_le(in_s, dwProtocol);
    in_uint8a(in_s, atr, sizeof(atr));
    in_uint32_le(in_s, cbAtrLen);

    if (cbAtrLen > sizeof(atr))
    {
        cbAtrLen = sizeof(atr);
    }
    if (readers_ref_ident != 0)
    {
        if (!s_check_rem_and_log(in_s, 4 + cBytes,
                                 "[MS-RDPESC] Status_Return(2)"))
        {
            goto done;
        }
        in_uint8s(in_s, 4); // cBytes copy
        utf8len = in_utf16_le_fixed_as_utf8_length(in_s, cBytes / 2);
        if ((msz_readers = (char *)malloc(utf8len)) == NULL)
        {
            LOG(LOG_LEVEL_ERROR, "scard_function_status_return: "
                "Can't allocate %u bytes of memory", utf8len);
            utf8len = 0;
            ReturnCode = XSCARD_E_NO_MEMORY;
        }
        else
        {
            in_utf16_le_fixed_as_utf8(in_s, cBytes / 2, msz_readers, utf8len);
        }
    }

done:
    rv = call_data->callback(client,
                             ReturnCode, dwState, dwProtocol,
                             utf8len, msz_readers, cbAtrLen, atr);
    free(msz_readers);
    return rv;
}

/*****************************************************************************/
/* returns error */
static int
scard_function_disconnect_return(struct scard_client *client,
                                 void *vcall_data, struct stream *in_s,
                                 unsigned int len, unsigned int status)
{
    /* see [MS-RDPESC] 2.2.3.3
     *
     * IDL:-
     * typedef struct _long_Return {
     *     long ReturnCode;
     * } long_Return;*
     *
     * Type summary:-
     *
     * ReturnCode         32-bit word
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        ReturnCode
     */
    struct hcard_and_disposition_call *call_data;
    call_data = (struct hcard_and_disposition_call *)vcall_data;
    int ReturnCode = XSCARD_E_UNEXPECTED;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_function_disconnect_return:");

    if (status == 0)
    {
        if (s_check_rem_and_log(in_s, 8 + 8 + 4,
                                "[MS-RDPESC] Long_Return"))
        {
            in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.1 */
            in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.2 */

            in_uint32_le(in_s, ReturnCode);
        }
        LOG_DEVEL(LOG_LEVEL_DEBUG,
                  "scard_function_disconnect_return: "
                  "result %d", ReturnCode);
    }

    return call_data->callback(client, ReturnCode);
}

/*****************************************************************************/
/* returns error */
static int
scard_function_transmit_return(struct scard_client *client,
                               void *vcall_data, struct stream *in_s,
                               unsigned int len, unsigned int status)
{
    /* see [MS-RDPESC] 2.2.3.11
     *
     * IDL:-
     * typedef struct _SCardIO_Request {
     *    unsigned long dwProtocol;
     *    [range(0,1024)] unsigned long cbExtraBytes;
     *    [unique] [size_is(cbExtraBytes)] byte *pbExtraBytes;
     *    } SCardIO_Request;
     *
     * typedef struct _Transmit_Return {
     *    long ReturnCode;
     *    [unique] SCardIO_Request *pioRecvPci;
     *    [range(0, 66560)] unsigned long cbRecvLength;
     *    [unique] [size_is(cbRecvLength)] byte *pbRecvBuffer;
     *    } Transmit_Return;
     *
     * Type summary:-
     *
     * ReturnCode         32-bit word
     * pioRecvPci         Pointer to SCardIO_Request later in stream
     * cbRecvLength       32-bit word
     * pbRecvBuffer       Embedded full pointer to conformant array of bytes
     *
     * NDR:-
     *
     * Offset   Decription
     * 0        ReturnCode
     * 4        Referent identifier for pioRecvPci
     * 8        cbRecvLength
     * 12       Referent identifier for pbRecvBuffer
     * if (pioRecvPci != NULL)
     * | 16       pioRecvPci->dwProtocol
     * | 20       pioRecvPci->cbExtraBytes
     * | 24       Referent identifier for pioRecvPci->pbExtraBytes
     * if (pbRecvBuffer != NULL)
     * | ??       cbRecvLength copy
     * | ??       pbRecvBuffer bytes
     * if (pioRecvPci->pbExtraBytes = NULL)
     * ??       pioRecvPci->cbExtraBytes copy
     * ??       pioRecvPci->pbExtraBytes bytes
     */
    struct transmit_call *call_data = (struct transmit_call *)vcall_data;
    unsigned int ReturnCode = XSCARD_E_UNEXPECTED;
    unsigned int cbRecvLength = 0;
    unsigned int recv_pci_ref = 0;
    unsigned int recv_buff_ref = 0;
    struct scard_io_request *pioRecvPci = NULL;
    const char *pbRecvBuffer = NULL;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "scard_transmit_return:");

    if (status != XSCARD_S_SUCCESS && status != XSCARD_E_INSUFFICIENT_BUFFER)
    {
        goto done;
    }
    if (!s_check_rem_and_log(in_s, 8 + 8 + 4 + 4 + 4 + 4,
                             "[MS-RDPESC] Transmit_Return"))
    {
        ReturnCode = XSCARD_F_INTERNAL_ERROR;
        goto done;
    }
    in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.1 */
    in_uint8s(in_s, 8); /* [MS-RPCE] 2.2.6.2 */

    in_uint32_le(in_s, ReturnCode);
    in_uint32_le(in_s, recv_pci_ref);
    in_uint32_le(in_s, cbRecvLength);
    in_uint32_le(in_s, recv_buff_ref);

    if (recv_pci_ref != 0)
    {
        unsigned int dwProtocol;
        unsigned int cbExtraBytes;
        if (!s_check_rem_and_log(in_s, 4 + 4 + 4,
                                 "[MS-RDPESC] Transmit_Return(2)"))
        {
            ReturnCode = XSCARD_F_INTERNAL_ERROR;
            goto done;
        }
        in_uint32_le(in_s, dwProtocol);
        in_uint32_le(in_s, cbExtraBytes);
        in_uint8s(in_s, 4);

        if ((pioRecvPci = MALLOC_SCARD_IO_REQUEST(cbExtraBytes)) == NULL)
        {
            ReturnCode = XSCARD_E_NO_MEMORY;
            goto done;
        }
        pioRecvPci->dwProtocol = dwProtocol;
        pioRecvPci->cbExtraBytes = cbExtraBytes;
    }
    if (recv_buff_ref != 0)
    {
        if (!s_check_rem_and_log(in_s, 4 + cbRecvLength,
                                 "[MS-RDPESC] Transmit_Return(2)"))
        {
            ReturnCode = XSCARD_F_INTERNAL_ERROR;
            goto done;
        }
        in_uint8s(in_s, 4);
        // For the input data, just use a pointer into the stream buffer
        pbRecvBuffer = in_s->p;
        in_uint8s(in_s, cbRecvLength);
    }
    if (pioRecvPci != NULL && pioRecvPci->cbExtraBytes > 0)
    {
        in_align_s(in_s, 4);
        if (!s_check_rem_and_log(in_s, 4 + pioRecvPci->cbExtraBytes,
                                 "[MS-RDPESC] Transmit_Return(3)"))
        {
            ReturnCode = XSCARD_F_INTERNAL_ERROR;
            goto done;
        }
        in_uint8s(in_s, 4);
        in_uint8a(in_s, pioRecvPci->pbExtraBytes, pioRecvPci->cbExtraBytes);
    }

done:
    call_data->callback(client, ReturnCode, pioRecvPci,
                        cbRecvLength, pbRecvBuffer);
    free(pioRecvPci);
    return 0;
}

/**
 *
 *****************************************************************************/
static void
scard_handle_Control_Return(struct stream *s, IRP *irp, tui32 DeviceId,
                            tui32 CompletionId, tui32 IoStatus)
{
    tui32 len;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "entered");

    /* sanity check */
    if ((DeviceId != irp->DeviceId) || (CompletionId != irp->CompletionId))
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "DeviceId/CompletionId do not match those in IRP");
        return;
    }

    /* get OutputBufferLen */
    xstream_rd_u32_le(s, len);
    scard_function_control_return(irp->user_data, s, len, IoStatus);
    devredir_irp_delete(irp);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "leaving");
}

/**
 *
 *****************************************************************************/
static void
scard_handle_GetAttrib_Return(struct stream *s, IRP *irp, tui32 DeviceId,
                              tui32 CompletionId, tui32 IoStatus)
{
    tui32 len;

    LOG_DEVEL(LOG_LEVEL_DEBUG, "entered");

    /* sanity check */
    if ((DeviceId != irp->DeviceId) || (CompletionId != irp->CompletionId))
    {
        LOG_DEVEL(LOG_LEVEL_ERROR, "DeviceId/CompletionId do not match those in IRP");
        return;
    }

    /* get OutputBufferLen */
    xstream_rd_u32_le(s, len);
    scard_function_get_attrib_return(irp->user_data, s, len, IoStatus);
    devredir_irp_delete(irp);
    LOG_DEVEL(LOG_LEVEL_DEBUG, "leaving");
}
