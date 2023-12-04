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
 * smartcard redirection support
 */

#include "arch.h"

#ifndef _SMARTCARD_H
#define _SMARTCARD_H

struct xrdp_scard_io_request
{
    tui32 dwProtocol;
    tui32 cbPciLength;
    int extra_bytes;
    char *extra_data;
};

typedef struct reader_state
{
    char   reader_name[128];
    tui32  current_state;
    tui32  event_state;
    tui32  atr_len; /* number of bytes in atr[] */
    tui8   atr[36];

    /*
     * share mode flag, can be one of:
     *  SCARD_SHARE_EXCLUSIVE  app not willing to share smartcard with other apps
     *  SCARD_SHARE_SHARED     app willing to share smartcard with other apps
     *  SCARD_SHARE_DIRECT     app demands direct control of smart card, hence
     *                         it is not available to other readers
     */
    tui32  dwShareMode;

    /*
     * This field MUST have a value from Table A which is logically
     * OR'ed with a value from Table B.
     */
    tui32  dwPreferredProtocols;

    /*
     * initialization type, must be one of the initialization type
     * defined above
     */
    tui32  init_type;

    /* required by scard_send_transmit(), scard_send_control() */
    tui32 map0;
    tui32 map1;
    tui32 map2;
    tui32 map3;
    tui32 map4;
    tui32 map5;
    tui32 map6;

    tui32 dwProtocol;
    tui32 cbPciLength;
    tui32 cbSendLength;
    tui32 cbRecvLength;
    tui32 dwControlCode;
    tui32 cbOutBufferSize;
    tui32 dwAttribId;
    tui32 dwAttrLen;

} READER_STATE;

struct scard_client;
struct stream;

/*****************************************************************************/
/* Structures used to hold call state while waiting for the
 * client to respond */

/**
 * Struct used to store private data within the xxx_call structs
 * below.
 *
 * This struct must be the first member of the xxx_call struct so
 * it can be recovered from a void pointer to the xxx_call struct
 */
struct common_call_private
{
    unsigned int client_id; ///< Use to locate the client when the I/O completes
    /// Callback used to unmarshall the result
    int (*unmarshall_callback)(struct scard_client *,
                               void *,
                               struct stream *,
                               unsigned int,
                               unsigned int);
};

/**
 * Use this struct to make an establish context call
 *
 * Fill in all fields (apart from p) and pass to
 * scard_send_establish_context(). The result will be received via the
 * callback, provided the client is still active.
 */
struct establish_context_call
{
    struct common_call_private p;

    /** How to pass the result back to the client */
    int (*callback)(struct scard_client *client,
                    unsigned int ReturnCode,
                    unsigned int app_context);

    /* See 2.2.2.1 */
    unsigned int dwScope;
};

/**
 * Use this struct to make a release context call
 *
 * Fill in all fields (apart from p) and pass to
 * scard_send_release_context(). The result will be received via the
 * callback, provided the client is still active.
 */
struct release_context_call
{
    struct common_call_private p;

    /** How to pass the result back to the client */
    int (*callback)(struct scard_client *client,
                    unsigned int ReturnCode);
    /* See 2.2.2.2 */
    unsigned int app_context;

};

/**
 * Use this struct to make a list readers call
 *
 * Fill in all fields (apart from p) and pass to
 * scard_send_list_readers(). The result will be received via the
 * callback, provided the client is still active.
 */
struct list_readers_call
{
    struct common_call_private p;

    /** How to pass the result back to the client */
    int (*callback)(struct scard_client *client,
                    unsigned int ReturnCode,
                    unsigned int cBytes,
                    const char *msz);

    /* See 2.2.2.4 */
    unsigned int app_context;
    unsigned int fmszReadersIsNULL;
    unsigned int cchReaders;
    unsigned int cBytes;
#ifdef __cplusplus
    char mszGroups[1];
#else
    char mszGroups[];
#endif
};

/**
 * Use this struct to make a connect call
 *
 * Fill in all fields (apart from p) and pass to
 * scard_send_connect(). The result will be received via the
 * callback, provided the client is still active.
 */
struct connect_call
{
    struct common_call_private p;

    /** How to pass the result back to the client */
    int (*callback)(struct scard_client *client,
                    unsigned int ReturnCode,
                    unsigned int hCard,
                    unsigned int dwActiveProtocol);

    /* See 2.2.1.3 + 2.2.2.14 */
    unsigned int app_context;
    unsigned int dwShareMode;
    unsigned int dwPreferredProtocols;
#ifdef __cplusplus
    char szReader[1];
#else
    char szReader[];
#endif
};

/**
 * Use this struct to make a status call
 *
 * Fill in all fields (apart from p) and pass to
 * scard_send_status(). The result will be received via the
 * callback, provided the client is still active.
 */
struct status_call
{
    struct common_call_private p;

    /** How to pass the result back to the client */
    int (*callback)(struct scard_client *client,
                    unsigned int ReturnCode,
                    unsigned int dwState,
                    unsigned int dwProtocol,
                    unsigned int cBytes,
                    const char *mszReaderNames,
                    unsigned int cbAtrLen,
                    const char *pbAtr);

    /* See 2.2.2.18 */
    unsigned int app_hcard;
};

void scard_device_announce(tui32 device_id);
int  scard_get_wait_objs(tbus *objs, int *count, int *timeout);
int  scard_check_wait_objs(void);
int  scard_init(void);
int  scard_deinit(void);

/**
 * Create a new scard client
 * @return Client data pointer or NULL if no memory
 */
struct scard_client *
scard_client_new(void);

/*
 * Destroy an scard client
 *
 * Resources held at the remote end will be released
 *
 * @param client Client to destroy
 */
void
scard_client_destroy(struct scard_client *client);

/**
 * Add callback data to a client
 *
 * Data added in this way can be read back with scard_get_client_cb_data()
 * @param client Client
 * @param key Key for data
 * @param value Value to set for key
 */
void
scard_client_set_cb_data(struct scard_client *client,
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
scard_client_get_cb_data(struct scard_client *client, unsigned char key);

/**
 * Sends an establish_context call to the RDP service
 *
 * @param client client
 * @param call_data Info about the call
 *
 * The call_data must be on the heap. After this call,
 * ownership of the call_data is taken away from the caller.
 */
void
scard_send_establish_context(struct scard_client *client,
                             struct establish_context_call *call_data);
/**
 * Sends a release_context call to the RDP service
 *
 * @param client client
 * @param call_data Info about the call
 *
 * The call_data must be on the heap. After this call,
 * ownership of the call_data is taken away from the caller.
 */
void
scard_send_release_context(struct scard_client *client,
                           struct release_context_call *call_data);

int  scard_send_is_valid_context(void *user_data,
                                 unsigned int app_context);
/**
 * Sends a list_readers call to the RDP service
 *
 * @param client client
 * @param call_data Info about the call
 *
 * The call_data must be on the heap. After this call,
 * ownership of the call_data is taken away from the caller.
 */
void
scard_send_list_readers(struct scard_client *client,
                        struct list_readers_call *call_data);

int  scard_send_get_status_change(void *user_data,
                                  char *context, int context_bytes,
                                  int wide, tui32 timeout,
                                  tui32 num_readers, READER_STATE *rsa);

/**
 * Sends a connect call to the RDP service
 *
 * @param client client
 * @param call_data Info about the call
 *
 * The call_data must be on the heap. After this call,
 * ownership of the call_data is taken away from the caller.
 */
void
scard_send_connect(struct scard_client *client,
                   struct connect_call *call_data);

int  scard_send_reconnect(void *user_data,
                          char *context, int context_bytes,
                          char *card, int card_bytes,
                          READER_STATE *rs);

int  scard_send_begin_transaction(void *user_data,
                                  char *context, int context_bytes,
                                  char *card, int card_bytes);
int  scard_send_end_transaction(void *user_data,
                                char *context, int context_bytes,
                                char *card, int card_bytes,
                                tui32 dwDisposition);
/**
 * Sends a connect call to the RDP service
 *
 * @param client client
 * @param call_data Info about the call
 *
 * The call_data must be on the heap. After this call,
 * ownership of the call_data is taken away from the caller.
 */
void
scard_send_status(struct scard_client *client,
                  struct status_call *call_data);
int  scard_send_disconnect(void *user_data,
                           char *context, int context_bytes,
                           char *card, int card_bytes,
                           int dwDisposition);

int  scard_send_transmit(void *user_data,
                         char *context, int context_bytes,
                         char *card, int card_bytes,
                         char *send_data, int send_bytes, int recv_bytes,
                         struct xrdp_scard_io_request *send_ior,
                         struct xrdp_scard_io_request *recv_ior);

int  scard_send_control(void *user_data,
                        char *context, int context_bytes,
                        char *card, int card_bytes,
                        char *send_data, int send_bytes,
                        int recv_bytes, int control_code);

int  scard_send_cancel(void *user_data,
                       unsigned int app_context);

int  scard_send_get_attrib(void *user_data, char *card, int card_bytes,
                           READER_STATE *rs);

/*
 * Notes:
 *      SCardTransmit - partially done
 *      SCardControl - partially done
 *      SCardListReaderGroups - not supported
 *      SCardSetAttrib - not supported
 */
#endif /* end #ifndef _SMARTCARD_H */
