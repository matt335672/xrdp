#ifndef XAK_H
#define XAK_H

/* Types */
typedef struct
{
    const char *name;
    const char *message;
    int need_free;
} xak_error;

typedef struct xak_connection xak_connection;
typedef struct xak_message xak_message;

typedef int (*xak_message_dispatch_func)(xak_message *m, void *userdata,
        xak_error *ret_error);

typedef struct
{
    unsigned char msg_no;
    xak_message_dispatch_func msg_func;
} xak_dispatch_table_entry;

/**
 * Connection calls
 */
xak_connection *xak_connection_create(int fd,
                                      unsigned int dispatch_table_size,
                                      const xak_dispatch_table_entry dispatch_table[]);
void xak_connection_delete(xak_connection *c);
int xak_connection_getfd(xak_connection *c);
int xak_connection_read(xak_connection *c);
int xak_connection_queue_count(xak_connection *c);
int xak_connection_dispatch_message(xak_connection *c);

/**
 * Message calls
 */

xak_message *xak_message_unref(xak_message *m);

/**
 * Method calls
 */
int xak_call_method(xak_connection *c, int member, xak_error *ret_error, xak_message **reply, const char *types, ...);


/**
 * Server-side calls
 */

int xak_message_read(xak_message *m, const char *types, ...);
int xak_reply_method_return(xak_message *m, const char *types, ...);


/**
 * Error handling
 */
#define XAK_ERROR_MAKE_CONST(name, message) ((const xak_error) {(name), (message), 0})
#define XAK_ERROR_NULL XAK_ERROR_MAKE_CONST(NULL, NULL)

const char *xak_error_message(const xak_error *e, int error);
void xak_error_free(xak_error *e);
void xak_error_setf(xak_error *e, const char *format, ...);


#endif /* XAK_H */
