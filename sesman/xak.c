#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "xak.h"

xak_connection *xak_connection_create(int fd,
                                      unsigned int dispatch_table_size,
                                      const xak_dispatch_table_entry dispatch_table[])
{
    return 0;
}

int xak_call_method(xak_connection *c, int member, xak_error *ret_error, xak_message **reply, const char *types, ...)
{
    /// Check for null connection!
    return -1;
}
int xak_reply_method_return(xak_message *reply, const char *types, ...)
{
    return 0;
}

int xak_message_read(xak_message *m, const char *types, ...)
{
    return -1;
}

int xak_connection_read(xak_connection *c)
{
    return 0;
}

int xak_connection_queue_count(xak_connection *c)
{
    return 0;
}

int xak_connection_dispatch_message(xak_connection *c)
{
    return 0;
}

const char *xak_error_message(const xak_error *e, int error)
{
    return 0;
}

void xak_error_free(xak_error *e)
{
}

void xak_error_setf(xak_error *e, const char *format, ...)
{
}

xak_message *xak_message_unref(xak_message *m)
{
    return 0;
}
