#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>

#include <winscard.h>

#include "xrdp_pcsc.h"

#define MSG_HEADER_SIZE 8

#define PCSC_API

PCSC_API const SCARD_IO_REQUEST g_rgSCardT0Pci  = { SCARD_PROTOCOL_T0,  8 };
PCSC_API const SCARD_IO_REQUEST g_rgSCardT1Pci  = { SCARD_PROTOCOL_T1,  8 };
PCSC_API const SCARD_IO_REQUEST g_rgSCardRawPci = { SCARD_PROTOCOL_RAW, 8 };

#define LLOG_LEVEL 5
#define LLOGLN(_level, _args) \
    do { if (_level < LLOG_LEVEL) { printf _args ; printf("\n"); } } while (0)
#define LHEXDUMP(_level, _args) \
    do { if  (_level < LLOG_LEVEL) { lhexdump _args ; } } while (0)

#define SET_UINT32(_data, _offset, _val) do { \
        (((BYTE*)(_data)) + (_offset))[0] = ((_val) >> 0)  & 0xff; \
        (((BYTE*)(_data)) + (_offset))[1] = ((_val) >> 8)  & 0xff; \
        (((BYTE*)(_data)) + (_offset))[2] = ((_val) >> 16) & 0xff; \
        (((BYTE*)(_data)) + (_offset))[3] = ((_val) >> 24) & 0xff; } while (0)

#define GET_UINT32(_data, _offset) \
    ((unsigned int)(((BYTE*)(_data)) + (_offset))[0] << 0)  | \
    ((unsigned int)(((BYTE*)(_data)) + (_offset))[1] << 8)  | \
    ((unsigned int)(((BYTE*)(_data)) + (_offset))[2] << 16) | \
    ((unsigned int)(((BYTE*)(_data)) + (_offset))[3] << 24)

#define LMIN(_val1, _val2) (_val1) < (_val2) ? (_val1) : (_val2)
#define LMAX(_val1, _val2) (_val1) > (_val2) ? (_val1) : (_val2)

static int g_sck = -1; /* unix domain socket */

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

/* for pcsc_stringify_error */
static char g_error_str[512];

/*****************************************************************************/
/* produce a hex dump */
static void
lhexdump(void *p, int len)
{
    unsigned char *line;
    int i;
    int thisline;
    int offset;

    line = (unsigned char *)p;
    offset = 0;

    while (offset < len)
    {
        printf("%04x ", offset);
        thisline = len - offset;

        if (thisline > 16)
        {
            thisline = 16;
        }

        for (i = 0; i < thisline; i++)
        {
            printf("%02x ", line[i]);
        }

        for (; i < 16; i++)
        {
            printf("   ");
        }

        for (i = 0; i < thisline; i++)
        {
            printf("%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');
        }

        printf("\n");
        offset += thisline;
        line += thisline;
    }
}

/*****************************************************************************/
static int
connect_to_chansrv(void)
{
    unsigned int bytes;
    int error;
    const char *sockname;
    struct sockaddr_un saddr;
    struct sockaddr *psaddr;

    if (g_sck != -1)
    {
        /* already connected */
        return 0;
    }
    if ((sockname = getenv("XRDP_LIBPCSCLITE_SOCKET")) == NULL)
    {
        /* XRDP_LIBPCSCLITE_SOCKET must be set */
        LLOGLN(0, ("connect_to_chansrv: error, not xrdp session"));
        return 1;
    }
    g_sck = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (g_sck == -1)
    {
        LLOGLN(0, ("connect_to_chansrv: error, socket failed"));
        return 1;
    }
    memset(&saddr, 0, sizeof(struct sockaddr_un));
    saddr.sun_family = AF_UNIX;
    bytes = sizeof(saddr.sun_path);
    snprintf(saddr.sun_path, bytes, "%s", sockname);
    LLOGLN(10, ("connect_to_chansrv: connecting to %s", saddr.sun_path));
    psaddr = (struct sockaddr *) &saddr;
    bytes = sizeof(struct sockaddr_un);
    error = connect(g_sck, psaddr, bytes);
    if (error == 0)
    {
    }
    else
    {
        perror("connect_to_chansrv");
        close(g_sck);
        g_sck = -1;
        LLOGLN(0, ("connect_to_chansrv: error, open %s", saddr.sun_path));
        return 1;
    }
    return 0;
}

/*****************************************************************************/
static int
send_message(int code, char *data, int bytes)
{
    char header[MSG_HEADER_SIZE];

    pthread_mutex_lock(&g_mutex);
    SET_UINT32(header, 0, bytes);
    SET_UINT32(header, 4, code);
    if (send(g_sck, header, MSG_HEADER_SIZE, 0) != 8)
    {
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    if (send(g_sck, data, bytes, 0) != bytes)
    {
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    LLOGLN(10, ("send_message:"));
    LHEXDUMP(10, (data, bytes));
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

/*****************************************************************************/
static int
get_message(unsigned int *code, char *data, unsigned int *bytes)
{
    char header[MSG_HEADER_SIZE];
    unsigned int max_bytes;
    int error;
    int recv_rv;
    unsigned int lcode;
    struct pollfd pollfd;

    LLOGLN(10, ("get_message:"));
    while (1)
    {
        LLOGLN(10, ("get_message: loop"));
        pollfd.fd = g_sck;
        pollfd.events = POLLIN;
        pollfd.revents = 0;
        error = poll(&pollfd, 1, 1000);
        if (error == 1)
        {
            pthread_mutex_lock(&g_mutex);
            pollfd.fd = g_sck;
            pollfd.events = POLLIN;
            pollfd.revents = 0;
            error = poll(&pollfd, 1, 0);
            if (error == 1)
            {
                /* just take a look at the next message */
                recv_rv = recv(g_sck, header, MSG_HEADER_SIZE, MSG_PEEK);
                if (recv_rv == 8)
                {
                    lcode = GET_UINT32(header, 4);
                    if (lcode == *code)
                    {
                        /* still have mutex lock */
                        break;
                    }
                    else
                    {
                        LLOGLN(10, ("get_message: lcode %u *code %u",
                                    lcode, *code));
                    }
                }
                else if (recv_rv == 0)
                {
                    pthread_mutex_unlock(&g_mutex);
                    LLOGLN(0, ("get_message: recv_rv 0, disconnect"));
                    return 1;
                }
                else
                {
                    LLOGLN(10, ("get_message: recv_rv %d", recv_rv));
                }
            }
            else
            {
                LLOGLN(10, ("get_message: select return %d", error));
            }
            pthread_mutex_unlock(&g_mutex);
            usleep(1000);
        }
    }

    if (recv(g_sck, header, MSG_HEADER_SIZE, 0) != 8)
    {
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    max_bytes = *bytes;
    *bytes = GET_UINT32(header, 0);
    *code = GET_UINT32(header, 4);
    if (*bytes > (max_bytes - 8))
    {
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    if (recv(g_sck, data, *bytes, 0) != (int) * bytes)
    {
        pthread_mutex_unlock(&g_mutex);
        return 1;
    }
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

/*****************************************************************************/
PCSC_API LONG
SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2,
                      LPSCARDCONTEXT phContext)
{
    char msg[256];
    DWORD context;
    unsigned int code;
    unsigned int bytes;
    unsigned int ReturnCode;

    LLOGLN(10, ("SCardEstablishContext:"));
    if (phContext == NULL)
    {
        return SCARD_E_INVALID_PARAMETER;
    }
    if (g_sck == -1)
    {
        if (connect_to_chansrv() != 0)
        {
            LLOGLN(0, ("SCardEstablishContext: error, can not connect "
                       "to chansrv"));
            return SCARD_F_INTERNAL_ERROR;
        }
    }
    SET_UINT32(msg, 0, dwScope);
    if (send_message(SCARD_ESTABLISH_CONTEXT, msg, 4) != 0)
    {
        LLOGLN(0, ("SCardEstablishContext: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    code = SCARD_ESTABLISH_CONTEXT;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardEstablishContext: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if ((code != SCARD_ESTABLISH_CONTEXT) || (bytes != 8))
    {
        LLOGLN(0, ("SCardEstablishContext: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    ReturnCode = GET_UINT32(msg, 0);
    context = GET_UINT32(msg, 4);
    LLOGLN(10, ("SCardEstablishContext: got context 0x%8.8x", (int)context));
    *phContext = context;
    return ReturnCode;
}

/*****************************************************************************/
/**
 * Code shared by methods which send a context and expect a long return
 */
PCSC_API LONG
send_context_get_long_return(unsigned int code, const char *func,
                             SCARDCONTEXT hContext)
{
    char msg[256];
    unsigned int bytes;
    unsigned int ReturnCode;

    LLOGLN(10, ("%s:", func));
    if (g_sck == -1)
    {
        LLOGLN(0, ("%s: error, not connected", func));
        return SCARD_F_INTERNAL_ERROR;
    }
    SET_UINT32(msg, 0, hContext);
    if (send_message(code, msg, 4) != 0)
    {
        LLOGLN(0, ("%s: error, send_message", func));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    ReturnCode = code;
    if (get_message(&ReturnCode, msg, &bytes) != 0)
    {
        LLOGLN(0, ("%s: error, get_message", func));
        return SCARD_F_INTERNAL_ERROR;
    }
    if ((ReturnCode != code) || (bytes != 4))
    {
        LLOGLN(0, ("%s: error, bad code", func));
        return SCARD_F_INTERNAL_ERROR;
    }
    ReturnCode = GET_UINT32(msg, 0);
    LLOGLN(10, ("%s: got status 0x%8.8x", func, ReturnCode));
    return ReturnCode;
}

/*****************************************************************************/
PCSC_API LONG
SCardReleaseContext(SCARDCONTEXT hContext)
{
    return send_context_get_long_return(SCARD_RELEASE_CONTEXT,
                                        "SCardReleaseContext", hContext);
}

/*****************************************************************************/
PCSC_API LONG
SCardIsValidContext(SCARDCONTEXT hContext)
{
    return send_context_get_long_return(SCARD_IS_VALID_CONTEXT,
                                        "SCardIsValidContext", hContext);
}

/*****************************************************************************/
PCSC_API LONG
SCardConnect(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode,
             DWORD dwPreferredProtocols, LPSCARDHANDLE phCard,
             LPDWORD pdwActiveProtocol)
{
    char msg[256];
    unsigned int code;
    unsigned int bytes;
    LONG status;
    int offset;

    LLOGLN(10, ("SCardConnect:"));
    LLOGLN(10, ("SCardConnect: hContext 0x%8.8x szReader %s dwShareMode %d "
                "dwPreferredProtocols %d",
                (int)hContext, szReader, (int)dwShareMode, (int)dwPreferredProtocols));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardConnect: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    offset = 0;
    SET_UINT32(msg, offset, hContext);
    offset += 4;
    SET_UINT32(msg, offset, dwShareMode);
    offset += 4;
    SET_UINT32(msg, offset, dwPreferredProtocols);
    offset += 4;
    bytes = strlen(szReader);
    if (bytes > 2047)
    {
        LLOGLN(0, ("SCardConnect: error, name too long"));
        return SCARD_F_INTERNAL_ERROR;
    }
    SET_UINT32(msg, offset, bytes);
    offset += 4;

    memcpy(msg + offset, szReader, bytes);
    offset += bytes;

    if (send_message(SCARD_CONNECT, msg, offset) != 0)
    {
        LLOGLN(0, ("SCardConnect: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    code = SCARD_CONNECT;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardConnect: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_CONNECT || (bytes != 12))
    {
        LLOGLN(0, ("SCardConnect: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    status = GET_UINT32(msg, 0);
    *phCard = GET_UINT32(msg, 4);
    *pdwActiveProtocol = GET_UINT32(msg, 8);
    LLOGLN(10, ("SCardConnect: got status 0x%8.8x hCard 0x%8.8x "
                "dwActiveProtocol %d",
                (int)status, (int)*phCard, (int)*pdwActiveProtocol));
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardReconnect(SCARDHANDLE hCard, DWORD dwShareMode,
               DWORD dwPreferredProtocols, DWORD dwInitialization,
               LPDWORD pdwActiveProtocol)
{
    char msg[256];
    unsigned int code;
    unsigned int bytes;
    LONG status;
    int offset;

    LLOGLN(10, ("SCardReconnect:"));
    LLOGLN(10, ("SCardReconnect: hCard 0x%8.8x dwShareMode %d "
                "dwPreferredProtocols %d dwInitialization %d",
                (int)hCard, (int)dwShareMode,
                (int)dwPreferredProtocols, (int)dwInitialization));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardReconnect: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    offset = 0;
    SET_UINT32(msg, offset, hCard);
    offset += 4;
    SET_UINT32(msg, offset, dwShareMode);
    offset += 4;
    SET_UINT32(msg, offset, dwPreferredProtocols);
    offset += 4;
    SET_UINT32(msg, offset, dwInitialization);
    offset += 4;

    if (send_message(SCARD_RECONNECT, msg, offset) != 0)
    {
        LLOGLN(0, ("SCardReconnect: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = sizeof(msg);
    code = SCARD_RECONNECT;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardReconnect: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_RECONNECT || (bytes != 8))
    {
        LLOGLN(0, ("SCardReconnect: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    status = GET_UINT32(msg, 0);
    *pdwActiveProtocol = GET_UINT32(msg, 8);
    LLOGLN(10, ("SCardReconnect: got status 0x%8.8x "
                "dwActiveProtocol %d",
                (int)status, (int)*pdwActiveProtocol));
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition)
{
    char msg[256];
    unsigned int code;
    unsigned int bytes;
    LONG status;

    LLOGLN(10, ("SCardDisconnect: hCard 0x%8.8x dwDisposition %d",
                (int)hCard, (int)dwDisposition));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardDisconnect: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    SET_UINT32(msg, 0, hCard);
    SET_UINT32(msg, 4, dwDisposition);
    if (send_message(SCARD_DISCONNECT, msg, 8) != 0)
    {
        LLOGLN(0, ("SCardDisconnect: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    code = SCARD_DISCONNECT;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardDisconnect: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if ((code != SCARD_DISCONNECT) || (bytes != 4))
    {
        LLOGLN(0, ("SCardDisconnect: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    status = GET_UINT32(msg, 0);
    LLOGLN(10, ("SCardDisconnect: got status 0x%8.8x", (int)status));
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardBeginTransaction(SCARDHANDLE hCard)
{
    char msg[256];
    unsigned int code;
    unsigned int bytes;
    LONG status;

    LLOGLN(10, ("SCardBeginTransaction: hCard 0x%8.8x", (int)hCard));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardBeginTransaction: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    SET_UINT32(msg, 0, hCard);
    if (send_message(SCARD_BEGIN_TRANSACTION, msg, 4) != 0)
    {
        LLOGLN(0, ("SCardBeginTransaction: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    code = SCARD_BEGIN_TRANSACTION;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardBeginTransaction: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if ((code != SCARD_BEGIN_TRANSACTION) || (bytes != 4))
    {
        LLOGLN(0, ("SCardBeginTransaction: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    status = GET_UINT32(msg, 0);
    LLOGLN(10, ("SCardBeginTransaction: got status 0x%8.8x", (int)status));
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardEndTransaction(SCARDHANDLE hCard, DWORD dwDisposition)
{
    char msg[256];
    unsigned int code;
    unsigned int bytes;
    LONG status;

    LLOGLN(10, ("SCardEndTransaction:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardEndTransaction: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    SET_UINT32(msg, 0, hCard);
    SET_UINT32(msg, 4, dwDisposition);
    if (send_message(SCARD_END_TRANSACTION, msg, 8) != 0)
    {
        LLOGLN(0, ("SCardEndTransaction: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = 256;
    code = SCARD_END_TRANSACTION;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardEndTransaction: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if ((code != SCARD_END_TRANSACTION) || (bytes != 4))
    {
        LLOGLN(0, ("SCardEndTransaction: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    status = GET_UINT32(msg, 0);
    LLOGLN(10, ("SCardEndTransaction: got status 0x%8.8x", (int)status));
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardStatus(SCARDHANDLE hCard, LPSTR szReaderName, LPDWORD pcchReaderLen,
            LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr,
            LPDWORD pcbAtrLen)
{
    char msg[8192];
    unsigned int code;
    unsigned int bytes;
    unsigned int status;
    unsigned int offset;
    unsigned int cBytes;
    unsigned int cbAtrLen;
    char *reader_out = NULL;

    LLOGLN(10, ("SCardStatus:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardStatus: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }

    if (pcchReaderLen == NULL || pcbAtrLen == NULL ||
            (*pcchReaderLen == SCARD_AUTOALLOCATE && szReaderName == NULL) ||
            (*pcbAtrLen == SCARD_AUTOALLOCATE && pbAtr == NULL))
    {
        return SCARD_E_INVALID_PARAMETER;
    }

    LLOGLN(10, ("  hCard 0x%8.8x", (int)hCard));
    LLOGLN(10, ("  cchReaderLen %d", (int)*pcchReaderLen));
    LLOGLN(10, ("  cbAtrLen %d", (int)*pcbAtrLen));

    SET_UINT32(msg, 0, hCard);
    if (send_message(SCARD_STATUS, msg, 4) != 0)
    {
        LLOGLN(0, ("SCardStatus: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = sizeof(msg);
    code = SCARD_STATUS;
    if (get_message(&code, msg, &bytes) != 0 || (bytes < 20))
    {
        LLOGLN(0, ("SCardStatus: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_STATUS)
    {
        LLOGLN(0, ("SCardStatus: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }

    // Get the fixed values
    offset = 0;
    status = GET_UINT32(msg, offset);
    offset += 4;
    if (pdwState != NULL)
    {
        // PCSCLite uses a bitmask with log-to-base-2 corresponding
        // to the MS values in [MS-RDPESC]
        unsigned int ms_state = GET_UINT32(msg, offset);
        *pdwState = (1 << ms_state);
    }
    offset += 4;
    if (pdwProtocol != NULL)
    {
        *pdwProtocol = GET_UINT32(msg, offset);
    }
    offset += 4;
    cBytes = GET_UINT32(msg, offset);
    offset += 4;
    cbAtrLen = GET_UINT32(msg, offset);
    offset += 4;

    // All the strings available?
    if (offset + cBytes + cbAtrLen > bytes)
    {
        return SCARD_F_INTERNAL_ERROR;
    }

    // Allocate memory if required
    if (status == SCARD_S_SUCCESS)
    {
        if (*pcchReaderLen == SCARD_AUTOALLOCATE)
        {
            if ((reader_out = (char *)malloc(cBytes + 1)) == NULL)
            {
                return SCARD_E_NO_MEMORY;
            }
            *(char **)szReaderName = reader_out; // Pass pointer to user
            szReaderName = reader_out; // Use pointer ourselves
            *pcchReaderLen = cBytes + 1;
        }

        if (*pcchReaderLen > cBytes)
        {
            memcpy(szReaderName, msg + offset, cBytes);
            szReaderName[cBytes] = '\0';
            *pcchReaderLen = cBytes;
        }
        else
        {
            status = SCARD_E_INSUFFICIENT_BUFFER;
        }
        offset += cBytes;
        LLOGLN(10, ("SCardStatus: szReaderName out %s", szReaderName));

        if (*pcbAtrLen == SCARD_AUTOALLOCATE)
        {
            unsigned char *atr_out;
            if ((atr_out = (unsigned char *)malloc(cbAtrLen)) == NULL)
            {
                free(reader_out);
                return SCARD_E_NO_MEMORY;
            }
            *(unsigned char **)pbAtr = atr_out; // Pass pointer to user
            pbAtr = atr_out; // Use pointer ourselves
            *pcbAtrLen = cbAtrLen;
        }

        if (*pcbAtrLen >= cbAtrLen)
        {
            memcpy(pbAtr, msg + offset, cbAtrLen);
            *pcbAtrLen = cbAtrLen;
        }
        else
        {
            status = SCARD_E_INSUFFICIENT_BUFFER;
        }
        offset += cbAtrLen;
        LLOGLN(10, ("SCardStatus: pbAtr out %s", pbAtr));
    }

    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardGetStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout,
                     LPSCARD_READERSTATE rgReaderStates, DWORD cReaders)
{
    char *msg;
    const char *rname;
    unsigned int bytes;
    unsigned int code;
    unsigned int index;
    int offset;
    int str_len;
    LONG ReturnCode;

    LLOGLN(10, ("SCardGetStatusChange:"));
    LLOGLN(10, ("  dwTimeout %d cReaders %d", (int)dwTimeout, (int)cReaders));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardGetStatusChange: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }

    if (cReaders > 0 && rgReaderStates == NULL)
    {
        return SCARD_E_INVALID_PARAMETER;
    }

    // Calculate how much memory we need for the request
    bytes = 64 + (cReaders * 64);
    for (index = 0 ; index < cReaders; ++index)
    {
        if (rgReaderStates[index].szReader != NULL)
        {
            bytes += (strlen(rgReaderStates[index].szReader) + 1);
        }
    }
    if ((msg = (char *) malloc(bytes)) == NULL)
    {
        return SCARD_E_NO_MEMORY;
    }
    SET_UINT32(msg, 0, hContext);
    SET_UINT32(msg, 4, dwTimeout);
    SET_UINT32(msg, 8, cReaders);
    offset = 12;
    for (index = 0; index < cReaders; ++index)
    {
        rname = rgReaderStates[index].szReader;

        str_len = rname == NULL ? 0 : strlen(rname);
        SET_UINT32(msg, offset, str_len);
        offset += 4;
        SET_UINT32(msg, offset, rgReaderStates[index].dwCurrentState);
        offset += 4;
        SET_UINT32(msg, offset, rgReaderStates[index].dwEventState);
        offset += 4;
        SET_UINT32(msg, offset, rgReaderStates[index].cbAtr);
        offset += 4;
        memcpy(msg + offset, rgReaderStates[index].rgbAtr, 36);
        offset += 36;
    }
    // Now copy the reader names
    for (index = 0; index < cReaders; ++index)
    {
        rname = rgReaderStates[index].szReader;
        if (rname != NULL)
        {
            unsigned int len = strlen(rname) + 1;
            memcpy(msg + offset, rname, len);
            offset += len;
        }
    }

    if (send_message(SCARD_GET_STATUS_CHANGE, msg, offset) != 0)
    {
        LLOGLN(0, ("SCardGetStatusChange: error, send_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = offset; // Return message is always smaller
    code = SCARD_GET_STATUS_CHANGE;
    if (get_message(&code, msg, &bytes) != 0 || bytes < 8)
    {
        LLOGLN(0, ("SCardGetStatusChange: error, get_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_GET_STATUS_CHANGE)
    {
        LLOGLN(0, ("SCardGetStatusChange: error, bad code"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    ReturnCode = GET_UINT32(msg, 0);
    cReaders = GET_UINT32(msg, 4);
    offset = 8;
    if (bytes < offset + 48 * cReaders)
    {
        LLOGLN(0, ("SCardGetStatusChange: error, bad length"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }

    for (index = 0; index < cReaders; index++)
    {
        rgReaderStates[index].dwCurrentState = GET_UINT32(msg + offset, 0);
        offset += 4;
        rgReaderStates[index].dwEventState = GET_UINT32(msg + offset, 0);
        offset += 4;
        rgReaderStates[index].cbAtr = GET_UINT32(msg + offset, 0);
        offset += 4;
        memcpy(rgReaderStates[index].rgbAtr, msg + offset, 36);
    }

    free(msg);
    return ReturnCode;
}

/*****************************************************************************/
PCSC_API LONG
SCardControl(SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer,
             DWORD cbSendLength, LPVOID pbRecvBuffer, DWORD cbRecvLength,
             LPDWORD lpBytesReturned)
{
    char *msg;
    unsigned int bytes;
    unsigned int code;
    int offset;
    LONG status = 0;

    LLOGLN(10, ("SCardControl:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardControl: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if (cbSendLength > 0 && pbSendBuffer == NULL)
    {
        return SCARD_E_INVALID_PARAMETER;
    }

    /* Use the larger of the send and receive buffer sizes to
     * allocate memory for the message */
    bytes = 64 + LMAX(cbSendLength, cbRecvLength);
    msg = (char *)malloc(bytes);
    if (msg == NULL)
    {
        return SCARD_E_NO_MEMORY;
    }

    offset = 0;
    SET_UINT32(msg, offset, hCard);
    offset += 4;
    SET_UINT32(msg, offset, dwControlCode);
    offset += 4;
    SET_UINT32(msg, offset, cbSendLength);
    offset += 4;
    SET_UINT32(msg, offset, cbRecvLength);
    offset += 4;
    memcpy(msg + offset, pbSendBuffer, cbSendLength);
    offset += cbSendLength;
    if (send_message(SCARD_CONTROL, msg, offset) != 0)
    {
        LLOGLN(0, ("SCardControl: error, send_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    code = SCARD_CONTROL;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardControl: error, get_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_CONTROL)
    {
        LLOGLN(0, ("SCardControl: error, bad code"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    offset = 0;
    status = GET_UINT32(msg, offset);
    offset += 4;
    *lpBytesReturned = GET_UINT32(msg, offset);
    offset += 4;

    if (status == SCARD_S_SUCCESS)
    {
        // Sanity-check the returned length
        if (*lpBytesReturned > cbRecvLength ||
                *lpBytesReturned > (bytes - offset))
        {
            status = SCARD_F_INTERNAL_ERROR;
        }
        else
        {
            memcpy(pbRecvBuffer, msg + offset, *lpBytesReturned);
        }
    }

    free(msg);
    return status;
}

/*****************************************************************************/
PCSC_API LONG
SCardTransmit(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci,
              LPCBYTE pbSendBuffer, DWORD cbSendLength,
              SCARD_IO_REQUEST *pioRecvPci, LPBYTE pbRecvBuffer,
              LPDWORD pcbRecvLength)
{
#define MAX_TRANSMIT_RETURN_SIZE (MSG_HEADER_SIZE + (4 * 6) + 66560 + 1024)
    char *msg;
    unsigned int msg_size;
    unsigned int bytes;
    unsigned int code;
    int offset;
    LONG status;
    unsigned int send_pci_extra_bytes;
    unsigned int recv_pci_extra_bytes;

    // Group some of the reply values together for readability
    struct
    {
        unsigned int got_pio_recv_pci;
        unsigned int dwProtocol;
        unsigned int cbExtraBytes;
        unsigned int cbRecvLength;
        unsigned int cbRecvBufferLength;
    } reply;

    LLOGLN(10, ("SCardTransmit:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardTransmit: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }

    // Same checks as PCSC-Lite
    if (pbSendBuffer == NULL || pbRecvBuffer == NULL ||
            pcbRecvLength == NULL || pioSendPci == NULL)
    {
        return SCARD_E_INVALID_PARAMETER;
    }

    LLOGLN(10, ("  hCard 0x%8.8x", (int)hCard));
    LLOGLN(10, ("  cbSendLength %d", (int)cbSendLength));
    LLOGLN(10, ("  cbRecvLength %d", (int)*pcbRecvLength));
    LLOGLN(10, ("  pioSendPci->dwProtocol %d", (int)(pioSendPci->dwProtocol)));
    LLOGLN(10, ("  pioSendPci->cbPciLength %d", (int)(pioSendPci->cbPciLength)));
    LLOGLN(10, ("  pioRecvPci %p", pioRecvPci));
    if (pioRecvPci != 0)
    {
        LLOGLN(10, ("    pioRecvPci->dwProtocol %d", (int)(pioRecvPci->dwProtocol)));
        LLOGLN(10, ("    pioRecvPci->cbPciLength %d", (int)(pioRecvPci->cbPciLength)));
    }

    // Work out the SendPci extra bytes (if any)
    if (pioSendPci->cbPciLength < sizeof(SCARD_IO_REQUEST))
    {
        send_pci_extra_bytes = 0;
    }
    else
    {
        send_pci_extra_bytes = pioSendPci->cbPciLength -
                               sizeof(SCARD_IO_REQUEST);
    }

    // Work out the RecvPci extra bytes (if any)
    if (pioRecvPci == NULL ||
            pioRecvPci->cbPciLength < sizeof(SCARD_IO_REQUEST))
    {
        recv_pci_extra_bytes = 0;
    }
    else
    {
        recv_pci_extra_bytes = pioRecvPci->cbPciLength -
                               sizeof(SCARD_IO_REQUEST);
    }

    // Size the buffer for both transmit and receive
    msg_size = 256 + cbSendLength +
               send_pci_extra_bytes + recv_pci_extra_bytes;
    if (msg_size < MAX_TRANSMIT_RETURN_SIZE)
    {
        msg_size = MAX_TRANSMIT_RETURN_SIZE;
    }
    msg = (char *) malloc(msg_size);
    if (msg == 0)
    {
        return SCARD_E_NO_MEMORY;
    }
    offset = 0;
    SET_UINT32(msg, offset, hCard);
    offset += 4;
    SET_UINT32(msg, offset, pioSendPci->dwProtocol);
    offset += 4;
    SET_UINT32(msg, offset, send_pci_extra_bytes);
    offset += 4;
    SET_UINT32(msg, offset, cbSendLength);
    offset += 4;
    if (pioRecvPci == NULL)
    {
        SET_UINT32(msg, offset, 0);
        offset += 4;
        SET_UINT32(msg, offset, 0);
        offset += 4;
        SET_UINT32(msg, offset, 0);
        offset += 4;
    }
    else
    {
        SET_UINT32(msg, offset, 1);
        offset += 4;
        SET_UINT32(msg, offset, pioRecvPci->dwProtocol);
        offset += 4;
        SET_UINT32(msg, offset, recv_pci_extra_bytes);
        offset += 4;
    }
    SET_UINT32(msg, offset, 0); // fpbRecvBufferIsNULL
    offset += 4;
    SET_UINT32(msg, offset, *pcbRecvLength);
    offset += 4;
    if (send_pci_extra_bytes > 0)
    {
        const char *p = (const char *)(pioSendPci + 1);
        memcpy(msg + offset, p, send_pci_extra_bytes);
        offset += send_pci_extra_bytes;
    }
    memcpy(msg + offset, pbSendBuffer, cbSendLength);
    offset += cbSendLength;
    if (pioRecvPci != NULL && recv_pci_extra_bytes > 0)
    {
        const char *p = (const char *)(pioRecvPci + 1);
        memcpy(msg + offset, p, recv_pci_extra_bytes);
        offset += recv_pci_extra_bytes;
    }

    if (send_message(SCARD_TRANSMIT, msg, offset) != 0)
    {
        LLOGLN(0, ("SCardTransmit: error, send_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    bytes = msg_size;
    code = SCARD_TRANSMIT;
    if (get_message(&code, msg, &bytes) != 0)
    {
        LLOGLN(0, ("SCardTransmit: error, get_message"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_TRANSMIT || bytes < 24)
    {
        LLOGLN(0, ("SCardTransmit: error, bad code"));
        free(msg);
        return SCARD_F_INTERNAL_ERROR;
    }
    offset = 0;
    status = GET_UINT32(msg, offset);
    offset += 4;
    reply.got_pio_recv_pci = GET_UINT32(msg, offset);
    offset += 4;
    reply.dwProtocol = GET_UINT32(msg, offset);
    offset += 4;
    reply.cbExtraBytes = GET_UINT32(msg, offset);
    offset += 4;
    reply.cbRecvLength = GET_UINT32(msg, offset);
    offset += 4;
    reply.cbRecvBufferLength = GET_UINT32(msg, offset);
    offset += 4;

    // All the remaining data we need available?
    if (offset + reply.cbRecvBufferLength + reply.cbExtraBytes > bytes)
    {
        return SCARD_F_INTERNAL_ERROR;
    }

    // Sort out reply data
    if (reply.cbRecvLength > *pcbRecvLength)
    {
        // Other end should have checked this
        status = SCARD_E_INSUFFICIENT_BUFFER;
    }
    else
    {
        memcpy(pbRecvBuffer, msg + offset, reply.cbRecvBufferLength);
    }
    *pcbRecvLength = reply.cbRecvLength;
    offset += reply.cbRecvBufferLength;

    if (pioRecvPci != NULL)
    {
        if (!reply.got_pio_recv_pci)
        {
            return SCARD_F_INTERNAL_ERROR;
        }
        pioRecvPci->dwProtocol = reply.dwProtocol;
        pioRecvPci->cbPciLength = reply.cbExtraBytes + sizeof(SCARD_IO_REQUEST);;
        if (recv_pci_extra_bytes >= reply.cbExtraBytes)
        {
            memcpy((char *)pioRecvPci + 1, msg + offset, reply.cbExtraBytes);
        }
    }
    free(msg);
    return status;
#undef MAX_TRANSMIT_RETURN_SIZE
}

/*****************************************************************************/
PCSC_API LONG
SCardListReaderGroups(SCARDCONTEXT hContext, LPSTR mszGroups,
                      LPDWORD pcchGroups)
{
    LLOGLN(10, ("SCardListReaderGroups:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardListReaderGroups: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    return SCARD_S_SUCCESS;
}

/*****************************************************************************/
PCSC_API LONG
SCardListReaders(SCARDCONTEXT hContext, /* @unused */ LPCSTR mszGroups,
                 LPSTR mszReaders, LPDWORD pcchReaders)
{
    char msg[256];
    unsigned int code;
    unsigned int bytes;
    unsigned int offset;
    LONG ReturnCode;
    unsigned int cBytes;

    (void)mszGroups;

    LLOGLN(10, ("SCardListReaders:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardListReaders: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }

    if (pcchReaders == NULL)
    {
        return SCARD_E_INVALID_PARAMETER;
    }

    if (*pcchReaders == SCARD_AUTOALLOCATE && mszReaders == NULL)
    {
        return SCARD_E_INVALID_PARAMETER;
    }

    offset = 0;
    SET_UINT32(msg, offset, hContext);
    offset += 4;

    // PCSC-Lite currently ignores the mszGroups parameter, so we
    // will too. We'll send 0, representing a NULL string
    SET_UINT32(msg, offset, 0);
    offset += 4;

    if (send_message(SCARD_LIST_READERS, msg, offset) != 0)
    {
        LLOGLN(0, ("SCardListReaders: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }

    bytes = sizeof(msg);
    code = SCARD_LIST_READERS;
    if (get_message(&code, msg, &bytes) != 0 || bytes < 8)
    {
        LLOGLN(0, ("SCardListReaders: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_LIST_READERS)
    {
        LLOGLN(0, ("SCardListReaders: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    offset = 0;
    ReturnCode = GET_UINT32(msg, offset);
    LLOGLN(10, ("SCardListReaders: status 0x%8.8x", (int)ReturnCode));
    offset += 4;
    cBytes = GET_UINT32(msg, offset);
    offset += 4;

    if (ReturnCode == SCARD_S_SUCCESS)
    {
        // auto-allocate memory, if the user has requested it
        if (*pcchReaders == SCARD_AUTOALLOCATE)
        {
            char *readers_list_out;
            if ((readers_list_out = (char *)malloc(cBytes)) == NULL)
            {
                return SCARD_E_NO_MEMORY;
            }
            *(char **)mszReaders = readers_list_out; // Pass pointer to  user
            mszReaders = readers_list_out; // Use pointer ourselves
            *pcchReaders = cBytes;
        }

        if (mszReaders == NULL)
        {
            // Do nothing - user wants length
        }
        else if (*pcchReaders < cBytes)
        {
            ReturnCode = SCARD_E_INSUFFICIENT_BUFFER;
        }
        else if ((bytes - offset) < cBytes)
        {
            LLOGLN(0, ("SCardListReaders: error, missing buffer"));
            ReturnCode = SCARD_F_INTERNAL_ERROR;
        }
        else
        {
            memcpy(mszReaders, msg + offset, cBytes);
        }
        *pcchReaders = cBytes;
    }

    return ReturnCode;
}

/*****************************************************************************/
PCSC_API LONG
SCardFreeMemory(SCARDCONTEXT hContext, LPCVOID pvMem)
{
    LLOGLN(0, ("SCardFreeMemory:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardFreeMemory: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    return SCARD_S_SUCCESS;
}

/*****************************************************************************/
PCSC_API LONG
SCardCancel(SCARDCONTEXT hContext)
{
    return send_context_get_long_return(SCARD_CANCEL, "SCardCancel", hContext);
}

/*****************************************************************************/
PCSC_API LONG
SCardGetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr,
               LPDWORD pcbAttrLen)
{
    char msg[256];
    unsigned int code;
    unsigned int bytes;
    unsigned int offset;
    LONG ReturnCode;
    unsigned int fpbAttrIsNULL = (pbAttr == NULL);
    unsigned int cbAttrLen;

    LLOGLN(0, ("SCardGetAttrib:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardGetAttrib: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }

    if (pcbAttrLen == NULL)
    {
        return SCARD_E_INVALID_PARAMETER;
    }

    if (*pcbAttrLen == SCARD_AUTOALLOCATE && fpbAttrIsNULL)
    {
        return SCARD_E_INVALID_PARAMETER;
    }

    offset = 0;
    SET_UINT32(msg, offset, hCard);
    offset += 4;
    SET_UINT32(msg, offset, dwAttrId);
    offset += 4;
    SET_UINT32(msg, offset, fpbAttrIsNULL);
    offset += 4;
    SET_UINT32(msg, offset, *pcbAttrLen);
    offset += 4;

    if (send_message(SCARD_GET_ATTRIB, msg, offset) != 0)
    {
        LLOGLN(0, ("SCardGetAttrib: error, send_message"));
        return SCARD_F_INTERNAL_ERROR;
    }

    bytes = sizeof(msg);
    code = SCARD_GET_ATTRIB;
    if (get_message(&code, msg, &bytes) != 0 || bytes < 8)
    {
        LLOGLN(0, ("SCardGetAttrib: error, get_message"));
        return SCARD_F_INTERNAL_ERROR;
    }
    if (code != SCARD_GET_ATTRIB)
    {
        LLOGLN(0, ("SCardGetAttrib: error, bad code"));
        return SCARD_F_INTERNAL_ERROR;
    }
    offset = 0;
    ReturnCode = GET_UINT32(msg, offset);
    LLOGLN(10, ("SCardListReaders: status 0x%8.8x", (int)ReturnCode));
    offset += 4;
    cbAttrLen = GET_UINT32(msg, offset);
    offset += 4;

    if (ReturnCode == SCARD_S_SUCCESS)
    {
        // auto-allocate memory, if the user has requested it
        if (*pcbAttrLen == SCARD_AUTOALLOCATE)
        {
            LPBYTE attr_out;
            if ((attr_out = (LPBYTE)malloc(cbAttrLen)) == NULL)
            {
                return SCARD_E_NO_MEMORY;
            }
            *(LPBYTE *)pbAttr = attr_out; // Pass pointer to  user
            pbAttr = attr_out; // Use pointer ourselves
            *pcbAttrLen = cbAttrLen;
        }

        if (fpbAttrIsNULL)
        {
            // Do nothing - user wants length
        }
        else if (*pcbAttrLen < cbAttrLen)
        {
            ReturnCode = SCARD_E_INSUFFICIENT_BUFFER;
        }
        else if ((bytes - offset) < cbAttrLen)
        {
            LLOGLN(0, ("SCardGetAttrib: error, missing buffer"));
            ReturnCode = SCARD_F_INTERNAL_ERROR;
        }
        else
        {
            memcpy(pbAttr, msg + offset, cbAttrLen);
        }
        *pcbAttrLen = cbAttrLen;
    }

    return ReturnCode;
}

/*****************************************************************************/
PCSC_API LONG
SCardSetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPCBYTE pbAttr,
               DWORD cbAttrLen)
{
    LLOGLN(0, ("SCardSetAttrib:"));
    if (g_sck == -1)
    {
        LLOGLN(0, ("SCardSetAttrib: error, not connected"));
        return SCARD_F_INTERNAL_ERROR;
    }
    return SCARD_S_SUCCESS;
}

/*****************************************************************************/
PCSC_API const char *
pcsc_stringify_error(const LONG code)
{
    LLOGLN(10, ("pcsc_stringify_error: 0x%8.8x", (int)code));
    switch (code)
    {
        case SCARD_S_SUCCESS:
            snprintf(g_error_str, 511, "Command successful.");
            break;
        case SCARD_F_INTERNAL_ERROR:
            snprintf(g_error_str, 511, "Internal error.");
            break;
        default:
            snprintf(g_error_str, 511, "error 0x%8.8x", (int)code);
            break;
    }
    g_error_str[511] = 0;
    return g_error_str;
}
