/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * MS-ERREF : Definitions from [MS-ERREF]
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
 * References to MS-ERREF are currently correct for v20180912 of that
 * document
 */

#if !defined(MS_ERREF_H)
#define MS_ERREF_H

/*
 * HRESULT codes (section 2.1)
 */
enum HRESULT
{
    /* FACILITY_SCARD
     *
     * These have X prefixes to prevent collisions with PCSC-Lite
     * definitions
     */
    XSCARD_S_SUCCESS = 0x00000000,
    XSCARD_F_INTERNAL_ERROR = 0x80100001,
    XSCARD_E_CANCELLED = 0x80100002,
    XSCARD_E_INVALID_HANDLE = 0x80100003,
    XSCARD_E_INVALID_PARAMETER = 0x80100004,
    XSCARD_E_INVALID_TARGET = 0x80100005,
    XSCARD_E_NO_MEMORY = 0x80100006,
    XSCARD_F_WAITED_TOO_LONG = 0x80100007,
    XSCARD_E_INSUFFICIENT_BUFFER = 0x80100008,
    XSCARD_E_UNKNOWN_READER = 0x80100009,
    XSCARD_E_TIMEOUT = 0x8010000A,
    XSCARD_E_SHARING_VIOLATION = 0x8010000B,
    XSCARD_E_NO_SMARTCARD = 0x8010000C,
    XSCARD_E_UNKNOWN_CARD = 0x8010000D,
    XSCARD_E_CANT_DISPOSE = 0x8010000E,
    XSCARD_E_PROTO_MISMATCH = 0x8010000F,
    XSCARD_E_NOT_READY = 0x80100010,
    XSCARD_E_INVALID_VALUE = 0x80100011,
    XSCARD_E_SYSTEM_CANCELLED = 0x80100012,
    XSCARD_F_COMM_ERROR = 0x80100013,
    XSCARD_F_UNKNOWN_ERROR = 0x80100014,
    XSCARD_E_INVALID_ATR = 0x80100015,
    XSCARD_E_NOT_TRANSACTED = 0x80100016,
    XSCARD_E_READER_UNAVAILABLE = 0x80100017,
    XSCARD_P_SHUTDOWN = 0x80100018,
    XSCARD_E_PCI_TOO_SMALL = 0x80100019,
    XSCARD_E_READER_UNSUPPORTED = 0x8010001A,
    XSCARD_E_DUPLICATE_READER = 0x8010001B,
    XSCARD_E_CARD_UNSUPPORTED = 0x8010001C,
    XSCARD_E_NO_SERVICE = 0x8010001D,
    XSCARD_E_SERVICE_STOPPED = 0x8010001E,
    XSCARD_E_UNEXPECTED = 0x8010001F,
    XSCARD_E_ICC_INSTALLATION = 0x80100020,
    XSCARD_E_ICC_CREATEORDER = 0x80100021,
    XSCARD_E_UNSUPPORTED_FEATURE = 0x80100022,
    XSCARD_E_DIR_NOT_FOUND = 0x80100023,
    XSCARD_E_FILE_NOT_FOUND = 0x80100024,
    XSCARD_E_NO_DIR = 0x80100025,
    XSCARD_E_NO_FILE = 0x80100026,
    XSCARD_E_NO_ACCESS = 0x80100027,
    XSCARD_E_WRITE_TOO_MANY = 0x80100028,
    XSCARD_E_BAD_SEEK = 0x80100029,
    XSCARD_E_INVALID_CHV = 0x8010002A,
    XSCARD_E_UNKNOWN_RES_MNG = 0x8010002B,
    XSCARD_E_NO_SUCH_CERTIFICATE = 0x8010002C,
    XSCARD_E_CERTIFICATE_UNAVAILABLE = 0x8010002D,
    XSCARD_E_NO_READERS_AVAILABLE = 0x8010002E,
    XSCARD_E_COMM_DATA_LOST = 0x8010002F,
    XSCARD_E_NO_KEY_CONTAINER = 0x80100030,
    XSCARD_E_SERVER_TOO_BUSY = 0x80100031,
    XSCARD_W_UNSUPPORTED_CARD = 0x80100065,
    XSCARD_W_UNRESPONSIVE_CARD = 0x80100066,
    XSCARD_W_UNPOWERED_CARD = 0x80100067,
    XSCARD_W_RESET_CARD = 0x80100068,
    XSCARD_W_REMOVED_CARD = 0x80100069,
    XSCARD_W_SECURITY_VIOLATION = 0x8010006A,
    XSCARD_W_WRONG_CHV = 0x8010006B,
    XSCARD_W_CHV_BLOCKED = 0x8010006C,
    XSCARD_W_EOF = 0x8010006D,
    XSCARD_W_CANCELLED_BY_USER = 0x8010006E,
    XSCARD_W_CARD_NOT_AUTHENTICATED = 0x8010006F
};

/*
 * NTSTATUS codes (section 2.3)
 */
enum NTSTATUS
{
    STATUS_SUCCESS               = 0x00000000,

    STATUS_NO_MORE_FILES         = 0x80000006,

    STATUS_UNSUCCESSFUL          = 0xc0000001,
    STATUS_NO_SUCH_FILE          = 0xc000000f,
    STATUS_ACCESS_DENIED         = 0xc0000022,
    STATUS_OBJECT_NAME_INVALID   = 0xc0000033,
    STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034,
    STATUS_SHARING_VIOLATION     = 0xc0000043,
    STATUS_NOT_SUPPORTED         = 0xc00000bb
};

#endif /* MS_ERREF_H */
