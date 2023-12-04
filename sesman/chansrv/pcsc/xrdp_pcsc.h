/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg and xrdp contributors 2013-2023
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
 * @file sesman/chansrv/pcsc/xrdp_pcsc.h
 *
 * Communications between the xrdp_pcsc shim and chansrv
 */

#if !defined(XRDP_PCSC_H)
#define XRDP_PCSC_H

/**
 * Message codes for messages between xrdp_pcsc.c and smartcard_pcsc.c
 */
enum pcsc_message_code
{
    SCARD_ESTABLISH_CONTEXT   = 0x01,
    SCARD_RELEASE_CONTEXT     = 0x02,
    SCARD_LIST_READERS        = 0x03,
    SCARD_CONNECT             = 0x04,
    SCARD_RECONNECT           = 0x05,
    SCARD_DISCONNECT          = 0x06,
    SCARD_BEGIN_TRANSACTION   = 0x07,
    SCARD_END_TRANSACTION     = 0x08,
    SCARD_TRANSMIT            = 0x09,
    SCARD_CONTROL             = 0x0A,
    SCARD_STATUS              = 0x0B,
    SCARD_GET_STATUS_CHANGE   = 0x0C,
    SCARD_CANCEL              = 0x0D,
    SCARD_CANCEL_TRANSACTION  = 0x0E,
    SCARD_GET_ATTRIB          = 0x0F,
    SCARD_SET_ATTRIB          = 0x10
};

/*
 * Word values are unsigned 32-bits, little-endian unless otherwise
 * specified.
 *
 * All messages are preceded by an 8 byte header as follows:-
 * Offset  Data
 * 0       Size of message following header
 * 4       Message code (from enum pcsc_message_code)
 *
 * Reply messages are send from chansrv to the client using the same
 * message code
 */

// *****************************************************************************
//  E S T A B L I S H   C O N T E X T
// *****************************************************************************
// Request (See [MS-RDPESC] 2.2.2.1) :-
// Offset Value
// 0      Header, code SCARD_ESTABLISH_CONTEXT
// 8      dwScope
//
// Response (See [MS-RDPESC] 2.2.3.2) :-
// Offset Value
// 0      Header, code SCARD_ESTABLISH_CONTEXT
// 8      ReturnCode
// 12     context value

// *****************************************************************************
//  R E L E A S E   C O N T E X T
// *****************************************************************************
// Request (See [MS-RDPESC] 2.2.2.2) :-
// Offset Value
// 0      Header, code SCARD_RELEASE_CONTEXT
// 8      hContext
//
// Response (See [MS-RDPESC] 2.2.3.3) :-
// Offset Value
// 0      Header, code SCARD_RELEASE_CONTEXT
// 8      ReturnCode
//
// *****************************************************************************
//  L I S T   R E A D E R S
// *****************************************************************************
// Request (See [MS-RDPESC] 2.2.2.4) :-
// Offset Value
// 0      Header, code SCARD_LIST_READERS
// 8      hContext
// 12     cBytes
// 16     mszGroups (UTF-8)
// 16 + cBytes     fmszReadersIsNULL
// 20 + cBytes     cchReaders
//
// Response (See [MS-RDPESC] 2.2.3.4) :-
// Offset Value
// 0      Header, code SCARD_LIST_READERS
// 8      ReturnCode
// 12     cBytes
// 16     msz (UTF-8)
//
// *****************************************************************************
//  C O N N E C T
// *****************************************************************************
// Request (See [MS-RDPESC] 2.2.2.14 and 2.2.1.3) :-
// 0      Header, code SCARD_CONNECT
// 8      hContext
// 12     dwShareMode
// 16     dwPreferredProtocols
// 20     Length of szReader without terminator
// 24     szReader (UTF-8). Terminator omitted
//
// Response (See [MS-RDPESC] 2.2.3.8) :-
// Offset Value
// 0      Header, code SCARD_CONNECT
// 8      ReturnCode
// 12     hCard
// 16     dwActiveProtocol
//
// *****************************************************************************
//  S T A T U S
// *****************************************************************************
// Request (See [MS-RDPESC] 2.2.2.18) :-
// Offset Value
// 0      Header, code SCARD_STATUS
// 8      hCard
//
// Response (See [MS-RDPESC] 2.2.3.10) :-
// Offset Value
// 0      Header, code SCARD_STATUS
// 8      ReturnCode
// 12     dwState (MS-style - not a PCSCLite bitmask)
// 16     dwProtocol
// 20     cBytes
// 24     cbAtrLen
// 28     Friendly name of reader (UTF-8)
// 28+cBytes cbAtr
//

#endif // XRDP_PCSC_H
