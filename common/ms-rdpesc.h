/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * MS-RDPESC : Definitions from [MS-RDPESC]
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
 * References to MS-RDPESC are currently correct for the June 25, 2021
 * release of that document
 */

#if !defined(MS_RDPESC_H)
#define MS_RDPESC_H

/* Mentioned in various sections */
#define SCARD_AUTOALLOCATE          0xffffffff

/* see [MS-RDPESC] 2.2.2.16 HCardAndDisposition_Call */
#define SCARD_LEAVE_CARD            0x00000000 /* do not do anything      */
#define SCARD_RESET_CARD            0x00000001 /* reset smart card        */
#define SCARD_UNPOWER_CARD          0x00000002 /* turn off and reset card */

/* see [MS-RDPESC] 2.2.5 protocol identifier - Table A */
#define SCARD_PROTOCOL_UNDEFINED    0x00000000
#define SCARD_PROTOCOL_T0           0x00000001
#define SCARD_PROTOCOL_T1           0x00000002
#define SCARD_PROTOCOL_Tx           0x00000003
#define SCARD_PROTOCOL_RAW          0x00010000

/* see [MS-RDPESC] 2.2.5 protocol identifier - Table B */
#define SCARD_PROTOCOL_DEFAULT      0x80000000
#define SCARD_PROTOCOL_OPTIMAL      0x00000000

/* see [MS-RDPESC] 2.2.6 Access Mode Flags */
#define SCARD_SHARE_EXCLUSIVE       0x00000001
#define SCARD_SHARE_SHARED          0x00000002
#define SCARD_SHARE_DIRECT          0x00000003

#endif /* MS_RDPESC_H */
