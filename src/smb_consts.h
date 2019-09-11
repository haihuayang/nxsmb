
#ifndef __smb_consts__h__
#define __smb_consts__h__

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Netbios over TCP (rfc 1002)
 */
#define NBSSmessage     0x00   /* session message */
#define NBSSrequest     0x81   /* session request */
#define NBSSpositive    0x82   /* positiv session response */
#define NBSSnegative    0x83   /* negativ session response */
#define NBSSretarget    0x84   /* retarget session response */
#define NBSSkeepalive   0x85   /* keepalive */

#define SMBnegprot    0x72   /* negotiate protocol */



#define SMB2_HDR_PROTOCOL_ID    0x00
#define SMB2_HDR_LENGTH         0x04
#define SMB2_HDR_CREDIT_CHARGE  0x06
#define SMB2_HDR_EPOCH          SMB2_HDR_CREDIT_CHARGE /* TODO: remove this */
#define SMB2_HDR_STATUS         0x08
#define SMB2_HDR_CHANNEL_SEQUENCE SMB2_HDR_STATUS /* in requests */
#define SMB2_HDR_OPCODE         0x0c
#define SMB2_HDR_CREDIT         0x0e
#define SMB2_HDR_FLAGS          0x10
#define SMB2_HDR_NEXT_COMMAND   0x14
#define SMB2_HDR_MESSAGE_ID     0x18
#define SMB2_HDR_PID            0x20
#define SMB2_HDR_TID            0x24
#define SMB2_HDR_SESSION_ID     0x28
#define SMB2_HDR_SIGNATURE      0x30 /* 16 bytes */
#define SMB2_HDR_BODY           0x40

/* header flags */
#define SMB2_HDR_FLAG_REDIRECT  0x01
#define SMB2_HDR_FLAG_ASYNC     0x02
#define SMB2_HDR_FLAG_CHAINED   0x04
#define SMB2_HDR_FLAG_SIGNED    0x08
#define SMB2_HDR_FLAG_PRIORITY_MASK 0x70
#define SMB2_HDR_FLAG_DFS       0x10000000
#define SMB2_HDR_FLAG_REPLAY_OPERATION 0x20000000

#define SMB2_OP_NEGPROT         0x00
#define SMB2_OP_SESSSETUP       0x01
#define SMB2_OP_LOGOFF          0x02
#define SMB2_OP_TCON            0x03
#define SMB2_OP_TDIS            0x04
#define SMB2_OP_CREATE          0x05
#define SMB2_OP_CLOSE           0x06
#define SMB2_OP_FLUSH           0x07
#define SMB2_OP_READ            0x08
#define SMB2_OP_WRITE           0x09
#define SMB2_OP_LOCK            0x0a
#define SMB2_OP_IOCTL           0x0b
#define SMB2_OP_CANCEL          0x0c
#define SMB2_OP_KEEPALIVE       0x0d
#define SMB2_OP_QUERY_DIRECTORY 0x0e
#define SMB2_OP_NOTIFY          0x0f
#define SMB2_OP_GETINFO         0x10
#define SMB2_OP_SETINFO         0x11
#define SMB2_OP_BREAK           0x12

/* SMB2 negotiate security_mode */
#define SMB2_NEGOTIATE_SIGNING_ENABLED   0x01
#define SMB2_NEGOTIATE_SIGNING_REQUIRED  0x02

/* SMB2 global capabilities */
#define SMB2_CAP_DFS                    0x00000001
#define SMB2_CAP_LEASING                0x00000002 /* only in dialect >= 0x210 */
#define SMB2_CAP_LARGE_MTU              0x00000004 /* only in dialect >= 0x210 */
#define SMB2_CAP_MULTI_CHANNEL          0x00000008 /* only in dialect >= 0x222 */
#define SMB2_CAP_PERSISTENT_HANDLES     0x00000010 /* only in dialect >= 0x222 */
#define SMB2_CAP_DIRECTORY_LEASING      0x00000020 /* only in dialect >= 0x222 */
#define SMB2_CAP_ENCRYPTION             0x00000040 /* only in dialect >= 0x222 */

#ifdef __cplusplus
}
#endif

#endif /* __smb_consts__h__ */

