
#ifndef __winbind_wrap__hxx__
#define __winbind_wrap__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif


extern "C" {
/* copy from samba/nsswitch/libwbclient/wbclient.h */
#define WBC_MSV1_0_CLEARTEXT_PASSWORD_ALLOWED           0x00000002
#define WBC_MSV1_0_UPDATE_LOGON_STATISTICS              0x00000004
#define WBC_MSV1_0_RETURN_USER_PARAMETERS               0x00000008
#define WBC_MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT           0x00000020
#define WBC_MSV1_0_RETURN_PROFILE_PATH                  0x00000200
#define WBC_MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT      0x00000800
#define WBC_MSV1_0_ALLOW_MSVCHAPV2                      0x00010000

/* the winbind struct modified with samba versions, so please
 * use the compatible version of winbind_struct_protocol.h with
 * winbindd on the system.
 */
#include <winbind_struct_protocol.h>
}


#endif /* __winbind_wrap__hxx__ */

