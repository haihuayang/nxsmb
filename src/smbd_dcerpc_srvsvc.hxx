
#ifndef __smbd_dcerpc_srvsvc__hxx__
#define __smbd_dcerpc_srvsvc__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif


#include "include/librpc/srvsvc.hxx"

void x_smbd_net_enum(std::vector<idl::srvsvc_NetSessInfo0> &array);
void x_smbd_net_enum(std::vector<idl::srvsvc_NetSessInfo1> &array);
void x_smbd_net_enum(std::vector<idl::srvsvc_NetSessInfo2> &array);
void x_smbd_net_enum(std::vector<idl::srvsvc_NetSessInfo10> &array);
void x_smbd_net_enum(std::vector<idl::srvsvc_NetSessInfo502> &array);



#endif /* __smbd_dcerpc_srvsvc__hxx__ */

