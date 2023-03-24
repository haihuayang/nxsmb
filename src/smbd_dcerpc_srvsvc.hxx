
#ifndef __smbd_dcerpc_srvsvc__hxx__
#define __smbd_dcerpc_srvsvc__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif


#include "include/librpc/srvsvc.hxx"

WERROR x_smbd_net_enum(idl::srvsvc_NetConnEnum &arg,
		std::vector<idl::srvsvc_NetConnInfo0> &array);
WERROR x_smbd_net_enum(idl::srvsvc_NetConnEnum &arg,
		std::vector<idl::srvsvc_NetConnInfo1> &array);

WERROR x_smbd_net_enum(idl::srvsvc_NetFileEnum &arg,
		std::vector<idl::srvsvc_NetFileInfo2> &array);
WERROR x_smbd_net_enum(idl::srvsvc_NetFileEnum &arg,
		std::vector<idl::srvsvc_NetFileInfo3> &array);

WERROR x_smbd_net_enum(idl::srvsvc_NetSessEnum &arg,
		std::vector<idl::srvsvc_NetSessInfo0> &array);
WERROR x_smbd_net_enum(idl::srvsvc_NetSessEnum &arg,
		std::vector<idl::srvsvc_NetSessInfo1> &array);
WERROR x_smbd_net_enum(idl::srvsvc_NetSessEnum &arg,
		std::vector<idl::srvsvc_NetSessInfo2> &array);
WERROR x_smbd_net_enum(idl::srvsvc_NetSessEnum &arg,
		std::vector<idl::srvsvc_NetSessInfo10> &array);
WERROR x_smbd_net_enum(idl::srvsvc_NetSessEnum &arg,
		std::vector<idl::srvsvc_NetSessInfo502> &array);
void x_smbd_net_sess_del(const std::u16string *user,
		const std::u16string *client);



#endif /* __smbd_dcerpc_srvsvc__hxx__ */

