
#ifndef __krb5_wrap__hxx__
#define __krb5_wrap__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/xdefines.h"
extern "C" {
#include <krb5.h>
#include <gssapi/gssapi.h>
}

#define HAVE_KRB5_KEYTAB_ENTRY_KEYBLOCK 1
#define HAVE_KRB5_KEYBLOCK_KEYVALUE 1
#define HAVE_CHECKSUM_IN_KRB5_CHECKSUM 1

#ifdef HAVE_KRB5_KEYTAB_ENTRY_KEY	       /* MIT */
#define KRB5_KT_KEY(k)	  (&(k)->key)
#elif HAVE_KRB5_KEYTAB_ENTRY_KEYBLOCK	  /* Heimdal */
#define KRB5_KT_KEY(k)	  (&(k)->keyblock)
#else
#error krb5_keytab_entry has no key or keyblock member
#endif /* HAVE_KRB5_KEYTAB_ENTRY_KEY */

#ifdef HAVE_KRB5_KEYBLOCK_KEYVALUE /* Heimdal */
#define KRB5_KEY_TYPE(k)	((k)->keytype)
#define KRB5_KEY_LENGTH(k)      ((k)->keyvalue.length)
#define KRB5_KEY_DATA(k)	((k)->keyvalue.data)
#define KRB5_KEY_DATA_CAST      void
#else /* MIT */
#define KRB5_KEY_TYPE(k)	((k)->enctype)
#define KRB5_KEY_LENGTH(k)      ((k)->length)
#define KRB5_KEY_DATA(k)	((k)->contents)
#define KRB5_KEY_DATA_CAST      krb5_octet
#endif /* HAVE_KRB5_KEYBLOCK_KEYVALUE */

#ifdef HAVE_E_DATA_POINTER_IN_KRB5_ERROR /* Heimdal */
#define KRB5_ERROR_CODE(k)      ((k)->error_code)
#else /* MIT */
#define KRB5_ERROR_CODE(k)      ((k)->error)
#endif /* HAVE_E_DATA_POINTER_IN_KRB5_ERROR */


#include "include/librpc/krb5pac.hxx"

NTSTATUS kerberos_pac_logon_info(gss_const_buffer_t pac_blob,
				 krb5_context context,
				 const krb5_keyblock *krbtgt_keyblock,
				 const krb5_keyblock *service_keyblock,
				 krb5_const_principal client_principal,
				 time_t tgs_authtime,
				 std::shared_ptr<idl::PAC_LOGON_INFO> &logon_info);

NTSTATUS kerberos_decode_pac(gss_const_buffer_t pac_buf,
			     krb5_context context,
			     const krb5_keyblock *krbtgt_keyblock,
			     const krb5_keyblock *service_keyblock,
			     krb5_const_principal client_principal,
			     time_t tgs_authtime,
			     idl::PAC_DATA &pac_data);

#endif /* __krb5_wrap__hxx__ */

