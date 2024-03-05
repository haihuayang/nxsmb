/*
   Unix SMB/CIFS implementation.
   kerberos authorization data (PAC) utility library
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Stefan Metzmacher 2004-2005
   Copyright (C) Guenther Deschner 2005,2007,2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "include/krb5_wrap.hxx"
#include "include/nttime.hxx"

#define DEBUG(...) do { } while (0)

#define HAVE_KRB5_KU_OTHER_CKSUM

static krb5_error_code check_pac_checksum(const void *input_data, size_t input_length,
					  idl::PAC_SIGNATURE_DATA *sig,
					  krb5_context context,
					  const krb5_keyblock *keyblock)
{
	krb5_error_code ret;
	krb5_checksum cksum;
	krb5_boolean checksum_valid = false;

	switch (int(sig->type)) {
	case CKSUMTYPE_HMAC_MD5:
		/* ignores the key type */
		break;
	case CKSUMTYPE_HMAC_SHA1_96_AES_256:
		if (KRB5_KEY_TYPE(keyblock) != ENCTYPE_AES256_CTS_HMAC_SHA1_96) {
			return EINVAL;
		}
		/* ok */
		break;
	case CKSUMTYPE_HMAC_SHA1_96_AES_128:
		if (KRB5_KEY_TYPE(keyblock) != ENCTYPE_AES128_CTS_HMAC_SHA1_96) {
			return EINVAL;
		}
		/* ok */
		break;
	default:
		DEBUG(2,("check_pac_checksum: Checksum Type %d is not supported\n",
			(int)sig->type));
		return EINVAL;
	}

#ifdef HAVE_CHECKSUM_IN_KRB5_CHECKSUM /* Heimdal */
	cksum.cksumtype	= (krb5_cksumtype)sig->type;
	cksum.checksum.length	= sig->signature.val.size();
	cksum.checksum.data	= sig->signature.val.data();
#else /* MIT */
	cksum.checksum_type	= (krb5_cksumtype)sig->type;
	cksum.length		= sig->signature.length;
	cksum.contents		= sig->signature.data;
#endif

#ifdef HAVE_KRB5_KU_OTHER_CKSUM /* Heimdal */
	krb5_keyusage usage = KRB5_KU_OTHER_CKSUM;
#elif defined(HAVE_KRB5_KEYUSAGE_APP_DATA_CKSUM) /* MIT */
	krb5_keyusage usage = KRB5_KEYUSAGE_APP_DATA_CKSUM;
#else
#error UNKNOWN_KRB5_KEYUSAGE
#endif

	krb5_data input;
	input.data = (char *)input_data;
	input.length = input_length;

	ret = krb5_c_verify_checksum(context,
				     keyblock,
				     usage,
				     &input,
				     &cksum,
				     &checksum_valid);
	if (!checksum_valid) {
		ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	}
	if (ret){
		DEBUG(2,("check_pac_checksum: PAC Verification failed: %s (%d)\n",
			error_message(ret), ret));
		return ret;
	}

	return ret;
}

/**
* @brief Decode a blob containing a NDR encoded PAC structure
*
* @param mem_ctx	  - The memory context
* @param pac_data_blob	  - The data blob containing the NDR encoded data
* @param context	  - The Kerberos Context
* @param service_keyblock - The Service Key used to verify the checksum
* @param client_principal - The client principal
* @param tgs_authtime     - The ticket timestamp
* @param pac_data_out	  - [out] The decoded PAC
*
* @return - A NTSTATUS error code
*/
NTSTATUS kerberos_decode_pac(gss_const_buffer_t pac_buf,
			     krb5_context context,
			     const krb5_keyblock *krbtgt_keyblock,
			     const krb5_keyblock *service_keyblock,
			     krb5_const_principal client_principal,
			     time_t tgs_authtime,
			     idl::PAC_DATA &pac_data)
{
	NTSTATUS status;
	krb5_error_code ret;

	idl::NTTIME tgs_authtime_nttime;

	// struct PAC_DATA *pac_data = NULL;

#if 0
	struct PAC_DATA_RAW *pac_data_raw = NULL;
	// pac_data = talloc(tmp_ctx, struct PAC_DATA);
	pac_data_raw = talloc(tmp_ctx, struct PAC_DATA_RAW);
	kdc_sig_wipe = talloc(tmp_ctx, struct PAC_SIGNATURE_DATA);
	srv_sig_wipe = talloc(tmp_ctx, struct PAC_SIGNATURE_DATA);
	if (!pac_data_raw || !pac_data || !kdc_sig_wipe || !srv_sig_wipe) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
#endif
	idl::x_ndr_off_t ndr_ret = idl::x_ndr_pull(pac_data, (const uint8_t *)pac_buf->value, pac_buf->length, 0);
	if (ndr_ret < 0) {
		status = idl::x_ndr_map_error2ntstatus(-ndr_ret);
		DEBUG(0,("can't parse the PAC: %s\n",
			nt_errstr(status)));
		return status;
	}

	if (pac_data.buffers.size() < 4) {
		/* we need logon_ingo, service_key and kdc_key */
		DEBUG(0,("less than 4 PAC buffers\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	idl::PAC_DATA_RAW pac_data_raw;
	ndr_ret = idl::x_ndr_pull(pac_data_raw, (const uint8_t *)pac_buf->value, pac_buf->length, 0);
	if (ndr_ret < 0) {
		status = idl::x_ndr_map_error2ntstatus(-ndr_ret);
		DEBUG(0,("can't parse the PAC: %s\n",
			nt_errstr(status)));
		return status;
	}

	if (pac_data_raw.buffers.size() < 4) {
		/* we need logon_ingo, service_key and kdc_key */
		DEBUG(0,("less than 4 PAC buffers\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (pac_data.buffers.size() != pac_data_raw.buffers.size()) {
		/* we need logon_ingo, service_key and kdc_key */
		DEBUG(0, ("misparse! PAC_DATA has %d buffers while "
			  "PAC_DATA_RAW has %d\n", pac_data->num_buffers,
			  pac_data_raw->num_buffers));
		return NT_STATUS_INVALID_PARAMETER;
	}

	std::shared_ptr<idl::PAC_LOGON_INFO> logon_info;
	idl::PAC_LOGON_NAME *logon_name = NULL;
	idl::PAC_SIGNATURE_DATA *srv_sig_ptr = NULL;
	idl::PAC_SIGNATURE_DATA *kdc_sig_ptr = NULL;
	idl::DATA_BLOB *srv_sig_blob = NULL;
	idl::DATA_BLOB *kdc_sig_blob = NULL;

	for (size_t i=0; i < pac_data.buffers.size(); i++) {
		auto &data_buf = pac_data.buffers[i];
		auto &raw_buf = pac_data_raw.buffers[i];

		if (data_buf.type != raw_buf.type) {
			DEBUG(0, ("misparse! PAC_DATA buffer %d has type "
				  "%d while PAC_DATA_RAW has %d\n", i,
				  data_buf->type, raw_buf->type));
			return NT_STATUS_INVALID_PARAMETER;
		}
		switch (data_buf.type) {
		case idl::PAC_TYPE_LOGON_INFO:
			logon_info = data_buf.info->logon_info.info;
			break;
		case idl::PAC_TYPE_SRV_CHECKSUM:
			srv_sig_ptr = &data_buf.info->srv_cksum;
			srv_sig_blob = &raw_buf.info->remaining;
			break;
		case idl::PAC_TYPE_KDC_CHECKSUM:
			kdc_sig_ptr = &data_buf.info->kdc_cksum;
			kdc_sig_blob = &raw_buf.info->remaining;
			break;
		case idl::PAC_TYPE_LOGON_NAME:
			logon_name = &data_buf.info->logon_name;
			break;
		default:
			break;
		}
	}

	if (!logon_info) {
		DEBUG(0,("PAC no logon_info\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!logon_name) {
		DEBUG(0,("PAC no logon_name\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!srv_sig_ptr || !srv_sig_blob) {
		DEBUG(0,("PAC no srv_key\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!kdc_sig_ptr || !kdc_sig_blob) {
		DEBUG(0,("PAC no kdc_key\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Find and zero out the signatures,
	 * as required by the signing algorithm */

	/* We find the data blobs above,
	 * now we parse them to get at the exact portion we should zero */
	idl::PAC_SIGNATURE_DATA kdc_sig_wipe;
	ndr_ret = x_ndr_pull(kdc_sig_wipe, kdc_sig_blob->val.data(), kdc_sig_blob->val.size(), 0);
	if (ndr_ret < 0) {
		status = idl::x_ndr_map_error2ntstatus(-ndr_ret);
		DEBUG(0,("can't parse the KDC signature: %s\n",
			nt_errstr(status)));
		return status;
	}

	idl::PAC_SIGNATURE_DATA srv_sig_wipe;
	ndr_ret = x_ndr_pull(srv_sig_wipe, srv_sig_blob->val.data(), srv_sig_blob->val.size(), 0);
	if (ndr_ret < 0) {
		status = idl::x_ndr_map_error2ntstatus(-ndr_ret);
		DEBUG(0,("can't parse the SRV signature: %s\n",
			nt_errstr(status)));
		return status;
	}

	/* Now zero the decoded structure */
	kdc_sig_wipe.signature.val.assign(kdc_sig_wipe.signature.val.size(), 0);
	srv_sig_wipe.signature.val.assign(srv_sig_wipe.signature.val.size(), 0);

	/* and reencode, back into the same place it came from */
	kdc_sig_blob->val.clear();
	ndr_ret = x_ndr_push(kdc_sig_wipe, kdc_sig_blob->val, 0);
	if (ndr_ret < 0) {
		status = idl::x_ndr_map_error2ntstatus(-ndr_ret);
		DEBUG(0,("can't repack the KDC signature: %s\n",
			nt_errstr(status)));
		return status;
	}

	srv_sig_blob->val.clear();
	ndr_ret = x_ndr_push(srv_sig_wipe, srv_sig_blob->val, 0);
	if (ndr_ret < 0) {
		status = idl::x_ndr_map_error2ntstatus(-ndr_ret);
		DEBUG(0,("can't repack the KDC signature: %s\n",
			nt_errstr(status)));
		return status;
	}

	std::vector<uint8_t> modified_pac_blob;
	/* push out the whole structure, but now with zero'ed signatures */
	ndr_ret = x_ndr_push(pac_data_raw, modified_pac_blob, 0);
	if (ndr_ret < 0) {
		status = idl::x_ndr_map_error2ntstatus(-ndr_ret);
		DEBUG(0,("can't repack the RAW PAC: %s\n",
			nt_errstr(status)));
		return status;
	}

	if (service_keyblock) {
		/* verify by service_key */
		ret = check_pac_checksum(modified_pac_blob.data(),
				modified_pac_blob.size(),
				srv_sig_ptr,
				context,
				service_keyblock);
		if (ret) {
			DEBUG(5, ("PAC Decode: Failed to verify the service "
				  "signature: %s\n", error_message(ret)));
			return NT_STATUS_ACCESS_DENIED;
		}

		if (krbtgt_keyblock) {
			/* verify the service key checksum by krbtgt_key */
			ret = check_pac_checksum(srv_sig_ptr->signature.val.data(),
					srv_sig_ptr->signature.val.size(),
					kdc_sig_ptr,
					context, krbtgt_keyblock);
			if (ret) {
				DEBUG(1, ("PAC Decode: Failed to verify the KDC signature: %s\n",
					  smb_get_krb5_error_message(context, ret, tmp_ctx)));
				return NT_STATUS_ACCESS_DENIED;
			}
		}
	}

	if (tgs_authtime) {
		/* Convert to NT time, so as not to loose accuracy in comparison */
		tgs_authtime_nttime = x_unix_to_nttime(tgs_authtime);

		if (tgs_authtime_nttime.val != logon_name->logon_time.val) {
			X_LOG(AUTH, ERR, "PAC Decode: "
				  "Logon time mismatch between ticket and PAC!");
			DEBUG(3, ("PAC Decode: PAC: %s\n",
				  nt_time_string(tmp_ctx, logon_name->logon_time)));
			DEBUG(3, ("PAC Decode: Ticket: %s\n",
				  nt_time_string(tmp_ctx, tgs_authtime_nttime)));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (client_principal) {
		X_TODO; /*
			   bool bool_ret;
		char *client_principal_string;
		ret = krb5_unparse_name_flags(context, client_principal,
					      KRB5_PRINCIPAL_UNPARSE_NO_REALM|KRB5_PRINCIPAL_UNPARSE_DISPLAY,
					      &client_principal_string);
		if (ret) {
			DEBUG(3, ("Could not unparse name from ticket to match with name from PAC: [%s]:%s\n",
				  logon_name->account_name, error_message(ret)));
			return NT_STATUS_INVALID_PARAMETER;
		}

		bool_ret = strcmp(client_principal_string, logon_name->account_name) == 0;

		if (!bool_ret) {
			DEBUG(3, ("Name in PAC [%s] does not match principal name "
				  "in ticket [%s]\n",
				  logon_name->account_name,
				  client_principal_string));
			SAFE_FREE(client_principal_string);
			return NT_STATUS_ACCESS_DENIED;
		}
		SAFE_FREE(client_principal_string);
		*/

	}

	DEBUG(3,("Found account name from PAC: %s [%s]\n",
		 logon_info->info3.base.account_name.string,
		 logon_info->info3.base.full_name.string));

	DEBUG(10,("Successfully validated Kerberos PAC\n"));
#if 0
	if (DEBUGLEVEL >= 11) {
		const char *s;
		s = NDR_PRINT_STRUCT_STRING(tmp_ctx, PAC_DATA, pac_data);
		if (s) {
			DEBUGADD(11,("%s\n", s));
		}
	}

	if (pac_data_out) {
		*pac_data_out = talloc_steal(mem_ctx, pac_data);
	}
#endif
	return NT_STATUS_OK;
}

NTSTATUS kerberos_pac_logon_info(gss_const_buffer_t pac_blob,
				 krb5_context context,
				 const krb5_keyblock *krbtgt_keyblock,
				 const krb5_keyblock *service_keyblock,
				 krb5_const_principal client_principal,
				 time_t tgs_authtime,
				 std::shared_ptr<idl::PAC_LOGON_INFO> &logon_info)
{
	NTSTATUS nt_status;
	idl::PAC_DATA pac_data;
	nt_status = kerberos_decode_pac(pac_blob,
					context,
					krbtgt_keyblock,
					service_keyblock,
					client_principal,
					tgs_authtime,
					pac_data);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	for (auto &pac_buf: pac_data.buffers) {
		if (pac_buf.type != idl::PAC_TYPE_LOGON_INFO) {
			continue;
		}
		if (!pac_buf.info->logon_info.info) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		logon_info = pac_buf.info->logon_info.info;
		return NT_STATUS_OK;
	}
	return NT_STATUS_INVALID_PARAMETER;
}

