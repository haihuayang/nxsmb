
#include "smbd_secrets.hxx"
#include "smbd_conf.hxx"
#include <string>
#include <tdb.h>
#include <fcntl.h>

/* copy from samba/source3/include/secrets.h, cannot include it
   because some type is undefined
 */

/* the first one is for the hashed password (NT4 style) the latter
   for plaintext (ADS)
*/
#define SECRETS_MACHINE_ACCT_PASS "SECRETS/$MACHINE.ACC"
#define SECRETS_MACHINE_PASSWORD "SECRETS/MACHINE_PASSWORD"
#define SECRETS_MACHINE_PASSWORD_PREV "SECRETS/MACHINE_PASSWORD.PREV"
#define SECRETS_MACHINE_LAST_CHANGE_TIME "SECRETS/MACHINE_LAST_CHANGE_TIME"
#define SECRETS_MACHINE_SEC_CHANNEL_TYPE "SECRETS/MACHINE_SEC_CHANNEL_TYPE"
#define SECRETS_MACHINE_TRUST_ACCOUNT_NAME "SECRETS/SECRETS_MACHINE_TRUST_ACCOUNT_NAME"
#define SECRETS_MACHINE_DOMAIN_INFO "SECRETS/MACHINE_DOMAIN_INFO"
/* this one is for storing trusted domain account password */
#define SECRETS_DOMTRUST_ACCT_PASS "SECRETS/$DOMTRUST.ACC"

/* Store the principal name used for Kerberos DES key salt under this key name. */
#define SECRETS_SALTING_PRINCIPAL "SECRETS/SALTING_PRINCIPAL"

/* The domain sid and our sid are stored here even though they aren't
   really secret. */
#define SECRETS_DOMAIN_SID    "SECRETS/SID"
#define SECRETS_SAM_SID       "SAM/SID"
#define SECRETS_PROTECT_IDS   "SECRETS/PROTECT/IDS"

/* The domain GUID and server GUID (NOT the same) are also not secret */
#define SECRETS_DOMAIN_GUID   "SECRETS/DOMGUID"
#define SECRETS_SERVER_GUID   "SECRETS/GUID"

#define SECRETS_LDAP_BIND_PW "SECRETS/LDAP_BIND_PW"

#define SECRETS_LOCAL_SCHANNEL_KEY "SECRETS/LOCAL_SCHANNEL_KEY"

/* Authenticated user info is stored in secrets.tdb under these keys */

#define SECRETS_AUTH_USER      "SECRETS/AUTH_USER"
#define SECRETS_AUTH_DOMAIN      "SECRETS/AUTH_DOMAIN"
#define SECRETS_AUTH_PASSWORD  "SECRETS/AUTH_PASSWORD"


struct secrets_fetch_state_t
{
	secrets_fetch_state_t(std::vector<uint8_t> *d) : data(d) { }
	std::vector<uint8_t> * const data;
};

static int secrets_fetch_parser(TDB_DATA key, TDB_DATA data,
		void *private_data)
{
	secrets_fetch_state_t *state = (secrets_fetch_state_t *)private_data;
	state->data->assign(data.dptr, data.dptr + data.dsize);
	return 0;
}

/* read a entry from the secrets database - the caller must free the result
   if size is non-null then the size of the entry is put in there
 */
static int secrets_fetch(struct tdb_context *db_ctx,
		const std::string &key, std::vector<uint8_t> &data)
{
	secrets_fetch_state_t state{&data};

	TDB_DATA tdb_key;
	tdb_key.dptr = (unsigned char *)key.data();
	tdb_key.dsize = key.size();
	int err = tdb_parse_record(db_ctx, tdb_key,
			secrets_fetch_parser, &state);
	return err;
}

struct secrets_fetch_string_state_t
{
	secrets_fetch_string_state_t(std::string *d) : data(d) { }
	std::string * const data;
};

static int secrets_fetch_string_parser(TDB_DATA key, TDB_DATA data,
		void *private_data)
{
	secrets_fetch_string_state_t *state = (secrets_fetch_string_state_t *)private_data;
	size_t dsize = data.dsize;
	if (dsize > 0 && data.dptr[dsize - 1] == '\0') {
		dsize--;
	}
	state->data->assign(data.dptr, data.dptr + dsize);
	return 0;
}

/* read a entry from the secrets database - the caller must free the result
   if size is non-null then the size of the entry is put in there
 */
static int secrets_fetch_string(struct tdb_context *db_ctx,
		const std::string &key, std::string &data)
{
	secrets_fetch_string_state_t state{&data};

	TDB_DATA tdb_key;
	tdb_key.dptr = (unsigned char *)key.data();
	tdb_key.dsize = key.size();
	int err = tdb_parse_record(db_ctx, tdb_key,
			secrets_fetch_string_parser, &state);
	return err;
}

/**
 * Form a key for fetching the machine previous trust account password
 *
 * @param domain domain name
 *
 * @return keystring
 **/
static std::string machine_prev_password_keystr(const std::string &domain)
{
	std::string ret = SECRETS_MACHINE_PASSWORD_PREV;
	ret += "/";
	ret += domain;
	return ret;
}

/**
 * Form a key for fetching the machine trust account password
 *
 * @param domain domain name
 *
 * @return keystring
 **/
static std::string machine_password_keystr(const std::string &domain)
{
	std::string ret = SECRETS_MACHINE_PASSWORD;
	ret += "/";
	ret += domain;
	return ret;
}

static inline int smbd_secrets_fetch_machine_password(
		struct tdb_context *db_ctx,
		const std::string &domain,
		std::string &password)
	//				     time_t *pass_last_set_time,
	//				     enum netr_SchannelType *channel)
{
	return secrets_fetch_string(db_ctx, machine_password_keystr(domain), password);
}

static inline int smbd_secrets_fetch_prev_machine_password(
		struct tdb_context *db_ctx,
		const std::string &domain,
		std::string &password)
{
	return secrets_fetch_string(db_ctx, machine_prev_password_keystr(domain), password);
}

static bool smbd_secrets_fetch_domain_guid(
		struct tdb_context *db_ctx,
		const std::string &domain,
		idl::GUID &guid)
{
	std::vector<uint8_t> data;
	int ret = secrets_fetch(db_ctx, SECRETS_DOMAIN_GUID "/" + domain, data);
	if (ret != 0) {
		return false;
	}

	X_ASSERT(data.size() == sizeof guid);
	memcpy(&guid, data.data(), sizeof guid);
	return true;
}

static bool smbd_secrets_fetch_domain_sid(
		struct tdb_context *db_ctx,
		const std::string &domain,
		idl::dom_sid &sid)
{
	std::vector<uint8_t> data;
	int ret = secrets_fetch(db_ctx, SECRETS_DOMAIN_SID "/" + domain, data);
	X_ASSERT(ret == 0);
	X_ASSERT(data.size() == sizeof sid);
	memcpy(&sid, data.data(), sizeof sid);
	return true;
}

static int smbd_secrets_load(struct tdb_context *db_ctx,
		x_smbd_secrets_t &secrets,
		const std::string &workgroup,
		const std::string &netbios_name)
{
	if (!smbd_secrets_fetch_domain_sid(db_ctx, netbios_name, secrets.sid)) {
		return -1;
	}
	if (!smbd_secrets_fetch_domain_sid(db_ctx, workgroup, secrets.domain_sid)) {
		return -1;
	}
	if (!smbd_secrets_fetch_domain_guid(db_ctx, workgroup, secrets.domain_guid)) {
		/* TODO old samba does not create it */
		memset(&secrets.domain_guid, 0, sizeof secrets.domain_guid);
	}

	int ret = smbd_secrets_fetch_machine_password(db_ctx, workgroup,
			secrets.machine_password);
	if (ret != 0) {
		return -1;
	}
	ret = smbd_secrets_fetch_prev_machine_password(db_ctx, workgroup,
			secrets.prev_machine_password);
	if (ret != 0) {
		secrets.prev_machine_password.clear();
	}

	return 0;
}

int x_smbd_secrets_load(x_smbd_secrets_t &secrets,
		const std::string &private_dir,
		const std::string &workgroup,
		const std::string &netbios_name)
{
	std::string path = private_dir + "/secrets.tdb";

	struct tdb_context *ctx = tdb_open(path.c_str(), 0, TDB_DEFAULT, O_RDONLY, 0600);
	if (ctx) {
		int ret = smbd_secrets_load(ctx, secrets, workgroup, netbios_name);
		tdb_close(ctx);
		return ret;
	}

	return -1;

}

