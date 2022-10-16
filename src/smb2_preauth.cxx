
#include "smb2.hxx"
extern "C" {
#include "samba/include/config.h"
#include "samba/lib/crypto/sha512.h"
}

void x_smb2_preauth_t::update(const void *data, size_t length)
{
	struct hc_sha512state sctx;
	samba_SHA512_Init(&sctx);
	samba_SHA512_Update(&sctx, this->data.data(), 64);
	samba_SHA512_Update(&sctx, data, length);
	samba_SHA512_Final(this->data.data(), &sctx);

	X_LOG_DBG("preauth=\n%s", x_hex_dump(this->data.data(), this->data.size(), "    ").c_str());
}
