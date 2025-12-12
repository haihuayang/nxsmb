
#include "include/crypto.hxx"
#include "smb2.hxx"
#include <openssl/sha.h>

void x_smb2_preauth_t::update(const void *data, size_t length)
{
	SHA512_CTX sctx;
	SHA512_Init(&sctx);
	SHA512_Update(&sctx, this->data.data(), 64);
	SHA512_Update(&sctx, data, length);
	SHA512_Final((unsigned char *)this->data.data(), &sctx);

	X_LOG(SMB, DBG, "preauth=\n%s", x_hex_dump(this->data.data(), this->data.size(), "    ").c_str());
}

void x_smb2_preauth_t::update(const x_bufref_t *buflist)
{
	SHA512_CTX sctx;
	SHA512_Init(&sctx);
	SHA512_Update(&sctx, this->data.data(), 64);
	while (buflist) {
		SHA512_Update(&sctx, buflist->get_data(), buflist->length);
		buflist = buflist->next;
	}
	SHA512_Final((unsigned char *)this->data.data(), &sctx);

	X_LOG(SMB, DBG, "preauth=\n%s", x_hex_dump(this->data.data(), this->data.size(), "    ").c_str());
}
