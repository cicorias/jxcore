//TODO:SPC - cleanup remnant 'crypto_extension_wrap2' from all files

/*
TODL: see if OPENSSL_cpuid_setup is needed (ref from   CRYPTO_library_init(); in boringssl)
*/

/* Copyright (c) 2014, Google Inc.
*
* Permission to use, copy, modify, and/or distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
* SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
* OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
* CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */


//TODO:SPC move to header

#include "jx/Proxy/JSEngine.h"
#include "jx/commons.h"


//#include "openssl/base.h"

#include "openssl/ossl_typ.h"

  /* Computes HKDF (as specified by RFC 5869) of initial keying material |secret|
  * with |salt| and |info| using |digest|, and outputs |out_len| bytes to
  * |out_key|. It returns one on success and zero on error.
  *
  * HKDF is an Extract-and-Expand algorithm. It does not do any key stretching,
  * and as such, is not suited to be used alone to generate a key from a
  * password. */
  /* OPENSSL_EXPORT*/ 

int HKDF(uint8_t *out_key, size_t out_len, const EVP_MD *digest,
  const uint8_t *secret, size_t secret_len,
  const uint8_t *salt, size_t salt_len,
  const uint8_t *info, size_t info_len);


//#define HKDF_R_OUTPUT_TOO_LARGE 100



#include "openssl/ssl.h"
#include "openssl/rand.h"
#include "openssl/err.h"
#include "openssl/pkcs12.h"

#include "node_buffer.h"


#include <assert.h>
#include <string.h>

//#include <openssl/hmac.h>


//TODO: SPC borrowed from node_crypto:


#define ASSERT_IS_BUFFER(val)             \
  if (!Buffer::jxHasInstance(val, com)) { \
    THROW_TYPE_EXCEPTION("Not a buffer"); \
  }


using namespace std;

namespace node {

  //decl
  class CryptoExtensionWrap2 {
  private:
    static DEFINE_JS_METHOD(GenerateHKDF2);

  public:
    INIT_CLASS_MEMBERS() {
      SET_CLASS_METHOD("generateHKDF2", GenerateHKDF2, 0);
    }
    END_INIT_MEMBERS
  };


  //sig: crypto.generateHKDF2(string, Buffer, Buffer, String, Int);
  //ex: crypto.generateHKDF2('sha256', sxy, expirationBuffer, '', 32);
  //impl
  ///// API that gets called by JS code to generate HKDF
  JS_METHOD(CryptoExtensionWrap2, GenerateHKDF2) {
    cout << "Insider GeneratateHKDF2" << endl;
    //check arguments and bail
    int len = args.Length();
    if (len != 5) THROW_TYPE_EXCEPTION("screwed up here...");
    if (!JS_IS_STRING(GET_ARG(0))) THROW_TYPE_EXCEPTION("hash type must be string");
    ASSERT_IS_BUFFER(GET_ARG(1));
    ASSERT_IS_BUFFER(GET_ARG(2));
    if (!JS_IS_STRING(GET_ARG(3))) THROW_TYPE_EXCEPTION("foo must be string");
    if (!JS_IS_UINT32(GET_ARG(4))) THROW_TYPE_EXCEPTION("size must be uint");

    uint8_t *out_key;
    uint8_t *secret;
    uint8_t *salt;
    uint8_t *info;

    //TODO: try to make dynamic lookup on 1st parm...
    const EVP_MD *(*md_func)(void) = EVP_sha256;
    const EVP_MD *digest = md_func();
    
    int rv = HKDF(out_key, 5, digest, secret, 5, salt, 5, info, 5);


    cout << "exiting .. GeneratateHKDF2" << endl;

   //RETURN_PARAM(hval);
  }
  JS_METHOD_END
}




int HKDF(uint8_t *out_key, size_t out_len,
  const EVP_MD *digest,
  const uint8_t *secret, size_t secret_len,
  const uint8_t *salt, size_t salt_len,
  const uint8_t *info, size_t info_len) {
  /* https://tools.ietf.org/html/rfc5869#section-2.2 */
  const size_t digest_len = EVP_MD_size(digest);
  uint8_t prk[EVP_MAX_MD_SIZE], previous[EVP_MAX_MD_SIZE];
  size_t n, done = 0;
  unsigned i, prk_len;
  int ret = 0;
  HMAC_CTX hmac;

  /* If salt is not given, HashLength zeros are used. However, HMAC does that
  * internally already so we can ignore it.*/

  /* Expand key material to desired length. */
  n = (out_len + digest_len - 1) / digest_len;
  if (out_len + digest_len < out_len || n > 255) {
    //OPENSSL_PUT_ERROR(HKDF, HKDF_R_OUTPUT_TOO_LARGE);
    return 0;
  }

  HMAC_CTX_init(&hmac);

  /* Extract input keying material into pseudorandom key |prk|. */
  if (HMAC(digest, salt, salt_len, secret, secret_len, prk, &prk_len) == NULL) {
    goto out;
  }
  assert(prk_len == digest_len);

  if (!HMAC_Init_ex(&hmac, prk, prk_len, digest, NULL)) {
    goto out;
  }

  for (i = 0; i < n; i++) {
    uint8_t ctr = i + 1;
    size_t todo;

    if (i != 0 && (!HMAC_Init_ex(&hmac, NULL, 0, NULL, NULL) ||
      !HMAC_Update(&hmac, previous, digest_len))) {
      goto out;
    }
    if (!HMAC_Update(&hmac, info, info_len) ||
      !HMAC_Update(&hmac, &ctr, 1) ||
      !HMAC_Final(&hmac, previous, NULL)) {
      goto out;
    }

    todo = digest_len;
    if (done + todo > out_len) {
      todo = out_len - done;
    }
    memcpy(out_key + done, previous, todo);
    done += todo;
  }

  ret = 1;

out:
  HMAC_CTX_cleanup(&hmac);
  if (ret != 1) {
    //OPENSSL_PUT_ERROR(HKDF, ERR_R_HMAC_LIB);
  }
  return ret;
}




NODE_MODULE(node_crypto_extension_wrap2, node::CryptoExtensionWrap2::Initialize)

