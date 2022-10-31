/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/sm4.h"
#include "prov/ciphercommon.h"
#include "crypto/sm4_platform.h"


typedef struct prov_sm4_xts_ctx_st {
    PROV_PCIPHER_CTX base;      /* Must be first */
    union {
        OSSL_UNION_ALIGN;
        SM4_KEY ks;
    } ks1, ks2;                /* SM4 key schedules to use */
    XTS128_CONTEXT xts;
    int std;
    OSSL_xts_stream_fn stream;
    OSSL_xts_stream_fn stream_gb;
} PROV_SM4_XTS_CTX;

const PROV_CIPHER_HW *ossl_prov_cipher_hw_sm4_xts(size_t keybits);
