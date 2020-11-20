// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines the algorithms identifiers.
    /// </summary>
    public enum AlgorithmId : short
    {
        /// <summary>undefined</summary>
         Undefined = -1,
         
        /// <summary>
        /// 'none'
        /// </summary>
         None = 0,

        /// <summary>
        /// 'HS256'
        /// https://tools.ietf.org/html/rfc8152#section-9.1
        /// </summary>
         HmacSha256 = 5,

        /// <summary>
        /// 'HS384'
        /// https://tools.ietf.org/html/rfc8152#section-9.1
        /// </summary>
         HmacSha384 = 6,

        /// <summary>
        /// 'HS512'
        /// https://tools.ietf.org/html/rfc8152#section-9.1
        /// </summary>
         HmacSha512 = 7,

        /// <summary>
        /// 'RS256'
        /// https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-08#section-2
        /// </summary>
         RsaSha256 = -257,

        /// <summary>
        /// 'RS384'
        /// https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-08#section-2
        /// </summary>
         RsaSha384 = -258,

        /// <summary>
        /// 'RS512'
        /// https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-08#section-2
        /// </summary>
         RsaSha512 = -259,

        /// <summary>
        /// 'ES256X'
        /// https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-05
        /// </summary>
         EcdsaSha256X = -46,

        /// <summary>
        /// 'ES256'
        /// https://tools.ietf.org/html/rfc8152#section-8.1
        /// </summary>
         EcdsaSha256 = -7,

        /// <summary>
        /// 'ES384'
        /// https://tools.ietf.org/html/rfc8152#section-8.1
        /// </summary>
         EcdsaSha384 = -35,

        /// <summary>
        /// 'ES512'
        /// https://tools.ietf.org/html/rfc8152#section-8.1
        /// </summary>
         EcdsaSha512 = -36,

        /// <summary>
        /// 'PS256'
        /// https://tools.ietf.org/html/rfc8230#section-2
        /// </summary>
         RsaSsaPssSha256 = -37,

        /// <summary>
        /// 'PS384'
        /// https://tools.ietf.org/html/rfc8230#section-2
        /// </summary>
         RsaSsaPssSha384 = -38,

        /// <summary>
        /// 'PS512'
        /// https://tools.ietf.org/html/rfc8230#section-2
        /// </summary>
         RsaSsaPssSha512 = -39,

        /// <summary>
        /// 'dir'
        /// https://tools.ietf.org/html/rfc8152#section-12.1.1
        /// </summary>
         Direct = -6,

        /// <summary>
        /// 'A128KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.2.1
        /// </summary>
         Aes128KW = -3,

        /// <summary>
        /// 'A192KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.2.1
        /// </summary>
         Aes192KW = -4,

        /// <summary>
        /// 'A256KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.2.1
        /// </summary>
         Aes256KW = -5,

        /// <summary>
        /// 'A128GCMKW'
        /// </summary>
         Aes128GcmKW = 1,

        /// <summary>
        /// 'A192GCMKW'
        /// </summary>
         Aes192GcmKW = 2,

        /// <summary>
        /// 'A256GCMKW'
        /// </summary>
         Aes256GcmKW = 3,

        /// <summary>
        /// 'RSA1_5'
        /// </summary>
         RsaPkcs1 = -44, // Undefined in CWT

        /// <summary>
        /// 'RSA-OAEP'
        /// https://tools.ietf.org/html/rfc8230#section-3
        /// </summary>
         RsaOaep = -40,

        /// <summary>
        /// 'RSA-OAEP-256'
        /// https://tools.ietf.org/html/rfc8230#section-3
        /// </summary>
         RsaOaep256 = -41,

        /// <summary>
        /// 'RSA-OAEP-256'
        /// https://tools.ietf.org/html/rfc8230#section-3
        /// </summary>
         RsaOaep384 = -43,

        /// <summary>
        /// 'RSA-OAEP-512'
        /// https://tools.ietf.org/html/rfc8230#section-3
        /// </summary>
         RsaOaep512 = -42,

        /// <summary>
        /// 'ECDH-ES'
        /// </summary>
         EcdhEs = -32768 + 29, // Undefined in CWT

        /// <summary>
        /// 'ECDH-ES+A128KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.5.1
        /// </summary>
         EcdhEsAes128KW = -29,

        /// <summary>
        /// 'ECDH-ES+A192KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.5.1
        /// </summary>
         EcdhEsAes192KW = -30,

        /// <summary>
        /// 'ECDH-ES+A256KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.5.1
        /// </summary>
         EcdhEsAes256KW = -31,

        /// <summary>
        /// A128CBC-HS256
        /// https://tools.ietf.org/html/rfc8152#section-9.2
        /// </summary>
         AesCbc128HS256 = 14,

        /// <summary>
        /// A192CBC-HS384
        /// https://tools.ietf.org/html/rfc8152#section-9.2
        /// </summary>
         AesCbc192HS384 = 16,

        /// <summary>
        /// A256CBC-HS512
        /// https://tools.ietf.org/html/rfc8152#section-9.2
        /// </summary>
         AesCbc256HS512 = 15,

        /// <summary>
        /// A128GCM
        /// https://tools.ietf.org/html/rfc8152#section-10.1
        /// </summary>
         Aes128Gcm = 1,

        /// <summary>
        /// A192GCM
        /// https://tools.ietf.org/html/rfc8152#section-10.1
        /// </summary>
         Aes192Gcm = 2,

        /// <summary>
        /// A256GCM
        /// https://tools.ietf.org/html/rfc8152#section-10.1
        /// </summary>
         Aes256Gcm = 3
    }
}