// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken.Cryptography
{
    /// <summary>Defines the algorithms identifiers.</summary>
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
        HS256 = 5,

        /// <summary>
        /// 'HS384'
        /// https://tools.ietf.org/html/rfc8152#section-9.1
        /// </summary>
        HS384 = 6,

        /// <summary>
        /// 'HS512'
        /// https://tools.ietf.org/html/rfc8152#section-9.1
        /// </summary>
        HS512 = 7,

        /// <summary>
        /// 'RS256'
        /// https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-08#section-2
        /// </summary>
        RS256 = -257,

        /// <summary>
        /// 'RS384'
        /// https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-08#section-2
        /// </summary>
        RS384 = -258,

        /// <summary>
        /// 'RS512'
        /// https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-08#section-2
        /// </summary>
        RS512 = -259,

        /// <summary>
        /// 'ES256K'
        /// https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-05
        /// </summary>
        ES256K = -46,

        /// <summary>
        /// 'ES256'
        /// https://tools.ietf.org/html/rfc8152#section-8.1
        /// </summary>
        ES256 = -7,

        /// <summary>
        /// 'ES384'
        /// https://tools.ietf.org/html/rfc8152#section-8.1
        /// </summary>
        ES384 = -35,

        /// <summary>
        /// 'ES512'
        /// https://tools.ietf.org/html/rfc8152#section-8.1
        /// </summary>
        ES512 = -36,

        /// <summary>
        /// 'PS256'
        /// https://tools.ietf.org/html/rfc8230#section-2
        /// </summary>
        PS256 = -37,

        /// <summary>
        /// 'PS384'
        /// https://tools.ietf.org/html/rfc8230#section-2
        /// </summary>
        PS384 = -38,

        /// <summary>
        /// 'PS512'
        /// https://tools.ietf.org/html/rfc8230#section-2
        /// </summary>
        PS512 = -39,

        /// <summary>
        /// 'dir'
        /// https://tools.ietf.org/html/rfc8152#section-12.1.1
        /// </summary>
        Dir = -6,

        /// <summary>
        /// 'A128KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.2.1
        /// </summary>
        A128KW = -3,

        /// <summary>
        /// 'A192KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.2.1
        /// </summary>
        A192KW = -4,

        /// <summary>
        /// 'A256KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.2.1
        /// </summary>
        A256KW = -5,

        /// <summary>
        /// 'A128GCMKW'
        /// </summary>
        A128GcmKW = 1,

        /// <summary>
        /// 'A192GCMKW'
        /// </summary>
        A192GcmKW = 2,

        /// <summary>
        /// 'A256GCMKW'
        /// </summary>
        A256GcmKW = 3,

        /// <summary>
        /// 'RSA1_5'
        /// </summary>
        Rsa1_5 = -44, // Undefined in CWT

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
        EcdhEsA128KW = -29,

        /// <summary>
        /// 'ECDH-ES+A192KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.5.1
        /// </summary>
        EcdhEsA192KW = -30,

        /// <summary>
        /// 'ECDH-ES+A256KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.5.1
        /// </summary>
        EcdhEsA256KW = -31,

        /// <summary>
        /// A128CBC-HS256
        /// https://tools.ietf.org/html/rfc8152#section-9.2
        /// </summary>
        A128CbcHS256 = 14,

        /// <summary>
        /// A192CBC-HS384
        /// https://tools.ietf.org/html/rfc8152#section-9.2
        /// </summary>
        A192CbcHS384 = 16,

        /// <summary>
        /// A256CBC-HS512
        /// https://tools.ietf.org/html/rfc8152#section-9.2
        /// </summary>
        A256CbcHS512 = 15,

        /// <summary>
        /// A128GCM
        /// https://tools.ietf.org/html/rfc8152#section-10.1
        /// </summary>
        A128Gcm = 1,

        /// <summary>
        /// A192GCM
        /// https://tools.ietf.org/html/rfc8152#section-10.1
        /// </summary>
        A192Gcm = 2,

        /// <summary>
        /// A256GCM
        /// https://tools.ietf.org/html/rfc8152#section-10.1
        /// </summary>
        A256Gcm = 3,

        /// <summary>
        /// PBES2-HS256+A128KW
        /// https://tools.ietf.org/html/rfc8152#section-10.1
        /// </summary>
        Pbes2HS256A128KW = -10,

        /// <summary>
        /// A192GCM
        /// https://tools.ietf.org/html/rfc8152#section-10.1
        /// </summary>
        Pbes2HS384A192KW = -12,

        /// <summary>
        /// A256GCM
        /// https://tools.ietf.org/html/rfc8152#section-10.1
        /// </summary>
        Pbes2HS512A256KW = -11
    }
}