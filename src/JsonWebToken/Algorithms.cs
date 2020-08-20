// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    internal static class Algorithms
    {
        /// <summary>
        /// 'none'
        /// </summary>
        public const int None = 0;

        /// <summary>
        /// 'HS256'
        /// https://tools.ietf.org/html/rfc8152#section-9.1
        /// </summary>
        public const int HmacSha256 = 5;

        /// <summary>
        /// 'HS384'
        /// https://tools.ietf.org/html/rfc8152#section-9.1
        /// </summary>
        public const int HmacSha384 = 6;

        /// <summary>
        /// 'HS512'
        /// https://tools.ietf.org/html/rfc8152#section-9.1
        /// </summary>
        public const int HmacSha512 = 7;

        /// <summary>
        /// 'RS256'
        /// https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-08#section-2
        /// </summary>
        public const int RsaSha256 = -257;

        /// <summary>
        /// 'RS384'
        /// https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-08#section-2
        /// </summary>
        public const int RsaSha384 = -258;

        /// <summary>
        /// 'RS512'
        /// https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-08#section-2
        /// </summary>
        public const int RsaSha512 = -259;

        /// <summary>
        /// 'ES256'
        /// https://tools.ietf.org/html/rfc8152#section-8.1
        /// </summary>
        public const int EcdsaSha256 = -7;

        /// <summary>
        /// 'ES384'
        /// https://tools.ietf.org/html/rfc8152#section-8.1
        /// </summary>
        public const int EcdsaSha384 = -35;

        /// <summary>
        /// 'ES512'
        /// https://tools.ietf.org/html/rfc8152#section-8.1
        /// </summary>
        public const int EcdsaSha512 = -36;

        /// <summary>
        /// 'PS256'
        /// https://tools.ietf.org/html/rfc8230#section-2
        /// </summary>
        public const int RsaSsaPssSha256 = -37;

        /// <summary>
        /// 'PS384'
        /// https://tools.ietf.org/html/rfc8230#section-2
        /// </summary>
        public const int RsaSsaPssSha384 = -38;

        /// <summary>
        /// 'PS512'
        /// https://tools.ietf.org/html/rfc8230#section-2
        /// </summary>
        public const int RsaSsaPssSha512 = -39;

        /// <summary>
        /// 'dir'
        /// https://tools.ietf.org/html/rfc8152#section-12.1.1
        /// </summary>
        public const int Direct = -6;

        /// <summary>
        /// 'A128KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.2.1
        /// </summary>
        public const int Aes128KW = -3;

        /// <summary>
        /// 'A192KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.2.1
        /// </summary>
        public const int Aes192KW = -4;

        /// <summary>
        /// 'A256KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.2.1
        /// </summary>
        public const int Aes256KW = -5;

        /// <summary>
        /// 'A128GCMKW'
        /// </summary>
        public const int Aes128GcmKW = 1;

        /// <summary>
        /// 'A192GCMKW'
        /// </summary>
        public const int Aes192GcmKW = 2;

        /// <summary>
        /// 'A256GCMKW'
        /// </summary>
        public const int Aes256GcmKW = 3;

        /// <summary>
        /// 'RSA1_5'
        /// </summary>
        public const int RsaPkcs1 = -65535;

        /// <summary>
        /// 'RSA-OAEP'
        /// https://tools.ietf.org/html/rfc8230#section-3
        /// </summary>
        public const int RsaOaep = -40;

        /// <summary>
        /// 'RSA-OAEP-256'
        /// https://tools.ietf.org/html/rfc8230#section-3
        /// </summary>
        public const int RsaOaep256 = -41;

        /// <summary>
        /// 'RSA-OAEP-256'
        /// https://tools.ietf.org/html/rfc8230#section-3
        /// </summary>
        public const int RsaOaep384 = -65535 + 40;

        /// <summary>
        /// 'RSA-OAEP-512'
        /// https://tools.ietf.org/html/rfc8230#section-3
        /// </summary>
        public const int RsaOaep512 = -42;

        /// <summary>
        /// 'ECDH-ES'
        /// </summary>
        public const int EcdhEs = -65535 + 29; // Undefined in CWT

        /// <summary>
        /// 'ECDH-ES+A128KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.5.1
        /// </summary>
        public const int EcdhEsAes128KW = -29;

        /// <summary>
        /// 'ECDH-ES+A192KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.5.1
        /// </summary>
        public const int EcdhEsAes192KW = -30;

        /// <summary>
        /// 'ECDH-ES+A256KW'
        /// https://tools.ietf.org/html/rfc8152#section-12.5.1
        /// </summary>
        public const int EcdhEsAes256KW = -31;

        /// <summary>
        /// A128CBC-HS256
        /// https://tools.ietf.org/html/rfc8152#section-9.2
        /// </summary>
        public const sbyte AesCbc128HS256 = 14;

        /// <summary>
        /// A192CBC-HS384
        /// https://tools.ietf.org/html/rfc8152#section-9.2
        /// </summary>
        public const sbyte AesCbc192HS384 = 16;

        /// <summary>
        /// A256CBC-HS512
        /// https://tools.ietf.org/html/rfc8152#section-9.2
        /// </summary>
        public const sbyte AesCbc256HS512 = 15;

        /// <summary>
        /// A128GCM
        /// https://tools.ietf.org/html/rfc8152#section-10.1
        /// </summary>
        public const sbyte Aes128Gcm = 1;

        /// <summary>
        /// A192GCM
        /// https://tools.ietf.org/html/rfc8152#section-10.1
        /// </summary>
        public const sbyte Aes192Gcm = 2;

        /// <summary>
        /// A256GCM
        /// https://tools.ietf.org/html/rfc8152#section-10.1
        /// </summary>
        public const sbyte Aes256Gcm = 3;
    }
}