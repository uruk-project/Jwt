// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    internal static class Algorithm
    {
        /// <summary>
        /// 'none'
        /// </summary>
        public const int None = 0;

        /// <summary>
        /// 'HS256'
        /// </summary>
        public const int HmacSha256 = 5;

        /// <summary>
        /// 'HS384'
        /// </summary>
        public const int HmacSha384 = 6;

        /// <summary>
        /// 'HS512'
        /// </summary>
        public const int HmacSha512 = 7;

        /// <summary>
        /// 'RS256'
        /// </summary>
        public const int RsaSha256 = -257;

        /// <summary>
        /// 'RS384'
        /// </summary>
        public const int RsaSha384 = -258;

        /// <summary>
        /// 'RS512'
        /// </summary>
        public const int RsaSha512 = -259;

        /// <summary>
        /// 'ES256'
        /// </summary>
        public const int EcdsaSha256 = -7;

        /// <summary>
        /// 'ES384'
        /// </summary>
        public const int EcdsaSha384 = -35;

        /// <summary>
        /// 'ES512'
        /// </summary>
        public const int EcdsaSha512 = -36;

        /// <summary>
        /// 'PS256'
        /// </summary>
        public const int RsaSsaPssSha256 = -37;

        /// <summary>
        /// 'PS384'
        /// </summary>
        public const int RsaSsaPssSha384 = -38;

        /// <summary>
        /// 'PS512'
        /// </summary>
        public const int RsaSsaPssSha512 = -39;

        /// <summary>
        /// 'dir'
        /// </summary>
        public const int Direct = -6;

        /// <summary>
        /// 'A128KW'
        /// </summary>
        public const int Aes128KW = -3;

        /// <summary>
        /// 'A192KW'
        /// </summary>
        public const int Aes192KW = -4;

        /// <summary>
        /// 'A256KW'
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
        /// </summary>
        public const int RsaOaep = -40;

        /// <summary>
        /// 'RSA-OAEP-256'
        /// </summary>
        public const int RsaOaep256 = -41;

        /// <summary>
        /// 'RSA-OAEP-512'
        /// </summary>
        public const int RsaOaep512 = -42;

        /// <summary>
        /// 'ECDH-ES'
        /// </summary>
        public const int EcdhEs = -24; // Undefined in CWT

        /// <summary>
        /// 'ECDH-ES+A128KW'
        /// </summary>
        public const int EcdhEsAes128KW = -29;

        /// <summary>
        /// 'ECDH-ES+A192KW'
        /// </summary>
        public const int EcdhEsAes192KW = -30;

        /// <summary>
        /// 'ECDH-ES+A256KW'
        /// </summary>
        public const int EcdhEsAes256KW = -31;
    }
}