// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.ComponentModel;

namespace JsonWebToken
{
    public sealed partial class KeyManagementAlgorithm
    {
#pragma warning disable CS8618 
        /// <summary>'dir'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(Dir) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly KeyManagementAlgorithm Direct;

        /// <summary>'A128KW'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(A128KW) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly KeyManagementAlgorithm Aes128KW;

        /// <summary>'A192KW'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(A192KW) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly KeyManagementAlgorithm Aes192KW;

        /// <summary>'A256KW'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(A256KW) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly KeyManagementAlgorithm Aes256KW;

        /// <summary>'A128GCMKW'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(A128GcmKW) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly KeyManagementAlgorithm Aes128GcmKW;

        /// <summary>'A192GCMKW'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(A192GcmKW) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly KeyManagementAlgorithm Aes192GcmKW;

        /// <summary>'A256GCMKW'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(A256GcmKW) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly KeyManagementAlgorithm Aes256GcmKW;

        /// <summary>'RSA1_5'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(Rsa1_5) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly KeyManagementAlgorithm RsaPkcs1;

        /// <summary>'ECDH-ES+A128KW'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(EcdhEsA128KW) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly KeyManagementAlgorithm EcdhEsAes128KW;

        /// <summary>'ECDH-ES+A192KW'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(EcdhEsA192KW) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly KeyManagementAlgorithm EcdhEsAes192KW;

        /// <summary>'ECDH-ES+A256KW'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(EcdhEsA256KW) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly KeyManagementAlgorithm EcdhEsAes256KW;
#pragma warning restore CS8618 
    }
}
