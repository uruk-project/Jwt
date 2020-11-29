// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.ComponentModel;

namespace JsonWebToken
{
    public sealed partial class EncryptionAlgorithm
    {
#pragma warning disable CS8618 
        /// <summary>'A128CBC-HS256'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(A128CbcHS256) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly EncryptionAlgorithm Aes128CbcHmacSha256;

        /// <summary>'A192CBC-HS384'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(A192CbcHS384) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly EncryptionAlgorithm Aes192CbcHmacSha384;

        /// <summary>'A256CBC-HS512'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(A256CbcHS512) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly EncryptionAlgorithm Aes256CbcHmacSha512;

        /// <summary>'A128GCM'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(A128Gcm) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly EncryptionAlgorithm Aes128Gcm;

        /// <summary>'A192GCM'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(A192Gcm) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly EncryptionAlgorithm Aes192Gcm;

        /// <summary>'A256GCM'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(A256Gcm) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly EncryptionAlgorithm Aes256Gcm;
#pragma warning restore CS8618 
    }
}
