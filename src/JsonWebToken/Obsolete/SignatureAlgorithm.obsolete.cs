// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.ComponentModel;

namespace JsonWebToken
{
    public partial class SignatureAlgorithm
    {
#pragma warning disable CS8618 
        /// <summary>'HS256'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(HS256) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm HmacSha256;

        /// <summary>'HS384'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(HS384) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm HmacSha384;

        /// <summary>'HS512'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(HS512) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm HmacSha512;

        /// <summary>'RS256'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(RS256) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm RsaSha256;

        /// <summary>'RS384'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(RS384) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm RsaSha384;

        /// <summary>'RS512'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(RS512) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm RsaSha512;

        /// <summary>'ES256K'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(ES256K) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm EcdsaSha256X;

        /// <summary>'ES256'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(ES256) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm EcdsaSha256;

        /// <summary>'ES384'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(ES384) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm EcdsaSha384;

        /// <summary>'ES512'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(ES512) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm EcdsaSha512;

        /// <summary>'PS256'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(PS256) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm RsaSsaPssSha256;

        /// <summary>'PS384'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(PS384) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm RsaSsaPssSha384;

        /// <summary>'PS512'</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(PS512) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly SignatureAlgorithm RsaSsaPssSha512;
#pragma warning restore CS8618 
    }
}
