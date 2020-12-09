// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.ComponentModel;

namespace JsonWebToken
{
    public sealed partial class CompressionAlgorithm
    {
#pragma warning disable CS8618 
        /// <summary>Deflate</summary>
        [Obsolete("This property is obsolete. Use property " + nameof(Def) + " instead.", error: true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static readonly CompressionAlgorithm Deflate;
#pragma warning restore CS8618 
    }
}
