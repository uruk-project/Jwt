// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken
{
    internal class DisabledJwtHeaderCache : IJwtHeaderCache
    {
        public void AddHeader(JwtHeader header, SignatureAlgorithm alg, string? kid, string? typ, ReadOnlySpan<byte> base6UrlHeader)
        {
        }

        public bool TryGetHeader(JwtHeader header, SignatureAlgorithm alg, string? kid, string? typ, [NotNullWhen(true)] out byte[]? base64UrlHeader)
        {
            base64UrlHeader = null;
            return false;
        }
    }
}
