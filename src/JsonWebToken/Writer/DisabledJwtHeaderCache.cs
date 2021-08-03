// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace JsonWebToken
{
    internal sealed class DisabledJwtHeaderCache : IJwtHeaderCache
    {
        public void AddHeader(JwtHeader header, SignatureAlgorithm alg, JsonEncodedText kid, string? typ, ReadOnlySpan<byte> base6UrlHeader)
        {
        }

        public void AddHeader(JwtHeader header, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, JsonEncodedText kid, string? typ, string? cty, ReadOnlySpan<byte> base6UrlHeader)
        {
        }

        public bool TryGetHeader(JwtHeader header, SignatureAlgorithm alg, JsonEncodedText kid, string? typ, [NotNullWhen(true)] out byte[]? base64UrlHeader)
        {
#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out base64UrlHeader);
#else
            base64UrlHeader = default;
#endif
            return false;
        }

        public bool TryGetHeader(JwtHeader header, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, JsonEncodedText kid, string? typ, string? cty, [NotNullWhen(true)] out byte[]? base64UrlHeader)
        {
#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out base64UrlHeader);
#else
            base64UrlHeader = default;
#endif
            return false;
        }
    }
}
