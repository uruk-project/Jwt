// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken
{
    /// <summary>Represents a cache for <see cref="JwtHeader"/> in JSON.</summary>
    public interface IJwtHeaderCache
    {
        /// <summary>Adds a base64-url encoded header to the cache.</summary>
        /// <param name="header"></param>
        /// <param name="alg"></param>
        /// <param name="kid"></param>
        /// <param name="typ"></param>
        /// <param name="base6UrlHeader"></param>
        void AddHeader(JwtHeader header, SignatureAlgorithm alg, string? kid, string? typ, ReadOnlySpan<byte> base6UrlHeader);

        /// <summary>Try to get the header.</summary>
        /// <param name="header"></param>
        /// <param name="alg"></param>
        /// <param name="kid"></param>
        /// <param name="typ"></param>
        /// <param name="base64UrlHeader"></param>
        /// <returns></returns>
        bool TryGetHeader(JwtHeader header, SignatureAlgorithm alg, string? kid, string? typ, [NotNullWhen(true)] out byte[]? base64UrlHeader);
    }
}   