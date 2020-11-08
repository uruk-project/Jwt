// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a cache for <see cref="JwtHeaderDocument"/>.
    /// </summary>
    public interface IJwtHeaderCache
    {
        /// <summary>
        /// Gets or sets whether the cache is enabled.
        /// </summary>
        bool Enabled { get; }

        /// <summary>
        /// Adds the <see cref="JwtHeader"/> to the cache.
        /// </summary>
        /// <param name="rawHeader"></param>
        /// <param name="header"></param>
        void AddHeader(ReadOnlySpan<byte> rawHeader, JwtHeaderDocument header);
        
        /// <summary>
        /// Try to get the <see cref="JwtHeader"/>.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="header"></param>
        /// <returns></returns>
        bool TryGetHeader(ReadOnlySpan<byte> buffer, [NotNullWhen(true)] out JwtHeaderDocument? header);
    }
}