// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken
{
    public interface IJwtHeaderCache
    {
        bool Enabled { get; }

        void AddHeader(ReadOnlySpan<byte> rawHeader, IJwtHeader header);
        bool TryGetHeader(ReadOnlySpan<byte> buffer, [NotNullWhen(true)] out IJwtHeader? header);
    }
}