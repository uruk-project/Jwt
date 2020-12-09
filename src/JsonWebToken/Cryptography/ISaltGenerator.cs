// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken.Cryptography
{
    /// <summary>Represents a salt generator for cryptographic operation</summary>
    public interface ISaltGenerator
    {
        /// <summary>Generates a salt.</summary>
        void Generate(Span<byte> salt);
    }
}
