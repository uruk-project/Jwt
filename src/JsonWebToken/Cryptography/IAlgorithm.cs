// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Text.Json;

namespace JsonWebToken.Cryptography
{
    /// <summary>
    /// Represents a cyrptographic algorithm.
    /// </summary>
    public interface IAlgorithm
    {
        /// <summary>
        /// Gets the UTF8 byte array of the name of the algorithm.
        /// </summary>
        public ReadOnlySpan<byte> Utf8Name { get; }

        /// <summary>
        /// Gets the name of the algorithm.
        /// </summary>
        public JsonEncodedText Name { get; }
    }
}