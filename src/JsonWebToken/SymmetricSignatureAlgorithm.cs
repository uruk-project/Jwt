﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Security.Cryptography;
using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Defines a symmetric signature algorithm.</summary>
    public sealed class SymmetricSignatureAlgorithm : SignatureAlgorithm
    {
        /// <summary>Initializes a new instance of <see cref="SymmetricSignatureAlgorithm"/>. </summary>
        public SymmetricSignatureAlgorithm(AlgorithmId id, string name, AlgorithmCategory category, ushort requiredKeySizeInBits, HashAlgorithmName hashAlgorithm) : base(id, name, category, requiredKeySizeInBits, hashAlgorithm)
        {
        }
    }
}