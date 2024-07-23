// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Security.Cryptography;
using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Define an Elliptical Curve signature algorithm.</summary>
    public sealed class ECSignatureAlgorithm : SignatureAlgorithm
    {
        /// <summary>Initializes a new instance of <see cref="ECSignatureAlgorithm"/>. </summary>
        public ECSignatureAlgorithm(AlgorithmId id, string name, AlgorithmCategory category, ushort requiredKeySizeInBits, HashAlgorithmName hashAlgorithm) : base(id, name, category, requiredKeySizeInBits, hashAlgorithm)
        {
        }
    }
}
