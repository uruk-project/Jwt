// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Defines RSA key management algorithm.</summary>
    public sealed class RsaKeyManagementAlgorithm : KeyManagementAlgorithm
    {
        /// <summary>Initializes a new instance of <see cref="RsaKeyManagementAlgorithm"/>. </summary>
        public RsaKeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits) 
            : base(id, name, keyType, requiredKeySizeInBits)
        {
        }
    }
}
