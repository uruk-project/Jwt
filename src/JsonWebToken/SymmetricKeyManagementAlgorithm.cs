// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Defines Symmetric-key management algorithm.</summary>
    public sealed class SymmetricKeyManagementAlgorithm : KeyManagementAlgorithm
    {
        /// <summary>Initializes a new instance of <see cref="SymmetricKeyManagementAlgorithm"/>. </summary>
        public SymmetricKeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType, ushort requiredKeySizeInBits)
            : base(id, name, keyType, requiredKeySizeInBits)
        {
        }

        /// <summary>Initializes a new instance of <see cref="SymmetricKeyManagementAlgorithm"/>. </summary>
        public SymmetricKeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType, bool produceEncryptedKey)
            : base(id, name, keyType, produceEncryptedKey)
        {
        }

        /// <summary>Initializes a new instance of <see cref="SymmetricKeyManagementAlgorithm"/>. </summary>
        public SymmetricKeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType, KeyManagementAlgorithm wrappedAlgorithm, Sha2 sha2)
            : base(id, name, keyType, wrappedAlgorithm, sha2)
        {
        }
    }
}
