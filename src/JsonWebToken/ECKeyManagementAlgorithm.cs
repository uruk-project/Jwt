// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Defines Elliptical Curve key management algorithm.</summary>
    public sealed class ECKeyManagementAlgorithm : KeyManagementAlgorithm
    {
        /// <summary>Initializes a new instance of <see cref="ECKeyManagementAlgorithm"/>. </summary>
        public ECKeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType, KeyManagementAlgorithm wrappedAlgorithm) 
            : base(id, name, keyType, wrappedAlgorithm)
        {
        }

        /// <summary>Initializes a new instance of <see cref="ECKeyManagementAlgorithm"/>. </summary>
        public ECKeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType, bool produceEncryptedKey) 
            : base(id, name, keyType, produceEncryptedKey)
        {
        }
    }
}
