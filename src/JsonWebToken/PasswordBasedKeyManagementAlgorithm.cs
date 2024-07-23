// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Defines password-based key management algorithm.</summary>
    public sealed class PasswordBasedKeyManagementAlgorithm : KeyManagementAlgorithm
    {
        /// <summary>Initializes a new instance of <see cref="PasswordBasedKeyManagementAlgorithm"/>. </summary>
        public PasswordBasedKeyManagementAlgorithm(AlgorithmId id, string name, AlgorithmCategory keyType, KeyManagementAlgorithm wrappedAlgorithm, Sha2 sha2)
            : base(id, name, keyType, wrappedAlgorithm, sha2)
        {
        }
    }
}
