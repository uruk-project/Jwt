// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a <see cref="Signer"/> factory.
    /// </summary>
    public interface ISignerFactory : IDisposable
    {
        /// <summary>
        /// Creates a <see cref="Signer"/>.
        /// </summary>
        /// <param name="key">The key used for signature.</param>
        /// <param name="algorithm">The signature algorithm.</param>
        /// <param name="willCreateSignatures"><c>true</c> if the <see cref="Signer"/> is used for creating signatures. <c>false</c> if the <see cref="Signer"/> is used for validating signatures.</param>
        /// <returns></returns>
        Signer Create(JsonWebKey key, SignatureAlgorithm algorithm, bool willCreateSignatures);
    }
}