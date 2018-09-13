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
        Signer Create(JsonWebKey key, SignatureAlgorithm algorithm, bool willCreateSignatures);
    }
}