// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a <see cref="KeyWrapper"/> factory.
    /// </summary>
    public interface IKeyWrapperFactory : IDisposable
    {
        KeyWrapper Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm);
    }
}