// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    public readonly struct CryptographicFactoryKey
    {
        public readonly Jwk Key;

        public readonly int Algorithm;

        public CryptographicFactoryKey(Jwk key, int algorithm)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            Algorithm = algorithm;
        }
    }
}