// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a key used by the <see cref="CryptographicStore{TCrypto}"/>.
    /// </summary>
    public readonly struct CryptographicFactoryKey : IEquatable<CryptographicFactoryKey>
    {
        /// <summary>
        /// The <see cref="Jwk"/>.
        /// </summary>
        public readonly Jwk Key;
        
        /// <summary>
        /// The algorithm.
        /// </summary>
        public readonly int Algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicFactoryKey"/> class.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="algorithm"></param>
        public CryptographicFactoryKey(Jwk key, int algorithm)
        {
            if (key == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.key);
            }

            Key = key;
            Algorithm = algorithm;
        }

        /// <inheritsdoc />
        public override bool Equals(object obj)
        {
            if (obj is CryptographicFactoryKey key)
            {
                return Algorithm == key.Algorithm && Key.Equals(key.Key);
            }

            return false;
        }

        /// <inheritsdoc />
        public bool Equals(CryptographicFactoryKey other)
        {
            return Algorithm == other.Algorithm && Key.Equals(other.Key);
        }

        /// <inheritsdoc />
        public override int GetHashCode()
        {
            var hashCode = -733196298;
            hashCode = hashCode * -1521134295 + Key.GetHashCode();
            hashCode = hashCode * -1521134295 + Algorithm;
            return hashCode;
        }
    }
}