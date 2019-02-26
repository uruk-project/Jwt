// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a key used by the <see cref="CryptographicStore{TCrypto}"/>.
    /// </summary>
    public readonly struct CryptographicFactoryKey
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
            if (!(obj is CryptographicFactoryKey))
            {
                return false;
            }

            var key = (CryptographicFactoryKey)obj;
            return EqualityComparer<Jwk>.Default.Equals(Key, key.Key) &&
                   Algorithm == key.Algorithm;
        }

        /// <inheritsdoc />
        public override int GetHashCode()
        {
            var hashCode = -733196298;
            hashCode = hashCode * -1521134295 + EqualityComparer<Jwk>.Default.GetHashCode(Key);
            hashCode = hashCode * -1521134295 + Algorithm.GetHashCode();
            return hashCode;
        }
    }
}