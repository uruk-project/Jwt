// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// The categories of algorithm.
    /// </summary>
    public enum AlgorithmCategory : sbyte
    {
        /// <summary>
        /// No category.
        /// </summary>
        None = 0,

        /// <summary>
        /// Elliptic curve algorithm.
        /// </summary>
        EllipticCurve,

        /// <summary>
        /// RSA algorithm.
        /// </summary>
        Rsa,

        /// <summary>
        /// AES algorithm
        /// </summary>
        Aes,

        /// <summary>
        /// HMAC algorithm
        /// </summary>
        Hmac
    }
}
