// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// The categories of algorithm.
    /// </summary>
    [Flags]
    public enum AlgorithmCategory : sbyte
    {
        /// <summary>
        /// No category.
        /// </summary>
        None = 0,

        /// <summary>
        /// Elliptic curve algorithm.
        /// </summary>
        EllipticCurve = 0x1,

        /// <summary>
        /// RSA algorithm.
        /// </summary>
        Rsa = 0x2,

        /// <summary>
        /// AES algorithm
        /// </summary>
        Aes = 0x3,

        /// <summary>
        /// AES-GCM algorithm
        /// </summary>
        AesGcm = Aes | 0x10,

        /// <summary>
        /// HMAC algorithm
        /// </summary>
        Hmac = 0x4
    }
}
