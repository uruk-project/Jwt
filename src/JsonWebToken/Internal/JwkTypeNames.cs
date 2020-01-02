// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Constants for JsonWebAlgorithms  "kty" Key Type (sec 6.1)
    /// http://tools.ietf.org/html/rfc7518#section-6.1
    /// </summary>
    public static class JwkTypeNames
    {
        /// <summary>
        /// Elliptic curve 'EC'.
        /// </summary>
        public static ReadOnlySpan<byte> EllipticCurve => new byte[] { (byte)'E', (byte)'C' };

        /// <summary>
        /// RSA 'RSA'.
        /// </summary>
        public static ReadOnlySpan<byte> Rsa => new byte[] { (byte)'R', (byte)'S', (byte)'A' };

        /// <summary>
        /// Octet 'oct';
        /// </summary>
        public static ReadOnlySpan<byte> Octet => new byte[] { (byte)'o', (byte)'c', (byte)'t' };
    }
}
