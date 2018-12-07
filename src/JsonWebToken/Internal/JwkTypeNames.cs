// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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
        public const string EllipticCurve = "EC";

        /// <summary>
        /// RSA 'RSA'.
        /// </summary>
        public const string Rsa = "RSA";

        /// <summary>
        /// Octet 'oct';
        /// </summary>
        public const string Octet = "oct";
    }
}
