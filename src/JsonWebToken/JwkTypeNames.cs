// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Constants for JsonWebAlgorithms  "kty" Key Type (sec 6.1)
    /// http://tools.ietf.org/html/rfc7518#section-6.1
    /// </summary>
    public static class JwkTypeNames
    {
        /// <summary>Elliptic curve 'EC'.</summary>
        public static readonly JsonEncodedText EllipticCurve = JsonEncodedText.Encode("EC");

        /// <summary>RSA 'RSA'.</summary>
        public static readonly JsonEncodedText Rsa = JsonEncodedText.Encode("RSA");

        /// <summary>Octet 'oct'.</summary>
        public static readonly JsonEncodedText Octet = JsonEncodedText.Encode("oct");

        /// <summary>Gets all the well-known 'kty'.</summary>
        public static JsonEncodedText[] All => new[] { Octet, EllipticCurve, Rsa };
    }
}
