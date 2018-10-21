// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Constants for JsonWebAlgorithms  "kty" Key Type (sec 6.1)
    /// http://tools.ietf.org/html/rfc7518#section-6.1
    /// </summary>
    public static class JsonWebKeyTypeNames
    {
        public const string EllipticCurve = "EC";
        public const string Rsa = "RSA";
        public const string Octet = "oct";
    }
}
