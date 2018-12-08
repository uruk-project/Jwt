// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Constants for JsonWebKey Elliptical Curve Types
    /// https://tools.ietf.org/html/rfc7518#section-6.2.1.1
    /// </summary>
    public static class EllipticalCurves
    {
        /// <summary>
        /// 'P-256'.
        /// </summary>
        public const string P256 = "P-256";

        /// <summary>
        /// 'P-384'.
        /// </summary>
        public const string P384 = "P-384";

        /// <summary>
        /// 'P-521'.
        /// </summary>
        public const string P521 = "P-521";
    }
}
