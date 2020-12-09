// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Names for Json Web Key parameters</summary>
    public static class JwkParameterNames
    {
        // commonly used fields
        /// <summary>The 'alg' JWK parameter.</summary>
        public static readonly JsonEncodedText Alg = JsonEncodedText.Encode("alg");

        /// <summary>The 'kid' JWK parameter.</summary>
        public static readonly JsonEncodedText Kid = JsonEncodedText.Encode("kid");

        /// <summary>The 'kty' JWK parameter.</summary>
        public static readonly JsonEncodedText Kty = JsonEncodedText.Encode("kty");

        /// <summary>The 'use' JWK parameter.</summary>
        public static readonly JsonEncodedText Use = JsonEncodedText.Encode("use");

        // less common fields
        /// <summary>The 'key_ops' JWK parameter.</summary>
        public static readonly JsonEncodedText KeyOps = JsonEncodedText.Encode("key_ops");

        /// <summary>The 'x5c' JWK parameter.</summary>
        public static readonly JsonEncodedText X5c = JsonEncodedText.Encode("x5c");

        /// <summary>The 'x5u' JWK parameter.</summary>
        public static readonly JsonEncodedText X5u = JsonEncodedText.Encode("x5u");

        /// <summary>The 'x5t' JWK parameter.</summary>
        public static readonly JsonEncodedText X5t = JsonEncodedText.Encode("x5t");

        /// <summary>The 'x5t#S256' JWK parameter.</summary>
        public static readonly JsonEncodedText X5tS256 = JsonEncodedText.Encode("x5t#S256");

        /// <summary>The 'oth' JWK parameter.</summary>
        public static readonly JsonEncodedText Oth = JsonEncodedText.Encode("oth");

        // Symmetric keys
        /// <summary>The 'k' JWK parameter.</summary>
        public static readonly JsonEncodedText K = JsonEncodedText.Encode("k");

        // Asymmetric keys
        /// <summary>The 'd' JWK parameter.</summary>
        public static readonly JsonEncodedText D = JsonEncodedText.Encode("d");

        // Elliptical curve keys
        /// <summary>The 'crv' JWK parameter.</summary>
        public static readonly JsonEncodedText Crv = JsonEncodedText.Encode("crv");

        /// <summary>The 'x' JWK parameter.</summary>
        public static readonly JsonEncodedText X = JsonEncodedText.Encode("x");

        /// <summary>The 'y' JWK parameter.</summary>
        public static readonly JsonEncodedText Y = JsonEncodedText.Encode("y");

        // RSA keys
        /// <summary>The 'e' JWK parameter.</summary>
        public static readonly JsonEncodedText E = JsonEncodedText.Encode("e");

        /// <summary>The 'n' JWK parameter.</summary>
        public static readonly JsonEncodedText N = JsonEncodedText.Encode("n");

        /// <summary>The 'p' JWK parameter.</summary>
        public static readonly JsonEncodedText P = JsonEncodedText.Encode("p");

        /// <summary>The 'q' JWK parameter.</summary>
        public static readonly JsonEncodedText Q = JsonEncodedText.Encode("q");

        /// <summary>The 'qi' JWK parameter.</summary>
        public static readonly JsonEncodedText QI = JsonEncodedText.Encode("qi");

        /// <summary>The 'dp' JWK parameter.</summary>
        public static readonly JsonEncodedText DP = JsonEncodedText.Encode("dp");

        /// <summary>The 'dq' JWK parameter.</summary>
        public static readonly JsonEncodedText DQ = JsonEncodedText.Encode("dq");

        /// <summary>The 'r' JWK parameter.</summary>
        public static readonly JsonEncodedText R = JsonEncodedText.Encode("r");

        /// <summary>The 't' JWK parameter.</summary>
        public static readonly JsonEncodedText T = JsonEncodedText.Encode("t");
    }
}
