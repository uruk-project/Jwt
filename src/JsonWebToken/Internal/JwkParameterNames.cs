// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Names for Json Web Key Values
    /// </summary>
    internal static class JwkParameterNames
    {
        // commonly used fields
        public static readonly JsonEncodedText Alg = JsonEncodedText.Encode("alg");
        public static readonly JsonEncodedText Kid = JsonEncodedText.Encode("kid");
        public static readonly JsonEncodedText Kty = JsonEncodedText.Encode("kty");
        public static readonly JsonEncodedText Use = JsonEncodedText.Encode("use");
        
        // less common fields
        public static readonly JsonEncodedText KeyOps = JsonEncodedText.Encode("key_ops");
        public static readonly JsonEncodedText X5c = JsonEncodedText.Encode("x5c");
        public static readonly JsonEncodedText X5u = JsonEncodedText.Encode("x5u");
        public static readonly JsonEncodedText X5t = JsonEncodedText.Encode("x5t");
        public static readonly JsonEncodedText X5tS256 = JsonEncodedText.Encode("x5t#S256");
        public static readonly JsonEncodedText Oth = JsonEncodedText.Encode("oth");

        // Symmetric keys
        public static readonly JsonEncodedText K = JsonEncodedText.Encode("k");

        // Asymmetric keys
        public static readonly JsonEncodedText D = JsonEncodedText.Encode("d");

        // Elliptical curve keys
        public static readonly JsonEncodedText Crv = JsonEncodedText.Encode("crv");
        public static readonly JsonEncodedText X = JsonEncodedText.Encode("x");
        public static readonly JsonEncodedText Y = JsonEncodedText.Encode("y");

        // RSA keys
        public static readonly JsonEncodedText E = JsonEncodedText.Encode("e");
        public static readonly JsonEncodedText N = JsonEncodedText.Encode("n");
        public static readonly JsonEncodedText P = JsonEncodedText.Encode("p");
        public static readonly JsonEncodedText Q = JsonEncodedText.Encode("q");
        public static readonly JsonEncodedText QI = JsonEncodedText.Encode("qi");
        public static readonly JsonEncodedText DP = JsonEncodedText.Encode("dp");
        public static readonly JsonEncodedText DQ = JsonEncodedText.Encode("dq");
        public static readonly JsonEncodedText R = JsonEncodedText.Encode("r");
        public static readonly JsonEncodedText T = JsonEncodedText.Encode("t");
    }
}
