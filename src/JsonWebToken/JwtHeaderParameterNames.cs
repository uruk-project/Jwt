// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>List of header parameter names  http://tools.ietf.org/html/rfc7519#section-5.</summary>
    public static class JwtHeaderParameterNames
    {
        /// <summary>https://tools.ietf.org/html/rfc7515#section-4.1.1</summary>
        public static readonly JsonEncodedText Alg = JsonEncodedText.Encode("alg");

        /// <summary>
        /// https://tools.ietf.org/html/rfc7515#section-4.1.10
        /// https://tools.ietf.org/html/rfc7519#section-5.2
        /// </summary>
        public static readonly JsonEncodedText Cty = JsonEncodedText.Encode("cty");

        /// <summary>https://tools.ietf.org/html/rfc7516#section-4.1.2</summary>
        public static readonly JsonEncodedText Enc = JsonEncodedText.Encode("enc");

        /// <summary>https://tools.ietf.org/html/rfc7516#section-4.1.2</summary>
        public static readonly JsonEncodedText Jku = JsonEncodedText.Encode("jku");

        /// <summary>https://tools.ietf.org/html/rfc7515#section-4.1.3</summary>
        public static readonly JsonEncodedText Jwk = JsonEncodedText.Encode("jwk");

        /// <summary>https://tools.ietf.org/html/rfc7515#section-4.1.4</summary>
        public static readonly JsonEncodedText Kid = JsonEncodedText.Encode("kid");

        /// <summary>
        /// https://tools.ietf.org/html/rfc7515#section-4.1.9
        /// https://tools.ietf.org/html/rfc7519#section-5.1
        /// </summary>
        public static readonly JsonEncodedText Typ = JsonEncodedText.Encode("typ");

        /// <summary>https://tools.ietf.org/html/rfc7515#section-4.1.6</summary>
        public static readonly JsonEncodedText X5c = JsonEncodedText.Encode("x5c");

        /// <summary>https://tools.ietf.org/html/rfc7515#page-12</summary>
        public static readonly JsonEncodedText X5t = JsonEncodedText.Encode("x5t");

        /// <summary>https://tools.ietf.org/html/rfc7515#section-4.1.5</summary>
        public static readonly JsonEncodedText X5u = JsonEncodedText.Encode("x5u");

        /// <summary>https://tools.ietf.org/html/rfc7515#section-4.1.5</summary>
        public static readonly JsonEncodedText Crit = JsonEncodedText.Encode("crit");

        /// <summary>https://tools.ietf.org/html/rfc7516#section-4.1.3</summary>
        public static readonly JsonEncodedText Zip = JsonEncodedText.Encode("zip");

        /// <summary>https://tools.ietf.org/html/rfc7518#section-4.6.1</summary>
        public static readonly JsonEncodedText Epk = JsonEncodedText.Encode("epk");

        /// <summary>https://tools.ietf.org/html/rfc7518#section-4.6.1</summary>
        public static readonly JsonEncodedText Apu = JsonEncodedText.Encode("apu");

        /// <summary>https://tools.ietf.org/html/rfc7518#section-4.6.1</summary>
        public static readonly JsonEncodedText Apv = JsonEncodedText.Encode("apv");

        /// <summary>https://tools.ietf.org/html/rfc7518#section-4.7</summary>
        public static readonly JsonEncodedText IV = JsonEncodedText.Encode("iv");

        /// <summary>https://tools.ietf.org/html/rfc7518#section-4.7</summary>
        public static readonly JsonEncodedText Tag = JsonEncodedText.Encode("tag");

        /// <summary>https://tools.ietf.org/html/rfc7518#section-4.8.1</summary>
        public static readonly JsonEncodedText P2s = JsonEncodedText.Encode("p2s");

        /// <summary>https://tools.ietf.org/html/rfc7518#section-4.8.1</summary>
        public static readonly JsonEncodedText P2c = JsonEncodedText.Encode("p2c");
    }
}
