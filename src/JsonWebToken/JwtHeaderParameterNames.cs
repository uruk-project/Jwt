// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// List of header parameter names see: http://tools.ietf.org/html/rfc7519#section-5.
    /// </summary>
    public static class JwtHeaderParameterNames
    {
        /// <summary>see:https://tools.ietf.org/html/rfc7515#section-4.1.1</summary>
        public static readonly JsonEncodedText Alg = JsonEncodedText.Encode("alg");

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.10
        /// also:https://tools.ietf.org/html/rfc7519#section-5.2
        /// </summary>
        public static readonly JsonEncodedText Cty = JsonEncodedText.Encode("cty");

        /// <summary>see:https://tools.ietf.org/html/rfc7516#section-4.1.2</summary>
        public static readonly JsonEncodedText Enc = JsonEncodedText.Encode("enc");

        /// <summary>see:https://tools.ietf.org/html/rfc7516#section-4.1.2</summary>
        public static readonly string Jku = "jku";

        /// <summary>see:https://tools.ietf.org/html/rfc7515#section-4.1.3</summary>
        public static readonly JsonEncodedText Jwk = JsonEncodedText.Encode("jwk");

        /// <summary>see:https://tools.ietf.org/html/rfc7515#section-4.1.4</summary>
        public static readonly JsonEncodedText Kid = JsonEncodedText.Encode("kid");

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.9
        /// also:https://tools.ietf.org/html/rfc7519#section-5.1
        /// </summary>
        public static readonly JsonEncodedText Typ = JsonEncodedText.Encode("typ");

        /// <summary>see:https://tools.ietf.org/html/rfc7515#section-4.1.6</summary>
        public static ReadOnlySpan<byte> X5cUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'c' };

        /// <summary>see:https://tools.ietf.org/html/rfc7515#section-4.1.6</summary>
        public static readonly string X5c = "x5c";

        /// <summary>see:https://tools.ietf.org/html/rfc7515#page-12</summary>
        public static ReadOnlySpan<byte> X5tUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'t' };

        /// <summary>see:https://tools.ietf.org/html/rfc7515#page-12</summary>
        public static readonly JsonEncodedText X5t = JsonEncodedText.Encode("x5t");

        /// <summary>see:https://tools.ietf.org/html/rfc7515#section-4.1.5</summary>
        public static ReadOnlySpan<byte> X5uUtf8 => new byte[] { (byte)'x', (byte)'5', (byte)'U' };

        /// <summary>see:https://tools.ietf.org/html/rfc7515#section-4.1.5</summary>
        public static readonly string X5u = "x5u";

        /// <summary>
        /// see:https://tools.ietf.org/html/rfc7515#section-4.1.5
        /// </summary>
        public static ReadOnlySpan<byte> CritUtf8 => new byte[] { (byte)'c', (byte)'r', (byte)'i', (byte)'t' };

        /// <summary>see:https://tools.ietf.org/html/rfc7515#section-4.1.5</summary>
        public static readonly JsonEncodedText Crit = JsonEncodedText.Encode("crit");

        /// <summary>see:https://tools.ietf.org/html/rfc7516#section-4.1.3</summary>
        public static readonly JsonEncodedText Zip = JsonEncodedText.Encode("zip");

        /// <summary>see:https://tools.ietf.org/html/rfc7518#section-4.6.1</summary>
        public static readonly JsonEncodedText Epk = JsonEncodedText.Encode("epk");

        /// <summary>see:https://tools.ietf.org/html/rfc7518#section-4.6.1</summary>
        public static readonly JsonEncodedText Apu = JsonEncodedText.Encode("apu");

        /// <summary>see:https://tools.ietf.org/html/rfc7518#section-4.6.1</summary>
        public static readonly JsonEncodedText Apv = JsonEncodedText.Encode("apv");

        /// <summary>see:https://tools.ietf.org/html/rfc7518#section-4.7</summary>
        public static readonly JsonEncodedText IV = JsonEncodedText.Encode("iv");

        /// <summary>see:https://tools.ietf.org/html/rfc7518#section-4.7</summary>
        public static readonly JsonEncodedText Tag = JsonEncodedText.Encode("tag");
    }
}
