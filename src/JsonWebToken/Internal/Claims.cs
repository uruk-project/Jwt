// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography.X509Certificates;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// List of registered claims from different sources
    /// http://tools.ietf.org/html/rfc7519#section-4
    /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    /// http://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
    /// https://tools.ietf.org/html/draft-ietf-secevent-token-13#section-2.2
    /// </summary>
    public static class Claims
    {
        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary> 
        public static ReadOnlySpan<byte> AudUtf8 => new byte[] { (byte)'a', (byte)'u', (byte)'d' };
        public static readonly string Aud = "aud";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> ExpUtf8 => new byte[] { (byte)'e', (byte)'x', (byte)'p' };
        public static readonly string Exp = "exp";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> IatUtf8 => new byte[] { (byte)'i', (byte)'a', (byte)'t' };
        public static readonly string Iat = "iat";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> IssUtf8 => new byte[] { (byte)'i', (byte)'s', (byte)'s' };
        public static readonly string Iss = "iss";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> JtiUtf8 => new byte[] { (byte)'j', (byte)'t', (byte)'i' };
        public static readonly string Jti = "jti";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> NbfUtf8 => new byte[] { (byte)'n', (byte)'b', (byte)'f' };
        public static readonly string Nbf = "nbf";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> SubUtf8 => new byte[] { (byte)'s', (byte)'u', (byte)'b' };
        public static readonly string Sub = "sub";
    }
}
