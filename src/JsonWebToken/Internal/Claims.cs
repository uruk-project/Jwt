// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Text;

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
        public const string Aud = "aud";
        public static readonly byte[] AudUtf8 = Encoding.UTF8.GetBytes(Aud);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Exp = "exp";
        public static readonly byte[] ExpUtf8 = Encoding.UTF8.GetBytes(Exp);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Iat = "iat";
        public static readonly byte[] IatUtf8 = Encoding.UTF8.GetBytes(Iat);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Iss = "iss";
        public static readonly byte[] IssUtf8 = Encoding.UTF8.GetBytes(Iss);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Jti = "jti";
        public static readonly byte[] JtiUtf8 = Encoding.UTF8.GetBytes(Jti);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Nbf = "nbf";
        public static readonly byte[] NbfUtf8 = Encoding.UTF8.GetBytes(Nbf);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Sub = "sub";
        public static readonly byte[] SubUtf8 = Encoding.UTF8.GetBytes(Sub);
    }
}
