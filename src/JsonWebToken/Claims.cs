// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
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
        public static readonly JsonEncodedText Aud = JsonEncodedText.Encode("aud");

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static readonly JsonEncodedText Exp = JsonEncodedText.Encode("exp");

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static readonly JsonEncodedText Iat = JsonEncodedText.Encode("iat");

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static readonly JsonEncodedText Iss = JsonEncodedText.Encode("iss");

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static readonly JsonEncodedText Jti = JsonEncodedText.Encode("jti");

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static readonly JsonEncodedText Nbf = JsonEncodedText.Encode("nbf");

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static readonly JsonEncodedText Sub = JsonEncodedText.Encode("sub");
    }
}
