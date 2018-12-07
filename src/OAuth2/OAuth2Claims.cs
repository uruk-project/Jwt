// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken.Internal
{
    /// <summary>
    /// List of registered claims from different sources
    /// http://tools.ietf.org/html/rfc7519#section-4
    /// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-14
    /// https://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-09
    /// https://tools.ietf.org/html/draft-richer-vectors-of-trust-11
    /// </summary>
    public static class OAuth2Claims
    {
        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Aud = "aud";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Exp = "exp";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Iat = "iat";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Iss = "iss";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Jti = "jti";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Nbf = "nbf";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Sub = "sub";
      
        /// <summary>
        /// https://tools.ietf.org/html/rfc7591#section-2
        /// </summary>
        public const string SoftwareId = "software_id";

        /// <summary>
        /// https://tools.ietf.org/html/draft-richer-vectors-of-trust-11
        /// </summary>
        public const string Vot = "vot";

        /// <summary>
        /// https://tools.ietf.org/html/draft-richer-vectors-of-trust-11
        /// </summary>
        public const string Vtm = "vtm";

        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-14
        /// </summary>
        public const string Act = "act";

        /// <summary>   
        /// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-14
        /// </summary>
        public const string Scope = "scope";

        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-14
        /// </summary>
        public const string ClientId = "client_id";

        /// <summary>
        /// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-14
        /// </summary>
        public const string MayAct = "may_act";

        /// <summary>
        /// https://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-09
        /// </summary>
        public const string Rfp = "rfp";

        /// <summary>
        /// https://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-09
        /// </summary>
        public const string TargetLinkUri = "target_link_uri";

        /// <summary>
        /// https://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-09
        /// </summary>
        public const string As = "as";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string CHash = "c_hash";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        /// </summary>
        public const string AtHash = "at_hash";
    }
}
