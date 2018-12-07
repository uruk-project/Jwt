// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// List of registered claims from different sources
    /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    /// http://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
    /// </summary>
    public static class OidcClaims
    {
        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Acr = "acr";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Amr = "amr";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string AuthTime = "auth_time";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Azp = "azp";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Birthdate = "birthdate";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string CHash = "c_hash";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        /// </summary>
        public const string AtHash = "at_hash";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Email = "email";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Gender = "gender";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string FamilyName = "family_name";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string GivenName = "given_name";

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Nonce = "nonce";

        /// <summary>
        /// http://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
        /// </summary>
        public const string Sid = "sid";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string MiddleName = "middle_name";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Nickname = "nickname";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string PreferredUsername = "preferred_username";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Profile = "profile";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Picture = "picture";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Website = "website";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string EmailVerified = "email_verified";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Zoneinfo = "zoneinfo";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Locale = "locale";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string PhoneNumber = "phone_number";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string PhoneNumberVerified = "phone_number_verified";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Address = "address";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string UpdatedAt = "updated_at";
    }
}
