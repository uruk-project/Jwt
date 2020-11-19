// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>
    /// List of registered claims from different sources
    /// http://tools.ietf.org/html/rfc7519#section-4
    /// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-14
    /// https://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-09
    /// https://tools.ietf.org/html/draft-richer-vectors-of-trust-15
    /// </summary>
    public static class OAuth2Claims
    {
        /// <summary>https://tools.ietf.org/html/rfc8693#section-4.3</summary>
        public static readonly JsonEncodedText ClientId = JsonEncodedText.Encode("client_id");

        /// <summary>https://tools.ietf.org/html/rfc8693#section-4.2</summary>
        public static readonly JsonEncodedText Scope = JsonEncodedText.Encode("scope");

        /// <summary>https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-10#section-2.2.1</summary>
        public static readonly JsonEncodedText AuthTime = JsonEncodedText.Encode("auth_time");

        /// <summary>https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-10#section-2.2.1</summary>
        public static readonly JsonEncodedText Acr = JsonEncodedText.Encode("acr");

        /// <summary>https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-10#section-2.2.1</summary>
        public static readonly JsonEncodedText Amr = JsonEncodedText.Encode("amr");

        /// <summary>https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-10#section-2.2.3.1</summary>
        public static readonly JsonEncodedText Groups = JsonEncodedText.Encode("groups");
        
        /// <summary>https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-10#section-2.2.3.1</summary>
        public static readonly JsonEncodedText Roles = JsonEncodedText.Encode("roles");
        
        /// <summary>https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-10#section-2.2.3.1</summary>
        public static readonly JsonEncodedText Entitlements = JsonEncodedText.Encode("entitlements");
        
        /// <summary>https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-10#section-2.2.3.1</summary>
        public static readonly JsonEncodedText MayAct = JsonEncodedText.Encode("may_act");

        /// <summary>https://tools.ietf.org/html/rfc8693#section-4.1</summary>
        public static readonly JsonEncodedText Act = JsonEncodedText.Encode("act");

        /// <summary>https://openid.net/specs/openid-connect-frontchannel-1_0.html</summary>
        public static readonly JsonEncodedText Sid = JsonEncodedText.Encode("sid");
        
        /// <summary>https://tools.ietf.org/html/draft-richer-vectors-of-trust-15#section-3.2</summary>
        public static readonly JsonEncodedText Vot = JsonEncodedText.Encode("vot");

        /// <summary>https://tools.ietf.org/html/draft-richer-vectors-of-trust-15#section-3.2</summary>
        public static readonly JsonEncodedText Vtm = JsonEncodedText.Encode("vtm");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Azp = JsonEncodedText.Encode("azp");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Birthdate = JsonEncodedText.Encode("birthdate");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText CHash = JsonEncodedText.Encode("c_hash");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText AtHash = JsonEncodedText.Encode("at_hash");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Email = JsonEncodedText.Encode("email");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Gender = JsonEncodedText.Encode("gender");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText FamilyName = JsonEncodedText.Encode("family_name");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText GivenName = JsonEncodedText.Encode("given_name");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Nonce = JsonEncodedText.Encode("nonce");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText MiddleName = JsonEncodedText.Encode("middle_name");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Nickname = JsonEncodedText.Encode("nickname");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText PreferredUsername = JsonEncodedText.Encode("preferred_username");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Profile = JsonEncodedText.Encode("profile");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Picture = JsonEncodedText.Encode("picture");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Website = JsonEncodedText.Encode("website");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText EmailVerified = JsonEncodedText.Encode("email_verified");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Zoneinfo = JsonEncodedText.Encode("zoneinfo");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Locale = JsonEncodedText.Encode("locale");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText PhoneNumber = JsonEncodedText.Encode("phone_number");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText PhoneNumberVerified = JsonEncodedText.Encode("phone_number_verified");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Address = JsonEncodedText.Encode("address");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText UpdatedAt = JsonEncodedText.Encode("updated_at");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Formatted = JsonEncodedText.Encode("formatted");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText StreetAddress = JsonEncodedText.Encode("street_address");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Locality = JsonEncodedText.Encode("locality");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Region = JsonEncodedText.Encode("region");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText PostalCode = JsonEncodedText.Encode("postal_code");

        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
        public static readonly JsonEncodedText Country = JsonEncodedText.Encode("country");

        public static readonly JsonEncodedText Rfp = JsonEncodedText.Encode("rfp");
    }
}
