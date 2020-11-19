//// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
//// Licensed under the MIT license. See LICENSE in the project root for license information.

//using System.Text.Json;

//namespace JsonWebToken
//{
//    /// <summary>
//    /// List of registered claims from different sources
//    /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
//    /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
//    /// http://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
//    /// </summary>
//    public static class OidcClaims
//    {
//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Acr = JsonEncodedText.Encode("acr");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Amr = JsonEncodedText.Encode("amr");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText AuthTime = JsonEncodedText.Encode("auth_time");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Azp = JsonEncodedText.Encode("azp");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Birthdate = JsonEncodedText.Encode("birthdate");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText CHash = JsonEncodedText.Encode("c_hash");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText AtHash = JsonEncodedText.Encode("at_hash");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Email = JsonEncodedText.Encode("email");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Gender = JsonEncodedText.Encode("gender");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText FamilyName = JsonEncodedText.Encode("family_name");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText GivenName = JsonEncodedText.Encode("given_name");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Nonce = JsonEncodedText.Encode("nonce");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Sid = JsonEncodedText.Encode("sid");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText MiddleName = JsonEncodedText.Encode("middle_name");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Nickname = JsonEncodedText.Encode("nickname");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText PreferredUsername = JsonEncodedText.Encode("preferred_username");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Profile = JsonEncodedText.Encode("profile");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Picture = JsonEncodedText.Encode("picture");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Website = JsonEncodedText.Encode("website");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText EmailVerified = JsonEncodedText.Encode("email_verified");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Zoneinfo = JsonEncodedText.Encode("zoneinfo");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Locale = JsonEncodedText.Encode("locale");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText PhoneNumber = JsonEncodedText.Encode("phone_number");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText PhoneNumberVerified = JsonEncodedText.Encode("phone_number_verified");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Address = JsonEncodedText.Encode("address");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText UpdatedAt = JsonEncodedText.Encode("updated_at");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Formatted = JsonEncodedText.Encode("formatted");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText StreetAddress = JsonEncodedText.Encode("street_address");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Locality = JsonEncodedText.Encode("locality");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Region = JsonEncodedText.Encode("region");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText PostalCode = JsonEncodedText.Encode("postal_code");

//        /// <summary>http://openid.net/specs/openid-connect-core-1_0.html#IDToken</summary>
//        public static readonly JsonEncodedText Country = JsonEncodedText.Encode("country");
//    }
//}
