// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Text;

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
        public static readonly byte[] AcrUtf8 = Encoding.UTF8.GetBytes(Acr);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Amr = "amr";
        public static readonly byte[] AmrUtf8 = Encoding.UTF8.GetBytes(Amr);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string AuthTime = "auth_time";
        public static readonly byte[] AuthTimeUtf8 = Encoding.UTF8.GetBytes(AuthTime);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Azp = "azp";
        public static readonly byte[] AzpUtf8 = Encoding.UTF8.GetBytes(Azp);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Birthdate = "birthdate";
        public static readonly byte[] BirthdateUtf8 = Encoding.UTF8.GetBytes(Birthdate);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string CHash = "c_hash";
        public static readonly byte[] CHashUtf8 = Encoding.UTF8.GetBytes(CHash);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        /// </summary>
        public const string AtHash = "at_hash";
        public static readonly byte[] AtHashUtf8 = Encoding.UTF8.GetBytes(AtHash);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Email = "email";
        public static readonly byte[] EmailUtf8 = Encoding.UTF8.GetBytes(Email);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Gender = "gender";
        public static readonly byte[] GenderUtf8 = Encoding.UTF8.GetBytes(Gender);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string FamilyName = "family_name";
        public static readonly byte[] FamilyNameUtf8 = Encoding.UTF8.GetBytes(FamilyName);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string GivenName = "given_name";
        public static readonly byte[] GivenNameUtf8 = Encoding.UTF8.GetBytes(GivenName);

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public const string Nonce = "nonce";
        public static readonly byte[] NonceUtf8 = Encoding.UTF8.GetBytes(Nonce);

        /// <summary>
        /// http://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
        /// </summary>
        public const string Sid = "sid";
        public static readonly byte[] SidUtf8 = Encoding.UTF8.GetBytes(Sid);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string MiddleName = "middle_name";
        public static readonly byte[] MiddleNameUtf8 = Encoding.UTF8.GetBytes(MiddleName);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Nickname = "nickname";
        public static readonly byte[] NicknameUtf8 = Encoding.UTF8.GetBytes(Nickname);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string PreferredUsername = "preferred_username";
        public static readonly byte[] PreferredUsernameUtf8 = Encoding.UTF8.GetBytes(PreferredUsername);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Profile = "profile";
        public static readonly byte[] ProfileUtf8 = Encoding.UTF8.GetBytes(Profile);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Picture = "picture";
        public static readonly byte[] PictureUtf8 = Encoding.UTF8.GetBytes(Picture);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Website = "website";
        public static readonly byte[] WebsiteUtf8 = Encoding.UTF8.GetBytes(Website);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string EmailVerified = "email_verified";
        public static readonly byte[] EmailVerifiedUtf8 = Encoding.UTF8.GetBytes(EmailVerified);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Zoneinfo = "zoneinfo";
        public static readonly byte[] ZoneinfoUtf8 = Encoding.UTF8.GetBytes(Zoneinfo);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Locale = "locale";
        public static readonly byte[] LocaleUtf8 = Encoding.UTF8.GetBytes(Locale);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string PhoneNumber = "phone_number";
        public static readonly byte[] PhoneNumberUtf8 = Encoding.UTF8.GetBytes(PhoneNumber);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string PhoneNumberVerified = "phone_number_verified";
        public static readonly byte[] PhoneNumberVerifiedUtf8 = Encoding.UTF8.GetBytes(PhoneNumberVerified);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string Address = "address";
        public static readonly byte[] AddressUtf8 = Encoding.UTF8.GetBytes(Address);

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public const string UpdatedAt = "updated_at";
        public static readonly byte[] UpdatedAtUtf8 = Encoding.UTF8.GetBytes(UpdatedAt);

        public const string Formatted = "formatted";
        public static ReadOnlyMemory<byte> FormattedUtf8 => new byte[] { (byte)'f', (byte)'o', (byte)'r', (byte)'m', (byte)'a', (byte)'t', (byte)'t', (byte)'e', (byte)'d' };

        public const string StreetAddress = "street_address";
        public static ReadOnlyMemory<byte> StreetAddressUtf8 => new byte[] { (byte)'s', (byte)'t', (byte)'r', (byte)'e', (byte)'e', (byte)'t', (byte)'_', (byte)'a', (byte)'d', (byte)'d', (byte)'r', (byte)'e', (byte)'s', (byte)'s' };

        public const string  Locality = "locality";
        public static ReadOnlyMemory<byte> LocalityUtf8 => new byte[] { (byte)'l', (byte)'o', (byte)'c', (byte)'a', (byte)'l', (byte)'i', (byte)'t', (byte)'y' };

        public const string Region = "region";
        public static ReadOnlyMemory<byte> RegionUtf8 => new byte[] { (byte)'r', (byte)'e', (byte)'g', (byte)'i', (byte)'o', (byte)'n' };

        public const string PostalCode = "postal_code";
        public static ReadOnlyMemory<byte> PostalCodeUtf8 => new byte[] { (byte)'p', (byte)'o', (byte)'s', (byte)'t', (byte)'a', (byte)'l', (byte)'_', (byte)'c', (byte)'o', (byte)'d', (byte)'e' };

        public const string Country = "country";
        public static ReadOnlyMemory<byte> CountryUtf8 => new byte[] { (byte)'c', (byte)'o', (byte)'u', (byte)'n', (byte)'t', (byte)'r', (byte)'y' };

    }
}
