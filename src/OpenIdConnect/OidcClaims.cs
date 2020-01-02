// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

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
        public static ReadOnlySpan<byte> AcrUtf8 => new[] { (byte)'a', (byte)'c', (byte)'r' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public static ReadOnlySpan<byte> AmrUtf8 => new[] { (byte)'a', (byte)'m', (byte)'r' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public static ReadOnlySpan<byte> AuthTimeUtf8 => new[] { (byte)'a', (byte)'u', (byte)'t', (byte)'h', (byte)'_', (byte)'t', (byte)'i', (byte)'m', (byte)'e' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public static ReadOnlySpan<byte> AzpUtf8 => new[] { (byte)'z', (byte)'z', (byte)'p' };

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> BirthdateUtf8 => new[] { (byte)'b', (byte)'i', (byte)'r', (byte)'t', (byte)'h', (byte)'d', (byte)'a', (byte)'t', (byte)'e' };

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> CHashUtf8 => new[] { (byte)'c', (byte)'_', (byte)'h', (byte)'a', (byte)'s', (byte)'h' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        /// </summary>
        public static ReadOnlySpan<byte> AtHashUtf8 => new[] { (byte)'a', (byte)'t', (byte)'_', (byte)'h', (byte)'a', (byte)'s', (byte)'h' };

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> EmailUtf8 => new[] { (byte)'e', (byte)'m', (byte)'a', (byte)'i', (byte)'l' };

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> GenderUtf8 => new[] { (byte)'g', (byte)'e', (byte)'n', (byte)'d', (byte)'e', (byte)'r' };

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> FamilyNameUtf8 => new[] { (byte)'f', (byte)'a', (byte)'m', (byte)'i', (byte)'l', (byte)'y', (byte)'_', (byte)'n', (byte)'a', (byte)'m', (byte)'e' };

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> GivenNameUtf8 => new[] { (byte)'g', (byte)'i', (byte)'v', (byte)'e', (byte)'n', (byte)'_', (byte)'n', (byte)'a', (byte)'m', (byte)'e' };

        /// <summary>
        /// http://tools.ietf.org/html/rfc7519#section-4
        /// </summary>
        public static ReadOnlySpan<byte> NonceUtf8 => new[] { (byte)'n', (byte)'o', (byte)'n', (byte)'c', (byte)'e' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
        /// </summary>
        public static ReadOnlySpan<byte> SidUtf8 => new[] { (byte)'s', (byte)'i', (byte)'d' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public static ReadOnlySpan<byte> MiddleNameUtf8 => new[] { (byte)'m', (byte)'i', (byte)'d', (byte)'d', (byte)'l', (byte)'e', (byte)'_', (byte)'n', (byte)'a', (byte)'m', (byte)'e' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public static ReadOnlySpan<byte> NicknameUtf8 => new[] { (byte)'n', (byte)'i', (byte)'c', (byte)'k', (byte)'n', (byte)'a', (byte)'m', (byte)'e' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public static ReadOnlySpan<byte> PreferredUsernameUtf8 => new[] { (byte)'p', (byte)'r', (byte)'e', (byte)'f', (byte)'e', (byte)'r', (byte)'r', (byte)'e', (byte)'d', (byte)'_', (byte)'u', (byte)'s', (byte)'e', (byte)'r', (byte)'n', (byte)'a', (byte)'m', (byte)'e' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public static ReadOnlySpan<byte> ProfileUtf8 => new[] { (byte)'p', (byte)'r', (byte)'o', (byte)'f', (byte)'i', (byte)'l', (byte)'e' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public static ReadOnlySpan<byte> PictureUtf8 => new[] { (byte)'p', (byte)'i', (byte)'c', (byte)'t', (byte)'u', (byte)'r', (byte)'e' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public static ReadOnlySpan<byte> WebsiteUtf8 => new[] { (byte)'w', (byte)'e', (byte)'b', (byte)'s', (byte)'i', (byte)'t', (byte)'e' };

    /// <summary>
    /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    /// </summary>
        public static ReadOnlySpan<byte> EmailVerifiedUtf8 => new[] { (byte)'e', (byte)'m', (byte)'a', (byte)'i', (byte)'l', (byte)'_', (byte)'v', (byte)'e', (byte)'r', (byte)'i', (byte)'f', (byte)'i', (byte)'e', (byte)'d' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public static ReadOnlySpan<byte> ZoneinfoUtf8 => new[] { (byte)'z', (byte)'o', (byte)'n', (byte)'e', (byte)'i', (byte)'n', (byte)'f', (byte)'o' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public static ReadOnlySpan<byte> LocaleUtf8 => new[] { (byte)'l', (byte)'o', (byte)'c', (byte)'a', (byte)'l', (byte)'e' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public static ReadOnlySpan<byte> PhoneNumberUtf8  => new[] { (byte)'p', (byte)'h', (byte)'o', (byte)'n', (byte)'e', (byte)'_', (byte)'n', (byte)'u', (byte)'m', (byte)'b', (byte)'e', (byte)'r' };

    /// <summary>
    /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    /// </summary>
        public static ReadOnlySpan<byte> PhoneNumberVerifiedUtf8 => new[] { (byte)'p', (byte)'h', (byte)'o', (byte)'n', (byte)'e', (byte)'_', (byte)'n', (byte)'u', (byte)'m', (byte)'b', (byte)'e', (byte)'r', (byte)'_', (byte)'v', (byte)'e', (byte)'r', (byte)'i', (byte)'f', (byte)'i', (byte)'e', (byte)'d' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public static ReadOnlySpan<byte> AddressUtf8 => new[] { (byte)'a', (byte)'d', (byte)'d', (byte)'r', (byte)'e', (byte)'s', (byte)'s' };

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        /// </summary>
        public static ReadOnlySpan<byte> UpdatedAtUtf8 => new byte[] { (byte)'u', (byte)'p', (byte)'d', (byte)'a', (byte)'t', (byte)'e', (byte)'d', (byte)'_', (byte)'a', (byte)'t' };

        public static ReadOnlySpan<byte> FormattedUtf8 => new byte[] { (byte)'f', (byte)'o', (byte)'r', (byte)'m', (byte)'a', (byte)'t', (byte)'t', (byte)'e', (byte)'d' };

        public static ReadOnlySpan<byte> StreetAddressUtf8 => new byte[] { (byte)'s', (byte)'t', (byte)'r', (byte)'e', (byte)'e', (byte)'t', (byte)'_', (byte)'a', (byte)'d', (byte)'d', (byte)'r', (byte)'e', (byte)'s', (byte)'s' };

        public static ReadOnlySpan<byte> LocalityUtf8 => new byte[] { (byte)'l', (byte)'o', (byte)'c', (byte)'a', (byte)'l', (byte)'i', (byte)'t', (byte)'y' };

        public static ReadOnlySpan<byte> RegionUtf8 => new byte[] { (byte)'r', (byte)'e', (byte)'g', (byte)'i', (byte)'o', (byte)'n' };

        public static ReadOnlySpan<byte> PostalCodeUtf8 => new byte[] { (byte)'p', (byte)'o', (byte)'s', (byte)'t', (byte)'a', (byte)'l', (byte)'_', (byte)'c', (byte)'o', (byte)'d', (byte)'e' };

        public static ReadOnlySpan<byte> CountryUtf8 => new byte[] { (byte)'c', (byte)'o', (byte)'u', (byte)'n', (byte)'t', (byte)'r', (byte)'y' };
    }
}
