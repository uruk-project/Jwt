// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class IdToken : Jwt
    {
        private readonly Jwt _token;

        public IdToken(Jwt token)
        {
            _token = token ?? throw new ArgumentNullException(nameof(token));
        }

        public override JwtHeader Header => _token.Header;

        public override JwtPayload Payload => _token.Payload;

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public DateTime? AuthenticationTime => ToDateTime(Payload[OidcClaims.AuthTimeUtf8]);

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Nonce => (string)Payload[OidcClaims.NonceUtf8];

        /// <summary>
        /// Authentication Context Class that the authentication performed satisfied.
        /// </summary>
        public string AuthenticationContextClassReference => (string)Payload[OidcClaims.AcrUtf8];

        /// <summary>
        /// Gets or sets the Authentication Methods References used in the authentication.
        /// </summary>
        public IReadOnlyList<string> AuthenticationMethodsReferences => (List<string>)Payload[OidcClaims.AmrUtf8];

        /// <summary>
        /// Gets or sets the Authorized party - the party to which the ID Token was issued.
        /// </summary>
        public string AuthorizedParty => (string)Payload[OidcClaims.AzpUtf8];

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string AccessTokenHash => (string)Payload[OidcClaims.AtHashUtf8];

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string CodeHash => (string)Payload[OidcClaims.CHashUtf8];

        /// <summary>
        /// Gets or sets the Given name(s) or first name(s) of the End-User.
        /// </summary>
        public string GivenName => (string)Payload[OidcClaims.GivenNameUtf8];

        /// <summary>
        /// Gets or sets the Surname(s) or last name(s) of the End-User.
        /// </summary>
        public string FamilyName => (string)Payload[OidcClaims.FamilyNameUtf8];

        /// <summary>
        /// Gets or sets the middle name(s) of the End-User.
        /// </summary>
        public string MiddleName => (string)Payload[OidcClaims.MiddleNameUtf8];

        /// <summary>
        /// Gets or sets the casual name of the End-User.
        /// </summary>
        public string Nickname => (string)Payload[OidcClaims.NicknameUtf8];

        /// <summary>
        /// Gets or sets the Shorthand name by which the End-User wishes to be referred to.
        /// </summary>
        public string PreferredUsername => (string)Payload[OidcClaims.PreferredUsernameUtf8];

        /// <summary>
        /// Gets or sets the URL of the End-User's profile page.
        /// </summary>
        public string Profile => (string)Payload[OidcClaims.ProfileUtf8];

        /// <summary>
        /// Gets or sets the URL of the End-User's profile picture.
        /// </summary>
        public string Picture => (string)Payload[OidcClaims.PictureUtf8];

        /// <summary>
        /// Gets or sets the URL of the End-User's Web page or blog.
        /// </summary>
        public string Website => (string)Payload[OidcClaims.WebsiteUtf8];

        /// <summary>
        /// Gets or sets the End-User's preferred e-mail address.
        /// </summary>
        public string Email => (string)Payload[OidcClaims.EmailUtf8];

        /// <summary>
        /// True if the End-User's e-mail address has been verified; otherwise false.
        /// </summary>
        public bool? EmailVerified
        {
            get { return (bool)Payload[OidcClaims.EmailVerifiedUtf8]; }
        }

        /// <summary>
        /// Gets or sets the End-User's gender. Values defined by this specification are female and male. 
        /// </summary>
        public string Gender => (string)Payload[OidcClaims.GenderUtf8];

        /// <summary>
        /// Gets or sets the End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed.
        /// </summary>
        public string Birthdate => (string)Payload[OidcClaims.BirthdateUtf8];

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Zoneinfo => (string)Payload[OidcClaims.ZoneinfoUtf8];

        /// <summary>
        /// Gets or sets the End-User's locale, represented as a BCP47 [RFC5646] language tag.
        /// </summary>
        public string Locale => (string)Payload[OidcClaims.LocaleUtf8];

        /// <summary>
        /// Gets or sets the End-User's preferred telephone number.
        /// </summary>
        public string PhoneNumber => (string)Payload[OidcClaims.PhoneNumberUtf8];

        /// <summary>
        /// True if the End-User's phone number has been verified; otherwise false.
        /// </summary>
        public bool? PhoneNumberVerified => (bool)Payload[OidcClaims.PhoneNumberVerifiedUtf8];

        /// <summary>
        /// Gets or sets the End-User's preferred postal address.
        /// </summary>
        public Address Address
        {
            get
            {
                var address = (string)Payload[OidcClaims.AddressUtf8];
                return address == null ? null : Address.FromJson(address);
            }
        }

        /// <summary>
        /// Gets or sets the time the End-User's information was last updated.
        /// </summary>
        public DateTime? UpdatedAt => ToDateTime(Payload[OidcClaims.UpdatedAtUtf8]);

        private static DateTime? ToDateTime(object token)
        {
            if (token == null)
            {
                return default;
            }

            return EpochTime.ToDateTime((long)token);
        }
    }
}