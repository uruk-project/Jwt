// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Linq;

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
        public DateTime? AuthenticationTime => ToDateTime(Payload[OidcClaims.AuthTime]);

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Nonce => (string)Payload[OidcClaims.Nonce];

        /// <summary>
        /// Authentication Context Class that the authentication performed satisfied.
        /// </summary>
        public string AuthenticationContextClassReference => (string)Payload[OidcClaims.Acr];

        /// <summary>
        /// Gets or sets the Authentication Methods References used in the authentication.
        /// </summary>
        public IReadOnlyList<string> AuthenticationMethodsReferences => (List<string>)Payload[OidcClaims.Amr];

        /// <summary>
        /// Gets or sets the Authorized party - the party to which the ID Token was issued.
        /// </summary>
        public string AuthorizedParty => (string)Payload[OidcClaims.Azp];

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string AccessTokenHash => (string)Payload[OidcClaims.AtHash];

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string CodeHash => (string)Payload[OidcClaims.CHash];

        /// <summary>
        /// Gets or sets the Given name(s) or first name(s) of the End-User.
        /// </summary>
        public string GivenName => (string)Payload[OidcClaims.GivenName];

        /// <summary>
        /// Gets or sets the Surname(s) or last name(s) of the End-User.
        /// </summary>
        public string FamilyName => (string)Payload[OidcClaims.FamilyName];

        /// <summary>
        /// Gets or sets the middle name(s) of the End-User.
        /// </summary>
        public string MiddleName => (string)Payload[OidcClaims.MiddleName];

        /// <summary>
        /// Gets or sets the casual name of the End-User.
        /// </summary>
        public string Nickname => (string)Payload[OidcClaims.Nickname];

        /// <summary>
        /// Gets or sets the Shorthand name by which the End-User wishes to be referred to.
        /// </summary>
        public string PreferredUsername => (string)Payload[OidcClaims.PreferredUsername];

        /// <summary>
        /// Gets or sets the URL of the End-User's profile page.
        /// </summary>
        public string Profile => (string)Payload[OidcClaims.Profile];

        /// <summary>
        /// Gets or sets the URL of the End-User's profile picture.
        /// </summary>
        public string Picture => (string)Payload[OidcClaims.Picture];

        /// <summary>
        /// Gets or sets the URL of the End-User's Web page or blog.
        /// </summary>
        public string Website => (string)Payload[OidcClaims.Website];

        /// <summary>
        /// Gets or sets the End-User's preferred e-mail address.
        /// </summary>
        public string Email => (string)Payload[OidcClaims.Email];

        /// <summary>
        /// True if the End-User's e-mail address has been verified; otherwise false.
        /// </summary>
        public bool? EmailVerified
        {
            get { return (bool)Payload[OidcClaims.EmailVerified]; }
        }

        /// <summary>
        /// Gets or sets the End-User's gender. Values defined by this specification are female and male. 
        /// </summary>
        public string Gender => (string)Payload[OidcClaims.Gender];

        /// <summary>
        /// Gets or sets the End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed.
        /// </summary>
        public string Birthdate => (string)Payload[OidcClaims.Birthdate];

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Zoneinfo => (string)Payload[OidcClaims.Zoneinfo];

        /// <summary>
        /// Gets or sets the End-User's locale, represented as a BCP47 [RFC5646] language tag.
        /// </summary>
        public string Locale => (string)Payload[OidcClaims.Locale];

        /// <summary>
        /// Gets or sets the End-User's preferred telephone number.
        /// </summary>
        public string PhoneNumber => (string)Payload[OidcClaims.PhoneNumber];

        /// <summary>
        /// True if the End-User's phone number has been verified; otherwise false.
        /// </summary>
        public bool? PhoneNumberVerified => (bool)Payload[OidcClaims.PhoneNumberVerified];

        /// <summary>
        /// Gets or sets the End-User's preferred postal address.
        /// </summary>
        public Address Address
        {
            get
            {
                var address = (string)Payload[OidcClaims.Address];
                return address == null ? null : Address.FromJson(address);
            }
        }

        /// <summary>
        /// Gets or sets the time the End-User's information was last updated.
        /// </summary>
        public DateTime? UpdatedAt => ToDateTime(Payload[OidcClaims.UpdatedAt]);

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