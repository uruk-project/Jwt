// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    public sealed class IdToken : Jwt
    {
        public IdToken(Jwt token)
            : base(token)
        {
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public long? AuthenticationTime => Payload?[OidcClaims.AuthTimeUtf8].GetInt64();

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string? Nonce => Payload?[OidcClaims.NonceUtf8].GetString();

        /// <summary>
        /// Authentication Context Class that the authentication performed satisfied.
        /// </summary>
        public string? AuthenticationContextClassReference => Payload?[OidcClaims.AcrUtf8].GetString();

        /// <summary>
        /// Gets or sets the Authentication Methods References used in the authentication.
        /// </summary>
        public IReadOnlyList<string?>? AuthenticationMethodsReferences => Payload?[OidcClaims.AmrUtf8].GetStringArray();

        /// <summary>
        /// Gets or sets the Authorized party - the party to which the ID Token was issued.
        /// </summary>
        public string? AuthorizedParty => Payload?[OidcClaims.AzpUtf8].GetString();

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string? AccessTokenHash => Payload?[OidcClaims.AtHashUtf8].GetString();

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string? CodeHash => Payload?[OidcClaims.CHashUtf8].GetString();

        /// <summary>
        /// Gets or sets the Given name(s) or first name(s) of the End-User.
        /// </summary>
        public string? GivenName => Payload?[OidcClaims.GivenNameUtf8].GetString();

        /// <summary>
        /// Gets or sets the Surname(s) or last name(s) of the End-User.
        /// </summary>
        public string? FamilyName => Payload?[OidcClaims.FamilyNameUtf8].GetString();

        /// <summary>
        /// Gets or sets the middle name(s) of the End-User.
        /// </summary>
        public string? MiddleName => Payload?[OidcClaims.MiddleNameUtf8].GetString();

        /// <summary>
        /// Gets or sets the casual name of the End-User.
        /// </summary>
        public string? Nickname => Payload?[OidcClaims.NicknameUtf8].GetString();

        /// <summary>
        /// Gets or sets the Shorthand name by which the End-User wishes to be referred to.
        /// </summary>
        public string? PreferredUsername => Payload?[OidcClaims.PreferredUsernameUtf8].GetString();

        /// <summary>
        /// Gets or sets the URL of the End-User's profile page.
        /// </summary>
        public string? Profile => Payload?[OidcClaims.ProfileUtf8].GetString();

        /// <summary>
        /// Gets or sets the URL of the End-User's profile picture.
        /// </summary>
        public string? Picture => Payload?[OidcClaims.PictureUtf8].GetString();

        /// <summary>
        /// Gets or sets the URL of the End-User's Web page or blog.
        /// </summary>
        public string? Website => Payload?[OidcClaims.WebsiteUtf8].GetString();

        /// <summary>
        /// Gets or sets the End-User's preferred e-mail address.
        /// </summary>
        public string? Email => Payload?[OidcClaims.EmailUtf8].GetString();

        /// <summary>
        /// True if the End-User's e-mail address has been verified; otherwise false.
        /// </summary>
        public bool? EmailVerified => Payload?[OidcClaims.EmailVerifiedUtf8].GetBoolean();

        /// <summary>
        /// Gets or sets the End-User's gender. Values defined by this specification are female and male. 
        /// </summary>
        public string? Gender => Payload?[OidcClaims.GenderUtf8].GetString();

        /// <summary>
        /// Gets or sets the End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed.
        /// </summary>
        public string? Birthdate => Payload?[OidcClaims.BirthdateUtf8].GetString();

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string? Zoneinfo => Payload?[OidcClaims.ZoneinfoUtf8].GetString();

        /// <summary>
        /// Gets or sets the End-User's locale, represented as a BCP47 [RFC5646] language tag.
        /// </summary>
        public string? Locale => Payload?[OidcClaims.LocaleUtf8].GetString();

        /// <summary>
        /// Gets or sets the End-User's preferred telephone number.
        /// </summary>
        public string? PhoneNumber => Payload?[OidcClaims.PhoneNumberUtf8].GetString();

        /// <summary>
        /// True if the End-User's phone number has been verified; otherwise false.
        /// </summary>
        public bool? PhoneNumberVerified => Payload?[OidcClaims.PhoneNumberVerifiedUtf8].GetBoolean();

        /// <summary>
        /// Gets or sets the End-User's preferred postal address.
        /// </summary>
        public Address? Address
        {
            get
            {
                if (Payload != null && Payload.TryGetClaim(OidcClaims.AddressUtf8, out var address))
                {
                    return address.Deserialize<Address>();
                }

                return null;
            }
        }

        /// <summary>
        /// Gets or sets the time the End-User's information was last updated.
        /// </summary>
        public DateTime? UpdatedAt => ToDateTime(Payload?[OidcClaims.UpdatedAtUtf8]);

        private static DateTime? ToDateTime(object? token)
        {
            if (token is null)
            {
                return default;
            }

            return EpochTime.ToDateTime((long)token);
        }
    }
}