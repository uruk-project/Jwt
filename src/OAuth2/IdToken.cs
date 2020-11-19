// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;

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
        public long? AuthenticationTime => Payload?[OAuth2Claims.AuthTime.EncodedUtf8Bytes].GetInt64();

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string? Nonce => Payload?[OAuth2Claims.Nonce.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Authentication Context Class that the authentication performed satisfied.
        /// </summary>
        public string? AuthenticationContextClassReference => Payload?[OAuth2Claims.Acr.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the Authentication Methods References used in the authentication.
        /// </summary>
        public IReadOnlyList<string?>? AuthenticationMethodsReferences => Payload?[OAuth2Claims.Amr.EncodedUtf8Bytes].GetStringArray();

        /// <summary>
        /// Gets or sets the Authorized party - the party to which the ID Token was issued.
        /// </summary>
        public string? AuthorizedParty => Payload?[OAuth2Claims.Azp.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string? AccessTokenHash => Payload?[OAuth2Claims.AtHash.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string? CodeHash => Payload?[OAuth2Claims.CHash.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the Given name(s) or first name(s) of the End-User.
        /// </summary>
        public string? GivenName => Payload?[OAuth2Claims.GivenName.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the Surname(s) or last name(s) of the End-User.
        /// </summary>
        public string? FamilyName => Payload?[OAuth2Claims.FamilyName.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the middle name(s) of the End-User.
        /// </summary>
        public string? MiddleName => Payload?[OAuth2Claims.MiddleName.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the casual name of the End-User.
        /// </summary>
        public string? Nickname => Payload?[OAuth2Claims.Nickname.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the Shorthand name by which the End-User wishes to be referred to.
        /// </summary>
        public string? PreferredUsername => Payload?[OAuth2Claims.PreferredUsername.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the URL of the End-User's profile page.
        /// </summary>
        public string? Profile => Payload?[OAuth2Claims.Profile.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the URL of the End-User's profile picture.
        /// </summary>
        public string? Picture => Payload?[OAuth2Claims.Picture.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the URL of the End-User's Web page or blog.
        /// </summary>
        public string? Website => Payload?[OAuth2Claims.Website.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the End-User's preferred e-mail address.
        /// </summary>
        public string? Email => Payload?[OAuth2Claims.Email.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// True if the End-User's e-mail address has been verified; otherwise false.
        /// </summary>
        public bool? EmailVerified => Payload?[OAuth2Claims.EmailVerified.EncodedUtf8Bytes].GetBoolean();

        /// <summary>
        /// Gets or sets the End-User's gender. Values defined by this specification are female and male. 
        /// </summary>
        public string? Gender => Payload?[OAuth2Claims.Gender.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed.
        /// </summary>
        public string? Birthdate => Payload?[OAuth2Claims.Birthdate.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string? Zoneinfo => Payload?[OAuth2Claims.Zoneinfo.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the End-User's locale, represented as a BCP47 [RFC5646] language tag.
        /// </summary>
        public string? Locale => Payload?[OAuth2Claims.Locale.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// Gets or sets the End-User's preferred telephone number.
        /// </summary>
        public string? PhoneNumber => Payload?[OAuth2Claims.PhoneNumber.EncodedUtf8Bytes].GetString();

        /// <summary>
        /// True if the End-User's phone number has been verified; otherwise false.
        /// </summary>
        public bool? PhoneNumberVerified => Payload?[OAuth2Claims.PhoneNumberVerified.EncodedUtf8Bytes].GetBoolean();

        /// <summary>
        /// Gets or sets the End-User's preferred postal address.
        /// </summary>
        public Address? Address
        {
            get
            {
                if (Payload != null && Payload.TryGetClaim(OAuth2Claims.Address.EncodedUtf8Bytes, out var address))
                {
                    return address.Deserialize<Address>();
                }

                return null;
            }
        }

        /// <summary>
        /// Gets or sets the time the End-User's information was last updated.
        /// </summary>
        public DateTime? UpdatedAt => ToDateTime(Payload?[OAuth2Claims.UpdatedAt.EncodedUtf8Bytes]);

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