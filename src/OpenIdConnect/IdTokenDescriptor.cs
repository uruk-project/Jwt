// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class IdTokenDescriptor : JwsDescriptor
    {
        public IdTokenDescriptor()
                    : base()
        {
        }

        public IdTokenDescriptor(JwtObject header, JwtObject payload)
            : base(header, payload)
        {
        }

        public IdTokenDescriptor(JwtObject payload)
            : base(new JwtObject(), payload)
        {
        }

        public OpenIdConnectFlow Flow { get; set; }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public DateTime? AuthenticationTime
        {
            get => GetDateTime(OidcClaims.AuthTimeUtf8);
            set => AddClaim(OidcClaims.AuthTimeUtf8, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Nonce
        {
            get => GetStringClaim(OidcClaims.NonceUtf8);
            set => AddClaim(OidcClaims.NonceUtf8, value);
        }

        /// <summary>
        /// Authentication Context Class that the authentication performed satisfied.
        /// </summary>
        public string AuthenticationContextClassReference
        {
            get => GetStringClaim(OidcClaims.AcrUtf8);
            set => AddClaim(OidcClaims.AcrUtf8, value);
        }

        /// <summary>
        /// Gets or sets the Authentication Methods References used in the authentication.
        /// </summary>
        public IReadOnlyList<string> AuthenticationMethodsReferences => GetListClaims<string>(OidcClaims.AmrUtf8);

        public void AddAuthenticationMethodsReferences(string acr)
        {
            AddClaim(OidcClaims.AcrUtf8, acr);
        }

        /// <summary>
        /// Gets or sets the Authorized party - the party to which the ID Token was issued.
        /// </summary>
        public string AuthorizedParty
        {
            get => GetStringClaim(OidcClaims.AzpUtf8);
            set => AddClaim(OidcClaims.AzpUtf8, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string AccessTokenHash
        {
            get => GetStringClaim(OidcClaims.AtHashUtf8);
            set => AddClaim(OidcClaims.AtHashUtf8, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string CodeHash
        {
            get => GetStringClaim(OidcClaims.CHashUtf8);
            set => AddClaim(OidcClaims.CHashUtf8, value);
        }

        /// <summary>
        /// Gets or sets the Given name(s) or first name(s) of the End-User.
        /// </summary>
        public string GivenName
        {
            get => GetStringClaim(OidcClaims.GivenNameUtf8);
            set => AddClaim(OidcClaims.GivenNameUtf8, value);
        }

        /// <summary>
        /// Gets or sets the Surname(s) or last name(s) of the End-User.
        /// </summary>
        public string FamilyName
        {
            get => GetStringClaim(OidcClaims.FamilyNameUtf8);
            set => AddClaim(OidcClaims.FamilyNameUtf8, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string MiddleName
        {
            get => GetStringClaim(OidcClaims.MiddleNameUtf8);
            set => AddClaim(OidcClaims.MiddleNameUtf8, value);
        }

        /// <summary>
        /// Gets or sets the Casual name of the End-User.
        /// </summary>
        public string Nickname
        {
            get => GetStringClaim(OidcClaims.NicknameUtf8);
            set => AddClaim(OidcClaims.NicknameUtf8, value);
        }

        /// <summary>
        /// Gets or sets the Shorthand name by which the End-User wishes to be referred to.
        /// </summary>
        public string PreferredUsername
        {
            get => GetStringClaim(OidcClaims.PreferredUsernameUtf8);
            set => AddClaim(OidcClaims.PreferredUsernameUtf8, value);
        }

        /// <summary>
        /// Gets or sets the URL of the End-User's profile page.
        /// </summary>
        public string Profile
        {
            get => GetStringClaim(OidcClaims.ProfileUtf8);
            set => AddClaim(OidcClaims.ProfileUtf8, value);
        }

        /// <summary>
        /// Gets or sets the URL of the End-User's profile picture.
        /// </summary>
        public string Picture
        {
            get => GetStringClaim(OidcClaims.PictureUtf8);
            set => AddClaim(OidcClaims.PictureUtf8, value);
        }

        /// <summary>
        /// Gets or sets the URL of the End-User's Web page or blog.
        /// </summary>
        public string Website
        {
            get => GetStringClaim(OidcClaims.WebsiteUtf8);
            set => AddClaim(OidcClaims.WebsiteUtf8, value);
        }

        /// <summary>
        /// Gets or sets the End-User's preferred e-mail address.
        /// </summary>
        public string Email
        {
            get => GetStringClaim(OidcClaims.EmailUtf8);
            set => AddClaim(OidcClaims.EmailUtf8, value);
        }

        /// <summary>
        /// True if the End-User's e-mail address has been verified; otherwise false.
        /// </summary>
        public bool? EmailVerified
        {
            get => GetBoolClaim(OidcClaims.EmailVerifiedUtf8);
            set => AddClaim(OidcClaims.EmailVerifiedUtf8, value);
        }

        /// <summary>
        /// Gets or sets the End-User's gender. Values defined by this specification are female and male. 
        /// </summary>
        public string Gender
        {
            get => GetStringClaim(OidcClaims.GenderUtf8);
            set => AddClaim(OidcClaims.GenderUtf8, value);
        }

        /// <summary>
        /// Gets or sets the End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed.
        /// </summary>
        public string Birthdate
        {
            get => GetStringClaim(OidcClaims.BirthdateUtf8);
            set => AddClaim(OidcClaims.BirthdateUtf8, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Zoneinfo
        {
            get => GetStringClaim(OidcClaims.ZoneinfoUtf8);
            set => AddClaim(OidcClaims.ZoneinfoUtf8, value);
        }

        /// <summary>
        /// Gets or sets the End-User's locale, represented as a BCP47 [RFC5646] language tag.
        /// </summary>
        public string Locale
        {
            get => GetStringClaim(OidcClaims.LocaleUtf8);
            set => AddClaim(OidcClaims.LocaleUtf8, value);
        }

        /// <summary>
        /// Gets or sets the End-User's preferred telephone number.
        /// </summary>
        public string PhoneNumber
        {
            get => GetStringClaim(OidcClaims.PhoneNumberUtf8);
            set => AddClaim(OidcClaims.PhoneNumberUtf8, value);
        }

        /// <summary>
        /// True if the End-User's phone number has been verified; otherwise false.
        /// </summary>
        public bool? PhoneNumberVerified
        {
            get => GetBoolClaim(OidcClaims.PhoneNumberVerifiedUtf8);
            set => AddClaim(OidcClaims.PhoneNumberVerifiedUtf8, value);
        }

        /// <summary>
        /// Gets or sets the End-User's preferred postal address.
        /// </summary>
        public Address Address
        {
            get
            {
                var address = GetStringClaim(OidcClaims.AddressUtf8);
                return string.IsNullOrEmpty(address) ? null : Address.FromJson(address);
            }

            set
            {
                var address = new JwtObject();
                if (value.Formatted != null)
                {
                    address.Add(new JwtProperty(OidcClaims.FormattedUtf8, value.Formatted));
                }

                if (value.StreetAddress != null)
                {
                    address.Add(new JwtProperty(OidcClaims.StreetAddressUtf8, value.StreetAddress));
                }

                if (value.Locality != null)
                {
                    address.Add(new JwtProperty(OidcClaims.LocalityUtf8, value.Locality));
                }

                if (value.Region != null)
                {
                    address.Add(new JwtProperty(OidcClaims.RegionUtf8, value.Region));
                }

                if (value.PostalCode != null)
                {
                    address.Add(new JwtProperty(OidcClaims.PostalCodeUtf8, value.PostalCode));
                }

                if (value.Country != null)
                {
                    address.Add(new JwtProperty(OidcClaims.CountryUtf8, value.Country));
                }
            }
        }

        /// <summary>
        /// Gets or sets the time the End-User's information was last updated.
        /// </summary>
        public DateTime? UpdatedAt
        {
            get => GetDateTime(OidcClaims.UpdatedAtUtf8);
            set => AddClaim(OidcClaims.UpdatedAtUtf8, value);
        }

        public override void Validate()
        {
            ValidateHeader(HeaderParameters.AlgUtf8, new[] { JwtTokenType.String, JwtTokenType.Utf8String });

            RequireClaim(Claims.IssUtf8, JwtTokenType.String);
            RequireClaim(Claims.SubUtf8, JwtTokenType.String);
            ValidateClaim(Claims.AudUtf8, new[] { JwtTokenType.String, JwtTokenType.Array });
            RequireClaim(Claims.ExpUtf8, JwtTokenType.Integer);
            RequireClaim(Claims.IatUtf8, JwtTokenType.Integer);
            if (Flow == OpenIdConnectFlow.Implicit)
            {
                RequireClaim(OidcClaims.NonceUtf8, JwtTokenType.String);
                RequireClaim(OidcClaims.AtHashUtf8, JwtTokenType.String);
            }
            else if (Flow == OpenIdConnectFlow.Hybrid)
            {
                RequireClaim(OidcClaims.NonceUtf8, JwtTokenType.String);
                RequireClaim(OidcClaims.AtHashUtf8, JwtTokenType.String);
                RequireClaim(OidcClaims.CHashUtf8, JwtTokenType.String);
            }
        }
    }
}
