// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace JsonWebToken
{
    public class IdTokenDescriptor : JwsDescriptor
    {
        private static readonly ReadOnlyDictionary<string, JwtTokenType[]> IdTokenRequiredOidcClaims = new ReadOnlyDictionary<string, JwtTokenType[]>(
            new Dictionary<string, JwtTokenType[]>
            {
                { Claims.Iss, new [] { JwtTokenType.String} },
                { Claims.Sub, new [] { JwtTokenType.String} },
                { Claims.Aud, new [] { JwtTokenType.String, JwtTokenType.Array} },
                { Claims.Exp, new [] { JwtTokenType.Integer } },
                { Claims.Iat, new [] { JwtTokenType.Integer } }
            });

        private static readonly ReadOnlyDictionary<string, JwtTokenType[]> IdTokenRequiredOidcClaimsImplicit = new ReadOnlyDictionary<string, JwtTokenType[]>(
            new Dictionary<string, JwtTokenType[]>
            {
                { Claims.Iss, new [] { JwtTokenType.String} },
                { Claims.Sub, new [] { JwtTokenType.String} },
                { Claims.Aud, new [] { JwtTokenType.String, JwtTokenType.Array} },
                { Claims.Exp, new [] { JwtTokenType.Integer } },
                { Claims.Iat, new [] { JwtTokenType.Integer } },
                { OidcClaims.Nonce, new [] { JwtTokenType.String} },
                { OidcClaims.AtHash, new [] { JwtTokenType.String } }
            });

        private static readonly ReadOnlyDictionary<string, JwtTokenType[]> IdTokenRequiredOidcClaimsHybrid = new ReadOnlyDictionary<string, JwtTokenType[]>(
            new Dictionary<string, JwtTokenType[]>
            {
                { Claims.Iss, new [] { JwtTokenType.String } },
                { Claims.Sub, new [] { JwtTokenType.String } },
                { Claims.Aud, new [] { JwtTokenType.String, JwtTokenType.Array} },
                { Claims.Exp, new [] { JwtTokenType.Integer } },
                { Claims.Iat, new [] { JwtTokenType.Integer } },
                { OidcClaims.Nonce, new [] { JwtTokenType.String } },
                { OidcClaims.AtHash, new [] { JwtTokenType.String } },
                { OidcClaims.CHash, new [] { JwtTokenType.String } }
            });

        public IdTokenDescriptor()
                    : base()
        {
        }

        public IdTokenDescriptor(HeaderDescriptor header, PayloadDescriptor payload)
            : base(header, payload)
        {
        }

        public IdTokenDescriptor(PayloadDescriptor payload)
            : base(new HeaderDescriptor(), payload)
        {
        }

        public OpenIdConnectFlow Flow { get; set; }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public DateTime? AuthenticationTime
        {
            get => GetDateTime(OidcClaims.AuthTime);
            set => AddClaim(OidcClaims.AuthTime, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Nonce
        {
            get => GetStringClaim(OidcClaims.Nonce);
            set => AddClaim(OidcClaims.Nonce, value);
        }

        /// <summary>
        /// Authentication Context Class that the authentication performed satisfied.
        /// </summary>
        public string AuthenticationContextClassReference
        {
            get => GetStringClaim(OidcClaims.Acr);
            set => AddClaim(OidcClaims.Acr, value);
        }

        /// <summary>
        /// Gets or sets the Authentication Methods References used in the authentication.
        /// </summary>
        public IReadOnlyList<string> AuthenticationMethodsReferences => GetListClaims<string>(OidcClaims.Amr);

        public void AddAuthenticationMethodsReferences(string acr)
        {
            AddClaim(OidcClaims.Acr, acr);
        }

        /// <summary>
        /// Gets or sets the Authorized party - the party to which the ID Token was issued.
        /// </summary>
        public string AuthorizedParty
        {
            get => GetStringClaim(OidcClaims.Azp);
            set => AddClaim(OidcClaims.Azp, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string AccessTokenHash
        {
            get => GetStringClaim(OidcClaims.AtHash);
            set => AddClaim(OidcClaims.AtHash, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string CodeHash
        {
            get => GetStringClaim(OidcClaims.CHash);
            set => AddClaim(OidcClaims.CHash, value);
        }

        protected override ReadOnlyDictionary<string, JwtTokenType[]> RequiredClaims
        {
            get
            {
                switch (Flow)
                {
                    case OpenIdConnectFlow.AuthorizationCode:
                        return IdTokenRequiredOidcClaims;
                    case OpenIdConnectFlow.Implicit:
                        return IdTokenRequiredOidcClaimsImplicit;
                    case OpenIdConnectFlow.Hybrid:
                        return IdTokenRequiredOidcClaimsHybrid;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(Flow));
                }
            }
        }

        /// <summary>
        /// Gets or sets the Given name(s) or first name(s) of the End-User.
        /// </summary>
        public string GivenName
        {
            get => GetStringClaim(OidcClaims.GivenName);
            set => AddClaim(OidcClaims.GivenName, value);
        }

        /// <summary>
        /// Gets or sets the Surname(s) or last name(s) of the End-User.
        /// </summary>
        public string FamilyName
        {
            get => GetStringClaim(OidcClaims.FamilyName);
            set => AddClaim(OidcClaims.FamilyName, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string MiddleName
        {
            get => GetStringClaim(OidcClaims.MiddleName);
            set => AddClaim(OidcClaims.MiddleName, value);
        }

        /// <summary>
        /// Gets or sets the Casual name of the End-User.
        /// </summary>
        public string Nickname
        {
            get => GetStringClaim(OidcClaims.Nickname);
            set => AddClaim(OidcClaims.Nickname, value);
        }

        /// <summary>
        /// Gets or sets the Shorthand name by which the End-User wishes to be referred to.
        /// </summary>
        public string PreferredUsername
        {
            get => GetStringClaim(OidcClaims.PreferredUsername);
            set => AddClaim(OidcClaims.PreferredUsername, value);
        }

        /// <summary>
        /// Gets or sets the URL of the End-User's profile page.
        /// </summary>
        public string Profile
        {
            get => GetStringClaim(OidcClaims.Profile);
            set => AddClaim(OidcClaims.Profile, value);
        }

        /// <summary>
        /// Gets or sets the URL of the End-User's profile picture.
        /// </summary>
        public string Picture
        {
            get => GetStringClaim(OidcClaims.Picture);
            set => AddClaim(OidcClaims.Picture, value);
        }

        /// <summary>
        /// Gets or sets the URL of the End-User's Web page or blog.
        /// </summary>
        public string Website
        {
            get => GetStringClaim(OidcClaims.Website);
            set => AddClaim(OidcClaims.Website, value);
        }

        /// <summary>
        /// Gets or sets the End-User's preferred e-mail address.
        /// </summary>
        public string Email
        {
            get => GetStringClaim(OidcClaims.Email);
            set => AddClaim(OidcClaims.Email, value);
        }

        /// <summary>
        /// True if the End-User's e-mail address has been verified; otherwise false.
        /// </summary>
        public bool? EmailVerified
        {
            get => GetBoolClaim(OidcClaims.EmailVerified);
            set => AddClaim(OidcClaims.EmailVerified, value);
        }

        /// <summary>
        /// Gets or sets the End-User's gender. Values defined by this specification are female and male. 
        /// </summary>
        public string Gender
        {
            get => GetStringClaim(OidcClaims.Gender);
            set => AddClaim(OidcClaims.Gender, value);
        }

        /// <summary>
        /// Gets or sets the End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed.
        /// </summary>
        public string Birthdate
        {
            get => GetStringClaim(OidcClaims.Birthdate);
            set => AddClaim(OidcClaims.Birthdate, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Zoneinfo
        {
            get => GetStringClaim(OidcClaims.Zoneinfo);
            set => AddClaim(OidcClaims.Zoneinfo, value);
        }

        /// <summary>
        /// Gets or sets the End-User's locale, represented as a BCP47 [RFC5646] language tag.
        /// </summary>
        public string Locale
        {
            get => GetStringClaim(OidcClaims.Locale);
            set => AddClaim(OidcClaims.Locale, value);
        }

        /// <summary>
        /// Gets or sets the End-User's preferred telephone number.
        /// </summary>
        public string PhoneNumber
        {
            get => GetStringClaim(OidcClaims.PhoneNumber);
            set => AddClaim(OidcClaims.PhoneNumber, value);
        }

        /// <summary>
        /// True if the End-User's phone number has been verified; otherwise false.
        /// </summary>
        public bool? PhoneNumberVerified
        {
            get => GetBoolClaim(OidcClaims.PhoneNumberVerified);
            set => AddClaim(OidcClaims.PhoneNumberVerified, value);
        }

        /// <summary>
        /// Gets or sets the End-User's preferred postal address.
        /// </summary>
        public Address Address
        {
            get
            {
                var address = GetStringClaim(OidcClaims.Address);
                return string.IsNullOrEmpty(address) ? null : Address.FromJson(address);
            }

            set => AddClaim(OidcClaims.Address, JObject.FromObject(value));
        }

        /// <summary>
        /// Gets or sets the time the End-User's information was last updated.
        /// </summary>
        public DateTime? UpdatedAt
        {
            get => GetDateTime(OidcClaims.UpdatedAt);
            set => AddClaim(OidcClaims.UpdatedAt, value);
        }
    }
}
