// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the claims contained in the JWT.
    /// </summary>
    public sealed class JwtPayload
    {
        internal const byte InvalidAudienceFlag = 0x01;
        internal const byte MissingAudienceFlag = 0x02;
        internal const byte InvalidIssuerFlag = 0x04;
        internal const byte MissingIssuerFlag = 0x08;
        internal const byte ExpiredFlag = 0x10;
        internal const byte MissingExpirationFlag = 0x20;
        internal const byte NotYetFlag = 0x40;

        private readonly JwtObject _inner;
        private byte _control;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class.
        /// </summary>
        /// <param name="inner"></param>
        public JwtPayload(JwtObject inner)
        {
            _inner = inner;
        }

        /// <summary>
        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public object? this[string key]
        {
            get
            {
                return _inner.TryGetValue(key, out var value) ? value.Value : null;
            }
        }

        /// <summary>
        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public object? this[ReadOnlySpan<byte> key]
        {
            get
            {
                return _inner.TryGetValue(key, out var value) ? value.Value : null;
            }
        }

        /// <summary>
        /// Gets the 'audience' claim as a list of strings.
        /// </summary>
        public IList<string> Aud
        {
            get
            {
                if (_inner.TryGetValue(Claims.AudUtf8, out var property) && !(property.Value is null))
                {
                    if (property.Type == JwtTokenType.Array)
                    {
                        var list = new List<string>();
                        var array = (JwtArray)property.Value;
                        for (int i = 0; i < array.Count; i++)
                        {
                            var value = array[i].Value;
                            if (!(value is null))
                            {
                                list.Add((string)value);
                            }
                        }

                        return list;
                    }
                    else if (property.Type == JwtTokenType.String)
                    {
                        return new List<string> { (string)property.Value };
                    }
                }

                return Array.Empty<string>();
            }
        }

        /// <summary>
        /// Gets the 'expiration time' claim.
        /// </summary>
        public long? Exp => _inner.TryGetValue(Claims.ExpUtf8, out var property) ? (long?)property.Value : null;

        /// <summary>
        /// Gets the 'JWT ID' claim.
        /// </summary>
        public string? Jti => _inner.TryGetValue(Claims.JtiUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the 'issued at' claim.
        /// </summary>
        public long? Iat => _inner.TryGetValue(Claims.IatUtf8, out var property) ? (long?)property.Value : null;

        /// <summary>
        /// Gets the 'issuer' claim.
        /// </summary>
        public string? Iss => _inner.TryGetValue(Claims.IssUtf8, out var property) ? (string?)property.Value : null;

        /// <summary>
        /// Gets the 'not before' claim.
        /// </summary>
        public long? Nbf => _inner.TryGetValue(Claims.NbfUtf8, out var property) ? (long?)property.Value : null;

        /// <summary>
        /// Gets the 'subject' claim.
        /// </summary>
        public string? Sub => _inner.TryGetValue(Claims.SubUtf8, out var property) ? (string?)property.Value : null;

        internal byte ValidationControl
        {
            get => _control;
            set => _control = value;
        }

        internal bool InvalidAudience
        {
            get => (_control & InvalidAudienceFlag) == InvalidAudienceFlag;
        }

        internal bool MissingAudience
        {
            get => (_control & MissingAudienceFlag) == MissingAudienceFlag;
        }

        internal bool InvalidIssuer
        {
            get => (_control & InvalidIssuerFlag) == InvalidIssuerFlag;
        }

        internal bool MissingIssuer
        {
            get => (_control & MissingIssuerFlag) == MissingIssuerFlag;
        }
        internal bool MissingExpirationTime
        {
            get => (_control & MissingExpirationFlag) == MissingExpirationFlag;
        }
        internal bool Expired
        {
            get => (_control & ExpiredFlag) == ExpiredFlag;
        }
        internal bool NotYetValid
        {
            get => (_control & NotYetFlag) == NotYetFlag;
        }

        /// <summary>
        /// Determines whether the <see cref="JwtPayload"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key)
        {
            return ContainsKey(Encoding.UTF8.GetBytes(key));
        }

        /// <summary>
        /// Determines whether the <see cref="JwtPayload"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(ReadOnlySpan<byte> key)
        {
            return _inner.ContainsKey(key);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetValue(ReadOnlySpan<byte> key, [NotNullWhen(true)] out JwtProperty value)
        {
            return _inner.TryGetValue(key, out value);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetValue(string key, out JwtProperty value)
        {
            return _inner.TryGetValue(key, out value);
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            return _inner.ToString();
        }
    }
}