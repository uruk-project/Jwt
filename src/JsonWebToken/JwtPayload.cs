// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using JsonWebToken.Internal;

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

        private static readonly JsonEncodedText AudEncodedText = JsonEncodedText.Encode("aud");
        private static readonly JsonEncodedText IssEncodedText = JsonEncodedText.Encode("iss");
        private static readonly JsonEncodedText JtiEncodedText = JsonEncodedText.Encode("jti");
        private static readonly JsonEncodedText ExpEncodedText = JsonEncodedText.Encode("exp");
        private static readonly JsonEncodedText IatEncodedText = JsonEncodedText.Encode("Iat");
        private static readonly JsonEncodedText NbfEncodedText = JsonEncodedText.Encode("nbf");
        private static readonly JsonEncodedText SubEncodedText = JsonEncodedText.Encode("sub");

        private JwtObject? _inner;
        private byte _control;
        private string[]? _aud;
        private string? _iss;
        private string? _jti;
        private string? _sub;
        private long? _exp;
        private long? _iat;
        private long? _nbf;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class.
        /// </summary>
        /// <param name="inner"></param>
        public JwtPayload(JwtObject inner)
        {
            _inner = inner;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class.
        /// </summary>
        public JwtPayload()
        {
        }

        internal JwtObject Inner => _inner ?? (_inner = new JwtObject());

        /// <summary>
        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public object? this[string key]
        {
            get
            {

                switch (key)
                {
                    case "iss":
                        return _iss;
                    case "jti":
                        return _jti;
                    case "sub":
                        return _sub;
                    case "exp":
                        return _exp;
                    case "_iat":
                        return _iat;
                    case "nbf":
                        return _nbf;
                    default:
                        if (_inner is null)
                        {
                            return null;
                        }

                        return _inner.TryGetValue(key, out var value) ? value.Value : null;
                }
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
                if (key.Length == 3)
                {
                    switch (IntegerMarshal.ReadUInt24(key))
                    {
                        case JwtPayloadParser.Aud:
                            return _aud;
                        case JwtPayloadParser.Iss:
                            return _iss;
                        case JwtPayloadParser.Jti:
                            return _jti;
                        case JwtPayloadParser.Exp:
                            return _exp;
                        case JwtPayloadParser.Iat:
                            return _iat;
                        case JwtPayloadParser.Nbf:
                            return _nbf;
                        case JwtPayloadParser.Sub:
                            return _sub;
                    }
                }

                if (_inner is null)
                {
                    return null;
                }

                return _inner.TryGetValue(key, out var value) ? value.Value : null;
            }
        }

        /// <summary>
        /// Gets the 'aud' claim as a list of strings.
        /// </summary>
        public string[] Aud
        {
            get => _aud ?? Array.Empty<string>();
            set => _aud = value;
        }

        /// <summary>
        /// Gets the 'expiration time' claim.
        /// </summary>
        public long? Exp
        {
            get => _exp;
            set => _exp = value;
        }

        /// <summary>
        /// Gets the 'JWT ID' claim.
        /// </summary>
        public string? Jti
        {
            get => _jti;
            set => _jti = value;
        }

        /// <summary>
        /// Gets the 'issued at' claim.
        /// </summary>
        public long? Iat
        {
            get => _iat;
            set => _iat = value;
        }

        /// <summary>
        /// Gets the 'issuer' claim.
        /// </summary>
        public string? Iss
        {
            get => _iss;
            set => _iss = value;
        }

        /// <summary>
        /// Gets the 'not before' claim.
        /// </summary>
        public long? Nbf
        {
            get => _nbf;
            set => _nbf = value;
        }

        /// <summary>
        /// Gets the 'subject' claim.
        /// </summary>
        public string? Sub
        {
            get => _sub;
            set => _sub = value;
        }

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
            return ContainsKey(Utf8.GetBytes(key));
        }

        /// <summary>
        /// Determines whether the <see cref="JwtPayload"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(ReadOnlySpan<byte> key)
        {
            switch (IntegerMarshal.ReadUInt24(key))
            {
                case JwtPayloadParser.Aud:
                    return !(_aud is null);
                case JwtPayloadParser.Iss:
                    return !(_iss is null);
                case JwtPayloadParser.Jti:
                    return !(_jti is null);
                case JwtPayloadParser.Exp:
                    return _exp.HasValue;
                case JwtPayloadParser.Iat:
                    return _iat.HasValue;
                case JwtPayloadParser.Nbf:
                    return _nbf.HasValue;
                case JwtPayloadParser.Sub:
                    return !(_sub is null);
            }

            if (_inner is null)
            {
                return false;
            }

            return _inner.ContainsKey(key);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetValue(ReadOnlySpan<byte> key, [NotNullWhen(true)] out JwtProperty value)
        {
            if (key.Length == 3)
            {
                switch (IntegerMarshal.ReadUInt24(key))
                {
                    case JwtPayloadParser.Aud:
                        if (!(_aud is null))
                        {
                            value = new JwtProperty(WellKnownProperty.Aud, new JwtArray(new List<string>(_aud)));
                            return true;
                        }
                        break;
                    case JwtPayloadParser.Iss:
                        if (!(_iss is null))
                        {
                            value = new JwtProperty(WellKnownProperty.Iss, _iss);
                            return true;
                        }
                        break;
                    case JwtPayloadParser.Jti:
                        if (!(_jti is null))
                        {
                            value = new JwtProperty(WellKnownProperty.Jti, _jti);
                            return true;
                        }
                        break;
                    case JwtPayloadParser.Exp:
                        if (_exp.HasValue)
                        {
                            value = new JwtProperty(WellKnownProperty.Exp, _exp.Value);
                            return true;
                        }
                        break;
                    case JwtPayloadParser.Iat:
                        if (_iat.HasValue)
                        {
                            value = new JwtProperty(WellKnownProperty.Iat, _iat.Value);
                            return true;
                        }
                        break;
                    case JwtPayloadParser.Nbf:
                        if (_nbf.HasValue)
                        {
                            value = new JwtProperty(WellKnownProperty.Nbf, _nbf.Value);
                            return true;
                        }
                        break;
                    case JwtPayloadParser.Sub:
                        if (!(_sub is null))
                        {
                            value = new JwtProperty(WellKnownProperty.Sub, _sub);
                            return true;
                        }
                        break;
                }
            }

            if (_inner is null)
            {
                value = default;
                return false;
            }

            return _inner.TryGetValue(key, out value);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetValue(string key, out JwtProperty value)
        {
            switch (key)
            {
                case "aud":
                    if (!(_aud is null))
                    {
                        value = new JwtProperty(WellKnownProperty.Aud, new JwtArray(new List<string>(_aud)));
                        return true;
                    }
                    break;
                case "iss":
                    if (!(_iss is null))
                    {
                        value = new JwtProperty(WellKnownProperty.Iss, _iss);
                        return true;
                    }
                    break;
                case "jti":
                    if (!(_jti is null))
                    {
                        value = new JwtProperty(WellKnownProperty.Jti, _jti);
                        return true;
                    }
                    break;
                case "exp":
                    if (_exp.HasValue)
                    {
                        value = new JwtProperty(WellKnownProperty.Exp, _exp.Value);
                        return true;
                    }
                    break;
                case "iat":
                    if (_iat.HasValue)
                    {
                        value = new JwtProperty(WellKnownProperty.Iat, _iat.Value);
                        return true;
                    }
                    break;
                case "nbf":
                    if (_nbf.HasValue)
                    {
                        value = new JwtProperty(WellKnownProperty.Nbf, _nbf.Value);
                        return true;
                    }
                    break;
                case "sub":
                    if (!(_sub is null))
                    {
                        value = new JwtProperty(WellKnownProperty.Sub, _sub);
                        return true;
                    }
                    break;
            }

            if (_inner is null)
            {
                value = default;
                return false;
            }

            return _inner.TryGetValue(key, out value);
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                if (!(_aud is null))
                {
                    if (_aud.Length == 1)
                    {
                        writer.WriteString(AudEncodedText, _aud[0]);
                    }
                    else
                    {
                        writer.WriteStartArray(AudEncodedText);
                        for (int i = 0; i < _aud.Length; i++)
                        {
                            writer.WriteStringValue(_aud[i]);
                        }

                        writer.WriteEndArray();
                    }
                }
                if (!(_iss is null))
                {
                    writer.WriteString(IssEncodedText, _iss);
                }
                if (!(_jti is null))
                {
                    writer.WriteString(JtiEncodedText, _jti);
                }
                if (_exp.HasValue)
                {
                    writer.WriteNumber(ExpEncodedText, _exp.Value);
                }
                if (_iat.HasValue)
                {
                    writer.WriteNumber(IatEncodedText, _iat.Value);
                }
                if (_nbf.HasValue)
                {
                    writer.WriteNumber(NbfEncodedText, _nbf.Value);
                }
                if (!(_sub is null))
                {
                    writer.WriteString(SubEncodedText, _sub);
                }
                if (!(_inner is null))
                {
                    _inner.WriteTo(writer);
                }

                writer.WriteEndObject();
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }
    }
}