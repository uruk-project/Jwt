// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Data;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the claims contained in the JWT.
    /// </summary>
    public sealed class JwtPayloadDocument : IDisposable
    {
        internal const byte InvalidAudienceFlag = 0x01;
        internal const byte MissingAudienceFlag = 0x02;
        internal const byte InvalidIssuerFlag = 0x04;
        internal const byte MissingIssuerFlag = 0x08;
        internal const byte ExpiredFlag = 0x10;
        internal const byte MissingExpirationFlag = 0x20;
        internal const byte NotYetFlag = 0x40;

        private JsonDocument _inner;
        private byte _control;
        //private string[]? _aud;
        //private string? _iss;
        //private string? _jti;
        //private string? _sub;
        //private long? _exp;
        //private long? _iat;
        //private long? _nbf;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class.
        /// </summary>
        /// <param name="inner"></param>
        public JwtPayloadDocument(JsonDocument inner)
        {
            _inner = inner;
        }

        /// <summary>
        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        //public object? this[string key]
        //{
        //    get
        //    {

        //        switch (key)
        //        {
        //            case "iss":
        //                return _iss;
        //            case "jti":
        //                return _jti;
        //            case "sub":
        //                return _sub;
        //            case "exp":
        //                return _exp;
        //            case "_iat":
        //                return _iat;
        //            case "nbf":
        //                return _nbf;
        //            default:
        //                if (_inner is null)
        //                {
        //                    return null;
        //                }

        //                return _inner.TryGetValue(key, out var value) ? value.Value : null;
        //        }
        //    }
        //}

        /// <summary>
        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        //public object? this[ReadOnlySpan<byte> key]
        //{
        //    get
        //    {
        //        if (key.Length == 3)
        //        {
        //            switch (IntegerMarshal.ReadUInt24(key))
        //            {
        //                case JwtPayloadParser.Aud:
        //                    return _aud;
        //                case JwtPayloadParser.Iss:
        //                    return _iss;
        //                case JwtPayloadParser.Jti:
        //                    return _jti;
        //                case JwtPayloadParser.Exp:
        //                    return _exp;
        //                case JwtPayloadParser.Iat:
        //                    return _iat;
        //                case JwtPayloadParser.Nbf:
        //                    return _nbf;
        //                case JwtPayloadParser.Sub:
        //                    return _sub;
        //            }
        //        }

        //        if (_inner is null)
        //        {
        //            return null;
        //        }

        //        return _inner.RootElement.TryGetProperty(key, out var value) ? value.Value : null;
        //    }
        //}

        /// <summary>
        /// Gets the 'aud' claim as a list of strings.
        /// </summary>
        public string[] Aud
        {
            get => _inner.RootElement.TryGetProperty(Claims.AudUtf8, out var property) ? property.EnumerateArray().Select(e => e.GetString()).ToArray() : null;
        }

        /// <summary>
        /// Gets the 'expiration time' claim.
        /// </summary>
        public long? Exp
        {
            get => _inner.RootElement.TryGetProperty(Claims.ExpUtf8, out var property) ? property.GetInt64() : default;
        }

        /// <summary>
        /// Gets the 'JWT ID' claim.
        /// </summary>
        public string? Jti
        {
            get => _inner.RootElement.TryGetProperty(Claims.JtiUtf8, out var property) ? property.GetString() : default;
        }

        /// <summary>
        /// Gets the 'issued at' claim.
        /// </summary>
        public long? Iat
        {
            get => _inner.RootElement.TryGetProperty(Claims.IatUtf8, out var property) ? property.GetInt64() : default;
        }

        /// <summary>
        /// Gets the 'issuer' claim.
        /// </summary>
        public string? Iss
        {
            get => _inner.RootElement.TryGetProperty(Claims.IssUtf8, out var property) ? property.GetString() : default;
        }

        /// <summary>
        /// Gets the 'not before' claim.
        /// </summary>
        public long? Nbf
        {
            get => _inner.RootElement.TryGetProperty(Claims.NbfUtf8, out var property) ? property.GetInt64() : default;
        }

        /// <summary>
        /// Gets the 'subject' claim.
        /// </summary>
        public string? Sub
        {
            get => _inner.RootElement.TryGetProperty(Claims.SubUtf8, out var property) ? property.GetString() : default;
        }

        //internal byte ValidationControl
        //{
        //    get => _control;
        //    set => _control = value;
        //}

        //internal bool InvalidAudience
        //{
        //    get => (_control & InvalidAudienceFlag) == InvalidAudienceFlag;
        //}

        //internal bool MissingAudience
        //{
        //    get => (_control & MissingAudienceFlag) == MissingAudienceFlag;
        //}

        //internal bool InvalidIssuer
        //{
        //    get => (_control & InvalidIssuerFlag) == InvalidIssuerFlag;
        //}

        //internal bool MissingIssuer
        //{
        //    get => (_control & MissingIssuerFlag) == MissingIssuerFlag;
        //}
        //internal bool MissingExpirationTime
        //{
        //    get => (_control & MissingExpirationFlag) == MissingExpirationFlag;
        //}
        //internal bool Expired
        //{
        //    get => (_control & ExpiredFlag) == ExpiredFlag;
        //}
        //internal bool NotYetValid
        //{
        //    get => (_control & NotYetFlag) == NotYetFlag;
        //}

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
            //switch (IntegerMarshal.ReadUInt24(key))
            //{
            //    case JwtPayloadParser.Aud:
            //        return !(_aud is null);
            //    case JwtPayloadParser.Iss:
            //        return !(_iss is null);
            //    case JwtPayloadParser.Jti:
            //        return !(_jti is null);
            //    case JwtPayloadParser.Exp:
            //        return _exp.HasValue;
            //    case JwtPayloadParser.Iat:
            //        return _iat.HasValue;
            //    case JwtPayloadParser.Nbf:
            //        return _nbf.HasValue;
            //    case JwtPayloadParser.Sub:
            //        return !(_sub is null);
            //}

            //if (_inner is null)
            //{
            //    return false;
            //}

            return _inner.RootElement.TryGetProperty(key, out _);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetValue(ReadOnlySpan<byte> key, [NotNullWhen(true)] out JsonElement value)
        {
            //if (key.Length == 3)
            //{
            //    switch (IntegerMarshal.ReadUInt24(key))
            //    {
            //        case JwtPayloadParser.Aud:
            //            if (!(_aud is null))
            //            {
            //                value = new JwtProperty(WellKnownProperty.Aud, new JwtArray(new List<string>(_aud)));
            //                return true;
            //            }
            //            break;
            //        case JwtPayloadParser.Iss:
            //            if (!(_iss is null))
            //            {
            //                value = new JwtProperty(WellKnownProperty.Iss, _iss);
            //                return true;
            //            }
            //            break;
            //        case JwtPayloadParser.Jti:
            //            if (!(_jti is null))
            //            {
            //                value = new JwtProperty(WellKnownProperty.Jti, _jti);
            //                return true;
            //            }
            //            break;
            //        case JwtPayloadParser.Exp:
            //            if (_exp.HasValue)
            //            {
            //                value = new JwtProperty(WellKnownProperty.Exp, _exp.Value);
            //                return true;
            //            }
            //            break;
            //        case JwtPayloadParser.Iat:
            //            if (_iat.HasValue)
            //            {
            //                value = new JwtProperty(WellKnownProperty.Iat, _iat.Value);
            //                return true;
            //            }
            //            break;
            //        case JwtPayloadParser.Nbf:
            //            if (_nbf.HasValue)
            //            {
            //                value = new JwtProperty(WellKnownProperty.Nbf, _nbf.Value);
            //                return true;
            //            }
            //            break;
            //        case JwtPayloadParser.Sub:
            //            if (!(_sub is null))
            //            {
            //                value = new JwtProperty(WellKnownProperty.Sub, _sub);
            //                return true;
            //            }
            //            break;
            //    }
            //}

            //if (_inner is null)
            //{
            //    value = default;
            //    return false;
            //}

            return _inner.RootElement.TryGetProperty(key, out value);
        }

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetValue(string key, out JsonElement value)
        {
            //switch (key)
            //{
            //    case "aud":
            //        if (!(_aud is null))
            //        {
            //            value = new JwtProperty(WellKnownProperty.Aud, new JwtArray(new List<string>(_aud)));
            //            return true;
            //        }
            //        break;
            //    case "iss":
            //        if (!(_iss is null))
            //        {
            //            value = new JwtProperty(WellKnownProperty.Iss, _iss);
            //            return true;
            //        }
            //        break;
            //    case "jti":
            //        if (!(_jti is null))
            //        {
            //            value = new JwtProperty(WellKnownProperty.Jti, _jti);
            //            return true;
            //        }
            //        break;
            //    case "exp":
            //        if (_exp.HasValue)
            //        {
            //            value = new JwtProperty(WellKnownProperty.Exp, _exp.Value);
            //            return true;
            //        }
            //        break;
            //    case "iat":
            //        if (_iat.HasValue)
            //        {
            //            value = new JwtProperty(WellKnownProperty.Iat, _iat.Value);
            //            return true;
            //        }
            //        break;
            //    case "nbf":
            //        if (_nbf.HasValue)
            //        {
            //            value = new JwtProperty(WellKnownProperty.Nbf, _nbf.Value);
            //            return true;
            //        }
            //        break;
            //    case "sub":
            //        if (!(_sub is null))
            //        {
            //            value = new JwtProperty(WellKnownProperty.Sub, _sub);
            //            return true;
            //        }
            //        break;
            //}

            //if (_inner is null)
            //{
            //    value = default;
            //    return false;
            //}

            return _inner.RootElement.TryGetProperty(key, out value);
        }

        /// <inheritsdoc />
        public override string ToString()
        {
            using var bufferWriter = new PooledByteBufferWriter();
            using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
            {
                _inner.WriteTo(writer);
                //writer.WriteStartObject();
                //if (!(_aud is null))
                //{
                //    if (_aud.Length == 1)
                //    {
                //        writer.WriteString(Claims.AudUtf8, _aud[0]);
                //    }
                //    else
                //    {
                //        writer.WriteStartArray(Claims.AudUtf8);
                //        for (int i = 0; i < _aud.Length; i++)
                //        {
                //            writer.WriteStringValue(_aud[i]);
                //        }

                //        writer.WriteEndArray();
                //    }
                //}
                //if (!(_iss is null))
                //{
                //    writer.WriteString(Claims.IssUtf8, _iss);
                //}
                //if (!(_jti is null))
                //{
                //    writer.WriteString(Claims.JtiUtf8, _jti);
                //}
                //if (_exp.HasValue)
                //{
                //    writer.WriteNumber(Claims.ExpUtf8, _exp.Value);
                //}
                //if (_iat.HasValue)
                //{
                //    writer.WriteNumber(Claims.IatUtf8, _iat.Value);
                //}
                //if (_nbf.HasValue)
                //{
                //    writer.WriteNumber(Claims.NbfUtf8, _nbf.Value);
                //}
                //if (!(_sub is null))
                //{
                //    writer.WriteString(Claims.SubUtf8, _sub);
                //}
                //if (!(_inner is null))
                //{
                //    _inner.WriteTo(writer);
                //}

                //writer.WriteEndObject();
            }

            var input = bufferWriter.WrittenSpan;
            return Utf8.GetString(input);
        }

        public void Dispose()
        {
            _inner.Dispose();
        }
    }
}