// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;
using System.Threading;
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

        internal JwtObject Inner => _inner ??= new JwtObject();

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
                    switch ((JwtClaims)IntegerMarshal.ReadUInt24(key))
                    {
                        case JwtClaims.Aud:
                            return _aud;
                        case JwtClaims.Iss:
                            return _iss;
                        case JwtClaims.Jti:
                            return _jti;
                        case JwtClaims.Exp:
                            return _exp;
                        case JwtClaims.Iat:
                            return _iat;
                        case JwtClaims.Nbf:
                            return _nbf;
                        case JwtClaims.Sub:
                            return _sub;
                    }
                }

                if (_inner is null)
                {
                    return null;
                }

                return _inner.TryGetProperty(key, out var value) ? value.Value : null;
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
            switch ((JwtClaims)IntegerMarshal.ReadUInt24(key))
            {
                case JwtClaims.Aud:
                    return !(_aud is null);
                case JwtClaims.Iss:
                    return !(_iss is null);
                case JwtClaims.Jti:
                    return !(_jti is null);
                case JwtClaims.Exp:
                    return _exp.HasValue;
                case JwtClaims.Iat:
                    return _iat.HasValue;
                case JwtClaims.Nbf:
                    return _nbf.HasValue;
                case JwtClaims.Sub:
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
                switch ((JwtClaims)IntegerMarshal.ReadUInt24(key))
                {
                    case JwtClaims.Aud:
                        if (!(_aud is null))
                        {
                            value = new JwtProperty(WellKnownProperty.Aud, new JwtArray(new List<string>(_aud)));
                            return true;
                        }
                        break;
                    case JwtClaims.Iss:
                        if (!(_iss is null))
                        {
                            value = new JwtProperty(WellKnownProperty.Iss, _iss);
                            return true;
                        }
                        break;
                    case JwtClaims.Jti:
                        if (!(_jti is null))
                        {
                            value = new JwtProperty(WellKnownProperty.Jti, _jti);
                            return true;
                        }
                        break;
                    case JwtClaims.Exp:
                        if (_exp.HasValue)
                        {
                            value = new JwtProperty(WellKnownProperty.Exp, _exp.Value);
                            return true;
                        }
                        break;
                    case JwtClaims.Iat:
                        if (_iat.HasValue)
                        {
                            value = new JwtProperty(WellKnownProperty.Iat, _iat.Value);
                            return true;
                        }
                        break;
                    case JwtClaims.Nbf:
                        if (_nbf.HasValue)
                        {
                            value = new JwtProperty(WellKnownProperty.Nbf, _nbf.Value);
                            return true;
                        }
                        break;
                    case JwtClaims.Sub:
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

            return _inner.TryGetProperty(key, out value);
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
                        writer.WriteString(Claims.AudUtf8, _aud[0]);
                    }
                    else
                    {
                        writer.WriteStartArray(Claims.AudUtf8);
                        for (int i = 0; i < _aud.Length; i++)
                        {
                            writer.WriteStringValue(_aud[i]);
                        }

                        writer.WriteEndArray();
                    }
                }
                if (!(_iss is null))
                {
                    writer.WriteString(Claims.IssUtf8, _iss);
                }
                if (!(_jti is null))
                {
                    writer.WriteString(Claims.JtiUtf8, _jti);
                }
                if (_exp.HasValue)
                {
                    writer.WriteNumber(Claims.ExpUtf8, _exp.Value);
                }
                if (_iat.HasValue)
                {
                    writer.WriteNumber(Claims.IatUtf8, _iat.Value);
                }
                if (_nbf.HasValue)
                {
                    writer.WriteNumber(Claims.NbfUtf8, _nbf.Value);
                }
                if (!(_sub is null))
                {
                    writer.WriteString(Claims.SubUtf8, _sub);
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

    /// <summary>
    /// Represents the claims contained in the JWT.
    /// </summary>
    public sealed class JwtPayloadX : IEnumerable
    {
        private readonly MemberStore _payload;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class.
        /// </summary>
        public JwtPayloadX()
        {
            _payload = new MemberStore();
        }

        internal MemberStore Inner => _payload;

        internal void CopyTo(JwtPayloadX destination)
        {
            _payload.CopyTo(destination._payload);
        }

        /// <summary>
        /// Gets or sets the value of the 'sub' claim.
        /// </summary>
        public void AddSub(string value)
            => _payload.TryAdd(new JwtMemberX(Claims.Sub, value));

        /// <summary>
        /// Gets or sets the value of the 'jti' claim.
        /// </summary>
        public void AddJti(string value)
            => _payload.TryAdd(new JwtMemberX(Claims.Jti, value));

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public void AddAud(string value)
            => _payload.TryAdd(new JwtMemberX(Claims.Aud, value));

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public void AddAud(string[] value)
            => _payload.TryAdd(new JwtMemberX(Claims.Aud, value));

        /// <summary>
        /// Gets or sets the value of the 'exp' claim.
        /// </summary>
        public void AddExp(long value)
            => _payload.TryAdd(new JwtMemberX(Claims.Exp, value));

        /// <summary>
        /// Gets or sets the value of the 'iss' claim.
        /// </summary>
        public void AddIss(string value)
            => _payload.TryAdd(new JwtMemberX(Claims.Iss, value));

        /// <summary>
        /// Gets or sets the value of the 'iat' claim.
        /// </summary>
        public void AddIat(string value)
            => _payload.TryAdd(new JwtMemberX(Claims.Iat, value));

        /// <summary>
        ///Gets or sets the value of the 'nbf' claim.
        /// </summary>
        public void AddNbf(long value)
            => _payload.TryAdd(new JwtMemberX(Claims.Nbf, value));

        /// <summary>
        /// Determines whether the <see cref="JwtPayload"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key)
        {
            return ContainsKey(key);
        }

        /// <summary>
        /// Determines whether the <see cref="JwtPayload"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        //public bool ContainsKey(ReadOnlySpan<byte> key)
        //{
        //    return _payload.ContainsKey(key);
        //}

        ///// <summary>
        ///// Gets the value associated with the specified key.
        ///// </summary>
        //public bool TryGetValue(ReadOnlySpan<byte> key, [NotNullWhen(true)] out JwtProperty value)
        //{
        //    return _payload.TryGetValue()
        //    if (key.Length == 3)
        //    {
        //        switch (IntegerMarshal.ReadUInt24(key))
        //        {
        //            case JwtPayloadParser.Aud:
        //                if (!(_aud is null))
        //                {
        //                    value = new JwtProperty(WellKnownProperty.Aud, new JwtArray(new List<string>(_aud)));
        //                    return true;
        //                }
        //                break;
        //            case JwtPayloadParser.Iss:
        //                if (!(_iss is null))
        //                {
        //                    value = new JwtProperty(WellKnownProperty.Iss, _iss);
        //                    return true;
        //                }
        //                break;
        //            case JwtPayloadParser.Jti:
        //                if (!(_jti is null))
        //                {
        //                    value = new JwtProperty(WellKnownProperty.Jti, _jti);
        //                    return true;
        //                }
        //                break;
        //            case JwtPayloadParser.Exp:
        //                if (_exp.HasValue)
        //                {
        //                    value = new JwtProperty(WellKnownProperty.Exp, _exp.Value);
        //                    return true;
        //                }
        //                break;
        //            case JwtPayloadParser.Iat:
        //                if (_iat.HasValue)
        //                {
        //                    value = new JwtProperty(WellKnownProperty.Iat, _iat.Value);
        //                    return true;
        //                }
        //                break;
        //            case JwtPayloadParser.Nbf:
        //                if (_nbf.HasValue)
        //                {
        //                    value = new JwtProperty(WellKnownProperty.Nbf, _nbf.Value);
        //                    return true;
        //                }
        //                break;
        //            case JwtPayloadParser.Sub:
        //                if (!(_sub is null))
        //                {
        //                    value = new JwtProperty(WellKnownProperty.Sub, _sub);
        //                    return true;
        //                }
        //                break;
        //        }
        //    }

        //    if (_payload is null)
        //    {
        //        value = default;
        //        return false;
        //    }

        //    return _payload.TryGetProperty(key, out value);
        //}

        /// <summary>
        /// Gets the value associated with the specified key.
        /// </summary>
        public bool TryGetValue(string key, out JwtMemberX value)
        {
            return _payload.TryGetValue(key, out value);
        }

        ///// <inheritsdoc />
        //public override string ToString()
        //{
        //    using var bufferWriter = new PooledByteBufferWriter();
        //    using (var writer = new Utf8JsonWriter(bufferWriter, new JsonWriterOptions { Indented = true }))
        //    {
        //        writer.WriteStartObject();
        //        if (!(_aud is null))
        //        {
        //            if (_aud.Length == 1)
        //            {
        //                writer.WriteString(Claims.AudUtf8, _aud[0]);
        //            }
        //            else
        //            {
        //                writer.WriteStartArray(Claims.AudUtf8);
        //                for (int i = 0; i < _aud.Length; i++)
        //                {
        //                    writer.WriteStringValue(_aud[i]);
        //                }

        //                writer.WriteEndArray();
        //            }
        //        }
        //        if (!(_iss is null))
        //        {
        //            writer.WriteString(Claims.IssUtf8, _iss);
        //        }
        //        if (!(_jti is null))
        //        {
        //            writer.WriteString(Claims.JtiUtf8, _jti);
        //        }
        //        if (_exp.HasValue)
        //        {
        //            writer.WriteNumber(Claims.ExpUtf8, _exp.Value);
        //        }
        //        if (_iat.HasValue)
        //        {
        //            writer.WriteNumber(Claims.IatUtf8, _iat.Value);
        //        }
        //        if (_nbf.HasValue)
        //        {
        //            writer.WriteNumber(Claims.NbfUtf8, _nbf.Value);
        //        }
        //        if (!(_sub is null))
        //        {
        //            writer.WriteString(Claims.SubUtf8, _sub);
        //        }
        //        if (!(_payload is null))
        //        {
        //            _payload.WriteTo(writer);
        //        }

        //        writer.WriteEndObject();
        //    }

        //    var input = bufferWriter.WrittenSpan;
        //    return Utf8.GetString(input);
        //}

        //public int Length => _payload.Length;

        internal void Add(JwtMemberX value)
        {
            _payload.TryAdd(value);
        }

        public void Add(string propertyName, string value)
        {
            _payload.TryAdd(new JwtMemberX(propertyName, value));
        }

        //public void Add(string propertyName, ReadOnlySpan<byte> value)
        //{
        //    _payload.TryAdd(propertyName, new JwtValueX(value));
        //}

        public void Add(string propertyName, long value)
        {
            _payload.TryAdd(new JwtMemberX(propertyName, value));
        }

        public void Add<T>(string propertyName, T[] value)
        {
            _payload.TryAdd(new JwtMemberX(propertyName, value));
        }

        public void Add(string propertyName, string?[] values)
        {
            _payload.TryAdd(new JwtMemberX(propertyName, values));
        }

        public void Add<T>(string propertyName, T value)
            where T : class
        {
            _payload.TryAdd(new JwtMemberX(propertyName, value));
        }

        //internal bool TryGetTokenType(ReadOnlySpan<byte> utf8Name, out JsonTokenType tokenType)
        //    => _payload.Try(utf8Name, out tokenType);

        //internal bool TryGetTokenType(ReadOnlySpan<char> utf8Name, out JsonTokenType tokenType)
        //    => _payload.TryGetTokenType(utf8Name, out tokenType);
        //internal bool TryGetTokenType(string name, out JsonTokenType tokenType)
        //    => _payload.TryGetTokenType(name, out tokenType);

        //internal bool TryGetValue(ReadOnlySpan<byte> utf8Name, out ReadOnlySpan<byte> value)
        //    => _payload.TryGetValue(utf8Name, out value);

        public IEnumerator GetEnumerator()
        {
            throw new NotImplementedException();
        }

        internal void WriteObjectTo(Utf8JsonWriter writer)
        {
            _payload.WriteTo(writer);
        }
    }
}