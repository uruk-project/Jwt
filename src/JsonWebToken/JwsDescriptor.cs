// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Defines a signed JWT with a JSON payload.
    /// </summary>
    public partial class JwsDescriptor : JwtDescriptor<JwtObject>, IEnumerable<JwtProperty>
    {
        private JwtProperty _alg;

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptor()
            : base(new JwtObject(3), new JwtObject())
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptor(JwtObject header, JwtObject payload)
            : base(header, payload)
        {
        }

        /// <summary>
        /// Gets or sets the algorithm header.
        /// </summary>
        public SignatureAlgorithm? Algorithm
        {
            get
            {
                if (_alg.IsEmpty)
                {
                    Header.TryGetProperty(HeaderParameters.AlgUtf8, out _alg);
                }

                if (_alg.Value is null)
                {
                    return null;
                }

                return (SignatureAlgorithm?)(byte[]?)_alg.Value;
            }

            set
            {
                SetHeaderParameter(HeaderParameters.AlgUtf8, value is null ? default : value.Utf8Name);
                _alg = default;
            }
        }

        /// <summary>
        /// Gets the <see cref="Jwk"/> used.
        /// </summary>
        public Jwk SigningKey
        {
            get => Key;
            set => Key = value;
        }

        /// <summary>
        /// Gets or sets the value of the 'sub' claim.
        /// </summary>
        public string? Subject
        {
            get { return GetStringClaim(Claims.SubUtf8); }
            set { AddClaim(Claims.SubUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'jti' claim.
        /// </summary>
        public string? JwtId
        {
            get { return GetStringClaim(Claims.JtiUtf8); }
            set { AddClaim(Claims.JtiUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public string? Audience
        {
            get { return Audiences?.FirstOrDefault(); }
            set { AddClaim(Claims.AudUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public List<string>? Audiences
        {
            get { return GetListClaims<string>(Claims.AudUtf8); }
            set
            {
                if (value is null)
                {
                    SetClaimToNull(Claims.AudUtf8);
                }
                else
                {
                    AddClaim(Claims.AudUtf8, value);
                }
            }
        }

        /// <summary>
        /// Gets or sets the value of the 'exp' claim.
        /// </summary>
        public DateTime? ExpirationTime
        {
            get { return GetDateTime(Claims.ExpUtf8); }
            set { AddClaim(Claims.ExpUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'iss' claim.
        /// </summary>
        public string? Issuer
        {
            get { return GetStringClaim(Claims.IssUtf8); }
            set { AddClaim(Claims.IssUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'iat' claim.
        /// </summary>
        public DateTime? IssuedAt
        {
            get { return GetDateTime(Claims.IatUtf8); }
            set { AddClaim(Claims.IatUtf8, value); }
        }

        /// <summary>
        ///Gets or sets the value of the 'nbf' claim.
        /// </summary>
        public DateTime? NotBefore
        {
            get { return GetDateTime(Claims.NbfUtf8); }
            set { AddClaim(Claims.NbfUtf8, value); }
        }

        /// <summary>
        /// Add a claim with the value <c>null</c>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        public void AddNullClaim(ReadOnlySpan<byte> utf8Name)
        {
            Payload.Add(new JwtProperty(utf8Name));
        }

        /// <summary>
        /// Add a claim with the value <c>null</c>.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public void AddNullClaim(string name)
        {
            Payload.Add(new JwtProperty(name));
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(ReadOnlySpan<byte> utf8Name, string? value)
        {
            // TODO: allow to add a value into an array
            Payload.Add(new JwtProperty(utf8Name, value));
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(ReadOnlySpan<byte> utf8Name, long value)
        {
            Payload.Add(new JwtProperty(utf8Name, value));
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, string value)
        {
            AddClaim(Utf8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(ReadOnlySpan<byte> utf8Name, bool? value)
        {
            if (value.HasValue)
            {
                Payload.Add(new JwtProperty(utf8Name, value.Value));
            }
            else
            {
                Payload.Add(new JwtProperty(utf8Name));
            }
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, bool? value)
        {
            AddClaim(Utf8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, long value)
        {
            AddClaim(Utf8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(ReadOnlySpan<byte> utf8Name, DateTime? value)
        {
            if (value.HasValue)
            {
                Payload.Add(new JwtProperty(utf8Name, value.Value.ToEpochTime()));
            }
            else
            {
                Payload.Add(new JwtProperty(utf8Name));
            }
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, DateTime? value)
        {
            AddClaim(Utf8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(ReadOnlySpan<byte> utf8Name, int value)
        {
            Payload.Add(new JwtProperty(utf8Name, value));
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, int value)
        {
            AddClaim(Utf8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(ReadOnlySpan<byte> utf8Name, bool value)
        {
            Payload.Add(new JwtProperty(utf8Name, value));
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, bool value)
        {
            AddClaim(Utf8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(ReadOnlySpan<byte> utf8Name, JwtObject value)
        {
            Payload.Add(new JwtProperty(utf8Name, value));
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, JwtObject value)
        {
            AddClaim(Utf8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(ReadOnlySpan<byte> utf8Name, JwtProperty value)
        {
            JwtObject jwtObject;
            if (Payload.TryGetProperty(utf8Name, out JwtProperty property) && property.Type == JwtTokenType.Object && !(property.Value is null))
            {
                jwtObject = (JwtObject)property.Value;
            }
            else
            {
                jwtObject = new JwtObject();
                Payload.Add(new JwtProperty(utf8Name, jwtObject));
            }

            jwtObject.Add(value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, JwtProperty value)
        {
            AddClaim(Utf8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, JwtArray value)
        {
            Payload.Add(name, value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(ReadOnlySpan<byte> utf8Name, JwtArray value)
        {
            Payload.Add(utf8Name, value);
        }

        /// <summary>
        /// Add a claim as a list of <see cref="string"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public void AddClaim(ReadOnlySpan<byte> utf8Name, List<string> value)
        {
            AddClaim(utf8Name, new JwtArray(value));
        }

        /// <summary>
        /// Add a claim as a list of <see cref="string"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public void AddClaim(string name, List<string> value)
        {
            AddClaim(Utf8.GetBytes(name), value);
        }

        /// <summary>
        /// Set a claim to null.
        /// </summary>
        /// <param name="utf8Name"></param>
        public void SetClaimToNull(ReadOnlySpan<byte> utf8Name)
        {
            Payload.Replace(new JwtProperty(utf8Name));
        }

        /// <summary>
        /// Set a claim to null.
        /// </summary>
        /// <param name="name"></param>
        public void SetClaimToNull(string name)
        {
            SetClaimToNull(Utf8.GetBytes(name));
        }

        /// <summary>
        /// Gets a claim as <see cref="string"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected string? GetStringClaim(ReadOnlySpan<byte> utf8Name)
        {
            if (Payload.TryGetProperty(utf8Name, out JwtProperty value))
            {
                return (string?)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as <see cref="string"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        protected string? GetStringClaim(string name)
        {
            return GetStringClaim(Utf8.GetBytes(name));
        }

        /// <summary>
        /// Gets a claim as <see cref="int"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected int? GetInt32Claim(ReadOnlySpan<byte> utf8Name)
        {
            if (Payload.TryGetProperty(utf8Name, out JwtProperty value))
            {
                return (int?)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as <typeparamref name="TClaim"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected TClaim? GetClaim<TClaim>(ReadOnlySpan<byte> claimType) where TClaim : struct
        {
            if (Payload.TryGetProperty(claimType, out JwtProperty value))
            {
                return (TClaim?)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as <see cref="bool"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected bool? GetBoolClaim(ReadOnlySpan<byte> utf8Name)
        {
            if (Payload.TryGetProperty(utf8Name, out JwtProperty value))
            {
                return (bool?)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as a list of <see cref="string"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected List<T>? GetListClaims<T>(ReadOnlySpan<byte> utf8Name)
        {
            if (Payload.TryGetProperty(utf8Name, out JwtProperty value) && !(value.Value is null))
            {
                var list = new List<T>();
                if (value.Type == JwtTokenType.Array)
                {
                    var array = (JwtArray)value.Value;
                    for (int i = 0; i < array.Count; i++)
                    {
                        var tValue = array[i].Value;
                        if (!(tValue is null))
                        {
                            list.Add((T)tValue);
                        }
                    }

                    return list;
                }

                list.Add((T)value.Value);
                return list;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as a list of <see cref="string"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        protected List<T>? GetListClaims<T>(string name)
        {
            return GetListClaims<T>(Utf8.GetBytes(name));
        }

        /// <summary>
        /// Gets a claim as <see cref="JwtObject"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected JwtObject? GetClaim(ReadOnlySpan<byte> claimType)
        {
            if (Payload.TryGetProperty(claimType, out JwtProperty value) && value.Type == JwtTokenType.Object && !(value.Value is null))
            {
                return (JwtObject)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as <see cref="DateTime"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected DateTime? GetDateTime(ReadOnlySpan<byte> utf8Name)
        {
            if (!Payload.TryGetProperty(utf8Name, out JwtProperty dateValue) || dateValue.Type != JwtTokenType.Integer || dateValue.Value is null)
            {
                return null;
            }

            return EpochTime.ToDateTime((long)dateValue.Value);
        }

        /// <inheritsdoc />
        public override void Encode(EncodingContext context)
        {
            var key = Key;
            var alg = (Algorithm ?? key?.SignatureAlgorithm) ?? SignatureAlgorithm.None;
            if (!(key is null) && key.TryGetSigner(alg, out var signer))
            {
                if (context.TokenLifetimeInSeconds != 0 || context.GenerateIssuedTime)
                {
                    long now = EpochTime.UtcNow;
                    if (context.GenerateIssuedTime && !Payload.ContainsKey(Claims.IatUtf8))
                    {
                        AddClaim(Claims.IatUtf8, now);
                    }

                    if (context.TokenLifetimeInSeconds != 0 && !Payload.ContainsKey(Claims.ExpUtf8))
                    {
                        AddClaim(Claims.ExpUtf8, now + context.TokenLifetimeInSeconds);
                    }
                }

                using var bufferWriter = new PooledByteBufferWriter();
                using var writer = new Utf8JsonWriter(bufferWriter, Constants.NoJsonValidation);
                Payload.WriteObjectTo(writer);
                int payloadLength = (int)writer.BytesCommitted + writer.BytesPending;
                int length = Base64Url.GetArraySizeRequiredToEncode(payloadLength)
                           + signer.Base64HashSizeInBytes
                           + (Constants.JwsSegmentCount - 1);
                ReadOnlySpan<byte> headerJson = default;
                var headerCache = context.HeaderCache;
                byte[]? cachedHeader = null;
                if (headerCache != null && headerCache.TryGetHeader(Header, alg, out cachedHeader))
                {
                    writer.Flush();
                    length += cachedHeader.Length;
                }
                else
                {
                    Header.WriteObjectTo(writer);
                    writer.Flush();
                    headerJson = bufferWriter.WrittenSpan.Slice(payloadLength + 1);
                    length += Base64Url.GetArraySizeRequiredToEncode(headerJson.Length);
                }

                var buffer = context.BufferWriter.GetSpan(length);
                int offset;
                if (cachedHeader != null)
                {
                    cachedHeader.CopyTo(buffer);
                    offset = cachedHeader.Length;
                }
                else
                {
                    offset = Base64Url.Encode(headerJson, buffer);
                    headerCache?.AddHeader(Header, alg, buffer.Slice(0, offset));
                }

                buffer[offset++] = Constants.ByteDot;
                offset += Base64Url.Encode(bufferWriter.WrittenSpan.Slice(0, payloadLength), buffer.Slice(offset));
                buffer[offset] = Constants.ByteDot;
                Span<byte> signature = stackalloc byte[signer.HashSizeInBytes];
                bool success = signer.TrySign(buffer.Slice(0, offset++), signature, out int signatureBytesWritten);
                Debug.Assert(success);
                Debug.Assert(signature.Length == signatureBytesWritten);

                int bytesWritten = Base64Url.Encode(signature, buffer.Slice(offset));

                Debug.Assert(length == offset + bytesWritten);
                context.BufferWriter.Advance(length);
            }
            else
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(alg, Key);
            }
        }

        /// <inheritsdoc />
        public override void Validate()
        {
            base.Validate();
            CheckRequiredHeader(HeaderParameters.AlgUtf8, JwtTokenType.Utf8String);
        }

        /// <summary>
        /// Validates the presence and the type of a required claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="type"></param>
        protected void RequireClaim(ReadOnlySpan<byte> utf8Name, JwtTokenType type)
        {
            if (!Payload.TryGetProperty(utf8Name, out var claim) || claim.Type == JwtTokenType.Null)
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimIsRequired(utf8Name);
            }

            if (claim.Type != type)
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, type);
            }
        }

        /// <summary>
        /// Validates the presence and the type of a required claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="types"></param>
        protected void ValidateClaim(ReadOnlySpan<byte> utf8Name, JwtTokenType[] types)
        {
            if (!Payload.TryGetProperty(utf8Name, out var claim) || claim.Type == JwtTokenType.Null)
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimIsRequired(utf8Name);
            }

            for (int i = 0; i < types.Length; i++)
            {
                if (claim.Type == types[i])
                {
                    return;
                }
            }

            ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, types);
        }

        /// <inheritsdoc />
        protected override void OnKeyChanged(Jwk? key)
        {
            if (!(key is null) && !key.Alg.IsEmpty)
            {
                Algorithm = key.SignatureAlgorithm;
            }
        }

        /// <inheritsdoc />
        public IEnumerator<JwtProperty> GetEnumerator()
        {
            return Payload.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return Payload.GetEnumerator();
        }
    }

    /// <summary>
    /// Defines a signed JWT with a JSON payload.
    /// </summary>
    public partial class JwsDescriptorX : JwtDescriptorX<JwtPayloadX>, IEnumerable
    {
        private SignatureAlgorithm? _alg;
        private JwtPayloadX _payload;

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptorX()
            : this(new JwtPayloadX())
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptorX(JwtPayloadX payload)
            //: base(payload)
        {
            _payload = payload;
        }

        /// <inheritdoc/>
        public override JwtPayloadX Payload
        {
            get => _payload;
            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                _payload.CopyTo(value);
                _payload = value;
            }
        }


        /// <summary>
        /// Gets or sets the algorithm header.
        /// </summary>
        public SignatureAlgorithm? Alg
        {
            get
            {
                if (_alg is null
                    && Header.TryGetValue(HeaderParameters.Alg, out var value)
                    && SignatureAlgorithm.TryParse((string?)value.Value, out _alg))
                {
                    return _alg;
                }

                return _alg;
            }

            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                _alg = value;
                Header.Add(HeaderParameters.Alg, value.Name);
            }
        }

        /// <summary>
        /// Gets the <see cref="Jwk"/> used.
        /// </summary>
        public Jwk SigningKey
        {
            get => Key;
            set => Key = value;
        }

        /// <summary>
        /// Gets or sets the value of the 'sub' claim.
        /// </summary>
        public void AddSub(string value)
            => Payload.AddSub(value);

        /// <summary>
        /// Gets or sets the value of the 'jti' claim.
        /// </summary>
        public void AddJti(string value)
            => Payload.AddJti(value);

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public void AddAud(string value)
            => Payload.AddAud(value);

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public void AddAud(string[] value)
            => Payload.AddAud(value);

        /// <summary>
        /// Gets or sets the value of the 'exp' claim.
        /// </summary>
        public void AddExp(long value)
            => Payload.AddExp(value);

        /// <summary>
        /// Gets or sets the value of the 'iss' claim.
        /// </summary>
        public void AddIss(string value)
            => Payload.AddIss(value);

        /// <summary>
        /// Gets or sets the value of the 'iat' claim.
        /// </summary>
        public void AddIat(string value)
            => Payload.AddIat(value);

        /// <summary>
        ///Gets or sets the value of the 'nbf' claim.
        /// </summary>
        public void AddNbf(long value)
            => Payload.AddNbf(value);

        /// <inheritsdoc />
        public override void Encode(EncodingContext context)
        {
            var key = Key;
            var alg = (Alg ?? key?.SignatureAlgorithm) ?? SignatureAlgorithm.None;
            if (!(key is null) && key.TryGetSigner(alg, out var signer))
            {
                if (context.TokenLifetimeInSeconds != 0 || context.GenerateIssuedTime)
                {
                    long now = EpochTime.UtcNow;
                    if (context.GenerateIssuedTime && !Payload.ContainsKey(Claims.Iat))
                    {
                        Payload.Add(Claims.Iat, now);
                    }

                    if (context.TokenLifetimeInSeconds != 0 && !Payload.ContainsKey(Claims.Exp))
                    {
                        Payload.Add(Claims.Exp, now + context.TokenLifetimeInSeconds);
                    }
                }

                using var bufferWriter = new PooledByteBufferWriter();
                using var writer = new Utf8JsonWriter(bufferWriter, Constants.NoJsonValidation);
                Payload.WriteTo(writer);
                int payloadLength = (int)writer.BytesCommitted + writer.BytesPending;
                int length = Base64Url.GetArraySizeRequiredToEncode(payloadLength)
                           + signer.Base64HashSizeInBytes
                           + (Constants.JwsSegmentCount - 1);
                ReadOnlySpan<byte> headerJson = default;
                var headerCache = context.HeaderCache;
                byte[]? cachedHeader = null;
                //if (headerCache != null && headerCache.TryGetHeader(Header, alg, out cachedHeader))
                //{
                //    writer.Flush();
                //    length += cachedHeader.Length;
                //}
                //else
                {
                    Header.WriteTo(writer);
                    writer.Flush();
                    headerJson = bufferWriter.WrittenSpan.Slice(payloadLength + 1);
                    length += Base64Url.GetArraySizeRequiredToEncode(headerJson.Length);
                }

                var buffer = context.BufferWriter.GetSpan(length);
                int offset;
                if (cachedHeader != null)
                {
                    cachedHeader.CopyTo(buffer);
                    offset = cachedHeader.Length;
                }
                else
                {
                    offset = Base64Url.Encode(headerJson, buffer);
                    //headerCache?.AddHeader(Header, alg, buffer.Slice(0, offset));
                }

                buffer[offset++] = Constants.ByteDot;
                offset += Base64Url.Encode(bufferWriter.WrittenSpan.Slice(0, payloadLength), buffer.Slice(offset));
                buffer[offset] = Constants.ByteDot;
                Span<byte> signature = stackalloc byte[signer.HashSizeInBytes];
                bool success = signer.TrySign(buffer.Slice(0, offset++), signature, out int signatureBytesWritten);
                Debug.Assert(success);
                Debug.Assert(signature.Length == signatureBytesWritten);

                int bytesWritten = Base64Url.Encode(signature, buffer.Slice(offset));

                Debug.Assert(length == offset + bytesWritten);
                context.BufferWriter.Advance(length);
            }
            else
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(alg, Key);
            }
        }

        /// <inheritsdoc />
        public override void Validate()
        {
            base.Validate();

            // It will be validated afterward
            //CheckRequiredHeader(HeaderParameters.Alg, JsonValueKind.String);
        }

        ///// <summary>
        ///// Validates the presence and the type of a required claim.
        ///// </summary>
        ///// <param name="utf8Name"></param>
        ///// <param name="type"></param>
        //protected void RequireClaim(string utf8Name, JsonTokenType type)
        //{
        //    if (!Payload.TryGetValue(utf8Name, out var claimType))
        //    {
        //        ThrowHelper.ThrowJwtDescriptorException_ClaimIsRequired(utf8Name);
        //    }

        //    if (claimType.Type != type)
        //    {
        //        ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, type);
        //    }
        //}

        ///// <summary>
        ///// Validates the presence and the type of a required claim.
        ///// </summary>
        ///// <param name="utf8Name"></param>
        ///// <param name="types"></param>
        //protected void ValidateClaim(ReadOnlySpan<byte> utf8Name, JsonTokenType[] types)
        //{
        //    if (!Payload.TryGetTokenType(utf8Name, out var claimType))
        //    {
        //        ThrowHelper.ThrowJwtDescriptorException_ClaimIsRequired(utf8Name);
        //    }

        //    for (int i = 0; i < types.Length; i++)
        //    {
        //        if (claimType == types[i])
        //        {
        //            return;
        //        }
        //    }

        //    ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, types);
        //}

        /// <inheritsdoc />
        protected override void OnKeyChanged(Jwk? key)
        {
            if (!(key is null) && !key.Alg.IsEmpty)
            {
                Alg = key.SignatureAlgorithm;
            }
        }

        /// <inheritsdoc />
        public IEnumerator<JwtProperty> GetEnumerator()
        {
            throw new NotImplementedException();
            //return Payload.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            throw new NotImplementedException();
            //return Payload.GetEnumerator();
        }
    }
}