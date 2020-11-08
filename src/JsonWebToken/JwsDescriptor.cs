// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Defines a signed JWT with a JSON payload.
    /// </summary>
    public partial class JwsDescriptor : JwtDescriptor<JwtPayload>
    {
        private SignatureAlgorithm? _alg;
        private JwtPayload _payload;

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptor()
            : this(new JwtPayload())
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptor(JwtPayload payload)
            //: base(payload)
        {
            _payload = payload;
        }

        /// <inheritdoc/>
        public override JwtPayload Payload
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
                if (headerCache != null && headerCache.TryGetHeader(Header, alg, out cachedHeader))
                {
                    writer.Flush();
                    length += cachedHeader.Length;
                }
                else
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

        internal bool TryGetValue(string name, out JwtMemberX value)
        {
            return _payload.TryGetValue(name, out value);
        }

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

        /// <summary>
        /// Validates the presence and the type of a required claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="type"></param>
        protected void RequireClaim(string utf8Name, JsonValueKind type)
        {
            if (!Payload.TryGetValue(utf8Name, out var claim))
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
        protected void ValidateClaim(string utf8Name, JsonValueKind[] types)
        {
            if (!Payload.TryGetValue(utf8Name, out var claim) || claim.Type == JsonValueKind.Null)
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

    }
}