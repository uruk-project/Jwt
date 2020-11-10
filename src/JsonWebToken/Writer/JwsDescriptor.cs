// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
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
        private readonly SignatureAlgorithm _alg;
        private readonly Jwk _signingKey;
        private JwtPayload _payload;

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        /// <param name="signingKey">The signing key.</param>
        /// <param name="alg">The signature algorithm.</param>
        public JwsDescriptor(Jwk signingKey, SignatureAlgorithm alg)
        {
            _alg = alg ?? throw new ArgumentNullException(nameof(alg));
            _signingKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey));
            _payload = new JwtPayload();
            Header.Add(HeaderParameters.Alg, alg.Name);
            if (signingKey.Kid != null)
            {
                Header.Add(HeaderParameters.Kid, signingKey.Kid);
            }
        }

        /// <inheritdoc/>
        public override JwtPayload?Payload
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
        /// Gets the 'alg' header.
        /// </summary>
        public SignatureAlgorithm Alg => _alg;

        /// <summary>
        /// Gets the <see cref="Jwk"/> used for signature.
        /// </summary>
        public Jwk SigningKey => _signingKey;

        /// <summary>
        /// Sets the value of the 'sub' claim.
        /// </summary>
        public void AddSub(string value)
            => _payload.AddSub(value);

        /// <summary>
        /// Sets the value of the 'jti' claim.
        /// </summary>
        public void AddJti(string value)
            => _payload.AddJti(value);

        /// <summary>
        /// Sets the value of the 'aud' claim.
        /// </summary>
        public void AddAud(string value)
            => _payload.AddAud(value);

        /// <summary>
        /// Sets the value of the 'aud' claim.
        /// </summary>
        public void AddAud(string[] value)
            => _payload.AddAud(value);

        /// <summary>
        /// Sets the value of the 'exp' claim.
        /// </summary>
        public void AddExp(long value)
            => _payload.AddExp(value);

        /// <summary>
        /// Sets the value of the 'iss' claim.
        /// </summary>
        public void AddIss(string value)
            => _payload.AddIss(value);

        /// <summary>
        /// Sets the value of the 'iat' claim.
        /// </summary>
        public void AddIat(string value)
            => _payload.AddIat(value);

        /// <summary>
        ///Sets the value of the 'nbf' claim.
        /// </summary>
        public void AddNbf(long value)
            => _payload.AddNbf(value);

        /// <inheritsdoc />
        public override void Encode(EncodingContext context)
        {
            var key = _signingKey;
            var alg = _alg;
            if (!(key is null) && key.TryGetSigner(alg, out var signer))
            {
                if (context.TokenLifetimeInSeconds != 0 || context.GenerateIssuedTime)
                {
                    long now = EpochTime.UtcNow;
                    if (context.GenerateIssuedTime && !_payload.ContainsKey(Claims.Iat))
                    {
                        _payload.Add(Claims.Iat, now);
                    }

                    if (context.TokenLifetimeInSeconds != 0 && !_payload.ContainsKey(Claims.Exp))
                    {
                        _payload.Add(Claims.Exp, now + context.TokenLifetimeInSeconds);
                    }
                }

                using var bufferWriter = new PooledByteBufferWriter();
                using var writer = new Utf8JsonWriter(bufferWriter, Constants.NoJsonValidation);
                _payload.WriteTo(writer);
                int payloadLength = (int)writer.BytesCommitted + writer.BytesPending;
                int length = Base64Url.GetArraySizeRequiredToEncode(payloadLength)
                           + signer.Base64HashSizeInBytes
                           + (Constants.JwsSegmentCount - 1);
                ReadOnlySpan<byte> headerJson = default;
                var headerCache = context.HeaderCache;
                byte[]? cachedHeader = null;
                if (headerCache.TryGetHeader(Header, alg, out cachedHeader))
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
                    headerCache.AddHeader(Header, alg, buffer.Slice(0, offset));
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
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(alg, _signingKey);
            }
        }

        internal bool TryGetValue(string name, out JwtMember value)
        {
            return _payload.TryGetValue(name, out value);
        }

        /// <inheritsdoc />
        public IEnumerator<JwtProperty> GetEnumerator()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Validates the presence and the type of a required claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="type"></param>
        protected void RequireClaim(string utf8Name, JsonValueKind type)
        {
            if (!_payload.TryGetValue(utf8Name, out var claim))
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
            if (!_payload.TryGetValue(utf8Name, out var claim) || claim.Type == JsonValueKind.Null)
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