// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Defines a signed JWT with a JSON payload.</summary>
    public partial class JwsDescriptor : JwtDescriptor<JwtPayload>
    {
        private readonly SignatureAlgorithm _alg;
        private readonly Jwk _signingKey;
        private readonly JsonEncodedText _kid;
        private readonly string? _typ;
        private JwtPayload _payload;

        /// <summary>Initializes a new instance of <see cref="JwsDescriptor"/>.</summary>
        /// <param name="signingKey">The signing key.</param>
        /// <param name="alg">The signature algorithm.</param>
        /// <param name="typ">Optional. The media type.</param>
        /// <param name="cty">Optional. The content type.</param>
        public JwsDescriptor(Jwk signingKey, SignatureAlgorithm alg, string? typ = null, string? cty = null)
        {
            _alg = alg ?? throw new ArgumentNullException(nameof(alg));
            _signingKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey));
            _payload = new JwtPayload();
            var kid = signingKey.Kid;
            if (!kid.EncodedUtf8Bytes.IsEmpty)
            {
                _kid = kid;
                if (typ != null)
                {
                    _typ = typ;
                    Header.FastAdd(
                        new JwtMember(JwtHeaderParameterNames.Alg, alg.Name),
                        new JwtMember(JwtHeaderParameterNames.Kid, kid),
                        new JwtMember(JwtHeaderParameterNames.Typ, typ));
                }
                else
                {
                    Header.FastAdd(
                        new JwtMember(JwtHeaderParameterNames.Alg, alg.Name),
                        new JwtMember(JwtHeaderParameterNames.Kid, kid));
                }
            }
            else
            {
                if (typ != null)
                {
                    _typ = typ;
                    Header.FastAdd(
                        new JwtMember(JwtHeaderParameterNames.Alg, alg.Name),
                        new JwtMember(JwtHeaderParameterNames.Typ, typ));
                }
                else
                {
                    Header.Add(JwtHeaderParameterNames.Alg, alg.Name);
                }
            }

            if (cty != null)
            {
                Header.Add(JwtHeaderParameterNames.Cty, cty);
            }
        }

        /// <inheritdoc/>
        public override JwtPayload? Payload
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

        /// <summary>Gets the 'alg' header.</summary>
        public SignatureAlgorithm Alg => _alg;

        /// <summary>Gets the <see cref="Jwk"/> used for signature.</summary>
        public Jwk SigningKey => _signingKey;

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
                    if (context.GenerateIssuedTime && !_payload.ContainsKey(JwtClaimNames.Iat))
                    {
                        _payload.Add(JwtClaimNames.Iat, now);
                    }

                    if (context.TokenLifetimeInSeconds != 0 && !_payload.ContainsKey(JwtClaimNames.Exp))
                    {
                        _payload.Add(JwtClaimNames.Exp, now + context.TokenLifetimeInSeconds);
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
                if (headerCache.TryGetHeader(Header, alg, _kid, _typ, out byte[]? cachedHeader))
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
                    headerCache.AddHeader(Header, alg, _kid, _typ, buffer.Slice(0, offset));
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

        internal bool TryGetClaim(JsonEncodedText name, out JwtMember value)
        {
            return _payload.TryGetValue(name, out value);
        }

        internal bool TryGetClaim(string name, out JwtMember value)
        {
            return _payload.TryGetValue(JsonEncodedText.Encode(name), out value);
        }

        /// <summary>Validates the presence and the type of a required claim.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckRequiredClaimAsString(JsonEncodedText utf8Name)
        {
            if (!_payload.TryGetValue(utf8Name, out var claim))
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimIsRequired(utf8Name);
            }

            if (!claim.Type.IsStringOrArray())
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, new[] { JwtValueKind.String, JwtValueKind.JsonEncodedString });
            }
        }

        /// <summary>Validates the presence and the type of a required claim.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckRequiredClaimAsNumber(JsonEncodedText utf8Name)
        {
            if (!_payload.TryGetValue(utf8Name, out var claim))
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimIsRequired(utf8Name);
            }

            if (!claim.Type.IsNumber())
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, new[] {
                    JwtValueKind.Int32,
                    JwtValueKind.UInt32,
                    JwtValueKind.Int64,
                    JwtValueKind.UInt64,
                    JwtValueKind.Float,
                    JwtValueKind.Double});
            }
        }
        /// <summary>Validates the presence and the type of a required claim.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckRequiredClaimAsInteger(JsonEncodedText utf8Name)
        {
            if (!_payload.TryGetValue(utf8Name, out var claim))
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimIsRequired(utf8Name);
            }

            if (!claim.Type.IsInteger())
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, new[] {
                    JwtValueKind.Int32,
                    JwtValueKind.Int64,
                    JwtValueKind.UInt32,
                    JwtValueKind.UInt64});
            }
        }

        /// <summary>Validates the presence and the type of a required claim.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckRequiredClaimAsStringOrArray(JsonEncodedText utf8Name)
        {
            if (!_payload.TryGetValue(utf8Name, out var claim))
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimIsRequired(utf8Name);
            }

            if (!claim.Type.IsStringOrArray())
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, new[] { JwtValueKind.String, JwtValueKind.JsonEncodedString, JwtValueKind.Array });
            }
        }

        /// <summary>Validates the presence and the type of a required claim.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckRequiredClaimAsObject(JsonEncodedText utf8Name)
        {
            if (!_payload.TryGetValue(utf8Name, out var claim))
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimIsRequired(utf8Name);
            }

            if (claim.Type != JwtValueKind.Object)
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, JwtValueKind.Object);
            }
        }

        /// <summary>Validates the type of a optional claim.</summary>
        /// <param name="utf8Name"></param>
        protected void OptionalString(JsonEncodedText utf8Name)
        {
            if (_payload.TryGetValue(utf8Name, out var claim))
            {
                if (!claim.Type.IsStringOrArray())
                {
                    ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, new[] { JwtValueKind.String, JwtValueKind.JsonEncodedString });
                }
            }
        }

        /// <summary>Validates the type of a optional claim.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckOptionalClaimAsNumber(JsonEncodedText utf8Name)
        {
            if (_payload.TryGetValue(utf8Name, out var claim))
            {
                if (!claim.Type.IsNumber())
                {
                    ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, new[] {
                    JwtValueKind.Int32,
                    JwtValueKind.Int64,
                    JwtValueKind.UInt32,
                    JwtValueKind.UInt64,
                    JwtValueKind.Float,
                    JwtValueKind.Double});
                }
            }
        }

        /// <summary>Validates the type of a optional claim.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckOptionalClaimAsInteger(JsonEncodedText utf8Name)
        {
            if (_payload.TryGetValue(utf8Name, out var claim))
            {
                if (!claim.Type.IsInteger())
                {
                    ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, new[] {
                    JwtValueKind.Int32,
                    JwtValueKind.Int64,
                    JwtValueKind.UInt32,
                    JwtValueKind.UInt64});
                }
            }
        }

        /// <summary>Validates the type of a optional claim.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckOptionalClaimAsStringOrArray(JsonEncodedText utf8Name)
        {
            if (_payload.TryGetValue(utf8Name, out var claim))
            {
                if (!claim.Type.IsStringOrArray())
                {
                    ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, new[] { JwtValueKind.String, JwtValueKind.JsonEncodedString, JwtValueKind.Array });
                }
            }
        }

        /// <summary>Validates the type of a optional claim.</summary>
        /// <param name="utf8Name"></param>
        protected void CheckOptionalClaimAsObject(JsonEncodedText utf8Name)
        {
            if (_payload.TryGetValue(utf8Name, out var claim))
            {
                if (claim.Type != JwtValueKind.Object)
                {
                    ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(utf8Name, JwtValueKind.Object);
                }
            }
        }
    }
}