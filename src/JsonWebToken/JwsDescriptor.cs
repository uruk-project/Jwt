// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Defines a signed JWT with a JSON payload.
    /// </summary>
    public partial class JwsDescriptor : JwtDescriptor<JwtObject>
    {
        private JwtProperty _alg;

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptor()
            : base(new JwtObject(), new JwtObject())
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
        public SignatureAlgorithm Algorithm
        {
            get
            {
                if (_alg.IsEmpty && Header.TryGetValue(HeaderParameters.AlgUtf8, out var value))
                {
                    _alg = value;
                }

                return (byte[])_alg.Value;
            }

            set
            {
                SetHeaderParameter(HeaderParameters.AlgUtf8, (byte[])value);
                _alg = default;
            }
        }

        /// <summary>
        /// Gets or sets the value of the 'sub' claim.
        /// </summary>
        public string Subject
        {
            get { return GetStringClaim(Claims.SubUtf8); }
            set { AddClaim(Claims.SubUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'jti' claim.
        /// </summary>
        public string JwtId
        {
            get { return GetStringClaim(Claims.JtiUtf8); }
            set { AddClaim(Claims.JtiUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public string Audience
        {
            get { return Audiences?.FirstOrDefault(); }
            set { AddClaim(Claims.AudUtf8, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public List<string> Audiences
        {
            get { return GetListClaims<string>(Claims.AudUtf8); }
            set { AddClaim(Claims.AudUtf8, value); }
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
        public string Issuer
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
        /// Adds a claim;
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(ReadOnlySpan<byte> utf8Name, string value)
        {
            // TODO: allow to add a value into an array
            Payload.Add(new JwtProperty(utf8Name, value));
        }

        /// <summary>
        /// Adds a claim;
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, string value)
        {
            AddClaim(Encoding.UTF8.GetBytes(name), value);
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
            AddClaim(Encoding.UTF8.GetBytes(name), value);
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
            AddClaim(Encoding.UTF8.GetBytes(name), value);
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
            AddClaim(Encoding.UTF8.GetBytes(name), value);
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
            AddClaim(Encoding.UTF8.GetBytes(name), value);
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
            AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        public void AddClaim(ReadOnlySpan<byte> utf8Name, JwtProperty value)
        {
            JwtObject jwtObject;
            if (Payload.TryGetValue(utf8Name, out JwtProperty property) && property.Type == JwtTokenType.Object)
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
            AddClaim(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Gets a claim as <see cref="string"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected string GetStringClaim(ReadOnlySpan<byte> utf8Name)
        {
            if (Payload.TryGetValue(utf8Name, out JwtProperty value))
            {
                return (string)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as <see cref="string"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        protected string GetStringClaim(string name)
        {
            return GetStringClaim(Encoding.UTF8.GetBytes(name));
        }

        /// <summary>
        /// Gets a claim as <see cref="int"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected int? GetInt32Claim(ReadOnlySpan<byte> utf8Name)
        {
            if (Payload.TryGetValue(utf8Name, out JwtProperty value))
            {
                return (int)value.Value;
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
            if (Payload.TryGetValue(claimType, out JwtProperty value))
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
            if (Payload.TryGetValue(utf8Name, out JwtProperty value))
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
        protected List<T> GetListClaims<T>(ReadOnlySpan<byte> utf8Name)
        {
            if (Payload.TryGetValue(utf8Name, out JwtProperty value))
            {
                if (value.Type == JwtTokenType.Array)
                {
                    return (List<T>)value.Value;
                }

                var list = new List<T> { (T)value.Value };
                return list;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as a list of <see cref="string"/>.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        protected List<T> GetListClaims<T>(string name)
        {
            return GetListClaims<T>(Encoding.UTF8.GetBytes(name));
        }

        /// <summary>
        /// Gets a claim as <see cref="JwtObject"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected JwtObject GetClaim(ReadOnlySpan<byte> claimType)
        {
            if (Payload.TryGetValue(claimType, out JwtProperty value) && value.Type == JwtTokenType.Object)
            {
                return (JwtObject)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Add a claim as a list of <see cref="string"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        protected void AddClaim(ReadOnlySpan<byte> utf8Name, List<string> value)
        {
            Payload.Add(new JwtProperty(utf8Name, new JwtArray(value)));
        }

        /// <summary>
        /// Gets a claim as <see cref="DateTime"/>.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <returns></returns>
        protected DateTime? GetDateTime(ReadOnlySpan<byte> utf8Name)
        {
            if (!Payload.TryGetValue(utf8Name, out JwtProperty dateValue) || dateValue.Type == JwtTokenType.Null)
            {
                return null;
            }

            return EpochTime.ToDateTime((long)dateValue.Value);
        }

        /// <inheritsdoc />
        public override void Encode(EncodingContext context, IBufferWriter<byte> output)
        {
            Signer signer = null;
            var alg = (Algorithm ?? Key?.SignatureAlgorithm) ?? SignatureAlgorithm.None;
            if (Key != null)
            {
                signer = context.SignatureFactory.Create(Key, alg, willCreateSignatures: true);
                if (signer == null)
                {
                    Errors.ThrowNotSupportedSignatureAlgorithm(alg, Key);
                }
            }

            if (context.TokenLifetimeInMinutes != 0 || context.GenerateIssuedTime)
            {
                DateTime now = DateTime.UtcNow;
                if (context.GenerateIssuedTime && !Payload.ContainsKey(Claims.IatUtf8))
                {
                    AddClaim(Claims.IatUtf8, now);
                }

                if (context.TokenLifetimeInMinutes != 0 && !Payload.ContainsKey(Claims.ExpUtf8))
                {
                    AddClaim(Claims.ExpUtf8, now + TimeSpan.FromMinutes(context.TokenLifetimeInMinutes));
                }
            }

            using (var payloadBufferWriter = new ArrayBufferWriter<byte>())
            {
                Payload.Serialize(payloadBufferWriter);
                var payloadJson = payloadBufferWriter.WrittenSpan;
                int length = Base64Url.GetArraySizeRequiredToEncode(payloadJson.Length)
                           + (Key == null ? 0 : Base64Url.GetArraySizeRequiredToEncode(signer.HashSizeInBytes))
                           + (Constants.JwsSegmentCount - 1);
                ReadOnlySpan<byte> headerJson = default;
                var headerCache = context.HeaderCache;
                byte[] cachedHeader = null;
                using (var headerBufferWriter = new ArrayBufferWriter<byte>())
                {
                    if (headerCache != null && headerCache.TryGetHeader(Header, alg, out cachedHeader))
                    {
                        length += cachedHeader.Length;
                    }
                    else
                    {
                        Header.Serialize(headerBufferWriter);
                        headerJson = headerBufferWriter.WrittenSpan;
                        length += Base64Url.GetArraySizeRequiredToEncode(headerJson.Length);
                    }

                    var buffer = output.GetSpan(length).Slice(0, length);
                    int headerBytesWritten;
                    if (cachedHeader != null)
                    {
                        cachedHeader.CopyTo(buffer);
                        headerBytesWritten = cachedHeader.Length;
                    }
                    else
                    {
                        headerBytesWritten = Base64Url.Encode(headerJson, buffer);
                        headerCache?.AddHeader(Header, alg, buffer.Slice(0, headerBytesWritten));
                    }

                    buffer[headerBytesWritten] = Constants.ByteDot;
                    int payloadBytesWritten = Base64Url.Encode(payloadJson, buffer.Slice(headerBytesWritten + 1));
                    buffer[payloadBytesWritten + headerBytesWritten + 1] = Constants.ByteDot;
                    int bytesWritten = 0;
                    if (signer != null)
                    {
                        Span<byte> signature = stackalloc byte[signer.HashSizeInBytes];
                        bool success = signer.TrySign(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + 1), signature, out int signatureBytesWritten);
                        Debug.Assert(success);
                        Debug.Assert(signature.Length == signatureBytesWritten);

                        bytesWritten = Base64Url.Encode(signature, buffer.Slice(payloadBytesWritten + headerBytesWritten + (Constants.JwsSegmentCount - 1)));
                    }

                    Debug.Assert(length == payloadBytesWritten + headerBytesWritten + (Constants.JwsSegmentCount - 1) + bytesWritten);
                    output.Advance(length);
                }
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
            if (!Payload.TryGetValue(utf8Name, out var claim) || claim.Type == JwtTokenType.Null)
            {
                Errors.ThrowClaimIsRequired(utf8Name);
            }

            if (claim.Type != type)
            {
                Errors.ThrowClaimMustBeOfType(utf8Name, type);
            }
        }

        /// <summary>
        /// Validates the presence and the type of a required claim.
        /// </summary>
        /// <param name="utf8Name"></param>
        /// <param name="types"></param>
        protected void ValidateClaim(ReadOnlySpan<byte> utf8Name, JwtTokenType[] types)
        {
            if (!Payload.TryGetValue(utf8Name, out var claim) || claim.Type == JwtTokenType.Null)
            {
                Errors.ThrowClaimIsRequired(utf8Name);
            }

            for (int i = 0; i < types.Length; i++)
            {
                if (claim.Type == types[i])
                {
                    return;
                }
            }

            Errors.ThrowClaimMustBeOfType(utf8Name, types);
        }

        /// <inheritsdoc />
        protected override void OnKeyChanged(Jwk key)
        {
            if (key != null && key.Alg != null)
            {
                Algorithm = key.Alg;
            }
        }
    }
}