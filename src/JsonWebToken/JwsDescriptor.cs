// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
#if NETCOREAPP3_0
using System.Text.Json;
#endif

namespace JsonWebToken
{
    /// <summary>
    /// Defines a signed JWT with a JSON payload.
    /// </summary>
    public partial class JwsDescriptor : JwtDescriptor<PayloadDescriptor>
    {
        private const byte dot = (byte)'.';
        private static readonly ReadOnlyDictionary<string, JwtTokenType[]> DefaultRequiredClaims = new ReadOnlyDictionary<string, JwtTokenType[]>(new Dictionary<string, JwtTokenType[]>());
        private static readonly string[] DefaultProhibitedClaims = Array.Empty<string>();
        private static readonly ReadOnlyDictionary<string, JwtTokenType[]> JwsRequiredHeaderParameters = new ReadOnlyDictionary<string, JwtTokenType[]>(
            new Dictionary<string, JwtTokenType[]>
            {
                { HeaderParameters.Alg, new [] { JwtTokenType.String } }
            });

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptor()
            : base(new HeaderDescriptor(), new PayloadDescriptor())
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptor(HeaderDescriptor header, PayloadDescriptor payload)
            : base(header, payload)
        {
        }

        /// <summary>
        /// Gets the required claims of the <see cref="JwsDescriptor"/>.
        /// </summary>
        protected virtual ReadOnlyDictionary<string, JwtTokenType[]> RequiredClaims => DefaultRequiredClaims;

        /// <summary>
        /// gets the prohibited claims of the <see cref="JwsDescriptor"/>.
        /// </summary>
        protected virtual IReadOnlyList<string> ProhibitedClaims => DefaultProhibitedClaims;

        /// <summary>
        /// Gets the required header parameters of the <see cref="JwsDescriptor"/>. 
        /// </summary>
        protected override ReadOnlyDictionary<string, JwtTokenType[]> RequiredHeaderParameters => JwsRequiredHeaderParameters;

        /// <summary>
        /// Gets or sets the value of the 'sub' claim.
        /// </summary>
        public string Subject
        {
            get { return GetStringClaim(Claims.Sub); }
            set { AddClaim(Claims.Sub, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'jti' claim.
        /// </summary>
        public string JwtId
        {
            get { return GetStringClaim(Claims.Jti); }
            set { AddClaim(Claims.Jti, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public string Audience
        {
            get { return Audiences?.FirstOrDefault(); }
            set { SetClaim(Claims.Aud, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public IReadOnlyList<string> Audiences
        {
            get { return GetListClaims<string>(Claims.Aud); }
            set { SetClaim(Claims.Aud, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'exp' claim.
        /// </summary>
        public DateTime? ExpirationTime
        {
            get { return GetDateTime(Claims.Exp); }
            set { AddClaim(Claims.Exp, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'iss' claim.
        /// </summary>
        public string Issuer
        {
            get { return GetStringClaim(Claims.Iss); }
            set { AddClaim(Claims.Iss, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'iat' claim.
        /// </summary>
        public DateTime? IssuedAt
        {
            get { return GetDateTime(Claims.Iat); }
            set { AddClaim(Claims.Iat, value); }
        }

        /// <summary>
        ///Gets or sets the value of the 'nbf' claim.
        /// </summary>
        public DateTime? NotBefore
        {
            get { return GetDateTime(Claims.Nbf); }
            set { AddClaim(Claims.Nbf, value); }
        }

        /// <summary>
        /// Adds a claim;
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, string value)
        {
            // TODO: allow to add a value into an array
            Payload[name] = new JwtProperty(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, bool? value)
        {
            if (value.HasValue)
            {
                Payload[name] = new JwtProperty(Encoding.UTF8.GetBytes(name), value.Value);
            }
            else
            {
                Payload[name] = new JwtProperty(Encoding.UTF8.GetBytes(name));
            }
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, DateTime? value)
        {
            if (value.HasValue)
            {
                Payload[name] = new JwtProperty(Encoding.UTF8.GetBytes(name), value.Value.ToEpochTime());
            }
            else
            {
                Payload[name] = new JwtProperty(Encoding.UTF8.GetBytes(name));
            }
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, int value)
        {
            Payload[name] = new JwtProperty(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, bool value)
        {
            Payload[name] = new JwtProperty(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, JObject value)
        {
            Payload[name] = new JwtProperty(Encoding.UTF8.GetBytes(name), value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, JwtProperty value)
        {
            JObject jObject;
            if (Payload.TryGetValue(name, out JwtProperty jToken) && jToken.Type == JwtTokenType.Object)
            {
                jObject = (JObject)jToken.Value;
            }
            else
            {
                jObject = new JObject();
                Payload[name] = new JwtProperty(Encoding.UTF8.GetBytes(name), jObject);
            }

#if NETSTANDARD
            jObject.Add(Encoding.UTF8.GetString(value.Utf8Name.ToArray()), (JObject)value.Value);
#else
            jObject.Add(Encoding.UTF8.GetString(value.Utf8Name.Span), (JObject)value.Value);
#endif
        }

        ///// <summary>
        ///// Adds a claim.
        ///// </summary>
        ///// <param name="name"></param>
        ///// <param name="value"></param>
        //public void AddClaim(string name, JValue value)
        //{
        //    Payload[name] = new JwtProperty(JwtTokenType.Object, Encoding.UTF8.GetBytes(name), value);
        //}

        /// <summary>
        /// Gets a claim as <see cref="string"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected string GetStringClaim(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JwtProperty value))
            {
                return (string)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as <see cref="int"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected int? GetInt32Claim(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JwtProperty value))
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
        protected TClaim? GetClaim<TClaim>(string claimType) where TClaim : struct
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
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected bool? GetBoolClaim(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JwtProperty value))
            {
                return (bool?)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as a list of <see cref="string"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected IReadOnlyList<T> GetListClaims<T>(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JwtProperty value))
            {
                if (value.Type == JwtTokenType.Array)
                {
                    return new ReadOnlyCollection<T>((List<T>)value.Value);
                }

                var list = new List<T> { (T)value.Value };
                return new ReadOnlyCollection<T>(list);
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as <see cref="JObject"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected JObject GetClaim(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JwtProperty value) && value.Type == JwtTokenType.Object)
            {
                return (JObject)value.Value;
            }

            return null;
        }

        /// <summary>
        /// Sets a claim as <see cref="string"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        protected void SetClaim(string claimType, string value)
        {
            Payload[claimType] = new JwtProperty(Encoding.UTF8.GetBytes(claimType), value);
        }

        /// <summary>
        /// Gets a claim as a list of <see cref="string"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        protected void SetClaim(string claimType, IReadOnlyList<string> value)
        {
            Payload[claimType] = new JwtProperty(Encoding.UTF8.GetBytes(claimType), JArray.FromObject(value));
        }

        /// <summary>
        /// Gets a claim as <see cref="DateTime"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected DateTime? GetDateTime(string claimType)
        {
            if (!Payload.TryGetValue(claimType, out JwtProperty dateValue) || dateValue.Type == JwtTokenType.Null)
            {
                return null;
            }

            return EpochTime.ToDateTime((long)dateValue.Value);
        }

        /// <inheritsdoc />
        public override byte[] Encode(EncodingContext context)
        {
            Signer signatureProvider = null;
            var alg = (SignatureAlgorithm)(Algorithm ?? Key?.Alg);
            if (Key != null)
            {
                signatureProvider = context.SignatureFactory.Create(Key, alg, willCreateSignatures: true);
                if (signatureProvider == null)
                {
                    Errors.ThrowNotSupportedSignatureAlgorithm(alg, Key);
                }
            }

            if (context.TokenLifetimeInMinutes != 0 || context.GenerateIssuedTime)
            {
                DateTime now = DateTime.UtcNow;
                if (context.GenerateIssuedTime && !Payload.ContainsKey(Claims.Iat))
                {
                    AddClaim(Claims.Iat, now);
                }

                if (context.TokenLifetimeInMinutes != 0 && !Payload.ContainsKey(Claims.Exp))
                {
                    AddClaim(Claims.Exp, now + TimeSpan.FromMinutes(context.TokenLifetimeInMinutes));
                }
            }

            var payloadJson = Serialize(Payload);
            int length = Base64Url.GetArraySizeRequiredToEncode((int)payloadJson.Length)
                       + (Key == null ? 0 : Base64Url.GetArraySizeRequiredToEncode(signatureProvider.HashSizeInBytes))
                       + (Constants.JwsSegmentCount - 1);
#if NETCOREAPP3_0
            ReadOnlySequence<byte> headerJson = default;
#else
            string headerJson = null;
#endif   
            var headerCache = context.HeaderCache;
            byte[] base64UrlHeader = null;
            if (headerCache != null && headerCache.TryGetHeader(Header, alg, out base64UrlHeader))
            {
                length += base64UrlHeader.Length;
            }
            else
            {
                headerJson = Serialize(Header, Formatting.None);
                length += Base64Url.GetArraySizeRequiredToEncode((int)headerJson.Length);
            }

            byte[] bufferToReturn = new byte[length];
            var buffer = bufferToReturn.AsSpan();
            int headerBytesWritten;
            if (base64UrlHeader != null)
            {
                base64UrlHeader.CopyTo(buffer);
                headerBytesWritten = base64UrlHeader.Length;
            }
            else
            {
                TryEncodeUtf8ToBase64Url(headerJson, buffer, out headerBytesWritten);
                headerCache?.AddHeader(Header, alg, buffer.Slice(0, headerBytesWritten));
            }

            buffer[headerBytesWritten] = dot;
            TryEncodeUtf8ToBase64Url(payloadJson, buffer.Slice(headerBytesWritten + 1), out int payloadBytesWritten);
            buffer[payloadBytesWritten + headerBytesWritten + 1] = dot;
            int bytesWritten = 0;
            if (signatureProvider != null)
            {
                Span<byte> signature = stackalloc byte[signatureProvider.HashSizeInBytes];
                bool success = signatureProvider.TrySign(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + 1), signature, out int signatureBytesWritten);
                Debug.Assert(success);
                Debug.Assert(signature.Length == signatureBytesWritten);

                bytesWritten = Base64Url.Base64UrlEncode(signature, buffer.Slice(payloadBytesWritten + headerBytesWritten + (Constants.JwsSegmentCount - 1)));
            }

            Debug.Assert(buffer.Length == payloadBytesWritten + headerBytesWritten + (Constants.JwsSegmentCount - 1) + bytesWritten);
            return bufferToReturn;
        }

        private static bool TryEncodeUtf8ToBase64Url(string input, Span<byte> destination, out int bytesWritten)
        {
            byte[] arrayToReturnToPool = null;
            var encodedBytes = input.Length <= Constants.MaxStackallocBytes
                  ? stackalloc byte[input.Length]
                  : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(input.Length)).AsSpan(0, input.Length);
            try
            {
#if !NETSTANDARD2_0
                Encoding.UTF8.GetBytes(input, encodedBytes);
#else
                EncodingHelper.GetUtf8Bytes(input, encodedBytes);
#endif
                bytesWritten = Base64Url.Base64UrlEncode(encodedBytes, destination);
                return bytesWritten == destination.Length;
            }
            finally
            {
                if (arrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                }
            }
        }

#if NETCOREAPP3_0
        private static bool TryEncodeUtf8ToBase64Url(ReadOnlySequence<byte> input, Span<byte> destination, out int bytesWritten)
        {
            if (input.IsSingleSegment)
            {
                bytesWritten = Base64Url.Base64UrlEncode(input.First.Span, destination);
                return bytesWritten == destination.Length;
            }
            else
            {
                byte[] arrayToReturnToPool = null;
                try
                {
                    var encodedBytes = input.Length <= Constants.MaxStackallocBytes
                          ? stackalloc byte[(int)input.Length]
                          : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent((int)input.Length)).AsSpan(0, (int)input.Length);

                    input.CopyTo(encodedBytes);
                    bytesWritten = Base64Url.Base64UrlEncode(encodedBytes, destination);
                    return bytesWritten == destination.Length;
                }
                finally
                {
                    if (arrayToReturnToPool != null)
                    {
                        ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                    }
                }
            }

        }
#endif

        /// <inheritsdoc />
        public override void Validate()
        {
            for (int i = 0; i < ProhibitedClaims.Count; i++)
            {
                if (Payload.ContainsKey(ProhibitedClaims[i]))
                {
                    Errors.ThrowClaimIsProhibited(ProhibitedClaims[i]);
                }
            }

            foreach (var claim in RequiredClaims)
            {
                if (!Payload.TryGetValue(claim.Key, out JwtProperty token) || token.Type == JwtTokenType.Null)
                {
                    Errors.ThrowClaimIsRequired(claim.Key);
                }

                bool claimFound = false;
                for (int i = 0; i < claim.Value.Length; i++)
                {
                    if (token.Type == claim.Value[i])
                    {
                        claimFound = true;
                        break;
                    }
                }

                if (!claimFound)
                {
                    Errors.ThrowClaimMustBeOfType(claim);
                }
            }

            base.Validate();
        }
    }
}