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

namespace JsonWebToken
{
    /// <summary>
    /// Defines a signed JWT with a JSON payload.
    /// </summary>
    public class JwsDescriptor : JwtDescriptor<JObject>
    {
        private static readonly byte dot = Convert.ToByte('.');
        private static readonly ReadOnlyDictionary<string, JTokenType[]> DefaultRequiredClaims = new ReadOnlyDictionary<string, JTokenType[]>(new Dictionary<string, JTokenType[]>());
        private static readonly string[] DefaultProhibitedClaims = Array.Empty<string>();
        private static readonly ReadOnlyDictionary<string, Type[]> JwsRequiredHeaderParameters = new ReadOnlyDictionary<string, Type[]>(
            new Dictionary<string, Type[]>
            {
                { HeaderParameters.Alg, new [] { typeof(string) } }
            });

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptor()
            : base(new Dictionary<string, object>(), new JObject())
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwsDescriptor"/>.
        /// </summary>
        public JwsDescriptor(IDictionary<string, object> header, JObject payload)
            : base(header, payload)
        {
        }

        /// <summary>
        /// Gets the required claims of the <see cref="JwsDescriptor"/>.
        /// </summary>
        protected virtual ReadOnlyDictionary<string, JTokenType[]> RequiredClaims => DefaultRequiredClaims;

        /// <summary>
        /// gets the prohibited claims of the <see cref="JwsDescriptor"/>.
        /// </summary>
        protected virtual IReadOnlyList<string> ProhibitedClaims => DefaultProhibitedClaims;

        /// <summary>
        /// Gets the required header parameters of the <see cref="JwsDescriptor"/>. 
        /// </summary>
        protected override ReadOnlyDictionary<string, Type[]> RequiredHeaderParameters => JwsRequiredHeaderParameters;

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
            get { return GetListClaims(Claims.Aud); }
            set { SetClaim(Claims.Aud, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'exp' claim.
        /// </summary>
        public DateTime? ExpirationTime
        {
            get { return GetDateTime(Claims.Exp); }
            set { SetClaim(Claims.Exp, value); }
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
            set { SetClaim(Claims.Iat, value); }
        }

        /// <summary>
        ///Gets or sets the value of the 'nbf' claim.
        /// </summary>
        public DateTime? NotBefore
        {
            get { return GetDateTime(Claims.Nbf); }
            set { SetClaim(Claims.Nbf, value); }
        }

        /// <summary>
        /// Adds a claim;
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, string value)
        {
            // TODO: allow to add a value into an array
            Payload[name] = value;
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, bool? value)
        {
            Payload[name] = value;
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, DateTime? value)
        {
            SetClaim(name, value);
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, int value)
        {
            Payload[name] = value;
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, bool value)
        {
            Payload[name] = value;
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, JObject value)
        {
            if (Payload.TryGetValue(name, out JToken jToken))
            {
                if (jToken.Type == JTokenType.Array)
                {
                    ((JArray)jToken).Add(value);
                }
                else
                {
                    var jArray = new JArray(jToken, value);
                    Payload[name] = value;
                }
            }
            else
            {
                Payload[name] = value;
            }
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, JProperty value)
        {
            JObject jObject;
            if (Payload.TryGetValue(name, out JToken jToken) && jToken.Type == JTokenType.Object)
            {
                jObject = (JObject)jToken;
            }
            else
            {
                jObject = new JObject();
            }

            jObject.Add(value.Name, value.Value);
            Payload[name] = jObject;
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, JValue value)
        {
            Payload[name] = value;
        }

        /// <summary>
        /// Adds a claim.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public void AddClaim(string name, JArray value)
        {
            Payload[name] = value;
        }

        /// <summary>
        /// Gets a claim as <see cref="string"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected string GetStringClaim(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JToken value))
            {
                return value.Value<string>();
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as <see cref="int"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected int? GetIntClaim(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JToken value))
            {
                return value.Value<int?>();
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
            if (Payload.TryGetValue(claimType, out JToken value))
            {
                return value.Value<TClaim?>();
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
            if (Payload.TryGetValue(claimType, out JToken value))
            {
                return value.Value<bool?>();
            }

            return null;
        }

        /// <summary>
        /// Gets a claim as a list of <see cref="string"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected IReadOnlyList<string> GetListClaims(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JToken value))
            {
                if (value.Type == JTokenType.Array)
                {
                    return new List<string>(value.Values<string>());
                }

                return new List<string>(new[] { value.Value<string>() });
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
            if (Payload.TryGetValue(claimType, out JToken value) && value.Type == JTokenType.Object)
            {
                return (JObject)value;
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
            Payload[claimType] = value;
        }

        /// <summary>
        /// Gets a claim as a list of <see cref="string"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        protected void SetClaim(string claimType, IReadOnlyList<string> value)
        {
            Payload[claimType] = JArray.FromObject(value);
        }

        /// <summary>
        /// Gets a claim as <see cref="DateTime"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <returns></returns>
        protected DateTime? GetDateTime(string claimType)
        {
            if (!Payload.TryGetValue(claimType, out JToken dateValue) || dateValue.Type == JTokenType.Null)
            {
                return null;
            }

            return EpochTime.ToDateTime(dateValue.Value<long>());
        }

        /// <summary>
        /// Sets a claim as <see cref="DateTime"/>.
        /// </summary>
        /// <param name="claimType"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        protected void SetClaim(string claimType, DateTime? value)
        {
            if (value.HasValue)
            {
                Payload[claimType] = value.ToEpochTime();
            }
            else
            {
                Payload[claimType] = null;
            }
        }

        /// <inheritsdoc />
        public override byte[] Encode(EncodingContext context)
        {
            Signer signatureProvider = null;
            var alg = (SignatureAlgorithm)(Algorithm ?? Key?.Alg);
            if (Key != null)
            {
                var key = Key;
                signatureProvider = context.SignatureFactory.Create(key, alg, willCreateSignatures: true);
                if (signatureProvider == null)
                {
                    Errors.ThrowNotSupportedSignatureAlgorithm(alg, key);
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

            var payloadJson = Serialize(Payload, Formatting.None);
            int length = Base64Url.GetArraySizeRequiredToEncode(payloadJson.Length)
                       + (Key == null ? 0 : Base64Url.GetArraySizeRequiredToEncode(signatureProvider.HashSizeInBytes))
                       + (Constants.JwsSegmentCount - 1);
            string headerJson = null;

            var headerCache = context.HeaderCache;
            byte[] base64UrlHeader = null;
            if (headerCache != null && headerCache.TryGetHeader(Header, alg, out base64UrlHeader))
            {
                length += base64UrlHeader.Length;
            }
            else
            {
                headerJson = Serialize(Header, Formatting.None);
                length += Base64Url.GetArraySizeRequiredToEncode(headerJson.Length);
            }

            byte[] arrayToReturnToPool = null;
            var buffer = length <= Constants.MaxStackallocBytes
                  ? stackalloc byte[length]
                  : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length)).AsSpan(0, length);
            try
            {
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
                return buffer.Slice(0, payloadBytesWritten + headerBytesWritten + (Constants.JwsSegmentCount - 1) + bytesWritten).ToArray();
            }
            finally
            {
                if (arrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                }
            }
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
                if (!Payload.TryGetValue(claim.Key, out JToken token) || token.Type == JTokenType.Null)
                {
                    Errors.ThrowClaimIsRequired(claim.Key);
                }

                bool claimFound = false;
                for (int i = 0; i < claim.Value.Length; i++)
                {
                    if (token?.Type == claim.Value[i])
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
