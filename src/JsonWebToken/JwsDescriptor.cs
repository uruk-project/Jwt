using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace JsonWebToken
{
    public class JwsDescriptor : JwtDescriptor<JObject>, IJwtPayloadDescriptor
    {
        private static readonly byte dot = Convert.ToByte('.');
        private static readonly Dictionary<string, JTokenType[]> DefaultRequiredClaims = new Dictionary<string, JTokenType[]>();
        private static readonly string[] DefaultProhibitedClaims = Array.Empty<string>();
        private static readonly Dictionary<string, JTokenType[]> JwsRequiredHeaderParameters = new Dictionary<string, JTokenType[]>
        {
            { HeaderParameters.Alg, new [] { JTokenType.String } }
        };

        public JwsDescriptor()
            : base(new JObject(), new JObject())
        {
        }

        public JwsDescriptor(JObject header, JObject payload)
            : base(header, payload)
        {
        }

        public JwsDescriptor(JObject payload)
            : base(new JObject(), payload)
        {
        }

        protected virtual IReadOnlyDictionary<string, JTokenType[]> RequiredClaims => DefaultRequiredClaims;

        protected virtual IReadOnlyList<string> ProhibitedClaims => DefaultProhibitedClaims;

        protected override IReadOnlyDictionary<string, JTokenType[]> RequiredHeaderParameters => JwsRequiredHeaderParameters;

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
        /// Gets or sets the issuer of this <see cref="JsonWebTokenDescriptor"/>.
        /// </summary>
        public string Issuer
        {
            get { return GetStringClaim(Claims.Iss); }
            set { AddClaim(Claims.Iss, value); }
        }

        /// <summary>
        /// Gets or sets the time the security token was issued.
        /// </summary>
        public DateTime? IssuedAt
        {
            get { return GetDateTime(Claims.Iat); }
            set { SetClaim(Claims.Iat, value); }
        }

        /// <summary>
        /// Gets or sets the notbefore time for the security token.
        /// </summary>
        public DateTime? NotBefore
        {
            get { return GetDateTime(Claims.Nbf); }
            set { SetClaim(Claims.Nbf, value); }
        }

        public void AddClaim(string name, string value)
        {
            // TODO: allow to add a value into an array
            Payload[name] = value;
        }

        public void AddClaim(string name, bool? value)
        {
            Payload[name] = value;
        }

        public void AddClaim(string name, DateTime? value)
        {
            SetClaim(name, value);
        }

        public void AddClaim(string name, int value)
        {
            Payload[name] = value;
        }

        public void AddClaim(string name, bool value)
        {
            Payload[name] = value;
        }

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

        public void AddClaim(string name, JProperty property)
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

            jObject.Add(property.Name, property.Value);
            Payload[name] = jObject;
        }

        public void AddClaim(string name, JValue value)
        {
            Payload[name] = value;
        }

        public void AddClaim(string name, JArray value)
        {
            Payload[name] = value;
        }

        protected string GetStringClaim(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JToken value))
            {
                return value.Value<string>();
            }

            return null;
        }

        protected int? GetIntClaim(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JToken value))
            {
                return value.Value<int?>();
            }

            return null;
        }
        protected TClaim? GetClaim<TClaim>(string claimType) where TClaim : struct
        {
            if (Payload.TryGetValue(claimType, out JToken value))
            {
                return value.Value<TClaim?>();
            }

            return null;
        }

        protected bool? GetBoolClaim(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JToken value))
            {
                return value.Value<bool?>();
            }

            return null;
        }

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

        protected JObject GetClaim(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JToken value) && value.Type == JTokenType.Object)
            {
                return (JObject)value;
            }

            return null;
        }

        protected void SetClaim(string claimType, string value)
        {
            Payload[claimType] = value;
        }

        protected void SetClaim(string claimType, IReadOnlyList<string> value)
        {
            Payload[claimType] = JArray.FromObject(value);
        }

        protected DateTime? GetDateTime(string key)
        {
            if (!Payload.TryGetValue(key, out JToken dateValue) || dateValue.Type == JTokenType.Null)
            {
                return null;
            }

            return EpochTime.ToDateTime(dateValue.Value<long>());
        }

        protected void SetClaim(string claimType, DateTime? value)
        {
            if (value.HasValue)
            {
                Payload[claimType] = EpochTime.GetIntDate(value.Value);
            }
            else
            {
                Payload[claimType] = null;
            }
        }

        public override string Encode(EncodingContext context)
        {
            SignatureProvider signatureProvider = null;
            var alg = (SignatureAlgorithm)(string.IsNullOrEmpty(Algorithm) ? Key?.Alg : Algorithm);
            if (Key != null)
            {
                var key = Key;
                signatureProvider = key.CreateSignatureProvider(alg, true);
                if (signatureProvider == null)
                {
                    throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedSignatureAlgorithm, key.Alg, (key.Kid ?? "Null")));
                }
            }

            var payloadJson = Serialize(Payload);
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
                headerJson = Serialize(Header);
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
                    try
                    {
                        bool success = signatureProvider.TrySign(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + 1), signature, out int signatureBytesWritten);
                        Debug.Assert(success);
                        Debug.Assert(signature.Length == signatureBytesWritten);

                        Base64Url.Base64UrlEncode(signature, buffer.Slice(payloadBytesWritten + headerBytesWritten + (Constants.JwsSegmentCount - 1)), out int bytesConsumed, out bytesWritten);
                    }
                    finally
                    {
                        Key.ReleaseSignatureProvider(signatureProvider);
                    }
                }

#if NETCOREAPP2_1
                string rawData = Encoding.UTF8.GetString(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + (Constants.JwsSegmentCount - 1) + bytesWritten));
#else
                string rawData = Encoding.UTF8.GetString(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + (Constants.JwsSegmentCount - 1) + bytesWritten).ToArray());
#endif
                return rawData;
            }
            finally
            {
                if (arrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                }
            }
        }

        public bool TryEncodeUtf8ToBase64Url(string input, Span<byte> destination, out int bytesWritten)
        {
#if NETCOREAPP2_1
            byte[] arrayToReturnToPool = null;
            var encodedBytes = input.Length <= Constants.MaxStackallocBytes
                  ? stackalloc byte[input.Length]
                  : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(input.Length)).AsSpan(0, input.Length);
            try
            {
                Encoding.UTF8.GetBytes(input, encodedBytes);
                var status = Base64Url.Base64UrlEncode(encodedBytes, destination, out int bytesConsumed, out bytesWritten);
                return status == OperationStatus.Done;
            }
            finally
            {
                if (arrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                }
            }
#else
            var encodedBytes = Encoding.UTF8.GetBytes(input);

            var status = Base64Url.Base64UrlEncode(encodedBytes, destination, out int bytesConsumed, out bytesWritten);
            return status == OperationStatus.Done;
#endif
        }

        protected bool HasMandatoryClaim(string claim)
        {
            return Payload.TryGetValue(claim, out var value) && value.Type != JTokenType.Null;
        }

        public override void Validate()
        {
            for (int i = 0; i < ProhibitedClaims.Count; i++)
            {
                if (Payload.ContainsKey(ProhibitedClaims[i]))
                {
                    throw new JwtDescriptorException(ErrorMessages.FormatInvariant("The claim '{0}' is prohibited.", ProhibitedClaims[i]));
                }
            }

            foreach (var claim in RequiredClaims)
            {
                if (!Payload.TryGetValue(claim.Key, out JToken token) || token.Type == JTokenType.Null)
                {
                    throw new JwtDescriptorException(ErrorMessages.FormatInvariant("The claim '{0}' is required.", claim.Key));
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
                    throw new JwtDescriptorException(ErrorMessages.FormatInvariant("The claim '{0}' must be of type [{1}].", claim.Key, string.Join(", ", claim.Value.Select(t => t.ToString()))));
                }
            }

            base.Validate();
        }
    }
}
