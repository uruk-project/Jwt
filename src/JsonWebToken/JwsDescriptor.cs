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

        public JwsDescriptor(JObject payload)
        {
            Payload = (JObject)payload.DeepClone();
        }

        public JwsDescriptor()
        {
            Payload = new JObject();
        }

        /// <summary>
        /// Gets or sets the value of the 'jti' claim.
        /// </summary>
        public string JwtId
        {
            get { return GetStringClaim(JwtRegisteredClaimNames.Jti); }
            set { AddClaim(JwtRegisteredClaimNames.Jti, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public string Audience
        {
            get { return Audiences?.FirstOrDefault(); }
            set { SetClaim(JwtRegisteredClaimNames.Aud, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public ICollection<string> Audiences
        {
            get { return GetListClaims(JwtRegisteredClaimNames.Aud); }
            set { SetClaim(JwtRegisteredClaimNames.Aud, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'exp' claim.
        /// </summary>
        public DateTime? ExpirationTime
        {
            get { return GetDateTime(JwtRegisteredClaimNames.Exp); }
            set { SetClaim(JwtRegisteredClaimNames.Exp, value); }
        }

        /// <summary>
        /// Gets or sets the issuer of this <see cref="JsonWebTokenDescriptor"/>.
        /// </summary>
        public string Issuer
        {
            get { return GetStringClaim(JwtRegisteredClaimNames.Iss); }
            set { AddClaim(JwtRegisteredClaimNames.Iss, value); }
        }

        /// <summary>
        /// Gets or sets the time the security token was issued.
        /// </summary>
        public DateTime? IssuedAt
        {
            get { return GetDateTime(JwtRegisteredClaimNames.Iat); }
            set { SetClaim(JwtRegisteredClaimNames.Iat, value); }
        }

        /// <summary>
        /// Gets or sets the notbefore time for the security token.
        /// </summary>
        public DateTime? NotBefore
        {
            get { return GetDateTime(JwtRegisteredClaimNames.Nbf); }
            set { SetClaim(JwtRegisteredClaimNames.Nbf, value); }
        }


        public void AddClaim(string name, string value)
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
            Payload[name] = value;
        }

        public void AddClaim(string name, JValue value)
        {
            Payload[name] = value;
        }

        public void AddClaim(string name, JArray value)
        {
            Payload[name] = value;
        }

        private string GetStringClaim(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JToken value))
            {
                return value.Value<string>();
            }

            return null;
        }

        private int? GetIntClaim(string claimType)
        {
            if (Payload.TryGetValue(claimType, out JToken value))
            {
                return value.Value<int?>();
            }

            return null;
        }

        private IList<string> GetListClaims(string claimType)
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

        private void SetClaim(string claimType, string value)
        {
            Payload[claimType] = value;
        }

        private void SetClaim(string claimType, ICollection<string> value)
        {
            Payload[claimType] = JArray.FromObject(value);
        }

        private DateTime? GetDateTime(string key)
        {
            if (!Payload.TryGetValue(key, out JToken dateValue) || !dateValue.HasValues)
            {
                return null;
            }

            return EpochTime.ToDateTime(dateValue.Value<long>());
        }


        private void SetClaim(string claimType, DateTime? value)
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

        public override string Encode()
        {
            JwtHeader header = Key == null ? new JwtHeader() : new JwtHeader(Key);
            foreach (var item in Header)
            {
                header[item.Key] = item.Value;
            }

            var headerJson = header.ToString();
            SignatureProvider signatureProvider = null;
            if (Key != null)
            {
                var key = Key;
                signatureProvider = key.CreateSignatureProvider(key.Alg, true);
                if (signatureProvider == null)
                {
                    throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedSignatureAlgorithm, (key == null ? "Null" : key.Kid), (key.Alg ?? "Null")));
                }
            }

            var payload = new JwtPayload(Payload);
            var payloadJson = payload.ToString();
            int length = Base64Url.GetArraySizeRequiredToEncode(headerJson.Length)
                + Base64Url.GetArraySizeRequiredToEncode(payloadJson.Length)
                + (Key == null ? 0 : Base64Url.GetArraySizeRequiredToEncode(signatureProvider.HashSizeInBits / 8))
                + JwtConstants.JwsSeparatorsCount;
            unsafe
            {
                byte[] arrayToReturnToPool = null;
                var buffer = length <= JwtConstants.MaxStackallocBytes
                      ? stackalloc byte[length]
                      : arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length);
                try
                {
                    TryEncodeUtf8ToBase64Url(headerJson, buffer, out int headerBytesWritten);
                    buffer[headerBytesWritten] = dot;
                    TryEncodeUtf8ToBase64Url(payloadJson, buffer.Slice(headerBytesWritten + 1), out int payloadBytesWritten);
                    buffer[payloadBytesWritten + headerBytesWritten + 1] = dot;
                    int bytesWritten = 0;
                    if (signatureProvider != null)
                    {
                        Span<byte> signature = stackalloc byte[signatureProvider.HashSizeInBits / 8];
                        try
                        {
                            bool success = signatureProvider.TrySign(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + 1), signature, out int signatureBytesWritten);
                            Debug.Assert(success);
                            Debug.Assert(signature.Length == signatureBytesWritten);

                            Base64Url.Base64UrlEncode(signature.Slice(0, signatureBytesWritten), buffer.Slice(payloadBytesWritten + headerBytesWritten + JwtConstants.JwsSeparatorsCount), out int bytesConsumed, out bytesWritten);
                        }
                        finally
                        {
                            Key.ReleaseSignatureProvider(signatureProvider);
                        }
                    }

#if NETCOREAPP2_1
                    string rawData = Encoding.UTF8.GetString(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + JwtConstants.JwsSeparatorsCount + bytesWritten));
#else
                    string rawData = Encoding.UTF8.GetString(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + JwtConstants.JwsSeparatorsCount + bytesWritten).ToArray());
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
        }

        public bool TryEncodeUtf8ToBase64Url(string input, Span<byte> destination, out int bytesWritten)
        {
#if NETCOREAPP2_1
            byte[] arrayToReturnToPool = null;
            var encodedBytes = input.Length <= JwtConstants.MaxStackallocBytes
                  ? stackalloc byte[input.Length]
                  : arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(input.Length);
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
    }
}
