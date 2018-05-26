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
        private const int MaxStackallocBytes = 1024 * 1024;

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
                var buffer = length <= MaxStackallocBytes
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
            var encodedBytes = input.Length <= MaxStackallocBytes
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

    public abstract class JwtDescriptor
    {
        public JwtDescriptor()
        {
            Header = new JObject();
        }

        public JObject Header { get; set; }

        public JsonWebKey Key { get; set; }

        public string Algorithm
        {
            get => GetHeaderParameter(JwtHeaderParameterNames.Alg) ?? Key?.Alg;
            set => Header[JwtHeaderParameterNames.Alg] = value;
        }

        public string KeyId
        {
            get => GetHeaderParameter(JwtHeaderParameterNames.Kid) ?? Key?.Kid;
            set => Header[JwtHeaderParameterNames.Kid] = value;
        }

        public string JwkSetUrl
        {
            get => GetHeaderParameter(JwtHeaderParameterNames.Jku);
            set => Header[JwtHeaderParameterNames.Jku] = value;
        }

        public string JsonWebKey
        {
            get => GetHeaderParameter(JwtHeaderParameterNames.Jwk);
            set => Header[JwtHeaderParameterNames.Jwk] = value;
        }

        public string X509Url
        {
            get => GetHeaderParameter(JwtHeaderParameterNames.X5u);
            set => Header[JwtHeaderParameterNames.X5u] = value;
        }

        public IList<string> X509CertificateChain
        {
            get => GetHeaderParameters(JwtHeaderParameterNames.X5c);
            set => Header[JwtHeaderParameterNames.X5c] = JArray.FromObject(value);
        }

        public string X509CertificateSha1Thumbprint
        {
            get => GetHeaderParameter(JwtHeaderParameterNames.X5t);
            set => Header[JwtHeaderParameterNames.X5t] = value;
        }

        public string Type
        {
            get => GetHeaderParameter(JwtHeaderParameterNames.Typ);
            set => Header[JwtHeaderParameterNames.Typ] = value;
        }

        public string ContentType
        {
            get => GetHeaderParameter(JwtHeaderParameterNames.Cty);
            set => Header[JwtHeaderParameterNames.Cty] = value;
        }

        public IList<string> Critical
        {
            get => GetHeaderParameters(JwtHeaderParameterNames.Cty);
            set => Header[JwtHeaderParameterNames.Cty] = JArray.FromObject(value);
        }

        public abstract string Encode();

        protected string GetHeaderParameter(string headerName)
        {
            if (Header.TryGetValue(headerName, out JToken value))
            {
                return value.Value<string>();
            }

            return null;
        }

        protected IList<string> GetHeaderParameters(string claimType)
        {
            if (Header.TryGetValue(claimType, out JToken value))
            {
                if (value.Type == JTokenType.Array)
                {
                    return new List<string>(value.Values<string>());
                }

                return new List<string>(new[] { value.Value<string>() });
            }

            return null;
        }
    }

    public abstract class JwtDescriptor<TPayload> : JwtDescriptor
    {
        public TPayload Payload { get; set; }
    }


    public abstract class JweDescriptor<TPayload> : JwtDescriptor<TPayload>
    {
        private const int MaxStackalloc = 1024 * 1024;

        public string EncryptionAlgorithm
        {
            get => GetHeaderParameter(JwtHeaderParameterNames.Enc);
            set => Header[JwtHeaderParameterNames.Enc] = value;
        }

        public string CompressionAlgorithm
        {
            get => GetHeaderParameter(JwtHeaderParameterNames.Zip);
            set => Header[JwtHeaderParameterNames.Zip] = value;
        }

        protected string EncryptToken(string payload)
        {
            var key = Key;
            string encryptionAlgorithm = EncryptionAlgorithm;
            string contentEncryptionAlgorithm = Algorithm;
            if (SecurityAlgorithms.Direct.Equals(contentEncryptionAlgorithm, StringComparison.Ordinal))
            {
                var encryptionProvider = key.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);
                if (encryptionProvider == null)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedEncryptionAlgorithm, encryptionAlgorithm));
                }

                var header = new JwtHeader(key, encryptionAlgorithm);
                try
                {
#if NETCOREAPP2_1
                    Span<byte> encodedPayload = stackalloc byte[payload.Length];
                    Encoding.UTF8.GetBytes(payload, encodedPayload);

                    var headerJson = header.ToString();
                    Span<byte> utf8EncodedHeader = stackalloc byte[headerJson.Length];
                    Encoding.UTF8.GetBytes(headerJson, utf8EncodedHeader);

                    Span<char> base64EncodedHeader = stackalloc char[Base64Url.GetArraySizeRequiredToEncode(utf8EncodedHeader.Length)];
                    int bytesWritten = Base64Url.Base64UrlEncode(utf8EncodedHeader, base64EncodedHeader);

                    Span<byte> asciiEncodedHeader = stackalloc byte[bytesWritten];
                    Encoding.ASCII.GetBytes(base64EncodedHeader.Slice(0, bytesWritten), asciiEncodedHeader);

                    var encryptionResult = encryptionProvider.Encrypt(encodedPayload, asciiEncodedHeader);
                    int encryptionLength =
                        base64EncodedHeader.Length
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.IV.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.Ciphertext.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.AuthenticationTag.Length)
                        + JwtConstants.JweSeparatorsCount;

                    char[] arrayToReturnToPool = null;
                    try
                    {
                        Span<char> encryptedToken = encryptionLength > MaxStackalloc
                        ? (arrayToReturnToPool = ArrayPool<char>.Shared.Rent(encryptionLength))
                        : stackalloc char[encryptionLength];

                        base64EncodedHeader.CopyTo(encryptedToken);
                        encryptedToken[bytesWritten++] = '.';
                        encryptedToken[bytesWritten++] = '.';
                        bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.IV, encryptedToken.Slice(bytesWritten));
                        encryptedToken[bytesWritten++] = '.';
                        bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.Ciphertext, encryptedToken.Slice(bytesWritten));
                        encryptedToken[bytesWritten++] = '.';
                        bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.AuthenticationTag, encryptedToken.Slice(bytesWritten));
                        Debug.Assert(encryptedToken.Length == bytesWritten);

                        return encryptedToken.ToString();
                    }
                    finally
                    {
                        if (arrayToReturnToPool != null)
                        {
                            ArrayPool<char>.Shared.Return(arrayToReturnToPool);
                        }
                    }
#else
                    var encryptionResult = encryptionProvider.Encrypt(Encoding.UTF8.GetBytes(payload), Encoding.ASCII.GetBytes(header.Base64UrlEncode()));
                    return string.Join(
                        ".",
                        header.Base64UrlEncode(),
                        string.Empty,
                        Base64Url.Encode(encryptionResult.IV),
                        Base64Url.Encode(encryptionResult.Ciphertext),
                        Base64Url.Encode(encryptionResult.AuthenticationTag));
#endif
                }
                catch (Exception ex)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.EncryptionFailed, encryptionAlgorithm, key), ex);
                }
            }
            else
            {
                SymmetricJwk symmetricKey = null;

                // only 128, 384 and 512 AesCbcHmac for CEK algorithm
                if (SecurityAlgorithms.Aes128CbcHmacSha256.Equals(encryptionAlgorithm, StringComparison.Ordinal))
                {
                    symmetricKey = SymmetricJwk.GenerateKey(256);
                }
                else if (SecurityAlgorithms.Aes192CbcHmacSha384.Equals(encryptionAlgorithm, StringComparison.Ordinal))
                {
                    symmetricKey = SymmetricJwk.GenerateKey(384);
                }
                else if (SecurityAlgorithms.Aes256CbcHmacSha512.Equals(encryptionAlgorithm, StringComparison.Ordinal))
                {
                    symmetricKey = SymmetricJwk.GenerateKey(512);
                }
                else
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, encryptionAlgorithm));
                }

                var kwProvider = key.CreateKeyWrapProvider(contentEncryptionAlgorithm);
                if (kwProvider == null)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, encryptionAlgorithm));
                }

                byte[] wrappedKey;
                try
                {
                    wrappedKey = kwProvider.WrapKey(symmetricKey.RawK);
                }
                finally
                {
                    key.ReleaseKeyWrapProvider(kwProvider);
                }

                var encryptionProvider = symmetricKey.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);
                if (encryptionProvider == null)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedEncryptionAlgorithm, encryptionAlgorithm));
                }

                try
                {
                    var header = new JwtHeader(key, encryptionAlgorithm);

#if NETCOREAPP2_1
                    Span<byte> encodedPayload = stackalloc byte[payload.Length];
                    Encoding.UTF8.GetBytes(payload, encodedPayload);

                    var headerJson = header.ToString();
                    Span<byte> utf8EncodedHeader = stackalloc byte[headerJson.Length];
                    Encoding.UTF8.GetBytes(headerJson, utf8EncodedHeader);

                    Span<char> base64EncodedHeader = stackalloc char[Base64Url.GetArraySizeRequiredToEncode(utf8EncodedHeader.Length)];
                    int bytesWritten = Base64Url.Base64UrlEncode(utf8EncodedHeader, base64EncodedHeader);

                    Span<byte> asciiEncodedHeader = stackalloc byte[bytesWritten];
                    Encoding.ASCII.GetBytes(base64EncodedHeader.Slice(0, bytesWritten), asciiEncodedHeader);

                    var encryptionResult = encryptionProvider.Encrypt(encodedPayload, asciiEncodedHeader);
                    int encryptionLength =
                        base64EncodedHeader.Length
                        + Base64Url.GetArraySizeRequiredToEncode(wrappedKey.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.IV.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.Ciphertext.Length)
                        + Base64Url.GetArraySizeRequiredToEncode(encryptionResult.AuthenticationTag.Length)
                        + JwtConstants.JweSeparatorsCount;

                    char[] arrayToReturnToPool = null;
                    try
                    {
                        Span<char> encryptedToken = encryptionLength > MaxStackalloc
                        ? (arrayToReturnToPool = ArrayPool<char>.Shared.Rent(encryptionLength))
                        : stackalloc char[encryptionLength];

                        base64EncodedHeader.CopyTo(encryptedToken);
                        encryptedToken[bytesWritten++] = '.';
                        bytesWritten += Base64Url.Base64UrlEncode(wrappedKey, encryptedToken.Slice(bytesWritten));
                        encryptedToken[bytesWritten++] = '.';
                        bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.IV, encryptedToken.Slice(bytesWritten));
                        encryptedToken[bytesWritten++] = '.';
                        bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.Ciphertext, encryptedToken.Slice(bytesWritten));
                        encryptedToken[bytesWritten++] = '.';
                        bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.AuthenticationTag, encryptedToken.Slice(bytesWritten));
                        Debug.Assert(bytesWritten == encryptedToken.Length);

                        return encryptedToken.ToString();
                    }
                    finally
                    {
                        if (arrayToReturnToPool != null)
                        {
                            ArrayPool<char>.Shared.Return(arrayToReturnToPool);
                        }
                    }
#else
                    var encryptionResult = encryptionProvider.Encrypt(Encoding.UTF8.GetBytes(payload), Encoding.ASCII.GetBytes(header.Base64UrlEncode()));
                    return string.Join(
                        ".",
                        header.Base64UrlEncode(),
                        Base64Url.Encode(wrappedKey),
                        Base64Url.Encode(encryptionResult.IV),
                        Base64Url.Encode(encryptionResult.Ciphertext),
                        Base64Url.Encode(encryptionResult.AuthenticationTag));
#endif
                }
                catch (Exception ex)
                {
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.EncryptionFailed, encryptionAlgorithm, key), ex);
                }
            }
        }
    }

    public class PlaintextJweDescriptor : JweDescriptor<string>
    {
        public override string Encode()
        {
            var payload = Payload;
            var rawData = EncryptToken(payload);

            return rawData;
        }
    }

    public class JweDescriptor : JweDescriptor<JwsDescriptor>
    {
        public JweDescriptor()
        {
            Payload = new JwsDescriptor();
        }

        public JweDescriptor(JwsDescriptor payload)
        {
            Payload = payload;
        }

        public JweDescriptor(JObject payload)
        {
            Payload = new JwsDescriptor((JObject)payload.DeepClone());
        }

        public override string Encode()
        {
            var payload = Payload.Encode();
            var rawData = EncryptToken(payload);

            return rawData;
        }
    }
}
