using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Collections.Generic;
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
            JToken value = null;
            if (Payload.TryGetValue(claimType, out value))
            {
                return value.Value<string>();
            }

            return null;
        }

        private int? GetIntClaim(string claimType)
        {
            JToken value;
            if (Payload.TryGetValue(claimType, out value))
            {
                return value.Value<int?>();
            }

            return null;
        }

        private IList<string> GetListClaims(string claimType)
        {
            JToken value = null;
            if (Payload.TryGetValue(claimType, out value))
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
            JToken dateValue;
            if (!Payload.TryGetValue(key, out dateValue) || !dateValue.HasValues)
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

            var headerJson = header.SerializeToJson();
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
                + Base64Url.GetArraySizeRequiredToEncode(signatureProvider?.HashSize ?? 0)
                + JwtConstants.JwsSeparatorsCount;
            unsafe
            {
                var array = ArrayPool<byte>.Shared.Rent(length);
                Span<byte> buffer = array;
                try
                {
                    header.TryBase64UrlEncode(buffer, out int headerBytesWritten);
                    buffer[headerBytesWritten] = dot;
                    payload.TryBase64UrlEncode(buffer.Slice(headerBytesWritten + 1), out int payloadBytesWritten);
                    buffer[payloadBytesWritten + headerBytesWritten + 1] = dot;
                    int signatureBytesWritten = 0;
                    if (signatureProvider != null)
                    {
                        Span<byte> signature = stackalloc byte[signatureProvider.HashSize];
                        try
                        {
                            signatureProvider.TrySign(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + 1), signature, out int signLength);
                            Base64Url.Base64UrlEncode(signature.Slice(0, signLength), buffer.Slice(payloadBytesWritten + headerBytesWritten + JwtConstants.JwsSeparatorsCount), out int bytesConsumed, out signatureBytesWritten);
                        }
                        finally
                        {
                            Key.ReleaseSignatureProvider(signatureProvider);
                        }
                    }

#if NETCOREAPP2_1
                    string rawData = Encoding.UTF8.GetString(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + JwtConstants.JwsSeparatorsCount + signatureBytesWritten));
#else
                    string rawData = Encoding.UTF8.GetString(buffer.Slice(0, payloadBytesWritten + headerBytesWritten + JwtConstants.JwsSeparatorsCount + signatureBytesWritten).ToArray());
#endif
                    return rawData;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(array);
                }
            }
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
            JToken value = null;
            if (Header.TryGetValue(headerName, out value))
            {
                return value.Value<string>();
            }

            return null;
        }

        protected IList<string> GetHeaderParameters(string claimType)
        {
            JToken value = null;
            if (Header.TryGetValue(claimType, out value))
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

                    var headerJson = header.SerializeToJson();
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

                    Span<char> encryptedToken = stackalloc char[encryptionLength];

                    base64EncodedHeader.CopyTo(encryptedToken);
                    encryptedToken[bytesWritten++] = '.';
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.IV, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.Ciphertext, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.AuthenticationTag, encryptedToken.Slice(bytesWritten));

                    return encryptedToken.Slice(0, bytesWritten).ToString();
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

                    var headerJson = header.SerializeToJson();
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

                    Span<char> encryptedToken = stackalloc char[encryptionLength];

                    base64EncodedHeader.CopyTo(encryptedToken);
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(wrappedKey, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.IV, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.Ciphertext, encryptedToken.Slice(bytesWritten));
                    encryptedToken[bytesWritten++] = '.';
                    bytesWritten += Base64Url.Base64UrlEncode(encryptionResult.AuthenticationTag, encryptedToken.Slice(bytesWritten));

                    return encryptedToken.Slice(0, bytesWritten).ToString();

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

    /// <summary>
    /// Contains some information which used to create a token.
    /// </summary>
    //public class JsonWebTokenDescriptor
    //{
    //    private string _plaintext;

    //    public JsonWebTokenDescriptor()
    //        : this((JObject)null, null)
    //    {
    //    }

    //    public JsonWebTokenDescriptor(string payloadJson, string headerJson)
    //        : this(JObject.Parse(payloadJson), JObject.Parse(headerJson))
    //    {
    //    }

    //    public JsonWebTokenDescriptor(string jsonPayload)
    //        : this(JObject.Parse(jsonPayload))
    //    {
    //    }

    //    public JsonWebTokenDescriptor(JObject payload)
    //        : this(payload, null)
    //    {
    //    }

    //    public JsonWebTokenDescriptor(JObject payload, JObject header)
    //    {
    //        Payload = payload ?? new JObject();
    //        Header = header ?? new JObject();
    //    }

    //    public JObject Payload { get; }

    //    public JObject Header { get; }

    //    public string Plaintext
    //    {
    //        get => _plaintext;
    //        set
    //        {
    //            if (Payload.Count != 0 && value != null)
    //            {
    //                throw new ArgumentException(ErrorMessages.PayloadIncompatibleWithPlaintext, nameof(value));
    //            }

    //            _plaintext = value;
    //        }
    //    }

    //    /// <summary>
    //    /// Gets or sets the value of the 'jti' claim.
    //    /// </summary>
    //    public string Id
    //    {
    //        get { return GetStringClaim(JwtRegisteredClaimNames.Jti); }
    //        set { AddClaim(JwtRegisteredClaimNames.Jti, value); }
    //    }

    //    /// <summary>
    //    /// Gets or sets the value of the 'aud' claim.
    //    /// </summary>
    //    public string Audience
    //    {
    //        get { return GetStringClaim(JwtRegisteredClaimNames.Aud); }
    //        set { AddClaim(JwtRegisteredClaimNames.Aud, value); }
    //    }

    //    /// <summary>
    //    /// Gets or sets the value of the 'aud' claim.
    //    /// </summary>
    //    public ICollection<string> Audiences
    //    {
    //        get { return GetListClaims(JwtRegisteredClaimNames.Aud); }
    //        set { SetClaim(JwtRegisteredClaimNames.Aud, value); }
    //    }

    //    /// <summary>
    //    /// Gets or sets the value of the 'exp' claim.
    //    /// </summary>
    //    public DateTime? Expires
    //    {
    //        get { return GetDateTime(JwtRegisteredClaimNames.Exp); }
    //        set { SetClaim(JwtRegisteredClaimNames.Exp, value); }
    //    }

    //    /// <summary>
    //    /// Gets or sets the issuer of this <see cref="JsonWebTokenDescriptor"/>.
    //    /// </summary>
    //    public string Issuer
    //    {
    //        get { return GetStringClaim(JwtRegisteredClaimNames.Iss); }
    //        set { AddClaim(JwtRegisteredClaimNames.Iss, value); }
    //    }

    //    /// <summary>
    //    /// Gets or sets the time the security token was issued.
    //    /// </summary>
    //    public DateTime? IssuedAt
    //    {
    //        get { return GetDateTime(JwtRegisteredClaimNames.Iat); }
    //        set { SetClaim(JwtRegisteredClaimNames.Iat, value); }
    //    }

    //    /// <summary>
    //    /// Gets or sets the notbefore time for the security token.
    //    /// </summary>
    //    public DateTime? NotBefore
    //    {
    //        get { return GetDateTime(JwtRegisteredClaimNames.Nbf); }
    //        set { SetClaim(JwtRegisteredClaimNames.Nbf, value); }
    //    }

    //    /// <summary>
    //    /// Gets or sets the <see cref="SigningKey"/> used to create a security token.
    //    /// </summary>
    //    public JsonWebKey SigningKey { get; set; }

    //    /// <summary>
    //    /// Gets or sets the <see cref="EncryptingKey"/> used to create a encrypted security token.
    //    /// </summary>
    //    public JsonWebKey EncryptingKey { get; set; }

    //    /// <summary>
    //    /// Reprensents the 'enc' header for a JWE.
    //    /// </summary>
    //    public string EncryptionAlgorithm { get; set; }

    //    public JsonWebTokenDescriptor NestedToken { get; set; }

    //    public void AddClaim(string name, string value)
    //    {
    //        AddClaim(name, value);
    //    }

    //    public void AddClaim(string name, DateTime? value)
    //    {
    //        SetClaim(name, value);
    //    }

    //    public void AddClaim(string name, int value)
    //    {
    //        Payload[name] = value;
    //    }

    //    public void AddClaim(string name, bool value)
    //    {
    //        Payload[name] = value;
    //    }

    //    public void AddClaim(string name, JObject value)
    //    {
    //        Payload[name] = value;
    //    }

    //    public void AddClaim(string name, JValue value)
    //    {
    //        Payload[name] = value;
    //    }

    //    public void AddClaim(string name, JArray value)
    //    {
    //        Payload[name] = value;
    //    }

    //    private string GetStringClaim(string claimType)
    //    {
    //        JToken value = null;
    //        if (Payload.TryGetValue(claimType, out value))
    //        {
    //            return value.Value<string>();
    //        }

    //        return null;
    //    }

    //    private int? GetIntClaim(string claimType)
    //    {
    //        JToken value;
    //        if (Payload.TryGetValue(claimType, out value))
    //        {
    //            return value.Value<int?>();
    //        }

    //        return null;
    //    }

    //    private IList<string> GetListClaims(string claimType)
    //    {
    //        JToken value = null;
    //        if (Payload.TryGetValue(claimType, out value))
    //        {
    //            if (value.Type == JTokenType.Array)
    //            {
    //                return new List<string>(value.Values<string>());
    //            }

    //            return new List<string>(new[] { value.Value<string>() });
    //        }

    //        return null;
    //    }

    //    private void SetClaim(string claimType, ICollection<string> value)
    //    {
    //        Payload[claimType] = JArray.FromObject(value);
    //    }

    //    private DateTime? GetDateTime(string key)
    //    {
    //        JToken dateValue;
    //        if (!Payload.TryGetValue(key, out dateValue))
    //        {
    //            return null;
    //        }

    //        return EpochTime.ToDateTime(dateValue.Value<int>());
    //    }


    //    private void SetClaim(string claimType, DateTime? value)
    //    {
    //        if (value.HasValue)
    //        {
    //            Payload[claimType] = EpochTime.GetIntDate(value.Value);
    //        }
    //        else
    //        {
    //            Payload[claimType] = null;
    //        }
    //    }
    //}
}
