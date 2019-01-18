// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
#if NETCOREAPP3_0
using System.Text.Json;
#endif

namespace JsonWebToken
{
    /// <summary>
    /// Represents a JSON Web Key as defined in http://tools.ietf.org/html/rfc7517.
    /// </summary>
    [JsonObject]
    [DebuggerDisplay("{DebuggerDisplay(),nq}")]
    public abstract class Jwk
    {
        private static readonly JwkJsonConverter jsonConverter = new JwkJsonConverter();
        private static readonly JwkContractResolver contractResolver = new JwkContractResolver();
        private static readonly JsonSerializerSettings serializerSettings = new JsonSerializerSettings { ContractResolver = contractResolver };

        internal static readonly JsonSerializer Serializer = new JsonSerializer { Converters = { jsonConverter }, ContractResolver = contractResolver };
        private List<Jwk> _certificateChain;

        /// <summary>
        /// When deserializing from JSON any properties that are not defined will be placed here.
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, object> AdditionalData { get; } = new Dictionary<string, object>();

        /// <summary>
        /// Gets or sets the 'alg' (KeyType).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.Alg, Required = Required.Default)]
        public string Alg { get; set; }

        /// <summary>
        /// Gets the 'key_ops' (Key Operations).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.KeyOps, Required = Required.Default)]
        public IList<string> KeyOps { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'kid' (Key ID).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.Kid, Required = Required.Default)]
        public string Kid { get; set; }

        /// <summary>
        /// Gets or sets the 'kty' (Key Type).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.Kty, Required = Required.Default)]
        public abstract string Kty { get; }

        // TODO : Replace string by another type faster to compare (4 comparisons).
        /// <summary>
        /// Gets or sets the 'use' (Public Key Use).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.Use, Required = Required.Default)]
        public string Use { get; set; }

        /// <summary>
        /// Gets the 'x5c' collection (X.509 Certificate Chain).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.X5c, Required = Required.Default, ItemConverterType = typeof(Base64Converter))]
        public List<byte[]> X5c { get; set; } = new List<byte[]>();

        /// <summary>
        /// Gets or sets the 'x5t' (X.509 Certificate SHA-1 thumbprint).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.X5t, Required = Required.Default)]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] X5t { get; set; }

        /// <summary>
        /// Gets or sets the 'x5t#S256' (X.509 Certificate SHA-256 thumbprint).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.X5tS256, Required = Required.Default)]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] X5tS256 { get; set; }

        /// <summary>
        /// Gets or sets the 'x5u' (X.509 URL).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.X5u, Required = Required.Default)]
        public string X5u { get; set; }

        /// <summary>
        /// Gets the key size of <see cref="Jwk"/>.
        /// </summary>
        [JsonIgnore]
        public abstract int KeySizeInBits { get; }

        /// <summary>
        /// Gets the X.509 certificate chain.
        /// </summary>
        [JsonIgnore]
        public IList<Jwk> X509CertificateChain
        {
            get
            {
                if (X5c == null)
                {
                    return null;
                }

                if (_certificateChain == null)
                {
                    _certificateChain = new List<Jwk>(X5c.Count);
                    foreach (var certString in X5c)
                    {
                        using (var certificate = new X509Certificate2(certString))
                        {
                            var key = FromX509Certificate(certificate, false);
                            key.Kid = Kid;
                            _certificateChain.Add(key);
                        }
                    }
                }

                return _certificateChain;
            }
        }

        /// <summary>
        /// Gets a bool that determines if the 'key_ops' (Key Operations) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'key_ops' (Key Operations) is not empty; otherwise, false.</return>
        public bool ShouldSerializeKeyOps()
        {
            return KeyOps.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'x5c' collection (X.509 Certificate Chain) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        ///</summary>
        /// <return>true if 'x5c' collection (X.509 Certificate Chain) is not empty; otherwise, false.</return>
        public bool ShouldSerializeX5c()
        {
            return X5c.Count > 0;
        }

        /// <summary>
        /// Determines if the <see cref="Jwk"/> supports the <paramref name="algorithm"/>.
        /// </summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> to verify.</param>
        /// <returns><c>true</c> if the key support the algorithm; otherwise <c>false</c></returns>
        public abstract bool IsSupported(SignatureAlgorithm algorithm);

        /// <summary>
        /// Determines if the <see cref="Jwk"/> supports the <paramref name="algorithm"/>.
        /// </summary>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> to verify.</param>
        /// <returns><c>true</c> if the key support the algorithm; otherwise <c>false</c></returns>
        public abstract bool IsSupported(KeyManagementAlgorithm algorithm);

        /// <summary>
        /// Determines if the <see cref="Jwk"/> supports the <paramref name="algorithm"/>.
        /// </summary>
        /// <param name="algorithm">The <see cref="EncryptionAlgorithm"/> to verify.</param>
        /// <returns><c>true</c> if the key support the algorithm; otherwise <c>false</c></returns>
        public abstract bool IsSupported(EncryptionAlgorithm algorithm);

        /// <summary>
        /// Returns a string that represents the <see cref="Jwk"/> in JSON.
        /// </summary>
        public override string ToString()
        {
            return ToString(Formatting.None);
        }

        /// <summary>
        /// Returns a string that represents the <see cref="Jwk"/> in JSON.
        /// </summary>
        public string ToString(Formatting formatting)
        {
            return JsonConvert.SerializeObject(this, formatting, serializerSettings);
        }

        /// <summary>
        /// Provides the binary representation of the key.
        /// </summary>
        public abstract byte[] ToByteArray();

        /// <summary>
        /// Creates a <see cref="Signer"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        /// <param name="willCreateSignatures">Determines if the <see cref="Signer"/> will create or only verify signatures.</param>
        public abstract Signer CreateSigner(SignatureAlgorithm algorithm, bool willCreateSignatures);

        /// <summary>
        /// Creates a <see cref="KeyWrapper"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for key wrapping.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/> used for key wrapping.</param>
        public abstract KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm);

        /// <summary>
        /// Creates a <see cref="AuthenticatedEncryptor"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="encryptionAlgorithm">The <see cref="EncryptionAlgorithm"/> used for encryption.</param>
        public abstract AuthenticatedEncryptor CreateAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm);

        /// <summary>
        /// Returns a new <see cref="Jwk"/> in its normal form, as defined by https://tools.ietf.org/html/rfc7638#section-3.2
        /// </summary>
        /// <returns></returns>
        public abstract Jwk Canonicalize();

#if !NETSTANDARD2_0
        /// <summary>
        /// Compute a hash as defined by https://tools.ietf.org/html/rfc7638.
        /// </summary>
        /// <returns></returns>
        public string ComputeThumbprint(bool normalize)
        {
            var key = normalize ? Canonicalize() : this;
            var json = key.ToString();
            int jsonLength = json.Length;
            byte[] arrayToReturnToPool = null;
            Span<byte> buffer = jsonLength <= Constants.MaxStackallocBytes
                                ? stackalloc byte[jsonLength]
                                : (arrayToReturnToPool = ArrayPool<byte>.Shared.Rent(jsonLength)).AsSpan(0, jsonLength);
            try
            {
                Encoding.UTF8.GetBytes(json, buffer);
                using (var hashAlgorithm = SHA256.Create())
                {
                    Span<byte> hash = stackalloc byte[hashAlgorithm.HashSize >> 3];
                    hashAlgorithm.TryComputeHash(buffer, hash, out int bytesWritten);
                    Debug.Assert(bytesWritten == hashAlgorithm.HashSize >> 3);

                    return Base64Url.Base64UrlEncode(hash);
                }
            }
            finally
            {
                if (arrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturnToPool);
                }
            }
        }
#else
        /// <summary>
        /// Compute a hash as defined by https://tools.ietf.org/html/rfc7638.
        /// </summary>
        public string ComputeThumbprint(bool normalize)
        {
            var json = normalize ? Canonicalize().ToString() : ToString();
            var buffer = Encoding.UTF8.GetBytes(json);
            using (var hashAlgorithm = SHA256.Create())
            {
                var hash = hashAlgorithm.ComputeHash(buffer);
                return Base64Url.Base64UrlEncode(hash);
            }
        }
#endif

        /// <summary>
        /// Compute a hash as defined by https://tools.ietf.org/html/rfc7638.
        /// </summary>
        public string ComputeThumbprint() => ComputeThumbprint(true);

        /// <summary>
        /// Returns a new instance of <see cref="AsymmetricJwk"/>.
        /// </summary>
        /// <param name="certificate">A <see cref="X509Certificate2"/> that contains JSON Web Key parameters.</param>
        /// <param name="withPrivateKey">Determines if the private key must be extracted from the certificate.</param>
        public static AsymmetricJwk FromX509Certificate(X509Certificate2 certificate, bool withPrivateKey)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            AsymmetricJwk key = null;
            if (withPrivateKey)
            {
                using (var rsa = certificate.GetRSAPrivateKey())
                {
                    if (rsa != null)
                    {
                        var rsaParameters = rsa.ExportParameters(false);
                        key = new RsaJwk(rsaParameters);
                    }
#if !NETSTANDARD2_0
                    else
                    {
                        using (var ecdsa = certificate.GetECDsaPrivateKey())
                        {
                            if (ecdsa != null)
                            {
                                var ecParameters = ecdsa.ExportParameters(false);
                                key = new ECJwk(ecParameters);
                            }
                        }
                    }
#endif
                }
            }
            else
            {
                using (var rsa = certificate.GetRSAPublicKey())
                {
                    if (rsa != null)
                    {
                        var rsaParameters = rsa.ExportParameters(false);
                        key = new RsaJwk(rsaParameters);
                    }
#if !NETSTANDARD2_0
                    else
                    {
                        using (var ecdsa = certificate.GetECDsaPublicKey())
                        {
                            if (ecdsa != null)
                            {
                                var ecParameters = ecdsa.ExportParameters(false);
                                key = new ECJwk(ecParameters);
                            }
                        }
                    }
#endif
                }
            }

            if (key != null)
            {
                key.X5t = certificate.GetCertHash();
                key.Kid = key.ComputeThumbprint();
                return key;
            }

            Errors.ThrowInvalidCertificate();
            return null;
        }

        /// <summary>
        /// Returns a new instance of <typeparamref name="TKey"/>.
        /// </summary>
        /// <param name="json">A string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><typeparamref name="TKey"/></returns>
        public static TKey FromJson<TKey>(string json) where TKey : Jwk
        {
            if (string.IsNullOrEmpty(json))
            {
                throw new ArgumentNullException(nameof(json));
            }

            return JsonConvert.DeserializeObject<TKey>(json, jsonConverter);
        }

        /// <summary>
        /// Returns a new instance of <see cref="Jwk"/>.
        /// </summary>
        /// <param name="json">A string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="Jwk"/></returns>
        public static Jwk FromJson(string json)
        {
            return FromJson<Jwk>(json);
        }

        internal static byte[] CloneByteArray(byte[] array)
        {
            var clone = new byte[array.Length];
            array.CopyTo(clone, 0);
            return clone;
        }

        private string DebuggerDisplay()
        {
            return ToString(Formatting.Indented);
        }

        internal sealed class JwkJsonConverter : JsonConverter
        {
            public override bool CanWrite => true;

            public override bool CanConvert(Type objectType)
            {
                return typeof(Jwk).GetTypeInfo().IsAssignableFrom(objectType.GetTypeInfo());
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                var jsonObject = JObject.Load(reader);
                switch (jsonObject[JwkParameterNames.Kty].Value<string>())
                {
                    case JwkTypeNames.Rsa:
                        return jsonObject.ToObject<RsaJwk>();
                    case JwkTypeNames.EllipticCurve:
                        return jsonObject.ToObject<ECJwk>();
                    case JwkTypeNames.Octet:
                        return jsonObject.ToObject<SymmetricJwk>();
                    default:
                        throw new NotSupportedException();
                }
            }

            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                serializer.Serialize(writer, value);
            }
        }

        private sealed class JwkContractResolver : DefaultContractResolver
        {
            protected override IList<JsonProperty> CreateProperties(Type type, MemberSerialization memberSerialization)
            {
                IList<JsonProperty> properties = base.CreateProperties(type, memberSerialization);
                properties = properties.OrderBy(p => p.PropertyName).ToList();
                return properties;
            }
        }

#if NETCOREAPP3_0
        internal static unsafe Jwk FromJsonReader(ref Utf8JsonReader reader)
        {
            var properties = new JwkInfo();
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                        var propertyName = reader.ValueSpan;
                        fixed (byte* pPropertyByte = propertyName)
                        {
                            switch (propertyName.Length)
                            {
                                case 3:
                                    uint property = (uint)(((*(ushort*)pPropertyByte) << 8) | *(pPropertyByte + 2));
                                    if (property == 7629689u /* 'kty' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            fixed (byte* pKeyType = reader.ValueSpan)
                                            {
                                                switch (reader.ValueSpan.Length)
                                                {
                                                    case 2:
                                                        if (*(ushort*)pKeyType == 17221u /* 'EC' */)
                                                        {
                                                            properties.Kty = 17221u;
                                                            ECJwk.ReadJson(ref reader, ref properties);
                                                        }
                                                        break;
                                                    case 3:
                                                        uint keyType = (uint)(((*(ushort*)pPropertyByte) << 8) | *(pPropertyByte + 2));
                                                        if (keyType == 5460545u /* 'RSA' */)
                                                        {
                                                            properties.Kty = keyType;
                                                            RsaJwk.ReadJson(ref reader, ref properties);
                                                        }
                                                        else if (keyType == 6516596u /* 'oct' */)
                                                        {
                                                            properties.Kty = keyType;
                                                            SymmetricJwk.ReadJson(ref reader, ref properties);
                                                        }
                                                        else
                                                        {
                                                            ThrowHelper.NotSupportedKey(reader.GetStringValue());
                                                        }
                                                        break;
                                                    default:
                                                        ThrowHelper.NotSupportedKey(reader.GetStringValue());
                                                        break;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            ThrowHelper.FormatMalformedJson(JwkParameterNames.Kty, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7102823u /* 'alg' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            properties.Add(property, reader.GetStringValue());
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(JwkParameterNames.Alg, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 6908772u /* 'kid' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            properties.Add(property, reader.GetStringValue());
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(JwkParameterNames.Kid, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 7566693u /* 'use' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            properties.Add(property, reader.GetStringValue());
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(JwkParameterNames.Use, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 3504227u /* 'x5c' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.StartArray)
                                        {
                                            if (reader.TokenType == JsonTokenType.StartArray)
                                            {
                                                var x5c = new List<string>(2);
                                                while (reader.Read() && reader.TokenType == JsonTokenType.String)
                                                {
                                                    x5c.Add(reader.GetStringValue());
                                                }

                                                if (reader.TokenType != JsonTokenType.EndArray)
                                                {
                                                    ThrowHelper.FormatMalformedJson(JwkParameterNames.X5c, JsonTokenType.String);
                                                }

                                                properties.Add(property, x5c);
                                            }
                                            else if (reader.TokenType != JsonTokenType.Null)
                                            {
                                                ThrowHelper.FormatMalformedJson(JwkParameterNames.X5c, JsonTokenType.StartArray);
                                            }
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(JwkParameterNames.X5c, JsonTokenType.StartArray);
                                        }

                                    }
                                    else if (property == 3504244u /* 'x5t' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            properties.Add(property, reader.GetStringValue());
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(JwkParameterNames.X5t, JsonTokenType.String);
                                        }
                                    }
                                    else if (property == 3504245u /* 'x5u' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            properties.Add(property, reader.GetStringValue());
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(JwkParameterNames.X5u, JsonTokenType.String);
                                        }
                                    }
                                    break;
                                case 7:
                                    ulong propertyInt64 = (ulong)(*(uint*)pPropertyByte << 32) | (uint)(*(ushort*)pPropertyByte[4] << 16) | pPropertyByte[6];

                                    if (propertyInt64 == 104975004561267uL /* 'key_ops' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.StartArray)
                                        {
                                            if (reader.TokenType == JsonTokenType.StartArray)
                                            {
                                                var keyOps = new List<string>(2);
                                                while (reader.Read() && reader.TokenType == JsonTokenType.String)
                                                {
                                                    keyOps.Add(reader.GetStringValue());
                                                }

                                                if (reader.TokenType != JsonTokenType.EndArray)
                                                {
                                                    ThrowHelper.FormatMalformedJson(JwkParameterNames.KeyOps, JsonTokenType.String);
                                                }

                                                properties.Add(propertyInt64, reader.GetStringValue());
                                            }
                                            else if (reader.TokenType != JsonTokenType.Null)
                                            {
                                                ThrowHelper.FormatMalformedJson(JwkParameterNames.KeyOps, JsonTokenType.StartArray);
                                            }
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(JwkParameterNames.KeyOps, JsonTokenType.StartArray);
                                        }
                                    }
                                    break;
                                case 8:
                                    if (*(ulong*)pPropertyByte == 3906083584472266104uL /* 'x5t#S256' */)
                                    {
                                        if (reader.Read() && reader.TokenType == JsonTokenType.String)
                                        {
                                            properties.Add(3906083584472266104uL, reader.GetStringValue());
                                        }
                                        else if (reader.TokenType != JsonTokenType.Null)
                                        {
                                            ThrowHelper.FormatMalformedJson(JwkParameterNames.X5tS256, JsonTokenType.String);
                                        }
                                    }
                                    break;
                                default:
                                    break;
                            }
                        }
                        break;
                    case JsonTokenType.StartObject:
                        // Ignore object
                        JsonParser.ReadJson(ref reader);
                        break;
                    case JsonTokenType.StartArray:
                        // Ignore object
                        JsonParser.ReadJsonArray(ref reader);
                        break;
                    default:
                        break;
                }
            }

            Jwk key;
            switch (properties.Kty)
            {
                case 17221u /* 'EC' */:
                    key = new ECJwk(properties);
                    break;
                case 5460545u /* 'RSA' */:
                    key = new RsaJwk(properties);
                    break;
                case 6516596u /* 'oct' */:
                    key = new SymmetricJwk(properties);
                    break;
                default:
                    throw new Exception();
            }

            for (int i = 0; i < properties.Properties.Count; i++)
            {
                var property = properties[i];
                switch (property.Key)
                {
                    case 7102823u /* 'alg' */:
                        key.Alg = (string)property.Value;
                        break;
                    case 6908772u /* 'kid' */:
                        key.Kid = (string)property.Value;
                        break;
                    case 7566693u /* 'use' */:
                        key.Use = (string)property.Value;
                        break;
                    case 3504227u /* 'x5c' */:
                        key.X5c = (List<byte[]>)property.Value;
                        break;
                    case 3504244u /* 'x5t' */:
                        key.X5t = (byte[])property.Value;
                        break;
                    case 3504245u /* 'x5u' */:
                        key.X5u = (string)property.Value;
                        break;
                    case 104975004561267uL /* 'key_ops' */:
                        key.KeyOps = (List<string>)property.Value;
                        break;
                    case 3906083584472266104uL /* 'x5t#S256' */:
                        key.X5tS256 = (byte[])property.Value;
                        break;
                }
            }

            return key;
        }
#endif
    }
}
