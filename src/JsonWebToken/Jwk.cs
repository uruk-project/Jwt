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
using System.Text.Json;

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
        public IList<string> KeyOps { get; private set; } = new List<string>();

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
        public List<byte[]> X5c { get; private set; } = new List<byte[]>();

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

        internal unsafe static Jwk FromJsonReader(ref Utf8JsonReader reader)
        {
            bool fastPath = true;
            JwtObject jwk = null;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndObject:
                        return FromJwtObject(jwk);

                    case JsonTokenType.PropertyName:
                        var nameSpan = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                        if (fastPath && nameSpan.SequenceEqual(JwkParameterNames.KtyUtf8))
                        {
                            reader.Read();
                            var valueSpan = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                            fixed (byte* pKty = valueSpan)
                            {
                                var pKtyShort = (short*)pKty;
                                switch (valueSpan.Length)
                                {
                                    case 2:
                                        if (*pKtyShort == 17221u)
                                        {
                                            return ECJwk.FromJsonReaderFast(ref reader);
                                        }

                                        Errors.ThrowNotSupportedJwk(Encoding.UTF8.GetString(valueSpan.ToArray()));
                                        break;
                                    case 3:
                                        switch (*pKtyShort)
                                        {
                                            case 21330 when *(pKty + 2) == (byte)'A' /* RSA */:
                                                return RsaJwk.FromJsonReaderFast(ref reader);
                                            case 25455 when *(pKty + 2) == (byte)'t' /* oct */:
                                                return SymmetricJwk.FromJsonReaderFast(ref reader);
                                            default:
                                                Errors.ThrowNotSupportedJwk(Encoding.UTF8.GetString(valueSpan.ToArray()));
                                                break;
                                        }
                                        break;
                                    default:
                                        Errors.ThrowNotSupportedJwk(Encoding.UTF8.GetString(valueSpan.ToArray()));
                                        break;
                                }
                            }
                        }

                        if(fastPath)
                        {
                            fastPath = false;
                            jwk = new JwtObject();
                        }

                        var name = nameSpan.ToArray();
                        reader.Read();
                        var type = reader.TokenType;
                        switch (type)
                        {
                            case JsonTokenType.String:
                                jwk.Add(new JwtProperty(name, reader.GetString()));
                                break;
                            case JsonTokenType.StartObject:
                                var jwtObject = JsonParser.ReadJson(ref reader);
                                jwk.Add(new JwtProperty(name, jwtObject));
                                break;
                            case JsonTokenType.True:
                                jwk.Add(new JwtProperty(name, true));
                                break;
                            case JsonTokenType.False:
                                jwk.Add(new JwtProperty(name, false));
                                break;
                            case JsonTokenType.Null:
                                jwk.Add(new JwtProperty(name));
                                break;
                            case JsonTokenType.Number:
                                if (reader.TryGetInt64(out long longValue))
                                {
                                    jwk.Add(new JwtProperty(name, longValue));
                                }
                                else
                                {
                                    if (reader.TryGetDouble(out double doubleValue))
                                    {
                                        jwk.Add(new JwtProperty(name, doubleValue));
                                    }
                                    else
                                    {
                                        JwtThrowHelper.FormatNotSupportedNumber(Encoding.UTF8.GetString(name));
                                    }
                                }
                                break;
                            case JsonTokenType.StartArray:
                                var array = JsonParser.ReadJsonArray(ref reader);
                                jwk.Add(new JwtProperty(name, array));
                                break;
                            default:
                                JwtThrowHelper.FormatMalformedJson();
                                break;
                        }
                        break;
                    default:
                        JwtThrowHelper.FormatMalformedJson();
                        break;
                }
            }

            return FromJwtObject(jwk);
        }

        private static Jwk FromJwtObject(JwtObject jwk)
        {
            if (jwk.TryGetValue(JwkParameterNames.KtyUtf8, out var property))
            {
                switch ((string)property.Value)
                {
                    case JwkTypeNames.Octet:
                        return SymmetricJwk.Populate(jwk);

                    case JwkTypeNames.EllipticCurve:
                        return ECJwk.Populate(jwk);

                    case JwkTypeNames.Rsa:
                        return RsaJwk.Populate(jwk);

                    default:
                        break;
                }
            }

            Errors.ThrowMalformedKey();
            return null;
        }

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
                    var thumbprint = Base64Url.Base64UrlEncode(hash);
#if !NETSTANDARD2_0
                    return Encoding.UTF8.GetString(thumbprint);
#else
                    return EncodingHelper.GetUtf8String(thumbprint);
#endif
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
                return Encoding.UTF8.GetString(Base64Url.Base64UrlEncode(hash));
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
            protected override IList<Newtonsoft.Json.Serialization.JsonProperty> CreateProperties(Type type, MemberSerialization memberSerialization)
            {
                var properties = base.CreateProperties(type, memberSerialization);
                properties = properties.OrderBy(p => p.PropertyName).ToList();
                return properties;
            }
        }

        internal void Populate(ReadOnlySpan<byte> name, string value)
        {
            if (name.SequenceEqual(JwkParameterNames.AlgUtf8))
            {
                Alg = value;
            }
            else if (name.SequenceEqual(JwkParameterNames.KidUtf8))
            {
                Kid = value;
            }
            else if (name.SequenceEqual(JwkParameterNames.UseUtf8))
            {
                Use = value;
            }
            else if (name.SequenceEqual(JwkParameterNames.X5uUtf8))
            {
                X5u = value;
            }
        }

        internal void Populate(ReadOnlySpan<byte> name, JwtArray value)
        {
            if (name.SequenceEqual(JwkParameterNames.X5cUtf8))
            {
                for (int i = 0; i < value.Count; i++)
                {
                    X5c.Add((byte[])value[i].Value);
                }
            }
            else if (name.SequenceEqual(JwkParameterNames.KeyOpsUtf8))
            {
                for (int i = 0; i < value.Count; i++)
                {
                    KeyOps.Add((string)value[i].Value);
                }
            }
        }

        internal void Populate(ReadOnlySpan<byte> name, byte[] value)
        {
            if (name.SequenceEqual(JwkParameterNames.X5tS256Utf8))
            {
                X5tS256 = value;
            }
            else if (name.SequenceEqual(JwkParameterNames.X5tUtf8))
            {
                X5t = value;
            }
        }

        internal static unsafe void PopulateEight(ref Utf8JsonReader reader, byte* pPropertyName, Jwk key)
        {
            if (*(ulong*)pPropertyName == 3906083584472266104u /* x5t#s256 */)
            {
                key.X5tS256 = Base64Url.Base64UrlDecode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
            }
        }

        internal static unsafe void PopulateArray(ref Utf8JsonReader reader, byte* pPropertyName, int propertyLength, Jwk key)
        {
            if (propertyLength == 7 && *((uint*)pPropertyName) == 1601791339u /* key_ */ && *((uint*)pPropertyName + 3) == 1936748383 /* _ops */)
            {
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    key.KeyOps.Add(reader.GetString());
                }
            }
            else
            {
                JsonParser.ReadJsonArray(ref reader);
            }
        }

        internal static unsafe void PopulateObject(ref Utf8JsonReader reader, byte* pPropertyName, int propertyLength, Jwk key)
        {
            JsonParser.ReadJson(ref reader);
        }

        internal static unsafe void PopulateThree(ref Utf8JsonReader reader, byte* pPropertytName, Jwk key)
        {
            short* pPropertyNameShort = (short*)(pPropertytName + 1);
            switch (*pPropertytName)
            {
                case (byte)'a' when *pPropertyNameShort == 26476 /* alg */ :
                    key.Alg = reader.GetString();
                    break;
                case (byte)'k' when *pPropertyNameShort == 25705 /* kid */ :
                    key.Kid = reader.GetString();
                    break;
                case (byte)'u' when *pPropertyNameShort == 25971 /* use */ :
                    key.Use = reader.GetString();
                    break;
                case (byte)'x' when *pPropertyNameShort == 25397 /* x5c */ :
                    while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                    {
                        var x5xItem = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                        key.X5c.Add(Base64Url.Base64UrlDecode(x5xItem));
                    }
                    break;
                case (byte)'x' when *pPropertyNameShort == 29749 /* x5t */ :
                    key.X5t = Base64Url.Base64UrlDecode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                    break;
                case (byte)'x' when *pPropertyNameShort == 30005 /* x5u */ :
                    key.X5u = reader.GetString();
                    break;

                default:
                    break;
            }
        }
    }
}
