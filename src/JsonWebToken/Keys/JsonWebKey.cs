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

namespace JsonWebToken
{
    internal sealed class SignatureAlgorithmConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(SignatureAlgorithm);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            return (SignatureAlgorithm)(string)reader.Value;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            writer.WriteValue(((SignatureAlgorithm)value).Name);
        }
    }
    internal sealed class CryptographicAlgorithmConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(EncryptionAlgorithm);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            return (EncryptionAlgorithm)(string)reader.Value;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            writer.WriteValue(((EncryptionAlgorithm)value).Name);
        }
    }

    /// <summary>
    /// Represents a JSON Web Key as defined in http://tools.ietf.org/html/rfc7517.
    /// </summary>
    [JsonObject]
    public abstract class JsonWebKey
    {
        internal sealed class JwkJsonConverter : JsonConverter
        {
            public override bool CanWrite => true;

            public override bool CanConvert(Type objectType)
            {
                return typeof(JsonWebKey).GetTypeInfo().IsAssignableFrom(objectType.GetTypeInfo());
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                var jsonObject = JObject.Load(reader);

                JsonWebKey jwk;
                switch (jsonObject[JsonWebKeyParameterNames.Kty].Value<string>())
                {
                    case JsonWebKeyTypeNames.Rsa:
                        jwk = new RsaJwk();
                        break;
                    case JsonWebKeyTypeNames.EllipticCurve:
                        jwk = new EccJwk();
                        break;
                    case JsonWebKeyTypeNames.Octet:
                        jwk = new SymmetricJwk();
                        break;
                    default:
                        throw new NotSupportedException();
                }

                serializer.Populate(jsonObject.CreateReader(), jwk);
                return jwk;
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

        private static readonly JwkJsonConverter jsonConverter = new JwkJsonConverter();
        private static readonly JwkContractResolver contractResolver = new JwkContractResolver();
        private static readonly JsonSerializerSettings serializerSettings = new JsonSerializerSettings { ContractResolver = contractResolver };

        private static readonly JsonSerializer jsonSerializer = new JsonSerializer() { Converters = { jsonConverter }, ContractResolver = contractResolver };
        private List<JsonWebKey> _certificateChain;

        /// <summary>
        /// Returns a new instance of <see cref="TKey"/>.
        /// </summary>
        /// <param name="json">A string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="TKey"/></returns>
        public static TKey FromJson<TKey>(string json) where TKey : JsonWebKey
        {
            if (string.IsNullOrEmpty(json))
            {
                throw new ArgumentNullException(nameof(json));
            }

            return JsonConvert.DeserializeObject<TKey>(json, jsonConverter);
        }

        /// <summary>
        /// Returns a new instance of <see cref="TKey"/>.
        /// </summary>
        /// <param name="jObject">A string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="TKey"/></returns>
        public static TKey FromJson<TKey>(JToken jObject) where TKey : JsonWebKey
        {
            if (jObject == null)
            {
                throw new ArgumentNullException(nameof(jObject));
            }

            return jObject.ToObject<TKey>(jsonSerializer);
        }

        /// <summary>
        /// Returns a new instance of <see cref="JsonWebKey"/>.
        /// </summary>
        /// <param name="json">A string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="JsonWebKey"/></returns>
        public static JsonWebKey FromJson(string json)
        {
            return FromJson<JsonWebKey>(json);
        }

        /// <summary>
        /// When deserializing from JSON any properties that are not defined will be placed here.
        /// </summary>
        [JsonExtensionData]
        public IDictionary<string, object> AdditionalData { get; } = new Dictionary<string, object>();

        /// <summary>
        /// Gets or sets the 'alg' (KeyType)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Alg, Required = Required.Default)]
        //[JsonConverter(typeof(SignatureAlgorithmConverter))]
        public string Alg { get; set; }

        /// <summary>
        /// Gets the 'key_ops' (Key Operations)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.KeyOps, Required = Required.Default)]
        public IList<string> KeyOps { get; private set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'kid' (Key ID)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Kid, Required = Required.Default)]
        public string Kid { get; set; }

        /// <summary>
        /// Gets or sets the 'kty' (Key Type)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Kty, Required = Required.Default)]
        public string Kty { get; set; }

        /// <summary>
        /// Gets or sets the 'use' (Public Key Use)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Use, Required = Required.Default)]
        public string Use { get; set; }

        /// <summary>
        /// Gets the 'x5c' collection (X.509 Certificate Chain)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5c, Required = Required.Default)]
        public IList<string> X5c { get; private set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'x5t' (X.509 Certificate SHA-1 thumbprint)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5t, Required = Required.Default)]
        public string X5t { get; set; }

        /// <summary>
        /// Gets or sets the 'x5t#S256' (X.509 Certificate SHA-1 thumbprint)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5tS256, Required = Required.Default)]
        public string X5tS256 { get; set; }

        /// <summary>
        /// Gets or sets the 'x5u' (X.509 URL)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5u, Required = Required.Default)]
        public string X5u { get; set; }

        /// <summary>
        /// Gets the key size of <see cref="JsonWebKey"/>.
        /// </summary>
        [JsonIgnore]
        public abstract int KeySizeInBits { get; }

        [JsonIgnore]
        public IList<JsonWebKey> X509CertificateChain
        {
            get
            {
                if (X5c == null)
                {
                    return null;
                }

                if (_certificateChain == null)
                {
                    _certificateChain = new List<JsonWebKey>();
                    foreach (var certString in X5c)
                    {
                        var certificate = new X509Certificate2(Convert.FromBase64String(certString));
                        var key = FromX509Certificate(certificate, false);
                        key.Kid = Kid;
                        _certificateChain.Add(key);
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

        public abstract bool IsSupportedAlgorithm(in SignatureAlgorithm algorithm);
        public abstract bool IsSupportedAlgorithm(in KeyManagementAlgorithm algorithm);
        public abstract bool IsSupportedAlgorithm(in EncryptionAlgorithm algorithm);

        public override string ToString()
        {
            return ToString(Formatting.None);
        }

        public string ToString(Formatting formatting)
        {
            return JsonConvert.SerializeObject(this, formatting, serializerSettings);
        }

        public abstract byte[] ToByteArray();

        public abstract SignatureProvider CreateSignatureProvider(in SignatureAlgorithm algorithm, bool willCreateSignatures);

        public void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {
            //if (signatureProvider != null)
            //{
            //    signatureProvider.Dispose();
            //}
        }

        public abstract KeyWrapProvider CreateKeyWrapProvider(in EncryptionAlgorithm encryptionAlgorithm, in KeyManagementAlgorithm contentEncryptionAlgorithm);

        public void ReleaseKeyWrapProvider(KeyWrapProvider provider)
        {
            //if (provider != null)
            //{
            //    provider.Dispose();
            //}
        }

        public abstract AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(in EncryptionAlgorithm encryptionAlgorithm);

        public void ReleaseAuthenticatedEncryptionProvider(AuthenticatedEncryptionProvider provider)
        {
            //if (provider != null)
            //{
            //    provider.Dispose();
            //}
        }

        public abstract JsonWebKey ExcludeOptionalMembers();

#if NETCOREAPP2_1
        /// <summary>
        /// Compute a hash as defined by https://tools.ietf.org/html/rfc7638.
        /// </summary>
        /// <returns></returns>
        public string ComputeThumbprint(bool excludeOptionalMembers = true)
        {
            var json = excludeOptionalMembers ? ExcludeOptionalMembers().ToString() : ToString();
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
                    Span<byte> hash = stackalloc byte[hashAlgorithm.HashSize / 8];
                    hashAlgorithm.TryComputeHash(buffer, hash, out int bytesWritten);
                    Debug.Assert(bytesWritten == hashAlgorithm.HashSize / 8);

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
        /// <returns></returns>
        public string ComputeThumbprint(bool excludeOptionalMembers = true)
        {
            var json = excludeOptionalMembers ? ExcludeOptionalMembers().ToString() : ToString();
            var buffer = Encoding.UTF8.GetBytes(json);
            using (var hashAlgorithm = SHA256.Create())
            {
                var hash = hashAlgorithm.ComputeHash(buffer);
                return Base64Url.Base64UrlEncode(hash);
            }
        }
#endif

        public static AsymmetricJwk FromX509Certificate(X509Certificate2 certificate, bool withPrivateKey)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            AsymmetricJwk key = null;
            if (withPrivateKey)
            {
                var rsa = certificate.GetRSAPrivateKey();
                if (rsa != null)
                {
                    var rsaParameters = rsa.ExportParameters(false);
                    key = new RsaJwk(rsaParameters);
                }
#if NETCOREAPP2_1
                else
                {
                    var ecdsa = certificate.GetECDsaPrivateKey();
                    if (ecdsa != null)
                    {
                        var ecParameters = ecdsa.ExportParameters(false);
                        key = new EccJwk(ecParameters);
                    }
                }
#endif
            }
            else
            {
                var rsa = certificate.GetRSAPublicKey();
                if (rsa != null)
                {
                    var rsaParameters = rsa.ExportParameters(false);
                    key = new RsaJwk(rsaParameters);
                }
#if NETCOREAPP2_1
                else
                {
                    var ecdsa = certificate.GetECDsaPublicKey();
                    if (ecdsa != null)
                    {
                        var ecParameters = ecdsa.ExportParameters(false);
                        key = new EccJwk(ecParameters);
                    }
                }
#endif
            }

            if (key == null)
            {
                throw new NotSupportedException(ErrorMessages.NotSupportedCertificate);
            }

            key.X5t = Base64Url.Encode(certificate.GetCertHash());
            key.Kid = key.ComputeThumbprint();
            key.X5t = Base64Url.Encode(certificate.GetCertHash());
            return key;
        }

        protected static byte[] CloneArray(byte[] array)
        {
            var clone = new byte[array.Length];
            array.CopyTo(clone, 0);
            return clone;
        }
    }
}
