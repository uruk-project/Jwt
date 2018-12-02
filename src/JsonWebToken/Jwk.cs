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

        private static readonly JsonSerializer jsonSerializer = new JsonSerializer { Converters = { jsonConverter }, ContractResolver = contractResolver };
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
        public string Kty { get; set; }

        /// <summary>
        /// Gets or sets the 'use' (Public Key Use).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.Use, Required = Required.Default)]
        public string Use { get; set; }

        /// <summary>
        /// Gets the 'x5c' collection (X.509 Certificate Chain).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.X5c, Required = Required.Default)]
        public List<string> X5c { get; private set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'x5t' (X.509 Certificate SHA-1 thumbprint).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.X5t, Required = Required.Default)]
        public string X5t { get; set; }

        /// <summary>
        /// Gets or sets the 'x5t#S256' (X.509 Certificate SHA-1 thumbprint).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.X5tS256, Required = Required.Default)]
        public string X5tS256 { get; set; }

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
                        using (var certificate = new X509Certificate2(Convert.FromBase64String(certString)))
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
        public abstract Jwk Normalize();

#if NETCOREAPP2_1
        /// <summary>
        /// Compute a hash as defined by https://tools.ietf.org/html/rfc7638.
        /// </summary>
        /// <returns></returns>
        public string ComputeThumbprint(bool normalize)
        {
            var key = normalize ? Normalize() : this;
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
            var json = normalize ? Normalize().ToString() : ToString();
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
#if NETCOREAPP2_1
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
#if NETCOREAPP2_1
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
                key.X5t = Base64Url.Base64UrlEncode(certificate.GetCertHash());
                key.Kid = key.ComputeThumbprint();
                return key;
            }

            Errors.ThrowInvalidCertificate();
            return null;
        }

        /// <summary>
        /// Returns a new instance of <see cref="TKey"/>.
        /// </summary>
        /// <param name="json">A string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="TKey"/></returns>
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
    }
}
