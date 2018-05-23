using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Reflection;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a JSON Web Key as defined in http://tools.ietf.org/html/rfc7517.
    /// </summary>
    [JsonObject]
    public abstract class JsonWebKey
    {
        internal class JwkJsonConverter : JsonConverter
        {
            public override bool CanWrite => false;

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
                    case JsonWebAlgorithmsKeyTypes.RSA:
                        jwk = new RsaJwk();
                        break;
                    case JsonWebAlgorithmsKeyTypes.EllipticCurve:
                        jwk = new EcdsaJwk();
                        break;
                    case JsonWebAlgorithmsKeyTypes.Octet:
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
                throw new NotImplementedException();
            }
        }

        private static readonly JwkJsonConverter jsonConverter = new JwkJsonConverter();

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

            return (TKey)JsonConvert.DeserializeObject(json, typeof(TKey), jsonConverter);
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
        public abstract int KeySize { get; }

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

        public abstract bool IsSupportedAlgorithm(string algorithm);

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }

        public abstract SignatureProvider CreateSignatureProvider(string algorithm, bool willCreateSignatures);

        public void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {
            if (signatureProvider != null)
            {
                signatureProvider.Dispose();
            }
        }

        public abstract KeyWrapProvider CreateKeyWrapProvider(string algorithm);

        public void ReleaseKeyWrapProvider(KeyWrapProvider provider)
        {
            if (provider != null)
            {
                provider.Dispose();
            }
        }

        public abstract AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(string algorithm);

        public void ReleaseAuthenticatedEncryptionProvider(AuthenticatedEncryptionProvider provider)
        {
            if (provider != null)
            {
                provider.Dispose();
            }
        }
    }
}
