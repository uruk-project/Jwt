using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;

namespace JsonWebToken
{
    public abstract class JwtDescriptor
    {
        private static readonly JsonSerializerSettings serializerSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore
        };

        private static readonly Dictionary<string, JTokenType[]> DefaultRequiredHeaderParameters = new Dictionary<string, JTokenType[]>();
        private JsonWebKey _key;

        public JwtDescriptor()
            :this(new JObject())
        {
        }

        public JwtDescriptor(JObject header)
        {
            Header = header;
        }

        public JObject Header { get; }

        public JsonWebKey Key
        {
            get => _key;
            set
            {
                _key = value;
                Algorithm = value.Alg;
                KeyId = value.Kid;
            }
        }

        protected virtual IReadOnlyDictionary<string, JTokenType[]> RequiredHeaderParameters => DefaultRequiredHeaderParameters;

        public string Algorithm
        {
            get => GetHeaderParameter(HeaderParameters.Alg);
            set => Header[HeaderParameters.Alg] = value;
        }
        
        public string KeyId
        {
            get => GetHeaderParameter(HeaderParameters.Kid);
            set => Header[HeaderParameters.Kid] = value;
        }

        public string JwkSetUrl
        {
            get => GetHeaderParameter(HeaderParameters.Jku);
            set => Header[HeaderParameters.Jku] = value;
        }

        public JsonWebKey JsonWebKey
        {
            get
            {
                var jwk = GetHeaderParameter(HeaderParameters.Jwk);
                return string.IsNullOrEmpty(jwk) ? null : JsonWebKey.FromJson(jwk);
            }

            set => Header[HeaderParameters.Jwk] = value?.ToString();
        }

        public string X509Url
        {
            get => GetHeaderParameter(HeaderParameters.X5u);
            set => Header[HeaderParameters.X5u] = value;
        }

        public IList<string> X509CertificateChain
        {
            get => GetHeaderParameters(HeaderParameters.X5c);
            set => Header[HeaderParameters.X5c] = JArray.FromObject(value);
        }

        public string X509CertificateSha1Thumbprint
        {
            get => GetHeaderParameter(HeaderParameters.X5t);
            set => Header[HeaderParameters.X5t] = value;
        }

        public string Type
        {
            get => GetHeaderParameter(HeaderParameters.Typ);
            set => Header[HeaderParameters.Typ] = value;
        }

        public string ContentType
        {
            get => GetHeaderParameter(HeaderParameters.Cty);
            set => Header[HeaderParameters.Cty] = value;
        }

        public IList<string> Critical
        {
            get => GetHeaderParameters(HeaderParameters.Crit);
            set => Header[HeaderParameters.Crit] = JArray.FromObject(value);
        }

        public abstract string Encode(EncodingContext context);

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
                var list = value as IList<string>;
                if (value.Type == JTokenType.Array)
                {
                    return new List<string>(value.Values<string>());
                }
                else
                {
                    var strValue = value.Value<string>();
                    if (strValue != null)
                    {
                        return new List<string>(new[] { strValue });
                    }
                }
            }

            return null;
        }

        protected bool HasMandatoryHeaderParameter(string header)
        {
            return Header.TryGetValue(header, out var value) && value != null;
        }

        public virtual void Validate()
        {
            foreach (var header in RequiredHeaderParameters)
            {
                if (!Header.TryGetValue(header.Key, out JToken token) || token.Type == JTokenType.Null)
                {
                    throw new JwtDescriptorException(ErrorMessages.FormatInvariant("The header parameter '{0}' is required.", header.Key));
                }

                bool headerFound = false;
                for (int i = 0; i < header.Value.Length; i++)
                {
                    if (token.Type == header.Value[i])
                    {
                        headerFound = true;
                        break;
                    }
                }

                if (!headerFound)
                {
                    throw new JwtDescriptorException(ErrorMessages.FormatInvariant("The header parameter '{0}' must be of type [{1}].", header.Key, string.Join(", ", header.Value.Select(t => t.ToString()))));
                }
            }
        }

        protected string Serialize(object value)
        {
            return JsonConvert.SerializeObject(value, serializerSettings);
        }
    }
}
