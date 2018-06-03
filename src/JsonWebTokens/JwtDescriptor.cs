using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Linq;

namespace JsonWebTokens
{
    public abstract class JwtDescriptor
    {
        private static readonly Dictionary<string, JTokenType[]> DefaultRequiredHeaderParameters = new Dictionary<string, JTokenType[]>();
        private JsonWebKey _key;

        public JwtDescriptor()
        {
            Header = new JObject();
        }

        public JObject Header { get; set; }

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
            get => GetHeaderParameter(HeaderParameterNames.Alg);
            set => Header[HeaderParameterNames.Alg] = value;
        }

        public string KeyId
        {
            get => GetHeaderParameter(HeaderParameterNames.Kid);
            set => Header[HeaderParameterNames.Kid] = value;
        }

        public string JwkSetUrl
        {
            get => GetHeaderParameter(HeaderParameterNames.Jku);
            set => Header[HeaderParameterNames.Jku] = value;
        }

        public JsonWebKey JsonWebKey
        {
            get
            {
                var jwk = GetHeaderParameter(HeaderParameterNames.Jwk);
                return string.IsNullOrEmpty(jwk) ? null : JsonWebKey.FromJson(jwk);
            }

            set => Header[HeaderParameterNames.Jwk] = value?.ToString();
        }

        public string X509Url
        {
            get => GetHeaderParameter(HeaderParameterNames.X5u);
            set => Header[HeaderParameterNames.X5u] = value;
        }

        public IList<string> X509CertificateChain
        {
            get => GetHeaderParameters(HeaderParameterNames.X5c);
            set => Header[HeaderParameterNames.X5c] = JArray.FromObject(value);
        }

        public string X509CertificateSha1Thumbprint
        {
            get => GetHeaderParameter(HeaderParameterNames.X5t);
            set => Header[HeaderParameterNames.X5t] = value;
        }

        public string Type
        {
            get => GetHeaderParameter(HeaderParameterNames.Typ);
            set => Header[HeaderParameterNames.Typ] = value;
        }

        public string ContentType
        {
            get => GetHeaderParameter(HeaderParameterNames.Cty);
            set => Header[HeaderParameterNames.Cty] = value;
        }

        public IList<string> Critical
        {
            get => GetHeaderParameters(HeaderParameterNames.Cty);
            set => Header[HeaderParameterNames.Cty] = JArray.FromObject(value);
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
        protected bool HasMandatoryHeaderParameter(string header)
        {
            return Header.TryGetValue(header, out var value) && value.Type != JTokenType.Null;
        }

        public virtual void Validate()
        {
            foreach (var header in RequiredHeaderParameters)
            {
                JToken token;
                if (!Header.TryGetValue(header.Key, out token) || token.Type == JTokenType.Null)
                {
                    throw new JwtDescriptorException(ErrorMessages.FormatInvariant("The header parameter '{0}' is required.", header.Key));
                }

                bool headerFound = false;
                for (int i = 0; i < header.Value.Length; i++)
                {
                    if (token?.Type == header.Value[i])
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
    }
}
