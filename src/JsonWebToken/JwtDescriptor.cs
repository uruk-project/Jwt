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
            get => GetHeaderParameters(HeaderParameters.Cty);
            set => Header[HeaderParameters.Cty] = JArray.FromObject(value);
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

        protected string Serialize(object value)
        {
            return JsonConvert.SerializeObject(value, serializerSettings);
        }

        //public static JwtDescriptor FromJsonWebToken(JsonWebToken token)
        //{
        //    JwtDescriptor descriptor;
        //    if (token.Header.HasHeader(HeaderParameterNames.Enc))
        //    {
        //        if (token.NestedToken != null)
        //        {
        //            var d = new JweDescriptor();
        //            d.Payload = FromJsonWebToken(token.NestedToken) as JwsDescriptor;
        //            descriptor = d;
        //        }
        //        else if (token.PlainText != null)
        //        {
        //            var d = new PlaintextJweDescriptor();
        //            d.Payload = token.PlainText;
        //            descriptor = d;
        //        }
        //        else if (token.Binary != null)
        //        {
        //            var d = new BinaryJweDescriptor();
        //            d.Payload = token.Binary;
        //            descriptor = d;
        //        }
        //        else
        //        {
        //            throw new ArgumentException("The token type is not supported.", nameof(token));
        //        }
        //    }
        //    else
        //    {
        //        var d = new JwsDescriptor();
        //        foreach (var claim in token.Claims)
        //        {
        //            d.Payload[claim.Name] = claim.Value;
        //        }

        //        descriptor = d;
        //    }

        //    foreach (var header in token.HeaderParameters)
        //    {
        //        descriptor.Header[header.Name] = header.Value;
        //    }

        //    return descriptor;
        //}
    }
}
