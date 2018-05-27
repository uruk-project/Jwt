using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace JsonWebToken
{
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

        public JsonWebKey JsonWebKey
        {
            get
            {
                var jwk = GetHeaderParameter(JwtHeaderParameterNames.Jwk);
                return string.IsNullOrEmpty(jwk) ? null : JsonWebKey.FromJson(jwk);
            }

            set => Header[JwtHeaderParameterNames.Jwk] = value?.ToString();
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
}
