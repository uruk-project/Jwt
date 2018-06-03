using Newtonsoft.Json.Linq;
using System;
using System.Security.Cryptography.X509Certificates;

namespace JsonWebTokens
{
    public class X5uKeyProvider : HttpKeyProvider
    {
        public X5uKeyProvider(HttpDocumentRetriever documentRetriever)
            : base(documentRetriever)
        {
        }

        public override JsonWebKeySet GetKeys(JObject header)
        {
            return GetKeys(header, header[HeaderParameterNames.X5u]?.Value<string>());
        }

        protected override JsonWebKeySet DeserializeKeySet(string value)
        {
            var certificate = new X509Certificate2(Convert.FromBase64String(value));

            return new JsonWebKeySet(new[] { ConvertFromX509(certificate) });
        }

        /// <summary>
        /// Convert X509 security key into json web key.
        /// </summary>
        /// <param name="certificate">X509 security key</param>
        /// <returns>json web key</returns>
        private static JsonWebKey ConvertFromX509(X509Certificate2 certificate)
        {
            var jsonWebKey = new RsaJwk();
            jsonWebKey.Kty = JsonWebAlgorithmsKeyTypes.RSA;
            jsonWebKey.Use = JsonWebKeyUseNames.Sig;
            jsonWebKey.Kid = certificate.Thumbprint;
            jsonWebKey.X5t = Base64Url.Encode(certificate.GetCertHash());
            if (certificate.RawData != null)
            {
                jsonWebKey.X5c.Add(Convert.ToBase64String(certificate.RawData));
            }

            return jsonWebKey;
        }
    }
}