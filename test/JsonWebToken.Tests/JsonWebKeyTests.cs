using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JsonWebKeyTests
    {
        [Theory]
        [MemberData(nameof(GetJsonKeys))]
        public void CreateFromJson(string json, string kid, string alg)
        {
            var jwk = JsonWebKey.FromJson(json);

            Assert.Equal(jwk.Kid, kid);
            Assert.Equal(jwk.Alg, alg);
        }

        [Theory]
        [MemberData(nameof(GetCertificates))]
        public void CreateFromCertificate(X509Certificate2 certificate, bool hasPrivateKey, int keySize)
        {
            var jwk = JsonWebKey.FromX509Certificate(certificate, hasPrivateKey);
            Assert.Equal(keySize, jwk.KeySize);
        }

        public static IEnumerable<object[]> GetJsonKeys()
        {
            var location = new Uri(typeof(JsonWebKeyTests).GetTypeInfo().Assembly.CodeBase).AbsolutePath;
            var dirPath = Path.GetDirectoryName(location);
            var keysPath = Path.Combine(dirPath, "./resources/jwks.json"); ;
            var keys = JArray.ReadFrom(new JsonTextReader(new StreamReader(keysPath)));
            foreach (var key in keys["keys"])
            {
                yield return new[] { key.ToString(), key["kid"].Value<string>(), key["alg"].Value<string>() };
            }
        }

        public static IEnumerable<object[]> GetCertificates()
        {
            return Keys.Certificates;
        }
    }
}
