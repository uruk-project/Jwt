using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
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
            var jwk = Jwk.FromJson(json);

            Assert.Equal(jwk.Kid, kid);
            Assert.Equal(jwk.Alg, alg);
        }

        [Theory]
        [MemberData(nameof(GetCertificates))]
        public void CreateFromCertificate(X509Certificate2 certificate, bool hasPrivateKey, int keySize)
        {
            var jwk = Jwk.FromX509Certificate(certificate, hasPrivateKey);
            Assert.Equal(keySize, jwk.KeySizeInBits);
        }

        public static IEnumerable<object[]> GetJsonKeys()
        {
            var location = new Uri(typeof(JsonWebKeyTests).GetTypeInfo().Assembly.CodeBase).AbsolutePath;
            var dirPath = Path.GetDirectoryName(location);
            var keysPath = Path.Combine(dirPath, "./resources/jwks.json"); ;
            var keys = JArray.ReadFrom(new JsonTextReader(new StreamReader(keysPath)));
            foreach (var key in keys["keys"])
            {
                yield return new object[] { key.ToString(), key["kid"].Value<string>(), key["alg"].Value<string>() };
            }
        }

        public static IEnumerable<object[]> GetCertificates()
        {
            return Keys.Certificates;
        }

        [Fact]
        public void Thumbprint()
        {
            // https://tools.ietf.org/html/rfc7638#section-3.1
            var key = new RsaJwk
            (
                e: "AQAB",
                n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            )
            {
                Kid = "2011-04-29",
                Alg = "RS256"
            };

            var thumbprint = key.ComputeThumbprint();

            Assert.Equal("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", thumbprint);
        }
    }
}
