using System;
using System.Text;
using Newtonsoft.Json.Linq;
using Xunit;
using Xunit.Sdk;

namespace JsonWebToken.Tests
{
    public static class AssertJwt
    {
        public static void Equal(string jwt1, string jwt2)
        {
            string[] parts1 = jwt1.Split('.');
            string[] parts2 = jwt2.Split('.');
            if (parts1.Length != parts2.Length)
            {
                throw new EqualException(jwt1, jwt2);
            }

            // This is a JWS
            if (parts1.Length == 3)
            {
                // assert the signature
                Assert.Equal(parts1[2], parts2[2]);

                // assert the header
                var rawHeader1 = Base64Url.Decode(parts1[0]);
                var header1 = JObject.Parse(Encoding.UTF8.GetString(rawHeader1));

                var rawHeader2 = Base64Url.Decode(parts2[0]);
                var header2 = JObject.Parse(Encoding.UTF8.GetString(rawHeader2));

                Assert.Equal(header1, header2);

                // assert the payload
                var rawPayload1 = Base64Url.Decode(parts1[1]);
                var payload1 = JObject.Parse(Encoding.UTF8.GetString(rawPayload1));
                var rawPayload2 = Base64Url.Decode(parts2[1]);
                var payload2 = JObject.Parse(Encoding.UTF8.GetString(rawPayload2));

                Assert.Equal(payload1, payload2);
            }
            else if (parts1.Length == 5)
            {
                // This is a JWE

                // assert the header
                var rawHeader1 = Base64Url.Decode(parts1[0]);
                var header1 = JObject.Parse(Encoding.UTF8.GetString(rawHeader1));

                var rawHeader2 = Base64Url.Decode(parts2[0]);
                var header2 = JObject.Parse(Encoding.UTF8.GetString(rawHeader2));

                Assert.Equal(header1, header2);

                // assert the encrypted key
                Assert.Equal(parts1[1], parts2[1]);
                // assert the IV
                Assert.Equal(parts1[2], parts2[2]);
                // assert the authentication tag
                Assert.Equal(parts1[4], parts2[4]);

                // assert the payload
                throw new NotSupportedException();
            }
            else
            {
                throw new NotSupportedException();
            }
        }
    }
}
