using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JsonWebTokenWriterTests
    {
        public JsonWebTokenWriterTests()
        {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
        }

        [Theory]
        [MemberData(nameof(GetDescriptors))]
        public void Write(JsonWebTokenDescriptor descriptor)
        {
            JsonWebTokenWriter writer = new JsonWebTokenWriter();
            var value = writer.WriteToken(descriptor);

            var reader = new JsonWebTokenReader(Keys.Jwks);
            var result = reader.TryReadToken(value, TokenValidationParameters.NoValidation);
            var jwt = result.Token;

            Assert.Equal(descriptor.IssuedAt, jwt.Payload.Iat);
            Assert.Equal(descriptor.Expires, jwt.Expires);
            Assert.Equal(descriptor.Issuer, jwt.Issuer);
            Assert.Equal(descriptor.Audience, jwt.Audiences.First());
            Assert.Equal(descriptor.Id, jwt.Id);
        }

        public static IEnumerable<object[]> GetDescriptors()
        {
            foreach (var key in Keys.Jwks.Keys.Where(k => k.Use == "sig"))
            {
                foreach (var jwt in Tokens.Descriptors)
                {
                    jwt.SigningKey = key;
                    //yield return new object[] { jwt };
                }
            }

            var encryptionAlgorithms = new[] { SecurityAlgorithms.Aes128CbcHmacSha256, SecurityAlgorithms.Aes192CbcHmacSha384, SecurityAlgorithms.Aes256CbcHmacSha512 };
            foreach (var encKey in Keys.Jwks.Keys.Where(k => k.Use == JsonWebKeyUseNames.Enc))
            {
                string alg;
                if (encKey.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                {
                    switch (encKey.KeySize)
                    {
                        case 128:
                            alg = SecurityAlgorithms.Aes128KW;
                            break;
                        case 256:
                            alg = SecurityAlgorithms.Aes256KW;
                            break;
                        case 2048:
                            alg = SecurityAlgorithms.Direct;
                            break;
                        default:
                            continue;
                    }
                }
                else if (encKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
                {
                    alg = SecurityAlgorithms.RsaOAEP;
                    // SecurityAlgorithms.RsaPKCS1
                }
                else
                {
                    continue;
                }

                foreach (var enc in encryptionAlgorithms)
                {
                    var sigKey = Keys.Jwks.Keys.First(k => k.Use == "sig");
                    foreach (var jwt in Tokens.Descriptors)
                    {
                        jwt.SigningKey = sigKey;
                        jwt.EncryptingKey = encKey;
                        jwt.EncryptionAlgorithm = enc;
                        jwt.ContentEncryptionAlgorithm = alg;
                        yield return new object[] { jwt };
                    }
                }
            }
        }
    }
}