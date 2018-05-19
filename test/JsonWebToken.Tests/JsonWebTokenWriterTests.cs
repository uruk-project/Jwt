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
            var jwt2 = reader.TryReadToken(value, ValidationBuilder.NoValidation);

            var handler = new JwtSecurityTokenHandler();
            //var jwt = handler.ReadJwtToken(value);

            var claims = new List<Claim>
            {
                new Claim("jti", jwt2.Token.Id)
            }            ;
            var identity = new ClaimsIdentity(claims);
            var wilsonDescriptor = new SecurityTokenDescriptor()
            {
                Expires = jwt2.Token.Expires,
                IssuedAt = jwt2.Token.Payload.Iat,
                Issuer = jwt2.Token.Issuer,
                Audience = jwt2.Token.Audiences.First(),
                Subject = identity,
                EncryptingCredentials = new EncryptingCredentials(Microsoft.IdentityModel.Tokens.JsonWebKey.Create(descriptor.EncryptingKey.ToString()), descriptor.EncryptingKey.Alg, descriptor.EncryptionAlgorithm),
                SigningCredentials = new SigningCredentials(Microsoft.IdentityModel.Tokens.JsonWebKey.Create(descriptor.SigningKey.ToString()), descriptor.SigningKey.Alg)
            };
            var wilsonJwt = handler.CreateEncodedJwt(wilsonDescriptor);
            var test = handler.ValidateToken(wilsonJwt, new Microsoft.IdentityModel.Tokens.TokenValidationParameters()
            {
                TokenDecryptionKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(descriptor.EncryptingKey.ToString()),
                IssuerSigningKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(descriptor.SigningKey.ToString()),
                ValidAudience = descriptor.Audience, 
                ValidIssuer = descriptor.Issuer
            }, out var validatedToken);

            var jwt = validatedToken as JwtSecurityToken;
            Assert.Equal(EpochTime.GetIntDate(descriptor.IssuedAt), jwt.Payload.Iat.Value);
            Assert.Equal(descriptor.Expires, jwt.ValidTo);
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
                    //  yield return new object[] { jwt };
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
                        encKey.Alg = alg;
                        jwt.EncryptingKey = encKey;
                        jwt.EncryptionAlgorithm = enc;
                        yield return new object[] { jwt };
                    }
                }
            }
        }
    }
}