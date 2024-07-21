#if NETCOREAPP
using System.Collections.Generic;
using JsonWebToken.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JweEllipticCurveTokenTests
    {
        private readonly ECJwk _bobKey = ECJwk.FromBase64Url
        (
            crv: EllipticalCurve.P256,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            d: "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        );
        private readonly SymmetricJwk _signingKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256);

        [Theory]
#if SUPPORT_ELLIPTIC_CURVE                                                         
        [InlineData("A128CBC-HS256", "ECDH-ES+A128KW")]
        [InlineData("A128CBC-HS256", "ECDH-ES+A192KW")]
        [InlineData("A128CBC-HS256", "ECDH-ES+A256KW")]
        [InlineData("A192CBC-HS384", "ECDH-ES+A128KW")]
        [InlineData("A192CBC-HS384", "ECDH-ES+A192KW")]
        [InlineData("A192CBC-HS384", "ECDH-ES+A256KW")]
        [InlineData("A256CBC-HS512", "ECDH-ES+A128KW")]
        [InlineData("A256CBC-HS512", "ECDH-ES+A192KW")]
        [InlineData("A256CBC-HS512", "ECDH-ES+A256KW")]
#endif
        [InlineData("A128CBC-HS256", "ECDH-ES")]
        [InlineData("A192CBC-HS384", "ECDH-ES")]
        [InlineData("A256CBC-HS512", "ECDH-ES")]
        public void Encode_Decode(string enc, string alg)
        {
            var writer = new JwtWriter();

            var descriptor = new JweDescriptor(_bobKey, (KeyManagementAlgorithm)alg, (EncryptionAlgorithm)enc)
            {
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HS256)
                {
                    Payload = new JwtPayload
                    {
                        {"sub", "Alice" }
                    }
                }
            };

            var token = writer.WriteToken(descriptor);

            var policy = new TokenValidationPolicyBuilder()
                .RequireSignatureByDefault(_signingKey)
                .WithDecryptionKey(_bobKey)
                .Build();

            var result = Jwt.TryParse(token, policy, out var jwt);
            Assert.True(result);
            Assert.True(jwt.Payload.TryGetClaim("sub", out var sub));
            Assert.Equal("Alice", sub.GetString());
            jwt.Dispose();
        }
    }
}
#endif