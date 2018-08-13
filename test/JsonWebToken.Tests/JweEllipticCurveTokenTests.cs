using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JweEllipticCurveTokenTests
    {
        private readonly EccJwk _bobKey = new EccJwk
        {
            Kty = "EC",
            Crv = "P-256",
            X = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            Y = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            D = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        };
        private readonly SymmetricJwk _signingKey = SymmetricJwk.GenerateKey(256, SignatureAlgorithm.HmacSha256.Name);

        [Theory]
        [InlineData(ContentEncryptionAlgorithms.Aes128CbcHmacSha256, KeyManagementAlgorithms.EcdhEs)]
        [InlineData(ContentEncryptionAlgorithms.Aes192CbcHmacSha384, KeyManagementAlgorithms.EcdhEs)]
        [InlineData(ContentEncryptionAlgorithms.Aes256CbcHmacSha512, KeyManagementAlgorithms.EcdhEs)]
        [InlineData(ContentEncryptionAlgorithms.Aes128CbcHmacSha256, KeyManagementAlgorithms.EcdhEsAes128KW)]
        [InlineData(ContentEncryptionAlgorithms.Aes128CbcHmacSha256, KeyManagementAlgorithms.EcdhEsAes192KW)]
        [InlineData(ContentEncryptionAlgorithms.Aes128CbcHmacSha256, KeyManagementAlgorithms.EcdhEsAes256KW)]
        public void Encode_Decode(string enc, string alg)
        {
            var writer = new JsonWebTokenWriter();

            var descriptor = new JweDescriptor
            {
                Key = _bobKey,
                EncryptionAlgorithm = (EncryptionAlgorithm)enc,
                Algorithm = alg,
                Payload = new JwsDescriptor
                {
                    Key = _signingKey,
                    Algorithm = SignatureAlgorithm.HmacSha256.Name,
                    Subject = "Alice"
                }
            };

            var token = writer.WriteToken(descriptor);

            var reader = new JsonWebTokenReader(_bobKey);
            var policy = new TokenValidationPolicyBuilder()
                .RequireSignature(_signingKey)
                    .Build();

            var result = reader.TryReadToken(token, policy);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
            Assert.Equal("Alice", result.Token.Subject);
        }
    }
}