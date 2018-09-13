using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JweEllipticCurveTokenTests
    {
        private readonly ECJwk _bobKey = new ECJwk
        {
            Kty = "EC",
            Crv = "P-256",
            X = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            Y = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            D = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        };
        private readonly SymmetricJwk _signingKey = SymmetricJwk.GenerateKey(256, SignatureAlgorithm.HmacSha256.Name);

        [Theory]
        [MemberData(nameof(GetSupportedAlgorithm))]
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

        public static IEnumerable<object[]> GetSupportedAlgorithm()
        {
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEs };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.EcdhEs };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEs };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes192KW };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes256KW };
        }
    }
}