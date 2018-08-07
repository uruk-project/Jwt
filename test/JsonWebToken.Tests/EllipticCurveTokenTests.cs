using Xunit;

namespace JsonWebToken.Tests
{
    public class EllipticCurveTokenTests
    {
        private readonly ECJwk _aliceKey = new ECJwk
        {
            Kty = "EC",
            Crv = "P-256",
            X = "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            Y = "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            D = "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
            Alg = KeyManagementAlgorithms.EcdhEsAes128KW
        };
        private readonly ECJwk _bobKey = new ECJwk
        {
            Kty = "EC",
            Crv = "P-256",
            X = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            Y = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            D = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        };
        private readonly SymmetricJwk _signingKey = SymmetricJwk.GenerateKey(256, SignatureAlgorithms.HmacSha256);

        [Fact]
        public void Encode_Decode()
        {
            var writer = new JsonWebTokenWriter();

            var descriptor = new JweDescriptor
            {
                Key = _bobKey,
                EncryptionAlgorithm = ContentEncryptionAlgorithms.Aes128CbcHmacSha256,
                Algorithm = KeyManagementAlgorithms.EcdhEsAes192KW,
                Payload = new JwsDescriptor
                {
                    Key = _signingKey,
                    Algorithm = SignatureAlgorithms.HmacSha256,
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
        }
    }
}