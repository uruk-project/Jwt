#if NETCOREAPP2_1 || NETCOREAPP3_0
using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JweEllipticCurveTokenTests
    {
        private readonly ECJwk _bobKey = new ECJwk
        (
            crv : EllipticalCurve.P256,
            x : "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y : "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            d : "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        );
        private readonly SymmetricJwk _signingKey = SymmetricJwk.GenerateKey(256, SignatureAlgorithm.HmacSha256);

        [Theory]
        [MemberData(nameof(GetSupportedAlgorithm))]
        public void Encode_Decode(string enc, byte[] alg)
        {
            var writer = new JwtWriter();

            var descriptor = new JweDescriptor
            {
                EncryptionKey = _bobKey,
                EncryptionAlgorithm = (EncryptionAlgorithm)enc,
                Algorithm = (KeyManagementAlgorithm)alg,
                Payload = new JwsDescriptor
                {
                    SigningKey = _signingKey,
                    Algorithm = SignatureAlgorithm.HmacSha256,
                    Subject = "Alice"
                }
            };

            var token = writer.WriteToken(descriptor);

            var reader = new JwtReader(_bobKey);
            var policy = new TokenValidationPolicyBuilder()
                .RequireSignature(_signingKey)
                    .Build();

            var result = reader.TryReadToken(token, policy);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
            Assert.Equal("Alice", result.Token.Subject);
        }

        public static IEnumerable<object[]> GetSupportedAlgorithm()
        {
            yield return new object[] { (string)EncryptionAlgorithm.Aes128CbcHmacSha256.Name, (byte[])KeyManagementAlgorithm.EcdhEs };
            yield return new object[] { (string)EncryptionAlgorithm.Aes192CbcHmacSha384.Name, (byte[])KeyManagementAlgorithm.EcdhEs };
            yield return new object[] { (string)EncryptionAlgorithm.Aes256CbcHmacSha512.Name, (byte[])KeyManagementAlgorithm.EcdhEs };
#if NETCOREAPP3_0
            yield return new object[] { (string)EncryptionAlgorithm.Aes128CbcHmacSha256.Name, (byte[])KeyManagementAlgorithm.EcdhEsAes128KW };
            yield return new object[] { (string)EncryptionAlgorithm.Aes128CbcHmacSha256.Name, (byte[])KeyManagementAlgorithm.EcdhEsAes192KW };
            yield return new object[] { (string)EncryptionAlgorithm.Aes128CbcHmacSha256.Name, (byte[])KeyManagementAlgorithm.EcdhEsAes256KW };
#endif
            yield break;
        }
    }
}
#endif