#if NETCOREAPP
using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JweEllipticCurveTokenTests
    {
        private readonly ECJwk _bobKey = new ECJwk
        (
            crv: EllipticalCurve.P256,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            d: "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
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

        [Fact]
        public void Issue578()
        {
            var alg = KeyManagementAlgorithm.EcdhEs;
            Assert.Equal("ECDH-ES", alg.Name);
            Assert.Equal(Algorithms.EcdhEs, alg.Id);
            Assert.Equal(AlgorithmCategory.Direct | AlgorithmCategory.EllipticCurve, alg.Category);
            Assert.False(alg.ProduceEncryptionKey);

            string json = "{\"alg\": \"ES256\",\"crv\": \"P-256\",\"kty\": \"EC\",\"use\": \"sig\",\"x\": \"OKs1T_4N9Z78RQ87olZ98PW__ROFWL5fw1671XB20zw\",\"y\": \"8y5YBG5RY4gK2bObN4Aj5eNmXBoLMrCHKEMwykPSTIg\"}";
            string payload = "teste";

            var descriptor = new PlaintextJweDescriptor(payload)
            {
                EncryptionKey = Jwk.FromJson(json),
                EncryptionAlgorithm = EncryptionAlgorithm.Aes256Gcm,
                Algorithm = KeyManagementAlgorithm.EcdhEs
            };

            var writer = new JwtWriter();
            string jwe = writer.WriteTokenString(descriptor);
            string[] parts = jwe.Split('.', System.StringSplitOptions.None);
            string cek = parts[1];
            System.Console.Write(jwe);
            Assert.Equal(
                "",
                cek);
        }

        public static IEnumerable<object[]> GetSupportedAlgorithm()
        {
            yield return new object[] { (string)EncryptionAlgorithm.Aes128CbcHmacSha256, (byte[])KeyManagementAlgorithm.EcdhEs };
            yield return new object[] { (string)EncryptionAlgorithm.Aes192CbcHmacSha384, (byte[])KeyManagementAlgorithm.EcdhEs };
            yield return new object[] { (string)EncryptionAlgorithm.Aes256CbcHmacSha512, (byte[])KeyManagementAlgorithm.EcdhEs };
#if SUPPORT_ELLIPTIC_CURVE
            yield return new object[] { (string)EncryptionAlgorithm.Aes128CbcHmacSha256, (byte[])KeyManagementAlgorithm.EcdhEsAes128KW };
            yield return new object[] { (string)EncryptionAlgorithm.Aes128CbcHmacSha256, (byte[])KeyManagementAlgorithm.EcdhEsAes192KW };
            yield return new object[] { (string)EncryptionAlgorithm.Aes128CbcHmacSha256, (byte[])KeyManagementAlgorithm.EcdhEsAes256KW };
#endif
            yield break;
        }
    }
}
#endif