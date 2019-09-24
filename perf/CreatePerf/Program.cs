using System;
using JsonWebToken;

namespace CreatePerf
{
    class Program
    {
        private static readonly Jwk signingKey = SymmetricJwk.GenerateKey(128, SignatureAlgorithm.HmacSha256);
        private static readonly Jwk encryptionKey = SymmetricJwk.GenerateKey(256, KeyManagementAlgorithm.Aes256KW);
        private static readonly JwtWriter writer = new JwtWriter();

        private static JwsDescriptor jwsDescriptor = new JwsDescriptor
        {
            IssuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc),
            ExpirationTime = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc),
            Issuer = "https://idp.example.com/",
            Audience = "636C69656E745F6964",
            SigningKey = signingKey
        };

        private static JweDescriptor jweDescriptor = new JweDescriptor
        {
            Payload = new JwsDescriptor
            {
                IssuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc),
                ExpirationTime = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc),
                Issuer = "https://idp.example.com/",
                Audience = "636C69656E745F6964",
                SigningKey = signingKey
            },
            EncryptionKey = encryptionKey,
            EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256
        };

        private static void Main()
        {
            Console.WriteLine("Starting...");
            writer.EnableHeaderCaching = false;
            writer.IgnoreTokenValidation = false;
            using (var buffer = new PooledByteBufferWriter())
            {
                while (true)
                {
                    writer.WriteToken(jwsDescriptor, buffer);
                    buffer.Clear();
                }
            }
        }
    }
}
