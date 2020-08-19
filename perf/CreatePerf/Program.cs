using System;
using JsonWebToken;

namespace CreatePerf
{
    class Program
    {
        private static readonly Jwk signingKey = SymmetricJwk.GenerateKey(256, SignatureAlgorithm.HmacSha512);
        private static readonly Jwk encryptionKey = SymmetricJwk.GenerateKey(256, KeyManagementAlgorithm.Aes256KW);
        private static readonly JwtWriter writer = new JwtWriter();

        private static readonly JwsDescriptor jwsDescriptor = new JwsDescriptor
        {
            IssuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc),
            ExpirationTime = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc),
            Issuer = "https://idp.example.com/",
            Audience = "636C69656E745F6964",
            SigningKey = signingKey
        };

        private static readonly JweDescriptor jweDescriptor = new JweDescriptor
        {
            Payload = jwsDescriptor,
            EncryptionKey = encryptionKey,
            EncryptionAlgorithm = EncryptionAlgorithm.Aes256CbcHmacSha512
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
                    writer.WriteToken(jweDescriptor, buffer);
                }
            }
        }
    }
}
