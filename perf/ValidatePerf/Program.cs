using System;
using JsonWebToken;

namespace ValidatePerf
{
    class Program
    {
        private static readonly Jwk signingKey = SymmetricJwk.GenerateKey(128, SignatureAlgorithm.HmacSha256);
        private static readonly JwtWriter _writer = new JwtWriter();
        private static readonly JwsDescriptor jwsDescriptor = new JwsDescriptor()
        {
            IssuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc),
            ExpirationTime = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc),
            Issuer = "https://idp.example.com/",
            Audience = "636C69656E745F6964",
            SigningKey = signingKey
        };
        private static readonly byte[] jwsToken = _writer.WriteToken(jwsDescriptor);

        private static readonly Jwk encryptionKey = SymmetricJwk.GenerateKey(256, KeyManagementAlgorithm.Aes256KW);
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
        private static readonly byte[] jweToken = _writer.WriteToken(jweDescriptor);

        private static void Main()
        {
            var policy = new TokenValidationPolicyBuilder()
                .RequireSignature(signingKey)
                .RequireAudience("636C69656E745F6964")
                .RequireIssuer("https://idp.example.com/")
                .EnableLifetimeValidation()
                .DisabledHeaderCache()
                .Build();

            Console.WriteLine("Starting...");
            while (true)
            {
                Jwt.TryParse(jwsToken, policy, out Jwt document);
                document.Dispose();
            }
        }
    }
}
