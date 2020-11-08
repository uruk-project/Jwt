using System;
using JsonWebToken;

namespace CreatePerf
{
    class Program
    {
        private static readonly Jwk signingKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HmacSha512);
        private static readonly Jwk encryptionKey = SymmetricJwk.GenerateKey(KeyManagementAlgorithm.Aes256KW);
        private static readonly JwtWriter writer = new JwtWriter();

        private static readonly JwsDescriptor jwsDescriptor = new JwsDescriptor
        {
            Payload = new JwtPayload
            {
                { "iat", new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc).ToEpochTime() },
                { "exp", new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc).ToEpochTime() },
                { "iss", "https://idp.example.com/" },
                { "aud", "636C69656E745F6964" },
            },
            SigningKey = signingKey
        };

        private static readonly JweDescriptor jweDescriptor = new JweDescriptor
        {
            Payload = jwsDescriptor,
            EncryptionKey = encryptionKey,
            Enc = EncryptionAlgorithm.Aes256CbcHmacSha512
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
