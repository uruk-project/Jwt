using System;
using JsonWebToken;

namespace CreatePerf
{
    class Program
    {
        private static readonly Jwk signingKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HmacSha512);
        private static readonly Jwk encryptionKey = SymmetricJwk.GenerateKey(KeyManagementAlgorithm.Aes256KW);
        private static readonly JwtWriter writer = new JwtWriter();

        private static readonly JwsDescriptor jwsDescriptor = new JwsDescriptor(signingKey, SignatureAlgorithm.HmacSha512)
        {
            Payload = new JwtPayload
            {
                { "iat", new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc).ToEpochTime() },
                { "exp", new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc).ToEpochTime() },
                { "iss", "https://idp.example.com/" },
                { "aud", "636C69656E745F6964" },
            },
        };

        private static readonly JweDescriptor jweDescriptor = new JweDescriptor(encryptionKey, KeyManagementAlgorithm.Aes256KW, EncryptionAlgorithm.Aes256CbcHmacSha512)
        {
            Payload = jwsDescriptor,
        };

        private static void Main()
        {
            Console.WriteLine("Starting...");
            writer.EnableHeaderCaching = false;
            writer.IgnoreTokenValidation = false;
            var buffer = new System.Buffers.ArrayBufferWriter<byte>();
            while (true)
            {
                writer.WriteToken(jweDescriptor, buffer);
            }
        }
    }
}
