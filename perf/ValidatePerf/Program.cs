using System;
using JsonWebToken;

namespace ValidatePerf
{
    class Program
    {
        private static readonly Jwk signingKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HmacSha256);
        private static readonly Jwk encryptionKey = SymmetricJwk.GenerateKey(EncryptionAlgorithm.Aes128CbcHmacSha256);

        private static void Main()
        {
            Console.WriteLine("Starting...");
            while (true)
            {
                Encode6();
            }
        }

        private static void Encode6()
        {
            JweDescriptor descriptor = new JweDescriptor(encryptionKey, KeyManagementAlgorithm.Direct, EncryptionAlgorithm.Aes128CbcHmacSha256)
            {
                Payload = new JwsDescriptor(Jwk.None, SignatureAlgorithm.None)
                {
                    Payload = new JwtPayload
                    {
                        { JwtClaimNames.Iat, 1500000000L },
                        { JwtClaimNames.Exp, 2000000000L },
                        { JwtClaimNames.Iss, "https://idp.example.com/" },
                        { JwtClaimNames.Aud, "636C69656E745F6964" },
                        { JwtClaimNames.Sub, "admin@example.com" },
                        { JwtClaimNames.Jti, "12345667890" }
                    }
                }
            };

            var bufferWriter2 = new PooledByteBufferWriter();
            var context2 = new EncodingContext(bufferWriter2, null, 0, false);
            descriptor.Encode(context2);
            bufferWriter2.Dispose();
        }
    }
}
