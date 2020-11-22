using System;
using JsonWebToken;
using JsonWebToken.Cryptography;

namespace ValidatePerf
{
    class Program
    {
        private static readonly Jwk signingKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HmacSha256);
        private static readonly Jwk encryptionKey = SymmetricJwk.GenerateKey(EncryptionAlgorithm.Aes128CbcHmacSha256);
        private static readonly ReadOnlyMemory<byte> _jws = CreateJws();
        private static readonly TokenValidationPolicy _policy =
            new TokenValidationPolicyBuilder()
            .RequireIssuer("https://idp.example.com/", signingKey, SignatureAlgorithm.HmacSha256)
            .Build();

        private static void Main()
        {
            Console.WriteLine("Starting...");
            var span = _jws.Span;
            while (true)
            {
                bool success = Jwt.TryParse(span, _policy, out var jwt);
                jwt.Dispose();
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

            var bufferWriter2 = new System.Buffers.ArrayBufferWriter<byte>();
            var context2 = new EncodingContext(bufferWriter2, null, 0, false);
            descriptor.Encode(context2);
        }

        private static ReadOnlyMemory<byte> CreateJws()
        {
            var descriptor = new JwsDescriptor(signingKey, SignatureAlgorithm.HmacSha256)
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
            };

            var bufferWriter = new System.Buffers.ArrayBufferWriter<byte>();
            var context = new EncodingContext(bufferWriter, null, 0, false);
            descriptor.Encode(context);
            return bufferWriter.WrittenMemory;
        }
    }
}
