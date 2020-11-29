using System;
using JsonWebToken;
using JsonWebToken.Cryptography;

namespace ValidatePerf
{
    class Program
    {
        private static readonly Jwk signingKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256);
        private static readonly Jwk encryptionKey = SymmetricJwk.GenerateKey(EncryptionAlgorithm.A128CbcHS256);
        private static readonly Jwk encryptionKey2 = ECJwk.GeneratePrivateKey(EllipticalCurve.P256, KeyManagementAlgorithm.EcdhEsA256KW);
        private static readonly ReadOnlyMemory<byte> _jws = CreateJws();
        private static readonly TokenValidationPolicy _policy =
            new TokenValidationPolicyBuilder()
            .RequireIssuer("https://idp.example.com/", signingKey, SignatureAlgorithm.HS256)
            .Build();

        private static void Main()
        {
            Console.WriteLine("Starting...");
            var span = _jws.Span;
            var writer = new JwtWriter();
            while (true)
            {
                Encode6(writer);
             //   bool success = Jwt.TryParse(span, _policy, out var jwt);
             //   jwt.Dispose();
            }
        }

        private static byte[] Encode6(JwtWriter writer)
        {
            JweDescriptor descriptor = new JweDescriptor(encryptionKey2, KeyManagementAlgorithm.EcdhEsA256KW, EncryptionAlgorithm.A256Gcm)
            {
                Payload = new JwsDescriptor(signingKey, SignatureAlgorithm.HS256)
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

            return writer.WriteToken(descriptor);
        }

        private static ReadOnlyMemory<byte> CreateJws()
        {
            var descriptor = new JwsDescriptor(signingKey, SignatureAlgorithm.HS256)
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
